import os
import sys
import json
import time
import signal
import logging
from typing import Optional, Dict, Any

from .queue.job_manager import JobStatus
from .db.database import SessionLocal, init_db
from .db.models import Scan as DBScan, Finding as DBFinding, Project as DBProject
from .core.models import FindingSeverity, FindingStatus
from .scanners import ScanManager
from .core.audit_logger import AuditLogger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [GuardianWorker] %(message)s")
logger = logging.getLogger("GuardianWorker")

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

class GuardianQueueWorker:
    def __init__(self, redis_host: Optional[str] = None, redis_port: Optional[int] = None, queue_name: str = "guardian:jobs:queue"):
        self.redis_host = redis_host or os.environ.get("REDIS_HOST")
        self.redis_port = int(redis_port or os.environ.get("REDIS_PORT", 6379))
        self.queue_name = queue_name
        self.running = True
        self.redis_client = None
        self.audit_logger = AuditLogger()
        self.scan_manager = ScanManager(self.audit_logger)

        if HAS_REDIS and self.redis_host:
            try:
                self.redis_client = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    socket_connect_timeout=2,
                    decode_responses=True
                )
                self.redis_client.ping()
                logger.info(f"Connected to Redis broker at {self.redis_host}:{self.redis_port}")
            except Exception as e:
                logger.warning(f"Could not connect to Redis at {self.redis_host}:{self.redis_port}: {e}. Worker will operate in standalone mode.")
                self.redis_client = None
        else:
            logger.info("REDIS_HOST not configured. Worker initialized in standalone mode.")

    def stop(self):
        logger.info("Stopping Guardian Queue Worker...")
        self.running = False

    def process_job(self, job_data: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a queued task and updates persistent storage."""
        job_id = job_data.get("job_id")
        job_type = job_data.get("job_type", "UNKNOWN")
        payload = job_data.get("payload", {})
        logger.info(f"Processing job {job_id} of type {job_type}")

        if job_type == "PROJECT_SCAN":
            project_id = payload.get("project_id")
            root_path = payload.get("root_path")
            scan_id = payload.get("scan_id")

            db = SessionLocal()
            try:
                findings = self.scan_manager.run_full_scan(project_id, root_path)
                for f in findings:
                    db_finding = DBFinding(
                        id=f.id,
                        scan_id=scan_id,
                        project_id=project_id,
                        fingerprint=f.fingerprint,
                        category=f.category,
                        severity=f.severity.value,
                        confidence=f.confidence,
                        status=f.status.value,
                        title=f.title,
                        summary=f.summary,
                        affected_path=f.affected_path,
                        line_start=f.line_start,
                        line_end=f.line_end,
                        root_cause=f.root_cause,
                        impact=f.impact,
                        remediation=f.remediation,
                        source_tool=f.source_tool
                    )
                    db.merge(db_finding)

                cur_scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
                if cur_scan:
                    import datetime
                    cur_scan.status = "COMPLETED"
                    cur_scan.findings_count = len(findings)
                    cur_scan.finished_at = datetime.datetime.utcnow()
                    db.commit()

                return {"status": "SUCCESS", "findings_count": len(findings)}
            finally:
                db.close()

        elif job_type == "HEALTH_PROBE":
            return {"status": "HEALTHY", "timestamp": time.time()}

        return {"status": "SKIPPED", "reason": f"Unknown job type {job_type}"}

    def run_once(self, timeout: int = 1) -> bool:
        """Polls Redis once for a job. Returns True if a job was processed, False otherwise."""
        if not self.redis_client:
            return False

        try:
            item = self.redis_client.brpop(self.queue_name, timeout=timeout)
            if not item:
                return False

            _, raw_data = item
            try:
                job_data = json.loads(raw_data)
            except Exception:
                job_data = {"job_id": raw_data, "job_type": "UNKNOWN"}

            job_id = job_data.get("job_id")
            if job_id and self.redis_client:
                # Update status to RUNNING in Redis
                self.redis_client.set(f"guardian:job:{job_id}:status", "RUNNING", ex=86400)

            result = self.process_job(job_data)

            if job_id and self.redis_client:
                self.redis_client.set(f"guardian:job:{job_id}:status", "COMPLETED", ex=86400)
                self.redis_client.set(f"guardian:job:{job_id}:result", json.dumps(result), ex=86400)

            return True
        except Exception as e:
            logger.error(f"Error executing job from queue: {e}")
            return False

    def start(self):
        """Continuously processes jobs from the Redis queue."""
        logger.info(f"Guardian Worker started. Listening on queue '{self.queue_name}'...")
        while self.running:
            try:
                processed = self.run_once(timeout=2)
                if not processed:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                time.sleep(1)
        logger.info("Guardian Worker shutdown complete.")

def main():
    init_db()
    worker = GuardianQueueWorker()

    def handle_signal(sig, frame):
        worker.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    worker.start()

if __name__ == "__main__":
    main()
