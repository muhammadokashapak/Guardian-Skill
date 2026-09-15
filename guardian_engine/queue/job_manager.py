import os
import json
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Callable, Optional
from pydantic import BaseModel, Field

try:
    import redis
    HAS_REDIS_LIB = True
except ImportError:
    HAS_REDIS_LIB = False

class JobStatus(BaseModel):
    job_id: str
    job_type: str
    status: str  # QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED
    progress: int = 0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    broker: str = "local"

class JobManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(JobManager, cls).__new__(cls)
                cls._instance.jobs: Dict[str, JobStatus] = {}
                cls._instance.executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="guardian_worker_")
                cls._instance.redis_client = None
                cls._instance._init_redis()
            return cls._instance

    def _init_redis(self):
        redis_host = os.environ.get("REDIS_HOST")
        redis_port = int(os.environ.get("REDIS_PORT", "6379"))
        if HAS_REDIS_LIB and redis_host:
            try:
                client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    socket_connect_timeout=2,
                    decode_responses=True
                )
                client.ping()
                self.redis_client = client
            except Exception:
                # Fallback to local memory if Redis server is not reachable
                self.redis_client = None

    def get_broker_info(self) -> Dict[str, Any]:
        return {
            "broker_type": "redis" if self.redis_client else "local_threadpool",
            "redis_connected": self.redis_client is not None,
            "active_workers": 5
        }

    def submit_job(self, job_type: str, task_func: Callable, *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())
        broker_type = "redis" if self.redis_client else "local_threadpool"
        status = JobStatus(
            job_id=job_id,
            job_type=job_type,
            status="QUEUED",
            progress=0,
            broker=broker_type
        )
        self.jobs[job_id] = status

        if self.redis_client:
            try:
                self.redis_client.set(f"guardian:job:{job_id}", status.model_dump_json(), ex=86400)
                self.redis_client.lpush("guardian:jobs:queue", job_id)
            except Exception:
                pass

        def run_wrapper():
            status.status = "RUNNING"
            status.updated_at = time.time()
            if self.redis_client:
                try:
                    self.redis_client.set(f"guardian:job:{job_id}", status.model_dump_json(), ex=86400)
                except Exception:
                    pass

            try:
                res = task_func(*args, **kwargs)
                status.status = "COMPLETED"
                status.progress = 100
                status.result = res if isinstance(res, dict) else {"data": str(res)}
            except Exception as e:
                status.status = "FAILED"
                status.error = str(e)
            finally:
                status.updated_at = time.time()
                if self.redis_client:
                    try:
                        self.redis_client.set(f"guardian:job:{job_id}", status.model_dump_json(), ex=86400)
                    except Exception:
                        pass

        self.executor.submit(run_wrapper)
        return job_id

    def get_job_status(self, job_id: str) -> Optional[JobStatus]:
        if self.redis_client:
            try:
                val = self.redis_client.get(f"guardian:job:{job_id}")
                if val:
                    data = json.loads(val)
                    return JobStatus(**data)
            except Exception:
                pass
        return self.jobs.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        if job_id in self.jobs and self.jobs[job_id].status in ["QUEUED", "RUNNING"]:
            self.jobs[job_id].status = "CANCELLED"
            self.jobs[job_id].updated_at = time.time()
            if self.redis_client:
                try:
                    self.redis_client.set(f"guardian:job:{job_id}", self.jobs[job_id].model_dump_json(), ex=86400)
                except Exception:
                    pass
            return True
        return False

job_manager = JobManager()
