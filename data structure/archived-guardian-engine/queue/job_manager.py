import os
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Callable, Optional
from pydantic import BaseModel, Field

class JobStatus(BaseModel):
    job_id: str
    job_type: str
    status: str  # QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED
    progress: int = 0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

class JobManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(JobManager, cls).__new__(cls)
                cls._instance.jobs: Dict[str, JobStatus] = {}
                cls._instance.executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="guardian_worker_")
            return cls._instance

    def submit_job(self, job_type: str, task_func: Callable, *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())
        status = JobStatus(
            job_id=job_id,
            job_type=job_type,
            status="QUEUED",
            progress=0
        )
        self.jobs[job_id] = status

        def run_wrapper():
            status.status = "RUNNING"
            status.updated_at = time.time()
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

        self.executor.submit(run_wrapper)
        return job_id

    def get_job_status(self, job_id: str) -> Optional[JobStatus]:
        return self.jobs.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        if job_id in self.jobs and self.jobs[job_id].status in ["QUEUED", "RUNNING"]:
            self.jobs[job_id].status = "CANCELLED"
            self.jobs[job_id].updated_at = time.time()
            return True
        return False

job_manager = JobManager()
