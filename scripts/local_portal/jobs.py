"""
Background analysis jobs for the local portal.

Each job runs the same pipeline as the CLI (collector.run + write_report)
in a worker thread, writes reports/<subscription>/ and refreshes
reports/README.md. Progress is kept in memory for the dashboard to poll.
"""

import logging
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("arg.portal.jobs")

ACTIVE_STATES = ("queued", "running")


@dataclass
class Job:
    id: str
    subscription_id: str
    subscription_name: str
    status: str = "queued"          # queued | running | completed | failed
    message: str = "Queued"
    step: int = 0
    total: int = 0
    queued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    folder: Optional[str] = None
    findings: Optional[int] = None
    error: Optional[str] = None

    @property
    def percent(self) -> int:
        return int(100 * self.step / self.total) if self.total else 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["percent"] = self.percent
        return data


def default_runner(credential: Any, subscription_id: str, reports_dir: Path,
                   progress: Callable[[str, int, int], None]) -> Dict[str, Any]:
    """Run the full analysis for one subscription and write its report folder."""
    from scripts.subscription_analysis.cli import analyse_one, default_config
    from scripts.subscription_analysis.estate import refresh_estate
    from scripts.subscription_analysis.report import write_index

    data, model, target = analyse_one(credential, subscription_id, reports_dir, None,
                                      config=default_config(), progress=progress)
    refresh_estate(reports_dir)
    write_index(reports_dir)
    return {"folder": target.name, "findings": len(data.findings)}


class JobManager:
    def __init__(self, reports_dir: Path, credential_provider: Callable[[], Any], *,
                 max_workers: int = 2, runner: Callable[..., Dict[str, Any]] = default_runner):
        self.reports_dir = reports_dir
        self._credential_provider = credential_provider
        self._runner = runner
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="arg-analysis")
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, subscription_id: str, subscription_name: str) -> Job:
        with self._lock:
            for job in self._jobs.values():
                if job.subscription_id == subscription_id and job.status in ACTIVE_STATES:
                    return job
            job = Job(id=uuid.uuid4().hex[:12], subscription_id=subscription_id,
                      subscription_name=subscription_name or subscription_id)
            self._jobs[job.id] = job
        self._executor.submit(self._run, job)
        return job

    def list(self) -> List[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.queued_at, reverse=True)

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def _update(self, job: Job, **changes: Any) -> None:
        with self._lock:
            for key, value in changes.items():
                setattr(job, key, value)

    def _run(self, job: Job) -> None:
        self._update(job, status="running", started_at=datetime.now(timezone.utc).isoformat(), message="Starting")

        def progress(message: str, step: int, total: int) -> None:
            self._update(job, message=message, step=step, total=total)

        try:
            result = self._runner(self._credential_provider(), job.subscription_id, self.reports_dir, progress)
            self._update(job, status="completed", message="Report ready", step=job.total or 1, total=job.total or 1,
                         folder=result.get("folder"), findings=result.get("findings"),
                         finished_at=datetime.now(timezone.utc).isoformat())
        except Exception as exc:
            logger.error("Analysis of %s failed: %s\n%s", job.subscription_id, exc, traceback.format_exc())
            self._update(job, status="failed", message="Failed", error=str(exc).splitlines()[0][:500] if str(exc) else
                         exc.__class__.__name__, finished_at=datetime.now(timezone.utc).isoformat())

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
