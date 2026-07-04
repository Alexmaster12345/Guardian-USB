"""APScheduler setup and job management backed by the ScheduledJob table."""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from guardian.automation import tasks
from guardian.core.models import ScheduledJob
from guardian.database.engine import session_scope

logger = logging.getLogger("guardian.scheduler")

_TASK_MAP = {
    "scan": tasks.scan_task,
    "report": tasks.report_task,
    "alert": tasks.alert_task,
    "update": tasks.update_task,
}


class GuardianScheduler:
    """Manages scheduled jobs using APScheduler + persistence in the DB."""

    def __init__(self) -> None:
        self.scheduler = BackgroundScheduler()

    def start(self) -> None:
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Scheduler started")
        self.load_jobs()

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def _make_callable(self, job_type: str, target: str | None):
        func = _TASK_MAP.get(job_type)
        if func is None:
            raise ValueError(f"Unknown job type: {job_type}")

        def runner():
            try:
                if job_type == "scan":
                    func(target_range=target)
                else:
                    func()
                self._record_run(target, job_type)
            except Exception as exc:
                logger.exception("Job %s failed: %s", job_type, exc)

        return runner

    def add_job(self, name: str, job_type: str, cron_expression: str,
                target: str | None = None, enabled: bool = True) -> ScheduledJob:
        with session_scope() as session:
            job = ScheduledJob(
                name=name, job_type=job_type, cron_expression=cron_expression,
                target=target, enabled=enabled,
            )
            session.merge(job)
            session.flush()
            session.expunge(job)
        if enabled:
            self._schedule(name, job_type, cron_expression, target)
        return job

    def remove_job(self, name: str) -> bool:
        removed = False
        if self.scheduler.get_job(name):
            self.scheduler.remove_job(name)
            removed = True
        with session_scope() as session:
            obj = session.query(ScheduledJob).filter_by(name=name).one_or_none()
            if obj:
                session.delete(obj)
                removed = True
        return removed

    def list_jobs(self) -> list[ScheduledJob]:
        with session_scope() as session:
            jobs = session.query(ScheduledJob).all()
            for j in jobs:
                session.expunge(j)
            return jobs

    def load_jobs(self) -> None:
        for job in self.list_jobs():
            if job.enabled:
                try:
                    self._schedule(job.name, job.job_type, job.cron_expression, job.target)
                except Exception as exc:
                    logger.warning("Failed to schedule %s: %s", job.name, exc)

    def _schedule(self, name, job_type, cron_expression, target) -> None:
        trigger = CronTrigger.from_crontab(cron_expression)
        self.scheduler.add_job(
            self._make_callable(job_type, target),
            trigger=trigger, id=name, replace_existing=True,
        )
        logger.info("Scheduled job %s (%s) [%s]", name, job_type, cron_expression)

    @staticmethod
    def _record_run(target, job_type) -> None:
        from datetime import datetime, timezone
        with session_scope() as session:
            obj = session.query(ScheduledJob).filter_by(job_type=job_type, target=target).first()
            if obj:
                obj.last_run = datetime.now(timezone.utc)
