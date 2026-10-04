"""
Observability Agent — merges logging persistence and report generation.
Consumes LogEntry messages and exposes report generation APIs.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import date, datetime, timedelta
from typing import Literal

from sqlalchemy import func, select

from backend.agents.queues import get_queues
from backend.database.connection import session_context
from backend.database.models import AttackEventModel, IncidentModel, MitigationActionModel
from backend.logs_module.db_logger import write_log_entry
from backend.logs_module.file_logger import write_to_log_file
from backend.models.messages import LogEntry
from backend.metrics import increment_events_processed

logger = logging.getLogger(__name__)

_BUFFER_MAX = 10_000
_FLUSH_INTERVAL = 5  # seconds between buffer flush attempts
_MAX_RETRIES = 3


class Report:
    def __init__(
        self,
        report_type: str,
        period_start: date,
        period_end: date,
        generated_at: datetime,
        attack_counts: dict[str, int] | None = None,
        total_events: int = 0,
        total_mitigations: int = 0,
        mttd_by_type: dict[str, float] | None = None,
        mttr_by_type: dict[str, float] | None = None,
    ) -> None:
        self.report_type = report_type
        self.period_start = period_start
        self.period_end = period_end
        self.generated_at = generated_at
        self.attack_counts = attack_counts or {}
        self.total_events = total_events
        self.total_mitigations = total_mitigations
        self.mttd_by_type = mttd_by_type or {}
        self.mttr_by_type = mttr_by_type or {}


class ObservabilityAgent:
    """
    Handles logging persistence and reporting.
    """

    def __init__(self) -> None:
        self._buffer: deque[LogEntry] = deque(maxlen=_BUFFER_MAX)
        self._file_buffer: deque[LogEntry] = deque(maxlen=_BUFFER_MAX)
        self._running = False
        self._task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None
        self._written = 0
        self._dropped = 0
        self._reports_generated = 0

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("ObservabilityAgent started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._flush_buffer()
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        logger.info("ObservabilityAgent stopped — written=%d dropped=%d reports=%d",
                    self._written, self._dropped, self._reports_generated)

    async def _run(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                entry: LogEntry = await asyncio.wait_for(
                    queues.logging_queue.get(), timeout=1.0
                )
                await self.log_event(entry)
                queues.logging_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("ObservabilityAgent consumer error: %s", exc)

    async def log_event(self, entry: LogEntry) -> None:
        increment_events_processed("ObservabilityAgent")
        try:
            await write_log_entry(entry)
            self._written += 1
        except Exception as exc:
            logger.error("DB log write failed: %s. Buffering.", exc)
            self._buffer.append(entry)

        try:
            await write_to_log_file(entry)
        except Exception as exc:
            logger.debug("File log write failed (buffering): %s", exc)
            self._file_buffer.append(entry)

    async def _flush_loop(self) -> None:
        while self._running:
            await asyncio.sleep(_FLUSH_INTERVAL)
            if self._buffer or self._file_buffer:
                await self._flush_buffer()

    async def _flush_buffer(self) -> None:
        flushed_db = 0
        failed_db: list[LogEntry] = []
        while self._buffer:
            entry = self._buffer.popleft()
            try:
                await write_log_entry(entry)
                flushed_db += 1
                self._written += 1
                try:
                    await write_to_log_file(entry)
                except Exception as exc:
                    logger.debug("File log write failed during DB flush (buffering): %s", exc)
                    self._file_buffer.append(entry)
            except Exception:
                failed_db.append(entry)
        for entry in failed_db:
            self._buffer.append(entry)

        flushed_file = 0
        failed_file: list[LogEntry] = []
        while self._file_buffer:
            entry = self._file_buffer.popleft()
            try:
                await write_to_log_file(entry)
                flushed_file += 1
            except Exception:
                failed_file.append(entry)
        for entry in failed_file:
            self._file_buffer.append(entry)

        if flushed_db or flushed_file:
            logger.info("Flushed %d DB logs, %d File logs from buffer", flushed_db, flushed_file)

    async def generate_daily_report(self, report_date: date) -> Report:
        return await self._generate_with_retry("daily", report_date, report_date + timedelta(days=1))

    async def generate_weekly_report(self, week_start: date) -> Report:
        return await self._generate_with_retry("weekly", week_start, week_start + timedelta(days=7))

    async def generate_monthly_report(self, month: int, year: int) -> Report:
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, month + 1, 1)
        return await self._generate_with_retry("monthly", start, end)

    async def _generate_with_retry(self, report_type: str, start: date, end: date) -> Report:
        last_exc = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                return await self._build_report(report_type, start, end)
            except Exception as exc:
                last_exc = exc
                logger.warning("Report generation attempt %d failed: %s", attempt, exc)
        logger.error("Report generation failed after %d attempts: %s", _MAX_RETRIES, last_exc)
        return Report(
            report_type=report_type,
            period_start=start,
            period_end=end,
            generated_at=datetime.utcnow(),
        )

    async def _build_report(self, report_type: str, start: date, end: date) -> Report:
        report = Report(
            report_type=report_type,
            period_start=start,
            period_end=end,
            generated_at=datetime.utcnow(),
        )
        start_dt = datetime.combine(start, datetime.min.time())
        end_dt = datetime.combine(end, datetime.min.time())

        async with session_context() as session:
            rows = await session.execute(
                select(AttackEventModel.attack_type, func.count())
                .where(AttackEventModel.timestamp >= start_dt)
                .where(AttackEventModel.timestamp < end_dt)
                .group_by(AttackEventModel.attack_type)
            )
            for attack_type, count in rows:
                report.attack_counts[attack_type or "unknown"] = count
                report.total_events += count

            mit_count = await session.scalar(
                select(func.count(MitigationActionModel.id))
                .where(MitigationActionModel.created_at >= start_dt)
                .where(MitigationActionModel.created_at < end_dt)
            )
            report.total_mitigations = mit_count or 0

        report.mttd_by_type = await self.calculate_mttd_all(start_dt, end_dt)
        report.mttr_by_type = await self.calculate_mttr_all(start_dt, end_dt)
        self._reports_generated += 1
        return report

    async def calculate_mttd(self, attack_type: str, start: datetime | None = None, end: datetime | None = None) -> float:
        if start is None:
            end = datetime.utcnow()
            start = end - timedelta(days=30)
        elif end is None:
            end = datetime.utcnow()
        all_mttd = await self.calculate_mttd_all(start, end)
        return all_mttd.get(attack_type, 0.0)

    async def calculate_mttr(self, attack_type: str, start: datetime | None = None, end: datetime | None = None) -> float:
        if start is None:
            end = datetime.utcnow()
            start = end - timedelta(days=30)
        elif end is None:
            end = datetime.utcnow()
        all_mttr = await self.calculate_mttr_all(start, end)
        return all_mttr.get(attack_type, 0.0)

    async def calculate_mttd_all(self, start: datetime, end: datetime) -> dict[str, float]:
        async with session_context() as session:
            rows = await session.execute(
                select(
                    AttackEventModel.attack_type,
                    func.avg(
                        func.extract("epoch", IncidentModel.detected_at)
                        - func.extract("epoch", AttackEventModel.timestamp)
                    ).label("mttd_seconds")
                )
                .join(IncidentModel, AttackEventModel.incident_id == IncidentModel.id)
                .where(AttackEventModel.timestamp >= start)
                .where(AttackEventModel.timestamp < end)
                .where(AttackEventModel.incident_id.isnot(None))
                .group_by(AttackEventModel.attack_type)
            )
            result = {}
            for attack_type, mttd in rows:
                result[attack_type or "unknown"] = max(0.0, float(mttd or 0.0))
            return result

    async def calculate_mttr_all(self, start: datetime, end: datetime) -> dict[str, float]:
        async with session_context() as session:
            rows = await session.execute(
                select(
                    IncidentModel.attack_type,
                    func.avg(
                        func.extract("epoch", IncidentModel.resolved_at)
                        - func.extract("epoch", IncidentModel.detected_at)
                    ).label("mttr_seconds")
                )
                .where(IncidentModel.detected_at >= start)
                .where(IncidentModel.detected_at < end)
                .where(IncidentModel.resolved_at.isnot(None))
                .group_by(IncidentModel.attack_type)
            )
            result = {}
            for attack_type, mttr in rows:
                result[attack_type or "unknown"] = max(0.0, float(mttr or 0.0))
            return result

    def export_report(self, report: Report, fmt: Literal["json", "csv"]) -> bytes:
        data = {
            "report_type": report.report_type,
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "generated_at": report.generated_at.isoformat(),
            "total_events": report.total_events,
            "total_mitigations": report.total_mitigations,
            "attack_counts": report.attack_counts,
            "mttd_by_type": report.mttd_by_type,
            "mttr_by_type": report.mttr_by_type,
        }
        if fmt == "json":
            import json
            return json.dumps(data, indent=2).encode()

        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["metric", "value"])
        for k, v in data.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    writer.writerow([f"{k}.{sub_k}", sub_v])
            else:
                writer.writerow([k, v])
        return buf.getvalue().encode()
