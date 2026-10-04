"""
Analysis Agent — combines supervised detection and Isolation Forest anomaly scoring.
Consumes FeatureVectors from detection_queue and anomaly_queue, emits ThreatScore to risk_queue.
"""
from __future__ import annotations

import asyncio
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from backend.agents.queues import get_queues, safe_put
from backend.ml.inference import MLInferencePipeline
from backend.models.messages import AttackEvent, FeatureVector, LogEntry, ThreatScore
from backend.utils.config_loader import BaselineProfile
from backend.metrics import increment_events_processed

logger = logging.getLogger(__name__)

_LEARNING_DAYS_DEFAULT = 7


class AnalysisAgent:
    """
    Combines the supervised DetectionAgent and anomaly-detection AnomalyAgent.
    """

    def __init__(self, pipeline: MLInferencePipeline | None = None) -> None:
        self._pipeline = pipeline or MLInferencePipeline()
        self._running = False
        self._task: asyncio.Task | None = None
        self._detection_task: asyncio.Task | None = None
        self._anomaly_task: asyncio.Task | None = None
        self._safe_mode_detection = False
        self._safe_mode_anomaly = False
        self._safe_mode = False
        self.learning_mode = False
        self._learning_end: datetime | None = None
        self._learning_stats: dict[str, list[float]] = defaultdict(list)
        self._classified = 0
        self._scored = 0

    async def start(self) -> None:
        await self._load_model()
        self._running = True
        self._detection_task = asyncio.create_task(self._run_detection())
        self._anomaly_task = asyncio.create_task(self._run_anomaly())
        self._task = asyncio.create_task(self._monitor_tasks())
        logger.info(
            "AnalysisAgent started (safe_mode_detection=%s safe_mode_anomaly=%s learning=%s)",
            self._safe_mode_detection,
            self._safe_mode_anomaly,
            self.learning_mode,
        )

    async def stop(self) -> None:
        self._running = False
        for task in (self._detection_task, self._anomaly_task, self._task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        logger.info(
            "AnalysisAgent stopped — %d flows classified, %d scored",
            self._classified,
            self._scored,
        )

    async def _load_model(self) -> None:
        try:
            self._pipeline.load_models()
            if not self._pipeline.lightgbm_available:
                logger.warning("AnalysisAgent: LightGBM unavailable — safe mode for detection")
                self._safe_mode_detection = True
                self._safe_mode = True
            if not self._pipeline.if_available:
                logger.warning("AnalysisAgent: IF model unavailable — safe mode for anomaly")
                self._safe_mode_anomaly = True
                self._safe_mode = True
        except Exception as exc:
            logger.error("AnalysisAgent model load error: %s — safe mode", exc)
            self._safe_mode_detection = True
            self._safe_mode_anomaly = True
            self._safe_mode = True

    async def _monitor_tasks(self) -> None:
        tasks = [t for t in (self._detection_task, self._anomaly_task) if t is not None]
        if not tasks:
            return
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    async def _run_detection(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                fv: FeatureVector = await asyncio.wait_for(
                    queues.detection_queue.get(), timeout=1.0
                )
                await self.classify(fv)
                queues.detection_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("AnalysisAgent detection error: %s", exc)

    async def _run_anomaly(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                fv: FeatureVector = await asyncio.wait_for(
                    queues.anomaly_queue.get(), timeout=1.0
                )
                await self.score(fv)
                queues.anomaly_queue.task_done()
            except asyncio.TimeoutError:
                if self.learning_mode and self._learning_end:
                    if datetime.utcnow() >= self._learning_end:
                        await self.establish_baseline()
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("AnalysisAgent anomaly error: %s", exc)

    @staticmethod
    def _normalize_attack_type(label: str | None) -> str | None:
        if label is None:
            return None
        normalized = label.strip().lower()
        if normalized in {"unknown", "benign", "null", "n/a", ""}:
            return None
        return label

    async def classify(self, fv: FeatureVector) -> ThreatScore | None:
        if self._safe_mode or self._safe_mode_detection:
            await self._log(fv, "safe_mode_detection")
            return None

        result = self._pipeline.predict_lightgbm(fv)
        if result is None:
            return None

        attack_type, probability = result
        if isinstance(attack_type, str) and attack_type.upper() == "BENIGN":
            if getattr(self._pipeline, "lightgbm_available", False):
                attack_type = None

        attack_type = self._normalize_attack_type(attack_type)

        score = ThreatScore(
            flow_id=fv.flow_id,
            source="lightgbm",
            score=probability,
            attack_type=attack_type,
            timestamp=datetime.utcnow(),
            feature_vector=fv,
        )

        await safe_put(get_queues().risk_queue, score)

        if probability >= 0.65:
            event = AttackEvent(
                flow_id=fv.flow_id,
                feature_vector=fv,
                lightgbm_score=probability,
                if_score=0.0,
                composite_score=probability,
                attack_type=attack_type or "unknown",
                timestamp=datetime.utcnow(),
            )
            if probability >= 0.90:
                priority = 1
            elif probability >= 0.75:
                priority = 2
            else:
                priority = 3
            await safe_put(get_queues().orchestrator_queue, (priority, event))
        self._classified += 1
        increment_events_processed("detection")
        increment_events_processed("AnalysisAgent")
        return score

    async def score(self, fv: FeatureVector) -> ThreatScore | None:
        if self.learning_mode:
            self._learning_stats["packet_rate"].append(fv.packet_rate)
            self._learning_stats["byte_rate"].append(fv.byte_rate)
            self._learning_stats.setdefault("src_ips", []).append(fv.src_ip)
            return None

        if self._safe_mode or self._safe_mode_anomaly:
            return None

        anomaly_score = self._pipeline.predict_if(fv)
        if anomaly_score is None:
            return None

        threshold = getattr(getattr(self._pipeline, "if_model", None), "decision_threshold", None)
        try:
            raw_thresh = float(threshold)
        except (TypeError, ValueError):
            raw_thresh = 0.11
        norm_thresh = 0.5 - raw_thresh

        attack_type = "zero_day_anomaly" if anomaly_score >= 0.6 else None

        threat = ThreatScore(
            flow_id=fv.flow_id,
            source="if",
            score=anomaly_score,
            attack_type=attack_type,
            timestamp=datetime.utcnow(),
            feature_vector=fv,
        )

        await safe_put(get_queues().risk_queue, threat)

        if anomaly_score >= 0.65:
            event = AttackEvent(
                flow_id=fv.flow_id,
                feature_vector=fv,
                lightgbm_score=0.0,
                if_score=anomaly_score,
                composite_score=anomaly_score,
                attack_type=attack_type or "zero_day_anomaly",
                timestamp=datetime.utcnow(),
            )
            if anomaly_score >= 0.90:
                priority = 1
            elif anomaly_score >= 0.75:
                priority = 2
            else:
                priority = 3
            await safe_put(get_queues().orchestrator_queue, (priority, event))
        self._scored += 1
        increment_events_processed("anomaly")
        increment_events_processed("AnalysisAgent")
        return threat

    async def enter_learning_mode(self, duration_days: int = _LEARNING_DAYS_DEFAULT) -> None:
        self.learning_mode = True
        self._learning_end = datetime.utcnow() + timedelta(days=duration_days)
        self._learning_stats.clear()
        logger.info("AnalysisAgent learning mode started for %d days", duration_days)

    async def establish_baseline(self) -> BaselineProfile | None:
        if not self._learning_stats:
            return None

        pkt_rates = self._learning_stats.get("packet_rate", [0.0])
        byte_rates = self._learning_stats.get("byte_rate", [0.0])

        profile = BaselineProfile(
            profile_id=f"baseline_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            created_at=datetime.utcnow(),
            network_id="default",
            mean_packet_rate=statistics.mean(pkt_rates),
            std_packet_rate=statistics.stdev(pkt_rates) if len(pkt_rates) > 1 else 0.0,
            mean_byte_rate=statistics.mean(byte_rates),
            std_byte_rate=statistics.stdev(byte_rates) if len(byte_rates) > 1 else 0.0,
            protocol_distribution={},
            port_distribution={},
            active_device_count=len(set(self._learning_stats.get("src_ips", []))),
            learning_duration_days=_LEARNING_DAYS_DEFAULT,
            is_active=True,
        )
        self.learning_mode = False
        logger.info("AnalysisAgent baseline established — mean_pkt_rate=%.2f", profile.mean_packet_rate)
        return profile

    async def _log(self, fv: FeatureVector, event_type: str) -> None:
        entry = LogEntry(
            level="info",
            source_agent="analysis_agent",
            event_type=event_type,
            payload={"flow_id": fv.flow_id},
            timestamp=datetime.utcnow(),
        )
        await safe_put(get_queues().logging_queue, entry)

    @property
    def safe_mode_detection(self) -> bool:
        return self._safe_mode_detection

    @property
    def safe_mode_anomaly(self) -> bool:
        return self._safe_mode_anomaly

    @property
    def safe_mode(self) -> bool:
        return self._safe_mode or self._safe_mode_detection or self._safe_mode_anomaly

    @safe_mode.setter
    def safe_mode(self, value: bool) -> None:
        self._safe_mode = value
        self._safe_mode_detection = value
        self._safe_mode_anomaly = value
