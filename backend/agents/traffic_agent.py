"""
Traffic Agent — reads Suricata eve.json and Zeek conn.log,
builds FeatureVector objects, and fans them out to the detection pipeline.
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections import deque
from pathlib import Path
from typing import Deque


def resolve_log_path(primary_path: str | None, candidates: list[str] | None = None) -> str:
    """Return the first existing log path, falling back to repo sample logs when needed."""
    if primary_path:
        if os.path.isfile(primary_path):
            return primary_path
        if os.path.isdir(primary_path):
            directory_candidates = [
                os.path.join(primary_path, "current", "conn.log"),
                os.path.join(primary_path, "conn.log"),
            ]
            for path in directory_candidates:
                if os.path.isfile(path):
                    return path

    search_paths = []
    if primary_path:
        search_paths.append(primary_path)
    if candidates:
        search_paths.extend(candidates)

    for path in search_paths:
        if path and os.path.isfile(path):
            return path

    repo_root = Path(__file__).resolve().parents[2]
    default_candidates = [
        str(repo_root / "conn.log"),
        str(repo_root / "dns.log"),
        str(repo_root / "http.log"),
        str(repo_root / "notice.log"),
        str(repo_root / "ssl.log"),
    ]
    for path in default_candidates:
        if os.path.exists(path):
            return path

    return primary_path or default_candidates[0]

from backend.agents.queues import get_queues, safe_put
from backend.ml.feature_extraction import (
    build_feature_vector_from_suricata,
    build_feature_vector_from_zeek,
)
from backend.models.messages import FeatureVector, LogEntry
from traffic_capture.log_watcher import tail_json_lines, tail_tsv_lines
from backend.api.ws_manager import ws_manager
from backend.metrics import increment_events_processed, add_network_stats

logger = logging.getLogger(__name__)

# Default log paths (overridable via env vars — matches .env SURICATA_LOG_PATH / ZEEK_LOG_PATH)
_SURICATA_LOG = os.environ.get("SURICATA_LOG_PATH", "/var/log/suricata/eve.json")
_ZEEK_CONN_LOG = os.environ.get("ZEEK_LOG_PATH", "/var/log/zeek/current/conn.log")


def _resolve_default_zeek_log() -> str:
    return resolve_log_path(_ZEEK_CONN_LOG, ["/tmp/zeek-logs/conn.log"])


def _split_log_paths(value: str) -> list[str]:
    return [path.strip() for path in value.split(",") if path.strip()]


class TrafficAgent:
    """
    Captures network flow metadata from Suricata and Zeek log files,
    extracts FeatureVectors, and publishes them to detection/anomaly queues.
    """

    def __init__(
        self,
        suricata_log: str | None = None,
        zeek_log: str | None = None,
    ) -> None:
        suricata_paths = (
            _split_log_paths(os.environ["SURICATA_LOG_PATHS"])
            if suricata_log is None and os.environ.get("SURICATA_LOG_PATHS")
            else [suricata_log or _SURICATA_LOG]
        )
        if zeek_log is None and os.environ.get("ZEEK_LOG_PATHS"):
            zeek_paths = _split_log_paths(os.environ["ZEEK_LOG_PATHS"])
        else:
            zeek_paths = [
                resolve_log_path(
                    zeek_log or _resolve_default_zeek_log(),
                    ["/tmp/zeek-logs/conn.log"],
                )
            ]

        if not suricata_paths:
            raise ValueError("SURICATA_LOG_PATHS must contain at least one log path")
        if not zeek_paths:
            raise ValueError("ZEEK_LOG_PATHS must contain at least one log path")

        self._suricata_logs = suricata_paths
        self._zeek_logs = zeek_paths
        self._suricata_log = suricata_paths[0]
        self._zeek_log = zeek_paths[0]
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._vectors_published = 0
        self._recent_flows: Deque[FeatureVector] = deque(maxlen=100)
        self._flow_broadcast_buffer: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start watching both log files concurrently."""
        logger.info(
            "TrafficAgent starting — watching %d Suricata log(s) and %d Zeek log(s)",
            len(self._suricata_logs),
            len(self._zeek_logs),
        )
        self._stop_event.clear()
        self._flow_broadcast_buffer = []
        self._tasks = [
            *(
                asyncio.create_task(self._watch_suricata_log(path))
                for path in self._suricata_logs
            ),
            *(
                asyncio.create_task(self._watch_zeek_log(path))
                for path in self._zeek_logs
            ),
            asyncio.create_task(self._broadcast_loop()),
        ]

    async def stop(self) -> None:
        """Signal stop and wait for in-flight processing to drain."""
        logger.info("TrafficAgent stopping")
        self._stop_event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("TrafficAgent stopped — %d vectors published", self._vectors_published)

    async def _broadcast_loop(self) -> None:
        """Aggregate flow events and broadcast them as a batch once per second."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(1.0)
                if self._flow_broadcast_buffer:
                    batch = self._flow_broadcast_buffer
                    self._flow_broadcast_buffer = []
                    await ws_manager.broadcast({
                        "type": "flow_batch",
                        "payload": batch
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in TrafficAgent broadcast loop: %s", e, exc_info=True)

    # ------------------------------------------------------------------
    # Log watchers
    # ------------------------------------------------------------------

    async def _watch_suricata_log(self, path: str) -> None:
        """Tail Suricata eve.json and publish FeatureVectors."""
        async for raw in tail_json_lines(path, self._stop_event):
            # Only process flow events
            if raw.get("event_type") != "flow":
                continue
            fv = build_feature_vector_from_suricata(raw)
            if fv is not None:
                self._recent_flows.append(fv)
                await self._publish(fv)
                try:
                    self._flow_broadcast_buffer.append(self._serialize_feature_vector(fv))
                except Exception:
                    pass

    async def _watch_zeek_log(self, path: str) -> None:
        """Tail Zeek conn.log and publish FeatureVectors."""
        async for raw in tail_tsv_lines(path, self._stop_event):
            fv = build_feature_vector_from_zeek(raw)
            logger.info("Zeek record parsed: %s", raw.get("uid"))
            if fv is not None:
                logger.info("FeatureVector created: %s", fv.flow_id)
                self._recent_flows.append(fv)
                await self._publish(fv)
                try:
                    self._flow_broadcast_buffer.append(self._serialize_feature_vector(fv))
                except Exception:
                    pass

    def _serialize_feature_vector(self, fv: FeatureVector) -> dict:
        """Serialize FeatureVector to JSON-friendly dict."""
        return {
            "flow_id": fv.flow_id,
            "timestamp": fv.timestamp.isoformat() if hasattr(fv.timestamp, 'isoformat') else str(fv.timestamp),
            "src_ip": fv.src_ip,
            "dst_ip": fv.dst_ip,
            "src_port": fv.src_port,
            "dst_port": fv.dst_port,
            "protocol": fv.protocol,
            "packet_rate": fv.packet_rate,
            "byte_rate": fv.byte_rate,
            "flow_duration": fv.flow_duration,
            "tcp_flags": fv.tcp_flags,
            "connection_errors": fv.connection_errors,
            "is_known_iot_port": fv.is_known_iot_port,
        }

    # ------------------------------------------------------------------
    # Feature vector builder (delegates to feature_extraction module)
    # ------------------------------------------------------------------

    async def _build_feature_vector(self, raw: dict) -> FeatureVector | None:
        """Build a FeatureVector from a raw log record (Suricata or Zeek)."""
        if "event_type" in raw:
            return build_feature_vector_from_suricata(raw)
        return build_feature_vector_from_zeek(raw)

    # ------------------------------------------------------------------
    # Publisher
    # ------------------------------------------------------------------

    async def _publish(self, fv: FeatureVector) -> None:
        """Fan out FeatureVector to both detection and anomaly queues.

        The traffic agent also maintains a bounded recent-flow buffer so the
        live-traffic API and WebSocket snapshot can render the latest flows
        even when the source is synthetic/mock traffic that bypasses the log
        tailers.
        """
        self._recent_flows.append(fv)

        # Track agent events processed and network bytes/packets
        increment_events_processed("TrafficAgent")
        
        bytes_count = (fv.fwd_bytes or 0.0) + (fv.bwd_bytes or 0.0)
        if bytes_count <= 0.0:
            bytes_count = (fv.byte_rate or 0.0) * max(fv.flow_duration or 0.0, 0.1)
        
        packets_count = (fv.total_fwd_packets or 0.0) + (fv.total_bwd_packets or 0.0)
        if packets_count <= 0.0:
            packets_count = (fv.packet_rate or 0.0) * max(fv.flow_duration or 0.0, 0.1)
            
        add_network_stats(bytes_count, packets_count)

        queues = get_queues()
        sent_d = await safe_put(queues.detection_queue, fv, drop_counter=True)
        sent_a = await safe_put(queues.anomaly_queue, fv, drop_counter=True)
        logger.info(
            "Publishing flow %s | detection=%s anomaly=%s",
            fv.flow_id,
            sent_d,
            sent_a,
        )
        if sent_d or sent_a:
            self._vectors_published += 1

    def get_recent_flows(self, limit: int = 50) -> list[FeatureVector]:
        """Return the most recent captured flows, newest first."""
        return list(self._recent_flows)[::-1][:limit]

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def vectors_published(self) -> int:
        return self._vectors_published
