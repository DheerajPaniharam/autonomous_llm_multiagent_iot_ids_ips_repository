"""
Core data models and message types for the IDS/IPS multi-agent system.
All inter-agent communication uses these dataclasses wrapped in MessageEnvelope.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_flow_id(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    timestamp: datetime,
    bucket_seconds: int = 10,
) -> str:
    """SHA256-based flow identifier bucketed to `bucket_seconds` windows."""
    bucket = int(timestamp.timestamp() / bucket_seconds) * bucket_seconds
    raw = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}-{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Feature Vector
# ---------------------------------------------------------------------------

@dataclass
class FeatureVector:
    """Extracted numerical representation of a network flow."""
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str           # TCP, UDP, ICMP, HTTP, MQTT, CoAP, Modbus
    packet_rate: float      # packets/second
    byte_rate: float        # bytes/second
    flow_duration: float    # seconds
    tcp_flags: str          # A, S, PA, SA, R, F
    connection_errors: int
    port_entropy: float     # Shannon entropy of dst_port distribution
    is_known_iot_port: bool  # MQTT/CoAP/Modbus/BACnet ports
    syn_flag_count: int = 0
    ack_flag_count: int = 0
    rst_flag_count: int = 0
    fwd_packets_per_second: float = 0.0
    bwd_packets_per_second: float = 0.0
    packet_length_mean: float = 0.0
    fwd_packet_length_mean: float = 0.0
    bwd_packet_length_mean: float = 0.0
    total_fwd_packets: float = 0.0
    total_bwd_packets: float = 0.0
    fwd_bytes: float = 0.0
    bwd_bytes: float = 0.0


# ---------------------------------------------------------------------------
# Threat Scores
# ---------------------------------------------------------------------------

@dataclass
class ThreatScore:
    """Score emitted by Detection or Anomaly agent for a given flow."""
    flow_id: str
    source: Literal["lightgbm", "if"]
    score: float            # [0.0, 1.0]
    attack_type: str | None
    timestamp: datetime
    feature_vector: FeatureVector | None = None


# ---------------------------------------------------------------------------
# Attack Event
# ---------------------------------------------------------------------------

@dataclass
class AttackEvent:
    """Composite event forwarded by Risk Agent to LLM Orchestrator."""
    flow_id: str
    feature_vector: FeatureVector | None
    lightgbm_score: float | None
    if_score: float | None
    composite_score: float
    attack_type: str
    timestamp: datetime
    threat_intel_context: dict | None = None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@dataclass
class MitigationCommand:
    """Instruction from Orchestrator to Prevention Agent."""
    event_id: str | None = None
    action: Literal["block_ip", "rate_limit", "isolate_device"] = "rate_limit"
    target_ip: str = "0.0.0.0"
    ttl_seconds: int = 0
    priority: int = 3       # 1=critical, 2=high, 3=normal


@dataclass
class HealingCommand:
    """Instruction from Orchestrator to Healing Agent."""
    incident_id: str
    action: Literal[
        "restart_service",
        "clear_rules",
        "optimize_resources",
        "restore_connectivity",
    ]
    target: str


# ---------------------------------------------------------------------------
# Log Entry
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """Structured log record written to PostgreSQL and forwarded to the Grafana/Loki pipeline."""
    level: Literal["info", "warning", "error", "critical"]
    source_agent: str
    event_type: str
    payload: dict
    timestamp: datetime


# ---------------------------------------------------------------------------
# Message Envelope
# ---------------------------------------------------------------------------

@dataclass
class MessageEnvelope:
    """Standard wrapper for all inter-agent queue messages."""
    message_id: str
    correlation_id: str
    source_agent: str
    destination_agent: str
    message_type: str
    payload: Any
    timestamp: datetime
    priority: int = 3       # 1=critical, 2=high, 3=normal


# ---------------------------------------------------------------------------
# Incident State Machine
# ---------------------------------------------------------------------------

class IncidentState(str, Enum):
    DETECTED   = "detected"
    ANALYZING  = "analyzing"
    MITIGATING = "mitigating"
    RESOLVED   = "resolved"
    CLOSED     = "closed"


@dataclass
class Incident:
    """Lifecycle record for a high-severity attack event."""
    id: str
    state: IncidentState
    severity: Literal["low", "medium", "high", "critical"]
    attack_type: str
    response_plan: list[MitigationCommand]
    detected_at: datetime
    resolved_at: datetime | None = None
    requires_manual_approval: bool = False
    admin_override: bool = False
