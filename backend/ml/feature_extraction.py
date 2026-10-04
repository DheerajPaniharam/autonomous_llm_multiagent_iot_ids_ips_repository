"""
Feature extraction: converts raw log dicts (Suricata eve.json / Zeek conn.log)
into FeatureVector objects, and preprocesses them into numpy arrays for ML.

Optimized models use a 17-feature input vector:
  [packet_rate, byte_rate, flow_duration, dst_port, syn_flag_count,
   ack_flag_count, rst_flag_count, connection_errors, fwd_packets_per_second,
   bwd_packets_per_second, packet_length_mean, fwd_packet_length_mean,
   bwd_packet_length_mean, total_fwd_packets, total_bwd_packets,
   fwd_bytes, bwd_bytes]

The original 8-feature legacy path is still supported as a fallback when the
scaler metadata is unavailable or when a legacy model is being used.
"""
from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque

import joblib
import numpy as np
import pandas as pd

from backend.models.messages import FeatureVector, compute_flow_id

logger = logging.getLogger(__name__)

# IoT-specific well-known ports
_IOT_PORTS = {1883, 8883, 5683, 5684, 502, 47808}

# Sliding window: last 100 dst_ports per src_ip within 10-second buckets
_port_window: dict[str, Deque[int]] = {}
_port_window_last_seen: dict[str, float] = {}
_prune_counter: int = 0


def _parse_tcp_flag_counts(flag_value: str) -> tuple[int, int, int]:
    """Extract SYN/ACK/RST counts from TCP flag representation."""
    if not isinstance(flag_value, str):
        return 0, 0, 0

    cleaned = flag_value.strip().lower()
    if not cleaned:
        return 0, 0, 0

    # Suricata may expose a hex string like '12', '18', etc.
    try:
        numeric = int(cleaned, 16)
        syn = 1 if numeric & 0x02 else 0
        ack = 1 if numeric & 0x10 else 0
        rst = 1 if numeric & 0x04 else 0
        return syn, ack, rst
    except ValueError:
        # Zeek history may contain a sequence of flag characters.
        history = cleaned.upper()
        return (
            history.count('S'),
            history.count('A'),
            history.count('R'),
        )


def _safe_int(value: object, default: int = 0) -> int:
    """Parse integers safely and fall back to a default."""
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (ValueError, OverflowError):
            return default
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or cleaned in {'-', 'nan', 'NaN', 'None', 'null'}:
            return default
        try:
            return int(float(cleaned))
        except (ValueError, TypeError):
            return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _port_entropy(src_ip: str, dst_port: int) -> float:
    """Shannon entropy of recent dst_port distribution for a given src_ip."""
    global _prune_counter
    now = time.monotonic()
    
    # Prune inactive IPs periodically (every 1000 calls) to prevent memory leak
    _prune_counter += 1
    if _prune_counter >= 1000:
        _prune_counter = 0
        cutoff = now - 600.0  # 10 minutes cache expiry
        expired_ips = [ip for ip, last_seen in list(_port_window_last_seen.items()) if last_seen < cutoff]
        for ip in expired_ips:
            _port_window.pop(ip, None)
            _port_window_last_seen.pop(ip, None)
            
    if src_ip not in _port_window:
        _port_window[src_ip] = deque(maxlen=100)
        
    window = _port_window[src_ip]
    window.append(dst_port)
    _port_window_last_seen[src_ip] = now
    
    counts: dict[int, int] = {}
    for p in window:
        counts[p] = counts.get(p, 0) + 1
    total = len(window)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def _safe_duration(value: object, default: float = 1.0) -> float:
    """Parse numeric durations safely and fall back to a default."""
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        parsed = float(value)
        return parsed if parsed > 0.0 else default
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or cleaned in {"-", "nan", "NaN", "None", "null"}:
            return default
        try:
            parsed = float(cleaned)
        except ValueError:
            return default
        return parsed if parsed > 0.0 else default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0.0 else default


def build_feature_vector_from_suricata(raw: dict) -> FeatureVector | None:
    """Parse a Suricata eve.json flow record into a FeatureVector."""
    try:
        flow = raw.get("flow", {})
        src_ip   = raw.get("src_ip", "0.0.0.0")
        dst_ip   = raw.get("dest_ip", "0.0.0.0")
        src_port = int(raw.get("src_port", 0))
        dst_port = int(raw.get("dest_port", 0))
        protocol = raw.get("proto", "TCP").upper()
        duration = _safe_duration(flow.get("age", 1))

        fwd_packets = int(flow.get("pkts_toserver", 0))
        bwd_packets = int(flow.get("pkts_toclient", 0))
        total_pkts = fwd_packets + bwd_packets
        fwd_bytes = int(flow.get("bytes_toserver", 0))
        bwd_bytes = int(flow.get("bytes_toclient", 0))
        total_bytes = fwd_bytes + bwd_bytes

        tcp_flags = raw.get("tcp", {}).get("tcp_flags_tc", "00")
        # Map hex flags to label
        flags_map = {"02": "S", "12": "SA", "18": "PA", "10": "A", "04": "R", "01": "F"}
        tcp_flags_label = flags_map.get(tcp_flags, "A")

        conn_errors = 1 if flow.get("state") in ("closed", "reset") and total_pkts < 3 else 0

        syn_flag_count, ack_flag_count, rst_flag_count = _parse_tcp_flag_counts(
            raw.get("tcp", {}).get("tcp_flags_tc", "")
        )

        fwd_packets_per_second = fwd_packets / duration
        bwd_packets_per_second = bwd_packets / duration
        packet_length_mean = total_bytes / total_pkts if total_pkts > 0 else 0.0
        fwd_packet_length_mean = fwd_bytes / fwd_packets if fwd_packets > 0 else 0.0
        bwd_packet_length_mean = bwd_bytes / bwd_packets if bwd_packets > 0 else 0.0

        ts = datetime.utcnow()
        flow_id = compute_flow_id(src_ip, src_port, dst_ip, dst_port, protocol, ts)

        return FeatureVector(
            flow_id=flow_id,
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_rate=total_pkts / duration,
            byte_rate=total_bytes / duration,
            flow_duration=duration,
            tcp_flags=tcp_flags_label,
            connection_errors=conn_errors,
            port_entropy=_port_entropy(src_ip, dst_port),
            is_known_iot_port=dst_port in _IOT_PORTS,
            syn_flag_count=syn_flag_count,
            ack_flag_count=ack_flag_count,
            rst_flag_count=rst_flag_count,
            fwd_packets_per_second=fwd_packets_per_second,
            bwd_packets_per_second=bwd_packets_per_second,
            packet_length_mean=packet_length_mean,
            fwd_packet_length_mean=fwd_packet_length_mean,
            bwd_packet_length_mean=bwd_packet_length_mean,
            total_fwd_packets=fwd_packets,
            total_bwd_packets=bwd_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
        )
    except Exception as exc:
        logger.warning("Failed to build FeatureVector from Suricata record: %s", exc)
        return None


def build_feature_vector_from_zeek(raw: dict) -> FeatureVector | None:
    """Parse a Zeek conn.log record into a FeatureVector."""
    try:
        src_ip   = raw.get("id.orig_h", "0.0.0.0")
        dst_ip   = raw.get("id.resp_h", "0.0.0.0")
        src_port = int(raw.get("id.orig_p", 0))
        dst_port = int(raw.get("id.resp_p", 0))
        protocol = raw.get("proto", "tcp").upper()
        duration = _safe_duration(raw.get("duration", 1.0))

        orig_pkts  = int(raw.get("orig_pkts", 0))
        resp_pkts  = int(raw.get("resp_pkts", 0))
        orig_bytes = int(raw.get("orig_bytes", 0) or 0)
        resp_bytes = int(raw.get("resp_bytes", 0) or 0)

        conn_state = raw.get("conn_state", "")
        conn_errors = 1 if conn_state in ("S0", "REJ", "RSTO", "RSTOS0") else 0

        syn_flag_count, ack_flag_count, rst_flag_count = _parse_tcp_flag_counts(raw.get("history", ""))

        fwd_packets_per_second = orig_pkts / duration
        bwd_packets_per_second = resp_pkts / duration
        total_pkts = orig_pkts + resp_pkts
        total_bytes = orig_bytes + resp_bytes
        packet_length_mean = total_bytes / total_pkts if total_pkts > 0 else 0.0
        fwd_packet_length_mean = orig_bytes / orig_pkts if orig_pkts > 0 else 0.0
        bwd_packet_length_mean = resp_bytes / resp_pkts if resp_pkts > 0 else 0.0

        ts = datetime.utcnow()
        flow_id = compute_flow_id(src_ip, src_port, dst_ip, dst_port, protocol, ts)

        return FeatureVector(
            flow_id=flow_id,
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_rate=(orig_pkts + resp_pkts) / duration,
            byte_rate=(orig_bytes + resp_bytes) / duration,
            flow_duration=duration,
            tcp_flags="A",
            connection_errors=conn_errors,
            port_entropy=_port_entropy(src_ip, dst_port),
            is_known_iot_port=dst_port in _IOT_PORTS,
            syn_flag_count=syn_flag_count,
            ack_flag_count=ack_flag_count,
            rst_flag_count=rst_flag_count,
            fwd_packets_per_second=fwd_packets_per_second,
            bwd_packets_per_second=bwd_packets_per_second,
            packet_length_mean=packet_length_mean,
            fwd_packet_length_mean=fwd_packet_length_mean,
            bwd_packet_length_mean=bwd_packet_length_mean,
            total_fwd_packets=orig_pkts,
            total_bwd_packets=resp_pkts,
            fwd_bytes=orig_bytes,
            bwd_bytes=resp_bytes,
        )
    except Exception as exc:
        logger.warning("Failed to build FeatureVector from Zeek record: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Preprocessing for ML
# ---------------------------------------------------------------------------

_PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "MQTT": 4, "COAP": 5, "MODBUS": 6}
_FLAGS_MAP    = {"S": 0, "SA": 1, "PA": 2, "A": 3, "R": 4, "F": 5}

# Feature names used by the backend when a strict 8-feature scaler is available.
FEATURE_NAMES = [
    "packet_rate",       # 0: packets per second
    "byte_rate",         # 1: bytes per second
    "flow_duration",     # 2: flow duration in seconds
    "dst_port",          # 3: destination port
    "protocol_enc",      # 4: protocol (0-6 encoded)
    "tcp_flags_enc",     # 5: TCP flags (0-5 encoded)
    "connection_errors", # 6: 0 or 1
    "port_entropy"       # 7: Shannon entropy of dst_port distribution
]

# Optimized optimized 17-feature set from trained model metadata.
OPTIMIZED_FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "flow_duration",
    "dst_port",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "connection_errors",
    "fwd_packets_per_second",
    "bwd_packets_per_second",
    "packet_length_mean",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
]

# Additional feature names that older or alternative scaler objects may expect.
FALLBACK_FEATURES = [
    "protocol",
    "tcp_flags",
    "src_port",
    "is_known_iot_port",
]


def preprocess(fv: FeatureVector, scaler=None) -> np.ndarray:
    """
    Encode categoricals and prepare features for ML inference.

    Returns a numpy array of shape (1, n_features), where n_features is either the
    strict backend feature set or the number of features expected by the provided
    scaler.

    If a scaler with feature_names_in_ is provided, the input features are aligned
    to the scaler's expected feature names. Missing expected columns are filled
    with zeros to preserve transform compatibility.
    """
    protocol_enc = _PROTOCOL_MAP.get(fv.protocol.upper(), 0)
    tcp_flags_enc = _FLAGS_MAP.get(fv.tcp_flags.upper(), 3)

    raw_features = {
        "packet_rate": fv.packet_rate,
        "byte_rate": fv.byte_rate,
        "flow_duration": fv.flow_duration,
        "dst_port": fv.dst_port,
        "syn_flag_count": fv.syn_flag_count,
        "ack_flag_count": fv.ack_flag_count,
        "rst_flag_count": fv.rst_flag_count,
        "connection_errors": fv.connection_errors,
        "fwd_packets_per_second": fv.fwd_packets_per_second,
        "bwd_packets_per_second": fv.bwd_packets_per_second,
        "packet_length_mean": fv.packet_length_mean,
        "fwd_packet_length_mean": fv.fwd_packet_length_mean,
        "bwd_packet_length_mean": fv.bwd_packet_length_mean,
        "total_fwd_packets": fv.total_fwd_packets,
        "total_bwd_packets": fv.total_bwd_packets,
        "fwd_bytes": fv.fwd_bytes,
        "bwd_bytes": fv.bwd_bytes,
        "protocol_enc": protocol_enc,
        "tcp_flags_enc": tcp_flags_enc,
        "port_entropy": fv.port_entropy,
        "protocol": fv.protocol,
        "tcp_flags": fv.tcp_flags,
        "src_port": fv.src_port,
        "is_known_iot_port": fv.is_known_iot_port,
    }

    raw = np.array([
        [raw_features[name] for name in OPTIMIZED_FEATURE_NAMES]
    ], dtype=np.float64)

    if scaler is not None:
        try:
            if hasattr(scaler, 'feature_names_in_'):
                expected_features = list(scaler.feature_names_in_)
                missing = [feature for feature in expected_features if feature not in raw_features]
                if missing:
                    logger.warning(
                        "StandardScaler expects features %s but missing %s. Filling missing values with 0.0.",
                        expected_features,
                        missing,
                    )
                row = [raw_features.get(name, 0.0) for name in expected_features]
                raw = np.array([row], dtype=np.float64)
                raw = scaler.transform(raw)
            else:
                if hasattr(scaler, 'n_features_in_') and int(scaler.n_features_in_) == len(OPTIMIZED_FEATURE_NAMES):
                    feature_order = OPTIMIZED_FEATURE_NAMES
                elif hasattr(scaler, 'n_features_in_') and int(scaler.n_features_in_) == len(FEATURE_NAMES):
                    feature_order = FEATURE_NAMES
                else:
                    feature_order = OPTIMIZED_FEATURE_NAMES

                raw = np.array([
                    [raw_features[name] for name in feature_order]
                ], dtype=np.float64)
                raw = scaler.transform(raw)
        except Exception as e:
            logger.warning("Scaler transform failed: %s. Using raw features.", e)

    return raw
