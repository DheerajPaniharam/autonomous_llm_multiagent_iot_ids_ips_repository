"""
Configuration loader, validator, and SystemConfig / supporting dataclasses.
Loads from YAML, supports environment variable substitution, validates all
fields, and provides round-trip export (Req 26.1–26.7).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

import yaml


# ---------------------------------------------------------------------------
# Validation rules (Req 26.2, 26.3)
# ---------------------------------------------------------------------------

VALIDATION_RULES: dict[str, object] = {
    "detection_threshold":              lambda v: 0.0 < v < 1.0,
    "anomaly_threshold":                lambda v: 0.0 < v < 1.0,
    "composite_threshold":              lambda v: 0.0 < v < 1.0,
    "alert_threshold_critical":         lambda v: 0.0 < v <= 1.0,
    "log_retention_days":               lambda v: 1 <= v <= 3650,
    "backup_retention_days":            lambda v: 1 <= v <= 365,
    "threat_intel_update_interval_hours": lambda v: 1 <= v <= 168,
}


# ---------------------------------------------------------------------------
# SystemConfig
# ---------------------------------------------------------------------------

@dataclass
class SystemConfig:
    detection_threshold: float = 0.7
    anomaly_threshold: float = 0.6
    composite_threshold: float = 0.65
    whitelist_ips: list[str] = field(default_factory=list)
    blacklist_ips: list[str] = field(default_factory=list)
    enabled_attack_categories: list[str] = field(default_factory=lambda: [
        "ddos", "dos", "port_scan", "brute_force",
        "botnet", "malware", "unauthorized_access",
    ])
    log_retention_days: int = 90
    privacy_mode: bool = False
    signature_updates_enabled: bool = True
    threat_intel_enabled: bool = False
    threat_intel_update_interval_hours: int = 6
    alert_threshold_critical: float = 0.9
    backup_retention_days: int = 30
    version: str = "1.0.0"


# ---------------------------------------------------------------------------
# BaselineProfile
# ---------------------------------------------------------------------------

@dataclass
class BaselineProfile:
    profile_id: str
    created_at: datetime
    network_id: str
    mean_packet_rate: float
    std_packet_rate: float
    mean_byte_rate: float
    std_byte_rate: float
    protocol_distribution: dict[str, float]
    port_distribution: dict[int, float]
    active_device_count: int
    learning_duration_days: int
    is_active: bool


# ---------------------------------------------------------------------------
# IoTDevice
# ---------------------------------------------------------------------------

@dataclass
class IoTDevice:
    device_id: str
    ip_address: str
    mac_address: str
    device_type: Literal["sensor", "camera", "actuator", "gateway", "unknown"]
    protocols: list[str]
    first_seen: datetime
    last_seen: datetime
    is_isolated: bool = False
    baseline_packet_rate: float = 0.0
    baseline_byte_rate: float = 0.0


# ---------------------------------------------------------------------------
# Config loader helpers
# ---------------------------------------------------------------------------

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _substitute_env(value: str) -> str:
    """Replace ${VAR} placeholders with environment variable values."""
    def _replace(match: re.Match) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))
    return _ENV_PATTERN.sub(_replace, value)


def _substitute_env_recursive(obj: object) -> object:
    if isinstance(obj, str):
        return _substitute_env(obj)
    if isinstance(obj, dict):
        return {k: _substitute_env_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_env_recursive(i) for i in obj]
    return obj


def _validate(config: SystemConfig) -> None:
    """Validate all fields against VALIDATION_RULES; raise ValueError on failure."""
    errors: list[str] = []
    for field_name, rule in VALIDATION_RULES.items():
        value = getattr(config, field_name, None)
        if value is not None and not rule(value):
            errors.append(f"  {field_name}={value!r} failed validation")
    if errors:
        raise ValueError("SystemConfig validation failed:\n" + "\n".join(errors))


def parse_yaml(yaml_str: str) -> SystemConfig:
    """Parse YAML string into SystemConfig with env substitution and validation."""
    raw = yaml.safe_load(yaml_str) or {}
    raw = _substitute_env_recursive(raw)
    cfg_data = raw.get("system", raw)  # support top-level 'system:' key or flat
    config = SystemConfig(**{
        k: v for k, v in cfg_data.items()
        if k in SystemConfig.__dataclass_fields__
    })
    _validate(config)
    return config


def load_config(path: str = "config/model_config.yaml") -> SystemConfig:
    """Load SystemConfig from a YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        return parse_yaml(fh.read())


def export_yaml(config: SystemConfig) -> str:
    """Serialize SystemConfig back to YAML string (round-trip safe)."""
    data = {
        k: getattr(config, k)
        for k in config.__dataclass_fields__
    }
    return yaml.dump({"system": data}, default_flow_style=False, sort_keys=True)
