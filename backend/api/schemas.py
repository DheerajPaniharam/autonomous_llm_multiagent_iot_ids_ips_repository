"""
Pydantic schemas for API request/response validation and serialization.
Covers authentication, alerts, incidents, devices, metrics, config, reports, health, and errors.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ---------------------------------------------------------------------------
# Authentication Schemas
# ---------------------------------------------------------------------------

class TokenRequest(BaseModel):
    """Request body for POST /auth/token (OAuth2 password flow)."""
    username: str = Field(..., min_length=1, max_length=64, example="admin")
    password: str = Field(..., min_length=1, example="s3cr3tP@ssword")


class TokenResponse(BaseModel):
    """Response for successful authentication."""
    access_token: str = Field(
        ...,
        example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTcwMDAwMDAwMH0.abc123",
    )
    token_type: str = Field("bearer", example="bearer")
    expires_in: int = Field(..., example=3600)  # seconds


class TokenData(BaseModel):
    """Decoded JWT payload data."""
    username: str = Field(..., example="admin")
    role: Literal["admin", "analyst", "viewer"] = Field(..., example="analyst")


# ---------------------------------------------------------------------------
# Alert Schemas (AttackEvent)
# ---------------------------------------------------------------------------

class AlertResponse(BaseModel):
    """Response schema for GET /api/v1/alerts."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., example="550e8400-e29b-41d4-a716-446655440000")
    flow_id: str = Field(..., example="flow-20240101-001")
    timestamp: datetime = Field(..., example="2024-01-15T10:30:00Z")
    src_ip: str = Field(..., example="192.168.1.100")
    dst_ip: str = Field(..., example="10.0.0.1")
    src_port: int | None = Field(None, example=54321)
    dst_port: int | None = Field(None, example=80)
    protocol: str | None = Field(None, example="TCP")
    attack_type: str | None = Field(None, example="DoS")
    lightgbm_score: float | None = Field(None, example=0.92)
    if_score: float | None = Field(None, example=0.88)
    composite_score: float = Field(..., example=0.91)
    severity: Literal["medium", "high", "critical"] = Field(..., example="critical")
    llm_analysis: str | None = Field(None, example="High-confidence DoS attack detected from 192.168.1.100 targeting port 80.")
    incident_id: str | None = Field(None, example="550e8400-e29b-41d4-a716-446655440001")

    @staticmethod
    def derive_severity(score: float) -> Literal["medium", "high", "critical"]:
        """Derive severity level from composite score."""
        if score >= 0.9:
            return "critical"
        if score >= 0.75:
            return "high"
        return "medium"

    @classmethod
    def from_db_model(cls, model: Any) -> AlertResponse:
        """Create AlertResponse from AttackEventModel."""
        return cls(
            id=model.id,
            flow_id=model.flow_id,
            timestamp=model.timestamp,
            src_ip=str(model.src_ip),
            dst_ip=str(model.dst_ip),
            src_port=model.src_port,
            dst_port=model.dst_port,
            protocol=model.protocol,
            attack_type=model.attack_type,
            lightgbm_score=model.lightgbm_score,
            if_score=model.if_score,
            composite_score=model.composite_score,
            severity=cls.derive_severity(model.composite_score),
            llm_analysis=model.llm_analysis,
            incident_id=model.incident_id,
        )


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""
    alerts: list[AlertResponse]
    total: int = Field(..., example=142)
    limit: int = Field(..., example=50)
    offset: int = Field(..., example=0)


class TrafficFlowResponse(BaseModel):
    """Recent live traffic flow summary for dashboard display."""
    model_config = ConfigDict(from_attributes=True)

    flow_id: str = Field(..., example="flow-20240101-001")
    timestamp: datetime = Field(..., example="2024-01-15T10:30:00Z")
    src_ip: str = Field(..., example="192.168.1.100")
    dst_ip: str = Field(..., example="10.0.0.1")
    src_port: int | None = Field(None, example=54321)
    dst_port: int | None = Field(None, example=80)
    protocol: str | None = Field(None, example="TCP")
    packet_rate: float = Field(..., example=120.5)
    byte_rate: float = Field(..., example=4096.0)
    flow_duration: float = Field(..., example=1.2)
    tcp_flags: str | None = Field(None, example="S")
    connection_errors: int = Field(..., example=0)
    is_known_iot_port: bool = Field(..., example=False)

    @classmethod
    def from_feature_vector(cls, fv: Any) -> "TrafficFlowResponse":
        return cls(
            flow_id=fv.flow_id,
            timestamp=fv.timestamp,
            src_ip=fv.src_ip,
            dst_ip=fv.dst_ip,
            src_port=fv.src_port,
            dst_port=fv.dst_port,
            protocol=fv.protocol,
            packet_rate=fv.packet_rate,
            byte_rate=fv.byte_rate,
            flow_duration=fv.flow_duration,
            tcp_flags=fv.tcp_flags,
            connection_errors=fv.connection_errors,
            is_known_iot_port=fv.is_known_iot_port,
        )


# ---------------------------------------------------------------------------
# Incident Schemas
# ---------------------------------------------------------------------------

class IncidentResponse(BaseModel):
    """Response schema for GET /api/v1/incidents."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., example="550e8400-e29b-41d4-a716-446655440001")
    state: Literal["detected", "analyzing", "mitigating", "resolved", "closed"] = Field(..., example="mitigating")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., example="high")
    attack_type: str | None = Field(None, example="PortScan")
    response_plan: dict | None = Field(None, example={"action": "block_ip", "target": "192.168.1.100"})
    detected_at: datetime = Field(..., example="2024-01-15T10:30:00Z")
    resolved_at: datetime | None = Field(None, example=None)
    created_at: datetime = Field(..., example="2024-01-15T10:30:05Z")

    @classmethod
    def from_db_model(cls, model: Any) -> IncidentResponse:
        """Create IncidentResponse from IncidentModel."""
        return cls(
            id=model.id,
            state=model.state,
            severity=model.severity,
            attack_type=model.attack_type,
            response_plan=model.response_plan,
            detected_at=model.detected_at,
            resolved_at=model.resolved_at,
            created_at=model.created_at,
        )


class IncidentDetailResponse(BaseModel):
    """Detailed incident response with context and related alerts."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., example="550e8400-e29b-41d4-a716-446655440001")
    state: Literal["detected", "analyzing", "mitigating", "resolved", "closed"] = Field(..., example="mitigating")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., example="high")
    attack_type: str | None = Field(None, example="PortScan")
    response_plan: dict | None = Field(None, example={"action": "block_ip", "target": "192.168.1.100"})
    detected_at: datetime = Field(..., example="2024-01-15T10:30:00Z")
    resolved_at: datetime | None = Field(None, example=None)
    created_at: datetime = Field(..., example="2024-01-15T10:30:05Z")
    summary: str = Field(..., example="PortScan detected with high severity and 2 related alerts.")
    alert_count: int = Field(..., example=2)
    related_alerts: list[AlertResponse] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    """Paginated list of incidents."""
    incidents: list[IncidentResponse]
    total: int = Field(..., example=8)
    limit: int = Field(..., example=50)
    offset: int = Field(..., example=0)


class AcknowledgeIncidentRequest(BaseModel):
    """Request body for POST /api/v1/incidents/{id}/acknowledge."""
    acknowledged_by: str = Field(..., min_length=1, max_length=64, example="analyst_jane")
    notes: str | None = Field(None, max_length=1000, example="Confirmed false positive — internal scanner.")


# ---------------------------------------------------------------------------
# Device Schemas
# ---------------------------------------------------------------------------

class DeviceResponse(BaseModel):
    """Response schema for GET /api/v1/devices."""
    model_config = ConfigDict(from_attributes=True)

    device_id: str = Field(..., example="dev-cam-001")
    ip_address: str = Field(..., example="192.168.10.25")
    mac_address: str | None = Field(None, example="AA:BB:CC:DD:EE:FF")
    device_type: Literal["sensor", "camera", "actuator", "gateway", "unknown"] = Field(..., example="camera")
    protocols: list[str] | None = Field(None, example=["RTSP", "HTTP"])
    first_seen: datetime = Field(..., example="2024-01-01T08:00:00Z")
    last_seen: datetime = Field(..., example="2024-01-15T10:29:55Z")
    is_isolated: bool = Field(..., example=False)
    baseline_packet_rate: float = Field(..., example=120.5)
    baseline_byte_rate: float = Field(..., example=15360.0)

    @classmethod
    def from_db_model(cls, model: Any) -> DeviceResponse:
        """Create DeviceResponse from IoTDeviceModel."""
        return cls(
            device_id=model.device_id,
            ip_address=str(model.ip_address),
            mac_address=model.mac_address,
            device_type=model.device_type,
            protocols=model.protocols or [],
            first_seen=model.first_seen,
            last_seen=model.last_seen,
            is_isolated=model.is_isolated,
            baseline_packet_rate=model.baseline_packet_rate,
            baseline_byte_rate=model.baseline_byte_rate,
        )


class DeviceListResponse(BaseModel):
    """Paginated list of devices."""
    devices: list[DeviceResponse]
    total: int = Field(..., example=34)
    limit: int = Field(..., example=50)
    offset: int = Field(..., example=0)


# ---------------------------------------------------------------------------
# Metrics Schemas
# ---------------------------------------------------------------------------

class QueueDepthMetrics(BaseModel):
    """Queue depth metrics for all agent queues."""
    detection: int = Field(..., example=3)
    anomaly: int = Field(..., example=2)
    risk: int = Field(..., example=1)
    orchestrator: int = Field(..., example=0)
    prevention: int = Field(..., example=0)
    healing: int = Field(..., example=0)
    logging: int = Field(..., example=5)


class MLLatencyMetrics(BaseModel):
    """ML inference latency percentiles in milliseconds."""
    lightgbm_p50: float = Field(..., example=4.2)
    lightgbm_p95: float = Field(..., example=9.8)
    lightgbm_p99: float = Field(..., example=14.1)
    if_p50: float = Field(..., example=6.5)
    if_p95: float = Field(..., example=12.3)
    if_p99: float = Field(..., example=18.7)


class AgentThroughputMetrics(BaseModel):
    """Processing activity / events processed per agent."""
    TrafficAgent: int = Field(0, description="Total events processed by TrafficAgent")
    AnalysisAgent: int = Field(0, description="Total events processed by AnalysisAgent")
    LLMOrchestrator: int = Field(0, description="Total events processed by LLMOrchestrator")
    ResponseAgent: int = Field(0, description="Total events processed by ResponseAgent")
    ObservabilityAgent: int = Field(0, description="Total events processed by ObservabilityAgent")


class NetworkThroughputMetrics(BaseModel):
    """Network throughput metrics (kbps and pps)."""
    kbps: float = Field(0.0, description="Network throughput in kilobits per second")
    pps: float = Field(0.0, description="Network throughput in packets per second")


class MetricsResponse(BaseModel):
    """Response schema for GET /api/v1/metrics."""
    total_events_processed: int = Field(..., example=48320)
    total_mitigations_applied: int = Field(..., example=127)
    queue_depths: QueueDepthMetrics
    ml_latency_ms: MLLatencyMetrics
    packet_drops: int = Field(..., example=0)
    active_incidents: int = Field(..., example=3)
    agent_throughput: AgentThroughputMetrics
    network_throughput: NetworkThroughputMetrics
    timestamp: datetime = Field(..., example="2024-01-15T10:30:00Z")


# ---------------------------------------------------------------------------
# Configuration Schemas
# ---------------------------------------------------------------------------

class ConfigResponse(BaseModel):
    """Response schema for GET /api/v1/config."""
    detection_threshold: float = Field(..., example=0.7)
    anomaly_threshold: float = Field(..., example=0.6)
    composite_threshold: float = Field(..., example=0.65)
    whitelist_ips: list[str] = Field(..., example=["10.0.0.1", "10.0.0.2"])
    blacklist_ips: list[str] = Field(..., example=["203.0.113.5"])
    enabled_attack_categories: list[str] = Field(..., example=["DoS", "PortScan", "Brute-Force"])
    log_retention_days: int = Field(..., example=90)
    privacy_mode: bool = Field(..., example=False)
    signature_updates_enabled: bool = Field(..., example=True)
    threat_intel_enabled: bool = Field(..., example=True)
    threat_intel_update_interval_hours: int = Field(..., example=24)
    alert_threshold_critical: float = Field(..., example=0.9)
    backup_retention_days: int = Field(..., example=30)
    version: str = Field(..., example="1.0.0")


class ConfigUpdateRequest(BaseModel):
    """Request body for PUT /api/v1/config (partial updates allowed)."""
    detection_threshold: float | None = Field(None, gt=0.0, lt=1.0)
    anomaly_threshold: float | None = Field(None, gt=0.0, lt=1.0)
    composite_threshold: float | None = Field(None, gt=0.0, lt=1.0)
    whitelist_ips: list[str] | None = None
    blacklist_ips: list[str] | None = None
    enabled_attack_categories: list[str] | None = None
    log_retention_days: int | None = Field(None, ge=1, le=3650)
    privacy_mode: bool | None = None
    signature_updates_enabled: bool | None = None
    threat_intel_enabled: bool | None = None
    threat_intel_update_interval_hours: int | None = Field(None, ge=1, le=168)
    alert_threshold_critical: float | None = Field(None, gt=0.0, le=1.0)
    backup_retention_days: int | None = Field(None, ge=1, le=365)

    @field_validator("whitelist_ips", "blacklist_ips")
    @classmethod
    def validate_ip_list(cls, v: list[str] | None) -> list[str] | None:
        """Validate IP address format (basic check)."""
        if v is None:
            return v
        import ipaddress
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip}")
        return v


# ---------------------------------------------------------------------------
# Report Schemas
# ---------------------------------------------------------------------------

class ReportMetadata(BaseModel):
    """Metadata for a generated report."""
    id: str
    report_type: Literal["daily", "weekly", "monthly"]
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    format: Literal["json", "csv"]


class ReportListResponse(BaseModel):
    """Response schema for GET /api/v1/reports."""
    reports: list[ReportMetadata]
    total: int


class ReportResponse(BaseModel):
    """Response schema for GET /api/v1/reports/{id}."""
    id: str
    report_type: Literal["daily", "weekly", "monthly"]
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    total_events: int
    total_mitigations: int
    attack_counts: dict[str, int]
    mttd_by_type: dict[str, float]  # seconds
    mttr_by_type: dict[str, float]  # seconds


# ---------------------------------------------------------------------------
# Health Check Schemas
# ---------------------------------------------------------------------------

class ComponentHealth(BaseModel):
    """Health status of a single component."""
    status: Literal["ok", "error", "unavailable", "degraded"]
    message: str | None = None


class MLModelsHealth(BaseModel):
    """Health status of ML models."""
    lightgbm: bool
    if_: bool = Field(..., alias="if")


class AgentHealth(BaseModel):
    """Health status of all agents."""
    traffic: bool
    detection: bool
    anomaly: bool
    risk: bool
    orchestrator: bool
    prevention: bool
    healing: bool
    logging: bool
    reporting: bool


class HealthResponse(BaseModel):
    """Response schema for GET /health."""
    status: Literal["healthy", "degraded"]
    timestamp: datetime
    database: ComponentHealth
    ml_models: MLModelsHealth
    ollama: ComponentHealth
    agents: AgentHealth


class ReadinessResponse(BaseModel):
    """Response schema for GET /health/ready."""
    status: Literal["ready", "not_ready"]
    reason: str | None = None


class LivenessResponse(BaseModel):
    """Response schema for GET /health/live."""
    status: Literal["alive"]


# ---------------------------------------------------------------------------
# Error Schemas
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    """Standard error response format."""
    detail: str | dict[str, Any]


class ValidationErrorDetail(BaseModel):
    """Detailed validation error for a specific field."""
    field: str
    message: str
    constraint: str | None = None


class ValidationErrorResponse(BaseModel):
    """Response for HTTP 422 validation errors."""
    detail: list[ValidationErrorDetail]


# ---------------------------------------------------------------------------
# Query Parameter Schemas
# ---------------------------------------------------------------------------

class PaginationParams(BaseModel):
    """Common pagination query parameters."""
    limit: int = Field(50, ge=1, le=500, description="Maximum number of items to return")
    offset: int = Field(0, ge=0, description="Number of items to skip")


class AlertQueryParams(PaginationParams):
    """Query parameters for GET /api/v1/alerts."""
    severity: Literal["medium", "high", "critical"] | None = Field(
        None, description="Filter by severity level"
    )


class IncidentQueryParams(PaginationParams):
    """Query parameters for GET /api/v1/incidents."""
    state: Literal["detected", "analyzing", "mitigating", "resolved", "closed"] | None = Field(
        None, description="Filter by incident state"
    )


class DeviceQueryParams(PaginationParams):
    """Query parameters for GET /api/v1/devices."""
    is_isolated: bool | None = Field(None, description="Filter by isolation status")


class ReportQueryParams(BaseModel):
    """Query parameters for GET /api/v1/reports/{id}."""
    format: Literal["json", "csv"] = Field("json", description="Report output format")


# ---------------------------------------------------------------------------
# Audit Log Schemas
# ---------------------------------------------------------------------------

class AuditLogResponse(BaseModel):
    """Response schema for audit log entries."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., example="550e8400-e29b-41d4-a716-446655440001")
    username: str = Field(..., example="analyst")
    action: str = Field(..., example="acknowledge_incident", description="Action performed by user")
    resource_type: str | None = Field(None, example="incident", description="Type of resource affected")
    resource_id: str | None = Field(None, example="550e8400-e29b-41d4-a716-446655440000", description="ID of resource affected")
    details: dict[str, Any] | None = Field(None, description="Additional context about the action")
    status: str = Field("success", example="success", description="success or failure")
    ip_address: str | None = Field(None, example="192.168.1.100", description="Client IP address")
    user_agent: str | None = Field(None, example="Mozilla/5.0...", description="User agent string")
    timestamp: datetime = Field(..., example="2024-01-15T10:30:00Z", description="When the action occurred")


class AuditLogListResponse(BaseModel):
    """Paginated list of audit logs."""
    audit_logs: list[AuditLogResponse] = Field(..., description="List of audit log entries")
    total: int = Field(..., example=150, ge=0, description="Total number of matching audit logs")
    limit: int = Field(..., example=50, ge=1, le=500, description="Requested limit")
    offset: int = Field(..., example=0, ge=0, description="Requested offset")


class AuditLogQueryParams(PaginationParams):
    """Query parameters for GET /api/v1/audit-logs."""
    username: str | None = Field(None, description="Filter by username")
    action: str | None = Field(None, description="Filter by action type")
    resource_type: str | None = Field(None, description="Filter by resource type")
    resource_id: str | None = Field(None, description="Filter by resource ID")
    start_time: datetime | None = Field(None, description="Filter by start time")
    end_time: datetime | None = Field(None, description="Filter by end time")
