"""
REST API route handlers for the IDS/IPS system.
Covers alerts, incidents, devices, metrics, configuration, and reports.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status, WebSocket
from fastapi.encoders import jsonable_encoder
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.auth import AuthService, get_current_user, require_role
from backend.api.schemas import (
    AcknowledgeIncidentRequest,
    AlertListResponse,
    AlertQueryParams,
    AlertResponse,
    AuditLogListResponse,
    AuditLogResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    DeviceListResponse,
    DeviceQueryParams,
    DeviceResponse,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentQueryParams,
    IncidentResponse,
    MetricsResponse,
    QueueDepthMetrics,
    MLLatencyMetrics,
    AgentThroughputMetrics,
    NetworkThroughputMetrics,
    TrafficFlowResponse,
    ReportListResponse,
    ReportMetadata,
    ReportResponse,
    TokenData,
)
from backend.database.connection import get_session
from backend.database.models import (
    AttackEventModel,
    AuditLogModel,
    IncidentModel,
    IoTDeviceModel,
    MitigationActionModel,
)
from backend.utils.config_loader import SystemConfig, load_config, export_yaml
from backend.api.ws_manager import ws_manager

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter()


# ---------------------------------------------------------------------------
# Alerts Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/alerts",
    response_model=AlertListResponse,
    response_description="Paginated list of attack alerts",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get attack alerts",
    description="Retrieve paginated list of attack events with optional severity filtering",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error — limit > 500 or invalid offset"},
    },
)
async def get_alerts(
    limit: Annotated[int, Query(ge=1, le=500, description="Maximum number of alerts to return (1–500)")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of alerts to skip (non-negative)")] = 0,
    severity: Annotated[
        str | None,
        Query(
            description="Filter by severity level",
            pattern="^(medium|high|critical)$",
        ),
    ] = None,
    session: AsyncSession = Depends(get_session),
) -> AlertListResponse:
    """
    Get paginated list of attack alerts.
    
    Query Parameters:
        - limit: Maximum number of alerts to return (1-500, default 50)
        - offset: Number of alerts to skip (default 0)
        - severity: Filter by severity level (medium, high, critical)
    
    Returns:
        AlertListResponse with alerts, total count, limit, and offset
    """
    # Build base query
    query = select(AttackEventModel).order_by(AttackEventModel.timestamp.desc())
    
    # Apply severity filter if provided
    if severity:
        severity_thresholds = {
            "critical": 0.9,
            "high": 0.75,
            "medium": 0.65,
        }
        threshold = severity_thresholds[severity]
        
        # For critical: >= 0.9, for high: >= 0.75 and < 0.9, for medium: >= 0.65 and < 0.75
        if severity == "critical":
            query = query.where(AttackEventModel.composite_score >= threshold)
        elif severity == "high":
            query = query.where(
                AttackEventModel.composite_score >= threshold,
                AttackEventModel.composite_score < 0.9,
            )
        else:  # medium
            query = query.where(
                AttackEventModel.composite_score >= threshold,
                AttackEventModel.composite_score < 0.75,
            )
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    # Execute query
    result = await session.execute(query)
    events = result.scalars().all()
    
    # Convert to response models
    alerts = [AlertResponse.from_db_model(event) for event in events]
    
    logger.info("Retrieved %d alerts (total: %d, limit: %d, offset: %d)", len(alerts), total, limit, offset)
    
    return AlertListResponse(
        alerts=alerts,
        total=total,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Incidents Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    response_description="Detailed incident view with related alerts",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get incident details",
    description="Retrieve a single incident with a summary and its related alerts",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Incident not found"},
        422: {"description": "Invalid UUID format for incident_id"},
    },
)
async def get_incident_detail(
    incident_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> IncidentDetailResponse:
    result = await session.execute(
        select(IncidentModel).where(IncidentModel.id == str(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    alert_result = await session.execute(
        select(AttackEventModel)
        .where(AttackEventModel.incident_id == str(incident_id))
        .order_by(AttackEventModel.timestamp.desc())
    )
    alerts = [AlertResponse.from_db_model(event) for event in alert_result.scalars().all()]

    summary = (
        f"{incident.attack_type or 'Security event'} detected with {incident.severity} severity "
        f"and {len(alerts)} related alert(s)."
    )

    return IncidentDetailResponse(
        id=str(incident.id),
        state=incident.state,
        severity=incident.severity,
        attack_type=incident.attack_type,
        response_plan=incident.response_plan,
        detected_at=incident.detected_at,
        resolved_at=incident.resolved_at,
        created_at=incident.created_at,
        summary=summary,
        alert_count=len(alerts),
        related_alerts=alerts,
    )


@router.get(
    "/incidents",
    response_model=IncidentListResponse,
    response_description="Paginated list of incidents",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get incidents",
    description="Retrieve paginated list of incidents with optional state filtering",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error — limit > 500, invalid offset, or unknown state value"},
    },
)
async def get_incidents(
    limit: Annotated[int, Query(ge=1, le=500, description="Maximum number of incidents to return (1–500)")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of incidents to skip (non-negative)")] = 0,
    state: Annotated[
        Literal["detected", "analyzing", "mitigating", "resolved", "closed"] | None,
        Query(description="Filter by incident state"),
    ] = None,
    session: AsyncSession = Depends(get_session),
) -> IncidentListResponse:
    """
    Get paginated list of incidents.
    
    Query Parameters:
        - limit: Maximum number of incidents to return (1-500, default 50)
        - offset: Number of incidents to skip (default 0)
        - state: Filter by incident state (detected, analyzing, mitigating, resolved, closed)
    
    Returns:
        IncidentListResponse with incidents, total count, limit, and offset
    """
    # Build base query
    query = select(IncidentModel).order_by(IncidentModel.detected_at.desc())
    
    # Apply state filter if provided
    if state:
        query = query.where(IncidentModel.state == state)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    # Execute query
    result = await session.execute(query)
    incidents = result.scalars().all()
    
    # Convert to response models
    incident_responses = [IncidentResponse.from_db_model(incident) for incident in incidents]
    
    logger.info("Retrieved %d incidents (total: %d, limit: %d, offset: %d)", len(incident_responses), total, limit, offset)
    
    return IncidentListResponse(
        incidents=incident_responses,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/incidents/{incident_id}/acknowledge",
    response_model=IncidentResponse,
    response_description="Updated incident after acknowledgment",
    dependencies=[Depends(require_role("analyst", "admin"))],
    summary="Acknowledge incident",
    description="Transition an incident to resolved state",
    responses={
        404: {"description": "Incident not found"},
        409: {"description": "Incident already closed"},
        422: {"description": "Invalid UUID format for incident_id"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def acknowledge_incident(
    incident_id: UUID,
    body: AcknowledgeIncidentRequest,
    user: Annotated[TokenData, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
) -> IncidentResponse:
    """
    Acknowledge an incident and transition it to resolved state.
    
    Path Parameters:
        - incident_id: UUID of the incident to acknowledge
    
    Request Body:
        - acknowledged_by: Username of the person acknowledging
        - notes: Optional notes about the acknowledgment
    
    Returns:
        Updated IncidentResponse
    
    Raises:
        404: Incident not found
        409: Incident already closed
        422: Invalid UUID format
    """
    # Fetch incident (UUID is already validated by FastAPI/Pydantic)
    result = await session.execute(
        select(IncidentModel).where(IncidentModel.id == str(incident_id))
    )
    incident = result.scalar_one_or_none()
    
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    
    # Check if already closed
    if incident.state == "closed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident already closed",
        )
    
    # Update incident state
    incident.state = "resolved"
    incident.resolved_at = datetime.now(timezone.utc)

    # Replace response_plan with a new dict so SQLAlchemy detects JSON changes
    original_plan = incident.response_plan or {}
    updated_plan = {
        **original_plan,
        "acknowledged_by": body.acknowledged_by,
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
    }
    if body.notes:
        updated_plan["acknowledgment_notes"] = body.notes
    incident.response_plan = updated_plan

    await session.commit()
    await session.refresh(incident)
    
    logger.info(
        "Incident %s acknowledged by %s (user: %s)",
        incident_id,
        body.acknowledged_by,
        user.username,
    )
    # Record audit log for the acknowledgment
    try:
        audit = AuditLogModel(
            username=user.username,
            action="acknowledge_incident",
            resource_type="incident",
            resource_id=str(incident_id),
            details={
                "acknowledged_by": body.acknowledged_by,
                **({"notes": body.notes} if body.notes else {}),
            },
            status="success",
            ip_address=None,
            user_agent=None,
        )
        session.add(audit)
        await session.commit()
    except Exception:
        # Don't block the main flow if audit logging fails
        logger.exception("Failed to record audit log for acknowledge_incident %s", incident_id)

    return IncidentResponse.from_db_model(incident)


# ---------------------------------------------------------------------------
# Devices Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/devices",
    response_model=DeviceListResponse,
    response_description="Paginated list of IoT devices",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get IoT devices",
    description="Retrieve paginated list of IoT devices with optional isolation filter",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error — limit > 500 or invalid offset"},
    },
)
async def get_devices(
    limit: Annotated[int, Query(ge=1, le=500, description="Maximum number of devices to return (1–500)")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of devices to skip (non-negative)")] = 0,
    is_isolated: Annotated[bool | None, Query(description="Filter by isolation status")] = None,
    session: AsyncSession = Depends(get_session),
) -> DeviceListResponse:
    """
    Get paginated list of IoT devices.
    
    Query Parameters:
        - limit: Maximum number of devices to return (1-500, default 50)
        - offset: Number of devices to skip (default 0)
        - is_isolated: Filter by isolation status (true/false)
    
    Returns:
        DeviceListResponse with devices, total count, limit, and offset
    """
    # Build base query
    query = select(IoTDeviceModel).order_by(IoTDeviceModel.last_seen.desc())
    
    # Apply isolation filter if provided
    if is_isolated is not None:
        query = query.where(IoTDeviceModel.is_isolated == is_isolated)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    # Execute query
    result = await session.execute(query)
    devices = result.scalars().all()
    
    # Convert to response models
    device_responses = [DeviceResponse.from_db_model(device) for device in devices]
    
    logger.info("Retrieved %d devices (total: %d, limit: %d, offset: %d)", len(device_responses), total, limit, offset)
    
    return DeviceListResponse(
        devices=device_responses,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/devices/{device_id}/isolate",
    response_model=DeviceResponse,
    response_description="Isolated IoT device details",
    dependencies=[Depends(require_role("analyst", "admin"))],
    summary="Isolate an IoT device",
    description="Mark a device as isolated in the system.",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Device not found"},
    },
)
async def isolate_device(
    device_id: str,
    request: Request,
    user: Annotated[TokenData, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
) -> DeviceResponse:
    result = await session.execute(
        select(IoTDeviceModel).where(IoTDeviceModel.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    device.is_isolated = True
    device.last_seen = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(device)
    # Audit log entry
    try:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        audit = AuditLogModel(
            username=user.username,
            action="isolate_device",
            resource_type="device",
            resource_id=device_id,
            details={"device_id": device_id},
            status="success",
            ip_address=ip,
            user_agent=ua,
        )
        session.add(audit)
        await session.commit()
    except Exception:
        logger.exception("Failed to record audit log for isolate_device %s", device_id)

    return DeviceResponse.from_db_model(device)


@router.post(
    "/devices/{device_id}/release",
    response_model=DeviceResponse,
    response_description="Released IoT device details",
    dependencies=[Depends(require_role("analyst", "admin"))],
    summary="Release an isolated IoT device",
    description="Mark a device as released from isolation in the system.",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Device not found"},
    },
)
async def release_device(
    device_id: str,
    request: Request,
    user: Annotated[TokenData, Depends(get_current_user)],
    session: AsyncSession = Depends(get_session),
) -> DeviceResponse:
    result = await session.execute(
        select(IoTDeviceModel).where(IoTDeviceModel.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    device.is_isolated = False
    device.last_seen = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(device)
    # Audit log entry
    try:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        audit = AuditLogModel(
            username=user.username,
            action="release_device",
            resource_type="device",
            resource_id=device_id,
            details={"device_id": device_id},
            status="success",
            ip_address=ip,
            user_agent=ua,
        )
        session.add(audit)
        await session.commit()
    except Exception:
        logger.exception("Failed to record audit log for release_device %s", device_id)

    return DeviceResponse.from_db_model(device)


@router.get(
    "/audit-logs",
    response_model=AuditLogListResponse,
    response_description="Paginated list of audit log entries",
    dependencies=[Depends(require_role("admin"))],
    summary="Get audit logs",
    description="Retrieve paginated audit logs with optional filters (admin only)",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error — limit > 500 or invalid offset"},
    },
)
async def get_audit_logs(
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    username: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    session: AsyncSession = Depends(get_session),
) -> AuditLogListResponse:
    # Build base query
    query = select(AuditLogModel).order_by(AuditLogModel.timestamp.desc())

    if username:
        query = query.where(AuditLogModel.username == username)
    if action:
        query = query.where(AuditLogModel.action == action)
    if resource_type:
        query = query.where(AuditLogModel.resource_type == resource_type)
    if resource_id:
        query = query.where(AuditLogModel.resource_id == resource_id)
    if start_time:
        query = query.where(AuditLogModel.timestamp >= start_time)
    if end_time:
        query = query.where(AuditLogModel.timestamp <= end_time)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    query = query.limit(limit).offset(offset)
    result = await session.execute(query)
    rows = result.scalars().all()

    # Map to response schema
    audit_list = [AuditLogResponse(
        id=row.id,
        username=row.username,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        details=row.details,
        status=row.status,
        ip_address=str(row.ip_address) if row.ip_address else None,
        user_agent=row.user_agent,
        timestamp=row.timestamp,
    ) for row in rows]

    return AuditLogListResponse(audit_logs=audit_list, total=total, limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# Metrics Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/metrics",
    response_model=MetricsResponse,
    response_description="Current system metrics including queue depths and ML latencies",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get system metrics",
    description="Retrieve current system metrics including queue depths and ML latencies",
    responses={
        200: {"description": "System metrics snapshot including event counts, queue depths, ML latency percentiles, and active incident count"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def get_metrics(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> MetricsResponse:
    """
    Get current system metrics.
    
    Returns:
        MetricsResponse with:
        - total_events_processed: Total number of events processed
        - total_mitigations_applied: Total number of mitigations applied
        - queue_depths: Current depth of all agent queues
        - ml_latency_ms: ML inference latency percentiles
        - packet_drops: Total packet drops
        - active_incidents: Number of active incidents
    """
    # Get agents and pipeline from app state
    agents = getattr(request.app.state, "agents", {})
    pipeline = getattr(request.app.state, "pipeline", None)
    
    # Get queue depths from AgentQueues
    from backend.agents.queues import get_queues
    queues = get_queues()
    
    queue_depths = QueueDepthMetrics(
        detection=queues.detection_queue.qsize(),
        anomaly=queues.anomaly_queue.qsize(),
        risk=queues.risk_queue.qsize(),
        orchestrator=queues.orchestrator_queue.qsize(),
        prevention=queues.prevention_queue.qsize(),
        healing=queues.healing_queue.qsize(),
        logging=queues.logging_queue.qsize(),
    )
    
    # Get ML latency metrics from pipeline
    ml_latency = MLLatencyMetrics(
        lightgbm_p50=0.0,
        lightgbm_p95=0.0,
        lightgbm_p99=0.0,
        if_p50=0.0,
        if_p95=0.0,
        if_p99=0.0,
    )
    
    if pipeline and hasattr(pipeline, "get_latency_stats"):
        stats = pipeline.get_latency_stats()
        ml_latency = MLLatencyMetrics(
            lightgbm_p50=stats.get("lightgbm_p50", 0.0) * 1000,  # Convert to ms
            lightgbm_p95=stats.get("lightgbm_p95", 0.0) * 1000,
            lightgbm_p99=stats.get("lightgbm_p99", 0.0) * 1000,
            if_p50=stats.get("if_p50", 0.0) * 1000,
            if_p95=stats.get("if_p95", 0.0) * 1000,
            if_p99=stats.get("if_p99", 0.0) * 1000,
        )
    
    # Get total events processed (count from attack_events table)
    events_result = await session.execute(select(func.count()).select_from(AttackEventModel))
    total_events = events_result.scalar() or 0
    
    # Get total mitigations applied (count from mitigation_actions table)
    mitigations_result = await session.execute(
        select(func.count()).select_from(MitigationActionModel).where(
            MitigationActionModel.status == "applied"
        )
    )
    total_mitigations = mitigations_result.scalar() or 0
    
    # Get active incidents count
    active_incidents_result = await session.execute(
        select(func.count()).select_from(IncidentModel).where(
            IncidentModel.state.in_(["detected", "analyzing", "mitigating"])
        )
    )
    active_incidents = active_incidents_result.scalar() or 0
    
    # Packet drops from in-memory counter
    from backend.metrics import get_packet_drops, get_events_processed, get_current_rates
    packet_drops = get_packet_drops()
    events_by_agent = get_events_processed()
    current_kbps, current_pps = get_current_rates()
    
    agent_throughput = AgentThroughputMetrics(
        TrafficAgent=events_by_agent.get("TrafficAgent", 0),
        AnalysisAgent=events_by_agent.get("AnalysisAgent", 0),
        LLMOrchestrator=events_by_agent.get("LLMOrchestrator", 0),
        ResponseAgent=events_by_agent.get("ResponseAgent", 0),
        ObservabilityAgent=events_by_agent.get("ObservabilityAgent", 0),
    )
    
    network_throughput = NetworkThroughputMetrics(
        kbps=current_kbps,
        pps=current_pps,
    )
    
    return MetricsResponse(
        total_events_processed=total_events,
        total_mitigations_applied=total_mitigations,
        queue_depths=queue_depths,
        ml_latency_ms=ml_latency,
        packet_drops=packet_drops,
        active_incidents=active_incidents,
        agent_throughput=agent_throughput,
        network_throughput=network_throughput,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/live-traffic",
    response_model=list[TrafficFlowResponse],
    response_description="Latest live traffic flow metadata from the traffic agent",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get live traffic flows",
    description="Retrieve the most recent captured network flow metadata from the live traffic agent.",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def get_live_traffic(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100, description="Maximum number of live flows to return")] = 50,
) -> list[TrafficFlowResponse]:
    """Get the latest live traffic flows captured by the traffic agent."""
    agents = getattr(request.app.state, "agents", {})
    traffic_agent = agents.get("traffic")
    if traffic_agent is None or not hasattr(traffic_agent, "get_recent_flows"):
        return []

    flows = traffic_agent.get_recent_flows(limit=limit)
    return [TrafficFlowResponse.from_feature_vector(flow) for flow in flows]


# ---------------------------------------------------------------------------
# Configuration Endpoints


@router.websocket("/ws/live-traffic")
async def ws_live_traffic(websocket: WebSocket):
    """Broadcast live flows to clients with a valid signed JWT."""
    authorization = websocket.headers.get("authorization", "")
    token = (
        authorization.split(" ", 1)[1]
        if authorization.lower().startswith("bearer ")
        else websocket.query_params.get("token", "")
    )
    try:
        AuthService.verify_token(token)
    except HTTPException:
        logger.warning("Rejected unauthenticated WebSocket connection")
        await websocket.close(code=1008)
        return

    logger.debug("WebSocket connection accepted, connecting manager")
    await ws_manager.connect(websocket)
    logger.info("WebSocket connection established")

    # Send an immediate snapshot of recent live flows so frontends can render
    # an initial state without waiting for the next flow event.
    agents = getattr(websocket.app.state, "agents", {})
    traffic_agent = agents.get("traffic")
    if traffic_agent is not None and hasattr(traffic_agent, "get_recent_flows"):
        recent_flows = traffic_agent.get_recent_flows(limit=50)
        snapshot_payload = [
            TrafficFlowResponse.from_feature_vector(flow).model_dump(mode="json")
            for flow in recent_flows
        ]
        await websocket.send_json({"type": "snapshot", "payload": snapshot_payload})

    try:
        # Keep connection open until client disconnects. The manager pushes updates.
        while True:
            # Wait for any message from client to allow ping/pong behavior; ignore payload.
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        await ws_manager.disconnect(websocket)
# ---------------------------------------------------------------------------

@router.get(
    "/config",
    response_model=ConfigResponse,
    response_description="Current system configuration",
    dependencies=[Depends(require_role("analyst", "admin"))],
    summary="Get system configuration",
    description="Retrieve current system configuration",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions — viewer role cannot access configuration"},
    },
)
async def get_config(request: Request) -> ConfigResponse:
    """
    Get current system configuration.
    
    Returns:
        ConfigResponse with all configuration parameters
    """
    # Load config from file or app state
    config = getattr(request.app.state, "config", None)
    if config is None:
        config = load_config()
    
    return ConfigResponse(
        detection_threshold=config.detection_threshold,
        anomaly_threshold=config.anomaly_threshold,
        composite_threshold=config.composite_threshold,
        whitelist_ips=config.whitelist_ips,
        blacklist_ips=config.blacklist_ips,
        enabled_attack_categories=config.enabled_attack_categories,
        log_retention_days=config.log_retention_days,
        privacy_mode=config.privacy_mode,
        signature_updates_enabled=config.signature_updates_enabled,
        threat_intel_enabled=config.threat_intel_enabled,
        threat_intel_update_interval_hours=config.threat_intel_update_interval_hours,
        alert_threshold_critical=config.alert_threshold_critical,
        backup_retention_days=config.backup_retention_days,
        version=config.version,
    )


@router.put(
    "/config",
    response_model=ConfigResponse,
    response_description="Updated system configuration after applying changes",
    dependencies=[Depends(require_role("admin"))],
    summary="Update system configuration",
    description="Update system configuration with validation and propagation to agents",
    responses={
        422: {"description": "Validation error — out-of-range threshold values, invalid IP addresses, or unknown attack categories"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions — only admin role can update configuration"},
    },
)
async def update_config(
    body: ConfigUpdateRequest,
    request: Request,
    user: Annotated[TokenData, Depends(get_current_user)],
) -> ConfigResponse:
    """
    Update system configuration.
    
    Request Body:
        Partial configuration update (only provided fields will be updated)
    
    Returns:
        Updated ConfigResponse
    
    Raises:
        422: Validation failure (out of range values, invalid IPs, etc.)
    """
    # Load current config
    config = getattr(request.app.state, "config", None)
    if config is None:
        config = load_config()
    
    # Apply updates (only fields that were provided)
    update_data = body.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        if hasattr(config, field):
            setattr(config, field, value)
    
    # Validate updated config
    from backend.utils.config_loader import _validate
    try:
        _validate(config)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    
    # Propagate changes to agents
    agents = getattr(request.app.state, "agents", {})
    
    # Propagate composite_threshold to Risk_Agent
    if "composite_threshold" in update_data and "risk" in agents:
        risk_agent = agents["risk"]
        if hasattr(risk_agent, "set_threshold"):
            risk_agent.set_threshold(config.composite_threshold)
            logger.info("Propagated composite_threshold=%f to Risk_Agent", config.composite_threshold)
    
    # Propagate whitelist_ips to Prevention_Agent
    if "whitelist_ips" in update_data and "prevention" in agents:
        prevention_agent = agents["prevention"]
        if hasattr(prevention_agent, "set_whitelist"):
            prevention_agent.set_whitelist(config.whitelist_ips)
            logger.info("Propagated whitelist_ips to Prevention_Agent: %s", config.whitelist_ips)
    
    # Store updated config in app state
    request.app.state.config = config
    
    logger.info("Configuration updated: %s", update_data.keys())
    # Audit log entry for configuration updates
    try:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        audit = AuditLogModel(
            username=user.username,
            action="update_config",
            resource_type="config",
            resource_id="system",
            details={"updated_fields": list(update_data.keys())},
            status="success",
            ip_address=ip,
            user_agent=ua,
        )
        # Use a new session to persist audit without affecting response flow
        from backend.database.connection import session_context
        async with session_context() as session:
            session.add(audit)
    except Exception:
        logger.exception("Failed to record audit log for update_config")
    
    return ConfigResponse(
        detection_threshold=config.detection_threshold,
        anomaly_threshold=config.anomaly_threshold,
        composite_threshold=config.composite_threshold,
        whitelist_ips=config.whitelist_ips,
        blacklist_ips=config.blacklist_ips,
        enabled_attack_categories=config.enabled_attack_categories,
        log_retention_days=config.log_retention_days,
        privacy_mode=config.privacy_mode,
        signature_updates_enabled=config.signature_updates_enabled,
        threat_intel_enabled=config.threat_intel_enabled,
        threat_intel_update_interval_hours=config.threat_intel_update_interval_hours,
        alert_threshold_critical=config.alert_threshold_critical,
        backup_retention_days=config.backup_retention_days,
        version=config.version,
    )


# ---------------------------------------------------------------------------
# Reports Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/reports",
    response_model=ReportListResponse,
    response_description="List of available report metadata, or a freshly generated report",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get reports",
    description="List available reports. Optionally generate one on-the-fly with ?type=daily|weekly|monthly",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error — invalid type value or out-of-range year/month"},
    },
)
async def get_reports(
    request: Request,
    type: Annotated[str | None, Query()] = None,
    year: Annotated[int | None, Query(ge=2020, le=2100)] = None,
    month: Annotated[int | None, Query(ge=1, le=12)] = None,
    session: AsyncSession = Depends(get_session),
) -> ReportListResponse:
    """
    List available reports, or generate a specific report on demand.

    Query Parameters:
        - type: Report type to generate (daily, weekly, monthly)
        - year: Year for monthly report (required when type=monthly)
        - month: Month for monthly report (required when type=monthly)

    Returns:
        ReportListResponse with report metadata
    """
    if type is None:
        # Return empty list — no persistent report store yet
        return ReportListResponse(reports=[], total=0)

    # Generate a report on demand via the merged observability agent
    reporting_agent = None
    if request and hasattr(request.app.state, "agents"):
        reporting_agent = request.app.state.agents.get("observability")

    if reporting_agent is None:
        from backend.agents.observability_agent import ObservabilityAgent
        reporting_agent = ObservabilityAgent()

    today = date.today()

    if type == "daily":
        report = await reporting_agent.generate_daily_report(today - timedelta(days=1))
    elif type == "weekly":
        week_start = today - timedelta(days=today.weekday() + 7)
        report = await reporting_agent.generate_weekly_report(week_start)
    elif type == "monthly":
        y = year or today.year
        m = month or (today.month - 1 or 12)
        if month is None and today.month == 1:
            y -= 1
        report = await reporting_agent.generate_monthly_report(m, y)
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="type must be one of: daily, weekly, monthly",
        )

    meta = ReportMetadata(
        id=f"{type}-{report.period_start.isoformat()}",
        report_type=type,
        period_start=datetime.combine(report.period_start, datetime.min.time()),
        period_end=datetime.combine(report.period_end, datetime.min.time()),
        generated_at=report.generated_at,
        format="json",
    )
    return ReportListResponse(reports=[meta], total=1)


@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
    response_description="Full report data for the requested period",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
    summary="Get report by ID",
    description="Generate and return a report. report_id format: daily-YYYY-MM-DD | weekly-YYYY-MM-DD | monthly-YYYY-MM-DD",
    responses={
        404: {"description": "Invalid report_id format or unrecognised report type"},
        422: {"description": "Invalid format query parameter — must be 'json' or 'csv'"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def get_report(
    request: Request,
    report_id: str,
    format: Annotated[str, Query()] = "json",
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """
    Generate and return a report by ID.

    report_id format: {type}-{period_start}
    Examples:
        - daily-2026-04-30
        - weekly-2026-04-27
        - monthly-2026-04-01

    Query Parameters:
        - format: Output format (json or csv) — csv returns the same schema, use export endpoint for raw CSV

    Returns:
        ReportResponse with full report data

    Raises:
        404: Invalid report_id format
        422: Invalid format parameter
    """
    if format not in ("json", "csv"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="format must be 'json' or 'csv'",
        )

    # Parse report_id: e.g. "daily-2026-04-30"
    parts = report_id.split("-", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid report_id format. Expected: {type}-{YYYY-MM-DD}",
        )

    report_type, date_str = parts
    if report_type not in ("daily", "weekly", "monthly"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid report type. Must be daily, weekly, or monthly",
        )

    try:
        period_start = date.fromisoformat(date_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Invalid date in report_id: {date_str}",
        )

    # Get or create the merged observability agent
    reporting_agent = None
    if request and hasattr(request.app.state, "agents"):
        reporting_agent = request.app.state.agents.get("observability")
    if reporting_agent is None:
        from backend.agents.observability_agent import ObservabilityAgent
        reporting_agent = ObservabilityAgent()

    # Generate the report
    if report_type == "daily":
        report = await reporting_agent.generate_daily_report(period_start)
    elif report_type == "weekly":
        report = await reporting_agent.generate_weekly_report(period_start)
    else:  # monthly
        report = await reporting_agent.generate_monthly_report(
            period_start.month, period_start.year
        )

    return ReportResponse(
        id=report_id,
        report_type=report_type,
        period_start=datetime.combine(report.period_start, datetime.min.time()),
        period_end=datetime.combine(report.period_end, datetime.min.time()),
        generated_at=report.generated_at,
        total_events=report.total_events,
        total_mitigations=report.total_mitigations,
        attack_counts=report.attack_counts,
        mttd_by_type=report.mttd_by_type,
        mttr_by_type=report.mttr_by_type,
    )
