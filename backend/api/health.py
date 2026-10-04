"""
Health check endpoints for Kubernetes/Docker readiness and liveness probes.
Checks database, ML models, Ollama, and agent task statuses.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any
import os

import httpx
from fastapi import APIRouter, Request, Response, status

from backend.api.schemas import HealthResponse, LivenessResponse, ReadinessResponse
from backend.database.connection import health_check

logger = logging.getLogger(__name__)

router = APIRouter()


async def check_ollama_health(ollama_url: str = "http://localhost:11434") -> bool:
    """
    Check if Ollama endpoint is reachable with 2-second timeout.
    Returns True if healthy, False otherwise.
    """
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{ollama_url}/api/tags")
            return response.status_code == 200
    except Exception as exc:
        logger.debug("Ollama health check failed: %s", exc)
        return False


async def check_loki_health(loki_url: str = "http://localhost:3100") -> bool:
    """Check whether Loki is reachable via its readiness endpoint."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{loki_url}/ready")
            return resp.status_code == 200
    except Exception as exc:
        logger.debug("Loki health check failed: %s", exc)
        return False


async def check_grafana_health(grafana_url: str = "http://localhost:3000") -> bool:
    """Check whether Grafana is reachable via its health API."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{grafana_url}/api/health")
            return resp.status_code == 200
    except Exception as exc:
        logger.debug("Grafana health check failed: %s", exc)
        return False


def check_agents_running(app_state: Any) -> dict[str, bool]:
    """
    Check whether the merged five-agent pipeline is running.
    Returns the canonical five-agent health view used by the health endpoints.
    """
    if not hasattr(app_state, "agent_tasks"):
        return {}

    agent_tasks = app_state.agent_tasks
    merged_keys = {
        "traffic": "traffic",
        "analysis": "analysis",
        "orchestrator": "orchestrator",
        "response": "response",
        "observability": "observability",
    }

    agent_status: dict[str, bool] = {}
    for output_key, source_key in merged_keys.items():
        task = agent_tasks.get(source_key)
        if task is None:
            agent_status[output_key] = False
        else:
            agent_status[output_key] = not task.done()

    return agent_status


@router.get(
    "/health",
    response_description="Overall system health status with per-component details",
    summary="System health check",
    description=(
        "Returns overall system health (healthy/degraded) with per-component status for "
        "database, ML models, Ollama, and the merged five-agent pipeline. "
        "Always returns HTTP 200 — inspect the `status` field to determine health."
    ),
    responses={
        200: {
            "description": "Health status (may be 'healthy' or 'degraded')",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "timestamp": "2024-01-15T10:30:00Z",
                        "database": {"status": "ok"},
                        "ml_models": {"supervised": True, "if": True},
                        "ollama": "ok",
                        "agents": {
                            "traffic": True,
                            "analysis": True,
                            "orchestrator": True,
                            "response": True,
                            "observability": True,
                        },
                    }
                }
            },
        }
    },
)
async def health_check_endpoint(request: Request) -> dict[str, Any]:
    """
    Comprehensive health check endpoint.

    Checks the following components in parallel:
    - **database**: PostgreSQL connectivity via ``health_check()``
    - **ml_models**: Whether the supervised classifier and Isolation Forest models are loaded
    - **ollama**: Reachability of the Ollama LLM endpoint (2-second timeout)
    - **loki/grafana**: Reachability of the Grafana/Loki monitoring stack
    - **agents**: Running status of the merged five-agent background pipeline

    The overall ``status`` is ``"healthy"`` only when the database is up, at least one
    ML model is loaded, and all core agents are running. Otherwise it is ``"degraded"``.

    Returns:
        JSON object with ``status``, ``timestamp``, and per-component details.

    Requirements: 4.1, 4.4, 4.5, 4.6, 4.7
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Check database
    db_healthy = await health_check()
    db_status = "ok" if db_healthy else "error"
    db_reason = None if db_healthy else "Database connection failed"
    
    # Check ML models
    ml_models = {"lightgbm": False, "if": False}
    if hasattr(request.app.state, "pipeline"):
        pipeline = request.app.state.pipeline
        ml_models["lightgbm"] = pipeline.lightgbm_available
        ml_models["if"] = pipeline.if_available

    # Check Ollama
    ollama_url = request.app.state.ollama_url if hasattr(request.app.state, "ollama_url") else "http://localhost:11434"
    ollama_healthy = await check_ollama_health(ollama_url)
    ollama_status = "ok" if ollama_healthy else "unavailable"

    # Check Loki and Grafana, but do not treat them as hard failure for overall healthy status.
    loki_url = os.environ.get("LOKI_URL", "http://loki:3100")
    loki_healthy = await check_loki_health(loki_url)
    loki_status = "ok" if loki_healthy else "unavailable"

    grafana_url = os.environ.get("GRAFANA_URL", "http://grafana:3000")
    grafana_healthy = await check_grafana_health(grafana_url)
    grafana_status = "ok" if grafana_healthy else "unavailable"
    
    # Check agents
    agents = check_agents_running(request.app.state)

    # Determine overall status
    all_agents_running = all(agents.values()) if agents else False
    at_least_one_model = ml_models["lightgbm"] or ml_models["if"]

    overall_healthy = db_healthy and at_least_one_model and all_agents_running
    overall_status = "healthy" if overall_healthy else "degraded"

    response = {
        "status": overall_status,
        "timestamp": timestamp,
        "database": db_status if db_reason is None else {"status": db_status, "reason": db_reason},
        "ml_models": ml_models,
        "ollama": ollama_status,
        "loki": loki_status,
        "grafana": grafana_status,
        "agents": agents,
    }
    
    return response


@router.get(
    "/health/ready",
    response_description="200 if all components are ready, 503 otherwise",
    summary="Readiness probe",
    description=(
        "Kubernetes/Docker readiness probe. Returns HTTP 200 when the service is ready to "
        "accept traffic (database connected, at least one ML model loaded, all agents running). "
        "Returns HTTP 503 with a reason string when any critical component is unavailable."
    ),
    responses={
        200: {
            "description": "Service is ready",
            "content": {"application/json": {"example": {"status": "ready"}}},
        },
        503: {
            "description": "Service is not ready — one or more components unavailable",
            "content": {
                "application/json": {
                    "examples": {
                        "database_down": {
                            "summary": "Database unavailable",
                            "value": {"status": "not_ready", "reason": "database_unavailable"},
                        },
                        "models_missing": {
                            "summary": "ML models not loaded",
                            "value": {"status": "not_ready", "reason": "ml_models_unavailable"},
                        },
                        "agents_down": {
                            "summary": "One or more agents not running",
                            "value": {
                                "status": "not_ready",
                                "reason": "agents_not_running",
                                "failed_agents": ["detection"],
                            },
                        },
                    }
                }
            },
        },
    },
)
async def readiness_probe(request: Request) -> Response:
    """
    Kubernetes readiness probe.

    Performs the following checks in order:
    1. Database connectivity — returns 503 with ``reason: database_unavailable`` on failure.
    2. ML model availability — returns 503 with ``reason: ml_models_unavailable`` if neither
       the supervised classifier nor the Isolation Forest model is loaded.
    3. Agent task health — returns 503 with ``reason: agents_not_running`` and a list of
       ``failed_agents`` if any of the merged background tasks have stopped.

    Returns HTTP 200 ``{"status": "ready"}`` only when all checks pass.

    Requirements: 4.2, 4.8
    """
    # Check database
    db_healthy = await health_check()
    if not db_healthy:
        return Response(
            content='{"status": "not_ready", "reason": "database_unavailable"}',
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )
    
    # Check at least one ML model is loaded
    ml_available = False
    if hasattr(request.app.state, "pipeline"):
        pipeline = request.app.state.pipeline
        ml_available = pipeline.lightgbm_available or pipeline.if_available
    
    if not ml_available:
        return Response(
            content='{"status": "not_ready", "reason": "ml_models_unavailable"}',
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )
    
    # Check all merged five agent tasks are running
    agents = check_agents_running(request.app.state)
    all_agents_running = all(agents.values()) if agents else False
    
    if not all_agents_running:
        failed_agents = [name for name, running in agents.items() if not running]
        return Response(
            content=json.dumps({
                "status": "not_ready",
                "reason": "agents_not_running",
                "failed_agents": failed_agents,
            }),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )
    
    # All checks passed
    return Response(
        content='{"status": "ready"}',
        status_code=status.HTTP_200_OK,
        media_type="application/json",
    )


@router.get(
    "/health/live",
    response_description="Always 200 while the process is running",
    summary="Liveness probe",
    description=(
        "Kubernetes/Docker liveness probe. Always returns HTTP 200 with "
        '``{"status": "alive"}`` as long as the Python process is running. '
        "Use this endpoint to detect process crashes or deadlocks."
    ),
    responses={
        200: {
            "description": "Process is alive",
            "content": {"application/json": {"example": {"status": "alive"}}},
        }
    },
)
async def liveness_probe() -> dict[str, str]:
    """
    Kubernetes liveness probe.

    This endpoint performs no I/O — it simply returns immediately to confirm the
    event loop is responsive.  If this endpoint stops responding, the container
    orchestrator should restart the pod/container.

    Returns:
        ``{"status": "alive"}`` with HTTP 200.

    Requirements: 4.3
    """
    return {"status": "alive"}
