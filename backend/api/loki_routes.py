"""
Loki-related API routes: lightweight proxy to Loki for log queries.
"""
from __future__ import annotations

import os
import logging
from typing import Annotated
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from backend.api.auth import require_role

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/logs",
    summary="Search Loki logs",
    dependencies=[Depends(require_role("viewer", "analyst", "admin"))],
)
async def search_logs(
    request: Request,
    q: Annotated[str | None, Query(description="LogQL query string")] = None,
    start: Annotated[str | None, Query(description="ISO8601 start time or nanoseconds timestamp")] = None,
    end: Annotated[str | None, Query(description="ISO8601 end time or nanoseconds timestamp")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict:
    """Proxy a simple query request to Loki.

    Returns the raw Loki JSON response.
    """
    loki_url = os.environ.get("LOKI_URL", "http://loki:3100")
    
    # Base LogQL query: if q is not specified, query everything
    # In LogQL, you must specify a stream selector, e.g. {job="ids_system"} or level=~".+"
    query = q if q else '{job="ids_system"}'
    
    params = {
        "query": query,
        "limit": limit
    }
    
    # Helper to parse datetime/timestamp to nanoseconds
    def parse_time_to_ns(t_str: str | None) -> str | None:
        if not t_str:
            return None
        try:
            # Check if it's already a numeric timestamp
            float(t_str)
            return t_str
        except ValueError:
            pass
        try:
            # Parse ISO8601
            dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
            return str(int(dt.timestamp() * 1e9))
        except Exception:
            return None

    ns_start = parse_time_to_ns(start)
    if ns_start:
        params["start"] = ns_start
        
    ns_end = parse_time_to_ns(end)
    if ns_end:
        params["end"] = ns_end

    url = f"{loki_url.rstrip('/')}/loki/api/v1/query_range"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("Loki query failed: %s", exc)
        raise HTTPException(status_code=502, detail="Loki query failed")
    except Exception as exc:
        logger.debug("Loki proxy error: %s", exc)
        raise HTTPException(status_code=503, detail="Loki unavailable")
