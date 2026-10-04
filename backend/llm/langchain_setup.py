"""
LangChain setup for local LLM inference via Ollama.
Wraps inference with a 5-second timeout and falls back gracefully.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
from typing import Any
from urllib.parse import urlparse

from pydantic import ValidationError

from backend.llm.schemas import ThreatAssessment

logger = logging.getLogger(__name__)


def _resolve_ollama_host() -> str:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip()
    parsed = urlparse(host)
    if parsed.hostname == "host.docker.internal":
        try:
            socket.gethostbyname(parsed.hostname)
        except OSError:
            fallback = "http://localhost:11434"
            if host != fallback:
                logger.warning(
                    "OLLAMA_HOST=%s is not resolvable; falling back to %s",
                    host,
                    fallback,
                )
            os.environ["OLLAMA_HOST"] = fallback
            return fallback
    return host


_OLLAMA_HOST = _resolve_ollama_host()
_LLM_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-3b-iot-ids")
_LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT_SECONDS", "5.0"))


def _build_llm():
    """Build Ollama LLM instance. Returns None if langchain unavailable."""
    try:
        from langchain_community.llms import Ollama
        return Ollama(base_url=_OLLAMA_HOST, model=_LLM_MODEL)
    except ImportError:
        logger.warning("langchain_community not installed — LLM disabled")
        return None
    except Exception as exc:
        logger.warning("Failed to build Ollama LLM: %s", exc)
        return None


_llm = None


def get_llm():
    global _llm
    if _llm is None:
        _llm = _build_llm()
    return _llm


async def analyze_threat(prompt: str) -> dict[str, Any] | None:
    """
    Run LLM inference with a 5-second timeout.
    Returns parsed JSON dict or None on timeout/error.
    """
    llm = get_llm()
    if llm is None:
        return None

    try:
        loop = asyncio.get_event_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(None, llm.invoke, prompt),
            timeout=_LLM_TIMEOUT,
        )
        # Extract JSON from response
        text = str(response).strip()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            payload = json.loads(text[start:end])
            return ThreatAssessment.model_validate(payload).model_dump()
        logger.warning("LLM response did not contain a JSON object")
        return None
    except asyncio.TimeoutError:
        logger.warning("LLM inference timed out after %.1fs", _LLM_TIMEOUT)
        return None
    except (json.JSONDecodeError, ValidationError) as exc:
        logger.warning("LLM response failed JSON/schema validation: %s", exc)
        return None
    except Exception as exc:
        logger.warning("LLM inference error: %s", exc)
        return None


async def check_ollama_health() -> bool:
    """Return True if Ollama is reachable."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{_OLLAMA_HOST}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False
