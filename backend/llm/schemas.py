"""Validated response models for local LLM threat analysis."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Literal["low", "medium", "high", "critical"]
    vector: str = Field(min_length=1)
    action: Literal["block_ip", "rate_limit", "monitor", "isolate_device"]
    explanation: str = Field(min_length=1)