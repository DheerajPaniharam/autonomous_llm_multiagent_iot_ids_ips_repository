from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest

from backend.llm import langchain_setup
from backend.llm.prompt_templates import THREAT_ANALYSIS_TEMPLATE


class FakeLLM:
    def __init__(self, response: str) -> None:
        self.invoke = Mock(return_value=response)


@pytest.mark.parametrize(
    "response,expected",
    [
        (
            '{"severity":"high","vector":"port scan",'
            '"action":"rate_limit","explanation":"Repeated probes."}',
            "rate_limit",
        ),
        (
            '{"severity":"low","vector":"routine traffic",'
            '"action":"monitor","explanation":"No mitigation needed."}',
            "monitor",
        ),
    ],
)
def test_analyze_threat_returns_validated_response(monkeypatch, response, expected):
    monkeypatch.setattr(langchain_setup, "get_llm", lambda: FakeLLM(response))

    result = asyncio.run(langchain_setup.analyze_threat("prompt"))

    assert result is not None
    assert result["action"] == expected


@pytest.mark.parametrize(
    "response",
    [
        "not json",
        '{"severity":"extreme","vector":"scan",'
        '"action":"block_ip","explanation":"Threat."}',
        '{"severity":"high","vector":"scan","action":"block_ip",'
        '"explanation":"Threat.","target_ip":"192.0.2.1"}',
    ],
)
def test_analyze_threat_rejects_invalid_response(monkeypatch, response):
    monkeypatch.setattr(langchain_setup, "get_llm", lambda: FakeLLM(response))

    assert asyncio.run(langchain_setup.analyze_threat("prompt")) is None


def test_threat_analysis_template_formats_without_keyerror():
    prompt = THREAT_ANALYSIS_TEMPLATE.format(
        attack_type="DDoS",
        threat_score=0.93,
        src_ip="198.51.100.12",
        dst_ip="192.168.1.10",
        protocol="TCP",
        flow_duration=1.5,
        recent_events="DDoS@0.90",
        baseline_deviation="5.2x",
    )

    assert '"severity":"low|medium|high|critical"' in prompt
    assert '"action":"block_ip|rate_limit|isolate_device|monitor"' in prompt