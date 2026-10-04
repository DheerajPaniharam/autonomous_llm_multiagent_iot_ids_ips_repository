"""
LangChain prompt templates for LLM-driven threat analysis.
"""
from __future__ import annotations

THREAT_ANALYSIS_TEMPLATE = """You are a cybersecurity analyst for an IoT network IDS/IPS system.
Analyze the following network threat and provide a concise assessment.

Attack Type: {attack_type}
Composite Threat Score: {threat_score:.2f}
Source IP: {src_ip}
Destination IP: {dst_ip}
Protocol: {protocol}
Flow Duration: {flow_duration:.2f}s
Recent Events (last 5): {recent_events}
Baseline Deviation: {baseline_deviation}

Provide:
1. Threat severity (low/medium/high/critical)
2. Likely attack vector
3. Recommended mitigation action (block_ip/rate_limit/isolate_device/monitor)
4. Brief explanation (2-3 sentences)

Return only a JSON object with exactly these keys:
{{"severity":"low|medium|high|critical","vector":"...","action":"block_ip|rate_limit|isolate_device|monitor","explanation":"..."}}
Use monitor when no active mitigation is warranted."""

CAMPAIGN_CORRELATION_TEMPLATE = """Analyze these related attack events and determine if they form a coordinated campaign:

Events:
{events_summary}

Are these events part of a coordinated attack campaign? 
Respond with JSON: {{\"is_campaign\": bool, \"campaign_type\": str, \"confidence\": float}}"""
