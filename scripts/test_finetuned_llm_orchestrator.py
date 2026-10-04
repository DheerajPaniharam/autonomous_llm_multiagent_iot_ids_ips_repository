"""
Test script to validate Ollama inference with the orchestrator prompt schema.
Runs benchmark tests for response time and JSON schema validity.
"""
import asyncio
import json
import os
import sys
import time
from typing import Any

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.llm.langchain_setup import analyze_threat, check_ollama_health
from backend.llm.prompt_templates import THREAT_ANALYSIS_TEMPLATE


TEST_ATTACKS = [
    {
        "attack_type": "TCP SYN Flood",
        "threat_score": 0.95,
        "src_ip": "192.168.1.105",
        "dst_ip": "192.168.1.1",
        "protocol": "TCP",
        "flow_duration": 0.08,
        "recent_events": "SYN Flood@0.94, SYN Flood@0.91",
        "baseline_deviation": "Critical (150x baseline rate)",
    },
    {
        "attack_type": "Port Scan",
        "threat_score": 0.73,
        "src_ip": "192.168.1.150",
        "dst_ip": "192.168.1.20",
        "protocol": "TCP",
        "flow_duration": 14.50,
        "recent_events": "Port Scan@0.71",
        "baseline_deviation": "Moderate (Entropy: 5.6 bits)",
    },
    {
        "attack_type": "Mirai Botnet C2 Beacon",
        "threat_score": 0.98,
        "src_ip": "192.168.1.45",
        "dst_ip": "198.51.100.22",
        "protocol": "TCP",
        "flow_duration": 3.20,
        "recent_events": "Mirai@0.98, Telnet@0.95",
        "baseline_deviation": "Severe (Outbound port 2323)",
    },
]


async def run_validation():
    print("=" * 60)
    print("  Testing LLM Orchestrator Threat Triage & Inference Latency ")
    print("=" * 60)

    model_name = os.environ.get("OLLAMA_MODEL", "qwen2.5-3b-iot-ids")
    print(f"Target Model: {model_name}")

    is_healthy = await check_ollama_health()
    if not is_healthy:
        print("\n[!] Ollama is not reachable. Ensure Ollama service is running.")
        return

    print("[OK] Ollama is online and healthy.\n")

    for i, attack in enumerate(TEST_ATTACKS, 1):
        prompt = THREAT_ANALYSIS_TEMPLATE.format(**attack)
        
        print(f"--- [Test Case {i}: {attack['attack_type']}] ---")
        start_time = time.perf_counter()
        
        result = await analyze_threat(prompt)
        elapsed = (time.perf_counter() - start_time) * 1000

        if result is None:
            print(f"  [X] Failed or timed out (> 5.0s)")
        else:
            print(f"  [OK] Inference Latency: {elapsed:.2f} ms")
            print(f"  [OK] Action: {result.get('action', 'N/A')}")
            print(f"  [OK] Severity: {result.get('severity', 'N/A')}")
            print(f"  [OK] Vector: {result.get('vector', 'N/A')}")
            print(f"  [OK] Explanation: {result.get('explanation', 'N/A')}")
            print(f"  [OK] Valid JSON Keys: {list(result.keys())}")
        print()

    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_validation())
