"""
IoT IDS/IPS LLM Fine-Tuning Dataset Generator.
Generates realistic, domain-specific threat analysis scenarios
matching the prompt format of backend/llm/prompt_templates.py.
"""
import json
import os
import random

SYSTEM_PROMPT = """You are a cybersecurity analyst for an IoT network IDS/IPS system.
Analyze the following network threat and provide a concise assessment.

Provide:
1. Threat severity (low/medium/high/critical)
2. Likely attack vector
3. Recommended mitigation action (block_ip/rate_limit/monitor/isolate_device)
4. Brief explanation (2-3 sentences)

Response format: JSON with keys: severity, vector, action, explanation"""

SCENARIOS = [
    # 1. TCP SYN Flood (Volumetric DoS)
    {
        "attack_type": "TCP SYN Flood",
        "protocol": "TCP",
        "flow_duration_range": (0.01, 0.5),
        "threat_score_range": (0.88, 0.99),
        "src_ip_pool": ["192.168.1.105", "192.168.1.142", "10.0.0.55", "172.16.0.88"],
        "dst_ip_pool": ["192.168.1.1", "10.0.0.1", "192.168.1.254"],
        "recent_events": "SYN Flood@0.94, SYN Flood@0.91, SYN Flood@0.89",
        "baseline_deviation": "Critical (SYN packet arrival rate is 150x above normal baseline)",
        "severity": "critical",
        "vector": "Volumetric TCP SYN Flood targeting IoT Gateway",
        "action": "block_ip",
        "explanation_template": "Massive volume of half-open TCP connections received from {src_ip} without completing handshakes. This is an active attempt to exhaust gateway socket buffers and disrupt routing. Kernel firewall block is immediately required."
    },
    # 2. Port Scanning / Reconnaissance
    {
        "attack_type": "Port Scan",
        "protocol": "TCP",
        "flow_duration_range": (5.0, 30.0),
        "threat_score_range": (0.68, 0.78),
        "src_ip_pool": ["192.168.1.150", "192.168.1.188", "10.0.0.210", "172.16.0.44"],
        "dst_ip_pool": ["192.168.1.10", "192.168.1.20", "10.0.0.50"],
        "recent_events": "Port Scan@0.72, Port Scan@0.69, Port Scan@0.65",
        "baseline_deviation": "Moderate (Shannon destination port entropy elevated at 5.76 bits)",
        "severity": "medium",
        "vector": "Adversarial Reconnaissance and Sequential Port Sweep",
        "action": "rate_limit",
        "explanation_template": "Host {src_ip} is systematically probing closed destination ports across the subnet. Elevated port entropy indicates automated scanner activity. Applying dynamic rate limiting suppresses network discovery."
    },
    # 3. Mirai Botnet C2 / Lateral Movement
    {
        "attack_type": "Mirai Botnet C2 Beacon",
        "protocol": "TCP",
        "flow_duration_range": (1.0, 10.0),
        "threat_score_range": (0.92, 0.99),
        "src_ip_pool": ["192.168.1.45", "192.168.1.62", "10.0.0.115"],
        "dst_ip_pool": ["198.51.100.22", "203.0.113.88", "198.51.100.104"],
        "recent_events": "Mirai_Beacon@0.96, Outbound_Telnet@0.94, Brute_Force@0.90",
        "baseline_deviation": "Severe (Unauthorized outbound Telnet/C2 beacon on port 2323)",
        "severity": "critical",
        "vector": "Compromised IoT Node Mirai Botnet Command-and-Control Communication",
        "action": "isolate_device",
        "explanation_template": "IoT device at {src_ip} is transmitting binary infection payload patterns and contacting external command-and-control infrastructure. Complete device network isolation is required to prevent lateral infection of adjacent smart sensors."
    },
    # 4. MQTT Broker Credential Stuffing / Brute Force
    {
        "attack_type": "MQTT Authentication Brute Force",
        "protocol": "TCP",
        "flow_duration_range": (2.0, 12.0),
        "threat_score_range": (0.78, 0.89),
        "src_ip_pool": ["192.168.1.80", "192.168.1.95", "10.0.0.75"],
        "dst_ip_pool": ["192.168.1.2", "10.0.0.10"],
        "recent_events": "MQTT_Auth_Fail@0.82, MQTT_Auth_Fail@0.80, MQTT_Auth_Fail@0.78",
        "baseline_deviation": "High (Repeated MQTT CONNACK error codes on port 1883)",
        "severity": "high",
        "vector": "Credential Stuffing against Core MQTT Telemetry Broker",
        "action": "block_ip",
        "explanation_template": "Repeated unauthorized MQTT connection handshakes observed from {src_ip} targeting port 1883 with invalid credentials. The high velocity indicates an automated dictionary attack. Immediate IP ban recommended."
    },
    # 5. CoAP / UDP Amplification Attack
    {
        "attack_type": "UDP / CoAP Amplification",
        "protocol": "UDP",
        "flow_duration_range": (0.05, 1.2),
        "threat_score_range": (0.85, 0.95),
        "src_ip_pool": ["192.168.1.220", "192.168.1.240", "10.0.0.199"],
        "dst_ip_pool": ["192.168.1.15", "10.0.0.25"],
        "recent_events": "UDP_Flood@0.91, CoAP_Amp@0.89",
        "baseline_deviation": "Severe (Outgoing UDP payload volume 80x larger than request packet)",
        "severity": "high",
        "vector": "Reflected UDP CoAP Amplification Flood",
        "action": "block_ip",
        "explanation_template": "Source host {src_ip} is leveraging unauthenticated CoAP reflection to blast amplified response packets into the IoT subnet. Immediate IP block is essential to restore wireless link bandwidth."
    },
    # 6. Modbus / Industrial IoT Unauthorized Write
    {
        "attack_type": "Modbus Rogue Command Injection",
        "protocol": "TCP",
        "flow_duration_range": (0.5, 4.0),
        "threat_score_range": (0.90, 0.97),
        "src_ip_pool": ["192.168.1.77", "10.0.0.60"],
        "dst_ip_pool": ["192.168.1.12", "10.0.0.100"],
        "recent_events": "Modbus_Write@0.94, Modbus_Write@0.91",
        "baseline_deviation": "Critical (Modbus Function Code 0x05 / 0x06 from unauthorized endpoint on port 502)",
        "severity": "critical",
        "vector": "Industrial IoT SCADA Command Injection / Actuator Tampering",
        "action": "isolate_device",
        "explanation_template": "An untrusted endpoint {src_ip} sent illegal Modbus register write instructions to an industrial PLC on port 502. Device quarantine is necessary to protect physical actuators from unauthorized state override."
    },
    # 7. DNS Tunneling & Data Exfiltration
    {
        "attack_type": "DNS Tunneling Exfiltration",
        "protocol": "UDP",
        "flow_duration_range": (10.0, 60.0),
        "threat_score_range": (0.75, 0.88),
        "src_ip_pool": ["192.168.1.33", "192.168.1.89", "10.0.0.42"],
        "dst_ip_pool": ["192.168.1.1", "10.0.0.1", "8.8.8.8"],
        "recent_events": "DNS_Tunnel@0.81, DNS_Tunnel@0.77",
        "baseline_deviation": "High (Anomalous Base64 encoded subdomains with high Shannon entropy on port 53)",
        "severity": "high",
        "vector": "Covert Channel DNS Data Exfiltration",
        "action": "block_ip",
        "explanation_template": "Continuous high-frequency DNS lookups containing high-entropy Base64 substrings originate from {src_ip}. This signature matches covert channel data theft bypassing standard egress filters."
    },
    # 8. ARP Spoofing / Man-In-The-Middle
    {
        "attack_type": "ARP Cache Poisoning (MITM)",
        "protocol": "ARP",
        "flow_duration_range": (1.0, 15.0),
        "threat_score_range": (0.86, 0.96),
        "src_ip_pool": ["192.168.1.112", "10.0.0.85"],
        "dst_ip_pool": ["192.168.1.1", "10.0.0.1"],
        "recent_events": "ARP_Poison@0.92, ARP_Poison@0.88",
        "baseline_deviation": "Severe (Gratuitous ARP replies remapping Gateway MAC address)",
        "severity": "high",
        "vector": "Layer 2 Man-In-The-Middle ARP Cache Poisoning",
        "action": "isolate_device",
        "explanation_template": "Host {src_ip} is broadcasting unsolicited ARP replies claiming ownership of the gateway IP address. The host must be isolated from the switch fabric to stop traffic interception."
    },
    # 9. Low-Risk Statistical Anomaly (Normal Sensor Telemetry Burst)
    {
        "attack_type": "Periodic Sensor Burst Telemetry",
        "protocol": "UDP",
        "flow_duration_range": (0.2, 1.5),
        "threat_score_range": (0.65, 0.69),
        "src_ip_pool": ["192.168.1.20", "192.168.1.21", "10.0.0.30"],
        "dst_ip_pool": ["192.168.1.2", "10.0.0.2"],
        "recent_events": "none",
        "baseline_deviation": "Low (Slight statistical variance during scheduled batch sync)",
        "severity": "low",
        "vector": "Legitimate Environmental Sensor Heartbeat Fluctuations",
        "action": "monitor",
        "explanation_template": "Minor deviation in transmission interval observed from trusted sensor {src_ip}. The payload matches regular environmental metrics without malicious indicators. Passive monitoring recommended."
    },
    # 10. HTTP Firmware Upload Brute Force / Web Attack
    {
        "attack_type": "HTTP Web Admin Brute Force",
        "protocol": "TCP",
        "flow_duration_range": (3.0, 20.0),
        "threat_score_range": (0.76, 0.87),
        "src_ip_pool": ["192.168.1.166", "10.0.0.99"],
        "dst_ip_pool": ["192.168.1.1", "192.168.1.254"],
        "recent_events": "HTTP_401_Burst@0.81, HTTP_401_Burst@0.77",
        "baseline_deviation": "High (Rapid HTTP 401 Unauthorized responses on port 80/443)",
        "severity": "high",
        "vector": "Web Management Interface Credential Stuffing",
        "action": "block_ip",
        "explanation_template": "High rate of failed administrative login requests received from {src_ip} on port 80/443. The source is actively executing password brute-forcing against the gateway UI."
    }
]


def generate_dataset(num_samples: int = 600, output_file: str = "data/iot_ids_finetune_dataset.jsonl"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    records = []

    for _ in range(num_samples):
        sc = random.choice(SCENARIOS)
        src_ip = random.choice(sc["src_ip_pool"])
        dst_ip = random.choice(sc["dst_ip_pool"])
        duration = round(random.uniform(*sc["flow_duration_range"]), 2)
        threat_score = round(random.uniform(*sc["threat_score_range"]), 2)
        
        user_prompt = (
            f"Attack Type: {sc['attack_type']}\n"
            f"Composite Threat Score: {threat_score:.2f}\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {sc['protocol']}\n"
            f"Flow Duration: {duration:.2f}s\n"
            f"Recent Events (last 5): {sc['recent_events']}\n"
            f"Baseline Deviation: {sc['baseline_deviation']}"
        )

        assistant_json = {
            "severity": sc["severity"],
            "vector": sc["vector"],
            "action": sc["action"],
            "explanation": sc["explanation_template"].format(src_ip=src_ip, dst_ip=dst_ip)
        }

        record = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": json.dumps(assistant_json)}
            ]
        }
        records.append(record)

    random.shuffle(records)
    with open(output_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} fine-tuning samples at {output_file}")


if __name__ == "__main__":
    generate_dataset()
