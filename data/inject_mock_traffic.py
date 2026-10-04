"""
Live mock traffic injector for local development.

Generates realistic IoT network flow events and writes them to a fake
Suricata eve.json file that the TrafficAgent tails in real time.

Usage:
    python data/inject_mock_traffic.py                  # default 1 event/sec
    python data/inject_mock_traffic.py --rate 5         # 5 events/sec
    python data/inject_mock_traffic.py --attacks-only   # only attack traffic
    python data/inject_mock_traffic.py --output /tmp/eve.json

Then set in .env:
    SURICATA_LOG_PATH=/tmp/eve.json   (or wherever you point --output)
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Traffic templates
# ---------------------------------------------------------------------------

_NORMAL_FLOWS = [
    {"proto": "TCP",  "src_port": 54321, "dest_port": 80,   "tcp_flags": "18", "label": "BENIGN"},
    {"proto": "TCP",  "src_port": 55000, "dest_port": 443,  "tcp_flags": "18", "label": "BENIGN"},
    {"proto": "UDP",  "src_port": 5683,  "dest_port": 5683, "tcp_flags": "00", "label": "BENIGN"},
    {"proto": "TCP",  "src_port": 60000, "dest_port": 1883, "tcp_flags": "18", "label": "BENIGN"},
    {"proto": "ICMP", "src_port": 0,     "dest_port": 0,    "tcp_flags": "00", "label": "BENIGN"},
]

_ATTACK_FLOWS = [
    # DDoS — high packet rate, SYN flood
    {"proto": "TCP",  "src_port": 12345, "dest_port": 80,   "tcp_flags": "02",
     "pkts": (2000, 8000), "bytes": (80000, 400000), "label": "DDoS"},
    # Port scan — many ports, SYN only
    {"proto": "TCP",  "src_port": 54321, "dest_port": None, "tcp_flags": "02",
     "pkts": (10, 50),     "bytes": (600, 3000),     "label": "PortScan"},
    # Brute force SSH
    {"proto": "TCP",  "src_port": 55555, "dest_port": 22,   "tcp_flags": "18",
     "pkts": (20, 80),     "bytes": (1200, 6000),    "label": "BruteForce"},
    # Botnet C2
    {"proto": "TCP",  "src_port": 49152, "dest_port": 6667, "tcp_flags": "18",
     "pkts": (5, 20),      "bytes": (300, 2000),     "label": "Botnet"},
]

_IOT_SRC_IPS = [f"192.168.1.{i}" for i in range(2, 30)]
_EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 50)] + \
                [f"198.51.100.{i}" for i in range(1, 50)]


def _make_flow_event(attack: bool = False) -> dict:
    """Build a Suricata-style eve.json flow event."""
    if attack:
        tmpl = random.choice(_ATTACK_FLOWS)
        src_ip = random.choice(_EXTERNAL_IPS)
        dst_ip = random.choice(_IOT_SRC_IPS)
        pkts_range = tmpl.get("pkts", (50, 500))
        bytes_range = tmpl.get("bytes", (3000, 30000))
        dst_port = tmpl["dest_port"] or random.randint(1, 1024)
        duration = random.uniform(0.1, 2.0)
    else:
        tmpl = random.choice(_NORMAL_FLOWS)
        src_ip = random.choice(_IOT_SRC_IPS)
        dst_ip = f"192.168.1.{random.randint(100, 200)}"
        pkts_range = (2, 50)
        bytes_range = (100, 5000)
        dst_port = tmpl["dest_port"]
        duration = random.uniform(0.5, 10.0)

    pkts_to_server = random.randint(*pkts_range)
    pkts_to_client = random.randint(1, max(1, pkts_to_server // 2))
    bytes_to_server = random.randint(*bytes_range)
    bytes_to_client = random.randint(100, max(100, bytes_to_server // 3))

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": tmpl["src_port"],
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": tmpl["proto"],
        "app_proto": "failed" if attack else "http",
        "flow": {
            "pkts_toserver": pkts_to_server,
            "pkts_toclient": pkts_to_client,
            "bytes_toserver": bytes_to_server,
            "bytes_toclient": bytes_to_client,
            "start": datetime.now(timezone.utc).isoformat(),
            "end": datetime.now(timezone.utc).isoformat(),
            "age": round(duration, 3),
            "state": "closed",
            "reason": "timeout",
        },
        "tcp": {
            "tcp_flags": tmpl["tcp_flags"],
            "tcp_flags_ts": tmpl["tcp_flags"],
            "tcp_flags_tc": tmpl["tcp_flags"],
        },
        "_label": tmpl["label"],  # informational only, not part of Suricata spec
    }


# ---------------------------------------------------------------------------
# Main injector loop
# ---------------------------------------------------------------------------

def run(output_path: str, rate: float, attacks_only: bool, attack_ratio: float) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Writing mock Suricata eve.json to: {path}")
    print(f"Rate: {rate} events/sec | Attack ratio: {attack_ratio:.0%}")
    print(f"Set SURICATA_LOG_PATH={path} in your .env")
    print("Press Ctrl+C to stop.\n")

    interval = 1.0 / rate
    count = 0

    with open(path, "a", encoding="utf-8") as f:
        try:
            while True:
                is_attack = attacks_only or (random.random() < attack_ratio)
                event = _make_flow_event(attack=is_attack)
                f.write(json.dumps(event) + "\n")
                f.flush()
                count += 1

                label = event["_label"]
                src = event["src_ip"]
                dst = f"{event['dest_ip']}:{event['dest_port']}"
                print(f"[{count:>6}] {label:<20} {src:<18} → {dst}")

                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\nStopped. Wrote {count} events to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject mock traffic into the IDS/IPS pipeline")
    parser.add_argument("--output", default="/tmp/eve.json",
                        help="Path to write the fake eve.json (default: /tmp/eve.json)")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="Events per second (default: 1.0)")
    parser.add_argument("--attack-ratio", type=float, default=0.3,
                        help="Fraction of events that are attacks (default: 0.3)")
    parser.add_argument("--attacks-only", action="store_true",
                        help="Generate only attack traffic")
    args = parser.parse_args()

    run(
        output_path=args.output,
        rate=args.rate,
        attacks_only=args.attacks_only,
        attack_ratio=args.attack_ratio,
    )


if __name__ == "__main__":
    main()
