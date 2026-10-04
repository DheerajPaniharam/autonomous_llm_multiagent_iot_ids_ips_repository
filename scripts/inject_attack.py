#!/usr/bin/env python3
"""
Inject Attack — manually inject threat flows to test device isolation.
Writes directly to the Suricata log file logs/eve.json.
"""
import os
import json
import sys
from datetime import datetime

DEVICES = {
    "1": ("smart-thermostat-01", "192.168.1.100"),
    "2": ("security-camera-02", "192.168.1.101"),
    "3": ("smart-lock-03", "192.168.1.102")
}

def load_log_path():
    log_path = "logs/eve.json"
    if os.path.exists(".env"):
        with open(".env", "r") as f:
            for line in f:
                if line.strip().startswith("SURICATA_LOG_PATH="):
                    val = line.strip().split("=", 1)[1]
                    log_path = val.strip("'\"")
                    break
    return log_path

def main():
    log_path = load_log_path()
    print("="*60)
    print("      IoT IDS/IPS Manual Threat Injector")
    print("="*60)
    print(f"Log Path: {os.path.abspath(log_path)}")
    print("-"*60)
    print("Select a device to simulate an attack FROM:")
    for key, (name, ip) in DEVICES.items():
        print(f" {key}. {name} ({ip})")
    print(" 4. Enter a custom IP address")
    print("-"*60)
    
    dev_choice = input("Select device (1-4): ").strip()
    if dev_choice in DEVICES:
        device_name, src_ip = DEVICES[dev_choice]
    elif dev_choice == "4":
        src_ip = input("Enter custom IP: ").strip()
        device_name = "custom_device"
    else:
        print("[!] Invalid selection. Exiting.")
        return

    print("\nSelect attack profile:")
    print(" 1. Critical DDoS (SYN Flood, triggers immediate isolation)")
    print(" 2. Port Scan (triggers rate limiting)")
    print("-"*60)
    
    profile_choice = input("Select profile (1-2): ").strip()
    
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    flow_event = {
        "timestamp": now,
        "event_type": "flow",
        "src_ip": src_ip,
        "dest_ip": "10.0.0.99",
        "src_port": 49152,
        "dest_port": 80,
        "proto": "TCP",
        "flow": {
            "age": 2.0,
            "pkts_toserver": 5,
            "pkts_toclient": 1,
            "bytes_toserver": 320,
            "bytes_toclient": 64,
            "state": "new"
        },
        "tcp": {
            "tcp_flags_tc": "02"
        }
    }

    if profile_choice == "1":
        # Force high rates for DDoS detection
        flow_event["flow"]["pkts_toserver"] = 50000
        flow_event["flow"]["bytes_toserver"] = 2500000
        flow_event["dest_port"] = 23 # Telnet / DDoS target port
        print(f"\n[*] Preparing Critical DDoS simulation from {device_name} ({src_ip})...")
    elif profile_choice == "2":
        flow_event["flow"]["pkts_toserver"] = 80
        flow_event["flow"]["bytes_toserver"] = 3200
        print(f"\n[*] Preparing Port Scan simulation from {device_name} ({src_ip})...")
    else:
        print("[!] Invalid selection. Exiting.")
        return

    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(flow_event) + "\n")
        print(f"[+] Successfully injected flow event to {log_path}!")
        print(f"    Source IP: {src_ip} (compromised device)")
        print(f"    Target IP: {flow_event['dest_ip']}")
        print(f"    Port:      {flow_event['dest_port']}")
        print("\nChecking backend logs will confirm if it detects and isolates the device.")
    except Exception as e:
        print(f"[!] Error writing to log: {e}")

if __name__ == "__main__":
    main()
