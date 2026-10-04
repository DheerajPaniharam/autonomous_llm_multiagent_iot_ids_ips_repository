#!/usr/bin/env python3
"""
Simulate Demo Attack — utility for live demonstration of the MCA project.
Generates and appends realistic Suricata flow logs to the configured log path.
"""
import os
import json
import sys
import time
from datetime import datetime

def load_log_path():
    # Read SURICATA_LOG_PATH from .env if present
    log_path = "logs/eve.json" # Default fallback
    if os.path.exists(".env"):
        with open(".env", "r") as f:
            for line in f:
                if line.strip().startswith("SURICATA_LOG_PATH="):
                    val = line.strip().split("=", 1)[1]
                    # Strip quotes if any
                    log_path = val.strip("'\"")
                    break
    
    # Ensure parent directories exist
    dir_name = os.path.dirname(log_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)
    
    return log_path

def write_flow(log_path, flow_dict):
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(flow_dict) + "\n")
        print(f"\n[+] Successfully injected event to: {log_path}")
        print(f"    Flow: {flow_dict['src_ip']}:{flow_dict['src_port']} -> {flow_dict['dest_ip']}:{flow_dict['dest_port']} ({flow_dict['proto']})")
    except PermissionError:
        print(f"\n[!] PERMISSION ERROR: Cannot write to {log_path}")
        print("    This is because the log path is configured inside system directories (e.g., /var/log/suricata/eve.json).")
        print("    To fix this for local/development simulation:")
        print("    1. Open '.env' file in your project root.")
        print("    2. Change 'SURICATA_LOG_PATH' to 'logs/eve.json'.")
        print("    3. Restart your backend / docker containers so they read the new local path.")
        print("    4. Run this script again.")
    except Exception as e:
        print(f"\n[!] Error writing to log file: {e}")

def get_base_flow(src_ip, dest_ip, src_port, dest_port, proto="TCP"):
    return {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "flow",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": proto,
        "flow": {
            "age": 1.0,
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 64,
            "bytes_toclient": 64,
            "state": "new"
        },
        "tcp": {
            "tcp_flags_tc": "02"
        }
    }

def run_menu():
    log_path = load_log_path()
    
    # Standard local IoT device seeded on startup
    device_ip = "192.168.1.100" # smart-thermostat-01

    while True:
        print("\n" + "="*50)
        print("    MCA Project Demo - IoT IDS/IPS Simulator")
        print("="*50)
        print(f"Targeting log file: {os.path.abspath(log_path)}")
        print(f"Seeded IoT Device target IP: {device_ip}")
        print("-"*50)
        print("1. Inject Benign Traffic (MQTT Poll)")
        print("2. Inject Port Scan Attack (Scanning 100+ ports)")
        print("3. Inject Critical Telnet Brute Force DDoS (Mirai Botnet)")
        print("4. Inject MQTT Exploitation Attempt")
        print("5. Exit")
        print("-"*50)
        
        choice = input("Select an event to inject (1-5): ").strip()
        
        if choice == "1":
            # Benign MQTT traffic
            flow = get_base_flow(
                src_ip="192.168.1.50", # Local laptop
                dest_ip=device_ip,
                src_port=48912,
                dest_port=1883, # MQTT
                proto="TCP"
            )
            flow["flow"]["pkts_toserver"] = 5
            flow["flow"]["bytes_toserver"] = 240
            flow["flow"]["age"] = 1.2
            write_flow(log_path, flow)
            
        elif choice == "2":
            # Port scan
            print("\n[*] Simulating Port Scan (writing scans)...")
            attacker_ip = "198.51.100.12"
            for port in [21, 22, 23, 80, 443, 8080, 1883, 502, 5683, 3389]:
                flow = get_base_flow(
                    src_ip=attacker_ip,
                    dest_ip=device_ip,
                    src_port=51000 + port,
                    dest_port=port,
                    proto="TCP"
                )
                flow["flow"]["pkts_toserver"] = 1
                flow["flow"]["bytes_toserver"] = 40
                flow["tcp"]["tcp_flags_tc"] = "02" # SYN
                write_flow(log_path, flow)
                time.sleep(0.1)
            print("[+] Done.")
            
        elif choice == "3":
            # DDoS Telnet flood (Critical)
            flow = get_base_flow(
                src_ip="198.51.100.4", # Threat source
                dest_ip=device_ip, # Targeting Thermostat
                src_port=38290,
                dest_port=23, # Telnet
                proto="TCP"
            )
            # Make packet/byte rates extremely high
            flow["flow"]["age"] = 2.0
            flow["flow"]["pkts_toserver"] = 3000
            flow["flow"]["pkts_toclient"] = 20
            flow["flow"]["bytes_toserver"] = 192000
            flow["flow"]["bytes_toclient"] = 1024
            flow["tcp"]["tcp_flags_tc"] = "02" # SYN Flood
            write_flow(log_path, flow)
            
        elif choice == "4":
            # MQTT Exploitation Attack
            flow = get_base_flow(
                src_ip="198.51.100.5",
                dest_ip=device_ip,
                src_port=41920,
                dest_port=1883,
                proto="TCP"
            )
            flow["flow"]["age"] = 1.5
            flow["flow"]["pkts_toserver"] = 800
            flow["flow"]["bytes_toserver"] = 54000
            flow["flow"]["state"] = "reset"
            flow["tcp"]["tcp_flags_tc"] = "04" # RST injection
            write_flow(log_path, flow)
            
        elif choice == "5":
            print("\nExiting simulator. Have a great demo!")
            break
        else:
            print("\n[!] Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    try:
        run_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
