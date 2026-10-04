import pandas as pd
import numpy as np
import random
import os
from faker import Faker

fake = Faker()

def generate_iot_traffic(num_samples=10000, output_file="data/mock_iot_traffic.csv"):
    """
    Generates a mock dataset of IoT network traffic.
    Includes mixed normal traffic and various attack types.
    """
    
    # Ensure data directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    data = []
    
    # Define Attack Types and their distributions
    attack_types = ['Normal', 'DoS', 'PortScan', 'BruteForce']
    weights = [0.70, 0.15, 0.10, 0.05] # 70% normal traffic
    
    # Define common IoT protocols
    protocols = ['TCP', 'UDP', 'ICMP', 'MQTT', 'HTTP']
    
    for _ in range(num_samples):
        attack_type = np.random.choice(attack_types, p=weights)
        
        # Base realistic features
        src_ip = fake.ipv4()
        # Simulate local IoT devices
        dst_ip = f"192.168.1.{random.randint(2, 50)}" 
        protocol = np.random.choice(protocols)
        
        # Default Normal Features
        packet_rate = random.uniform(0.1, 50.0)
        byte_rate = random.uniform(10.0, 5000.0)
        flow_duration = random.uniform(0.01, 10.0)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 1883, 22, 53]) # HTTP, HTTPS, MQTT, SSH, DNS
        tcp_flags = "A" # ACK
        connection_errors = 0
        
        # Modify features based on Attack Type
        if attack_type == 'DoS':
            packet_rate = random.uniform(500.0, 5000.0) # High packet rate
            byte_rate = random.uniform(10000.0, 100000.0)
            dst_port = 80 # Target web server
            protocol = 'TCP'
            tcp_flags = "S" # SYN Flood
            
        elif attack_type == 'PortScan':
            packet_rate = random.uniform(10.0, 100.0)
            dst_port = random.randint(1, 1024) # Scanning low ports
            protocol = 'TCP'
            tcp_flags = "S" # SYN Stealth scan
            connection_errors = random.randint(1, 5) # Many resets
            
        elif attack_type == 'BruteForce':
            packet_rate = random.uniform(5.0, 20.0)
            dst_port = 22 # SSH
            protocol = 'TCP'
            tcp_flags = "PA" # PSH, ACK
            connection_errors = random.randint(3, 10) # Failed logins

        # Append structured row
        data.append({
            'timestamp': fake.date_time_this_month().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_rate': round(packet_rate, 2),
            'byte_rate': round(byte_rate, 2),
            'flow_duration': round(flow_duration, 3),
            'tcp_flags': tcp_flags,
            'connection_errors': connection_errors,
            'label': 0 if attack_type == 'Normal' else 1, # Binary Label
            'attack_type': attack_type # Multi-class Label
        })
        
    df = pd.DataFrame(data)
    
    # Sort by timestamp to simulate real log flow
    df = df.sort_values(by='timestamp').reset_index(drop=True)
    
    df.to_csv(output_file, index=False)
    print(f"Generated {num_samples} rows of mock traffic at {output_file}")
    
    print("\nAttack Distribution:")
    print(df['attack_type'].value_counts())

if __name__ == "__main__":
    generate_iot_traffic(num_samples=15000)
    
