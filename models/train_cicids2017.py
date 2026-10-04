import pandas as pd
import numpy as np
import os
import glob
from sklearn.preprocessing import LabelEncoder
import joblib

def preprocess_cicids2017_data(data_dir="data/mock_iot_traffic/", output_file="data/cicids2017_processed.csv"):
    """
    Preprocess CICIDS2017 CSV files to match the format expected by the training scripts.
    """
    print("Loading CICIDS2017 data files...")

    # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    print(f"Found {len(csv_files)} CSV files")

    dfs = []
    for file in csv_files:
        print(f"Loading {file}...")
        try:
            df = pd.read_csv(file)
            dfs.append(df)
        except Exception as e:
            print(f"Error loading {file}: {e}")
            continue

    if not dfs:
        raise ValueError("No valid CSV files found")

    # Combine all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"Combined dataset shape: {combined_df.shape}")

    # CICIDS2017 column mapping to expected format
    # The files seem to have flow-level features without IP/port info
    # We'll create synthetic IP/port data and use available features

    # Rename columns (remove leading spaces)
    df_processed = combined_df.copy()
    df_processed.columns = df_processed.columns.str.strip()

    # Map available columns
    column_mapping = {
        'Destination Port': 'dst_port',
        'Flow Duration': 'flow_duration',
        'Total Fwd Packets': 'total_fwd_packets',
        'Total Backward Packets': 'total_bwd_packets',
        'Total Length of Fwd Packets': 'fwd_bytes',
        'Total Length of Bwd Packets': 'bwd_bytes',
        'Flow Bytes/s': 'byte_rate',
        'Flow Packets/s': 'packet_rate',
        'SYN Flag Count': 'syn_flags',
        'ACK Flag Count': 'ack_flags',
        'RST Flag Count': 'rst_flags',
        'Label': 'attack_type'
    }

    # Rename columns
    df_processed = df_processed.rename(columns=column_mapping)

    # Convert data types
    df_processed['dst_port'] = pd.to_numeric(df_processed['dst_port'], errors='coerce')
    df_processed['flow_duration'] = pd.to_numeric(df_processed['flow_duration'], errors='coerce') / 1000000  # Convert to seconds
    df_processed['total_fwd_packets'] = pd.to_numeric(df_processed['total_fwd_packets'], errors='coerce')
    df_processed['total_bwd_packets'] = pd.to_numeric(df_processed['total_bwd_packets'], errors='coerce')
    df_processed['fwd_bytes'] = pd.to_numeric(df_processed['fwd_bytes'], errors='coerce')
    df_processed['bwd_bytes'] = pd.to_numeric(df_processed['bwd_bytes'], errors='coerce')
    df_processed['byte_rate'] = pd.to_numeric(df_processed['byte_rate'], errors='coerce')
    df_processed['packet_rate'] = pd.to_numeric(df_processed['packet_rate'], errors='coerce')
    df_processed['syn_flags'] = pd.to_numeric(df_processed['syn_flags'], errors='coerce').fillna(0)
    df_processed['ack_flags'] = pd.to_numeric(df_processed['ack_flags'], errors='coerce').fillna(0)
    df_processed['rst_flags'] = pd.to_numeric(df_processed['rst_flags'], errors='coerce').fillna(0)

    # Create synthetic data for missing columns
    np.random.seed(42)
    num_samples = len(df_processed)

    # Generate synthetic IPs
    df_processed['src_ip'] = [f"192.168.1.{np.random.randint(2, 255)}" for _ in range(num_samples)]
    df_processed['dst_ip'] = [f"192.168.1.{np.random.randint(2, 255)}" for _ in range(num_samples)]

    # Generate synthetic source ports
    df_processed['src_port'] = np.random.randint(1024, 65535, num_samples)

    # Set protocol (most flows are TCP based on flags)
    df_processed['protocol'] = np.where(df_processed['syn_flags'] > 0, 'TCP', 'UDP')

    # Set timestamp
    df_processed['timestamp'] = pd.date_range('2023-01-01', periods=num_samples, freq='1s').astype(str)

    # Set TCP flags based on counts
    def get_tcp_flags(row):
        flags = []
        if row['syn_flags'] > 0:
            flags.append('S')
        if row['ack_flags'] > 0:
            flags.append('A')
        if row['rst_flags'] > 0:
            flags.append('R')
        return ''.join(flags) if flags else 'A'

    df_processed['tcp_flags'] = df_processed.apply(get_tcp_flags, axis=1)

    # Set connection errors based on RST flags
    df_processed['connection_errors'] = df_processed['rst_flags']

    # Create binary label
    df_processed['label'] = (df_processed['attack_type'] != 'BENIGN').astype(int)

    # Handle infinite values
    df_processed = df_processed.replace([np.inf, -np.inf], np.nan)

    # Fill missing values
    df_processed = df_processed.fillna(0)

    # Select final columns
    final_columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                     'packet_rate', 'byte_rate', 'flow_duration', 'tcp_flags',
                     'connection_errors', 'label', 'attack_type']

    df_final = df_processed[final_columns]

    # Save processed data
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df_final.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}")
    print(f"Final dataset shape: {df_final.shape}")
    print("Attack distribution:")
    print(df_final['attack_type'].value_counts())

    # Sample the data for faster training (optional - remove for full training)
    sample_size = min(50000, len(df_final))  # Use up to 50k samples
    df_sample = df_final.sample(n=sample_size, random_state=42)
    print(f"Using sample of {sample_size} records for training")

    # Save sampled data
    sampled_data_path = "data/cicids2017_sampled.csv"
    df_sample.to_csv(sampled_data_path, index=False)

    return sampled_data_path

def train_models_with_cicids2017():
    """
    Train the ML models using preprocessed CICIDS2017 data.
    """
    # Preprocess the data
    processed_data_path = preprocess_cicids2017_data()

    # Now use the current training flow
    import sys
    sys.path.append('.')
    import train_realtime_optimized
    import train_isolation_forest

    # Train the supervised model
    print("\n" + "="*50)
    print("Training LightGBM supervised model with CICIDS2017 data...")
    train_realtime_optimized.main()

    # Train Isolation Forest
    print("\n" + "="*50)
    print("Training Isolation Forest with CICIDS2017 data...")
    train_isolation_forest.train_isolation_forest(processed_data_path)

    print("\nTraining completed! Models saved in models/ directory.")

    print("\nTraining completed! Models saved in models/ directory.")

if __name__ == "__main__":
    train_models_with_cicids2017()