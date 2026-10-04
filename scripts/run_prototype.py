import os
import pandas as pd
import numpy as np
import joblib
import warnings

warnings.filterwarnings('ignore')  # Ignore scikit-learn warnings for cleaner output logs


def load_models():
    print("Loading ML models and preprocessors...\n")
    scaler_path = 'models/scaler_optimized.joblib' if os.path.exists('models/scaler_optimized.joblib') else 'models/scaler.joblib'
    scaler = joblib.load(scaler_path)
    le_protocol = joblib.load('models/le_protocol.joblib')
    le_flags = joblib.load('models/le_flags.joblib')

    supervised_path = 'models/lgb_model_optimized.joblib' if os.path.exists('models/lgb_model_optimized.joblib') else 'models/lgb_model_optimized.joblib'
    supervised_model = joblib.load(supervised_path)
    if_model = joblib.load('models/if_model.joblib')

    return scaler, le_protocol, le_flags, supervised_model, if_model


def simulate_pipeline():
    scaler, le_protocol, le_flags, supervised_model, if_model = load_models()

    # Load some random samples to simulate a stream of incoming traffic
    df = pd.read_csv('data/mock_iot_traffic.csv')

    # Let's take 2 normal packets and 3 attack packets
    normals = df[df['label'] == 0].sample(2, random_state=42)
    attacks = df[df['label'] == 1].sample(3, random_state=42)
    stream_df = pd.concat([normals, attacks]).sample(frac=1).reset_index(drop=True)

    features = ['src_port', 'dst_port', 'protocol', 'packet_rate', 'byte_rate',
                'flow_duration', 'tcp_flags', 'connection_errors']

    print("--- Simulating Real-time IoT Gateway Traffic --- \n")

    for _, row in stream_df.iterrows():
        print(f"[{row['timestamp']}] Incoming Packet: {row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']} ({row['protocol']})")

        # 1. Preprocess
        X_raw = row[features].to_frame().T

        # Handle unseen labels gracefully for the simulation
        if X_raw['protocol'].values[0] not in le_protocol.classes_:
            X_raw['protocol'] = le_protocol.classes_[0]
        X_raw['protocol'] = le_protocol.transform(X_raw['protocol'])

        if X_raw['tcp_flags'].values[0] not in le_flags.classes_:
            X_raw['tcp_flags'] = le_flags.classes_[0]
        X_raw['tcp_flags'] = le_flags.transform(X_raw['tcp_flags'])

        X_scaled = scaler.transform(X_raw)

        # 2. Known Threat Detection (LightGBM)
        supervised_prediction = supervised_model.predict(X_scaled)[0]

        # 3. Anomaly Detection (Isolation Forest)
        if_prediction = if_model.predict(X_scaled)[0]  # 1 is Normal, -1 is Anomaly
        is_anomaly = True if if_prediction == -1 else False

        # 4. Agentic Routing Logic (Simulated Orchestrator input)
        print("  -> Analysis:")

        if supervised_prediction != 'Normal':
            print(f"     [!!] DETECTION AGENT ALERT: Known Attack Signature Match -> {supervised_prediction}")
        elif is_anomaly:
            print(f"     [?] ANOMALY AGENT ALERT: Zero-Day / Abnormal Behavior Detected")
        else:
            print(f"     [OK] Traffic is Benign.")

        print("-" * 50)


if __name__ == "__main__":
    simulate_pipeline()
