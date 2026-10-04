import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

def train_isolation_forest(filepath="data/mock_iot_traffic.csv"):
    print(f"Loading data from {filepath}...")
    df = pd.read_csv(filepath)
    
    # We only want to train the Isolation Forest on NORMAL data
    # so it learns what "normal" looks like. Everything else will be an anomaly.
    normal_df = df[df['label'] == 0].copy()
    
    features = ['src_port', 'dst_port', 'protocol', 'packet_rate', 'byte_rate', 
                'flow_duration', 'tcp_flags', 'connection_errors']
    
    X_normal = normal_df[features].copy()
    
    print("Loading preprocessors...")
    # Load previously fitted preprocessors from the LightGBM training
    scaler = joblib.load('models/scaler.joblib')
    le_protocol = joblib.load('models/le_protocol.joblib')
    le_flags = joblib.load('models/le_flags.joblib')
    
    print("Preprocessing normal data...")
    # Since we might have unseen labels in a small slice, we use a try-except 
    # or just handle the transform carefully. For our mock data, transform is safe.
    X_normal['protocol'] = le_protocol.transform(X_normal['protocol'])
    X_normal['tcp_flags'] = le_flags.transform(X_normal['tcp_flags'])
    
    X_normal_scaled = scaler.transform(X_normal)
    
    print(f"Training Isolation Forest on {len(X_normal_scaled)} normal samples...")
    # contamination is the expected proportion of outliers in the dataset.
    # Since we are training strictly on normal data, we set a very low contamination
    # just to handle noise in the "normal" data.
    clf_if = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    
    clf_if.fit(X_normal_scaled)
    
    # Let's test it on a mix of data to see how well it flags anomalies (-1) vs normal (1)
    print("\nEvaluating Isolation Forest on the full dataset...")
    X_full = df[features].copy()
    # Handle unseen labels in full dataset safely
    X_full['protocol'] = X_full['protocol'].apply(lambda x: x if x in le_protocol.classes_ else le_protocol.classes_[0])
    X_full['protocol'] = le_protocol.transform(X_full['protocol'])
    
    X_full['tcp_flags'] = X_full['tcp_flags'].apply(lambda x: x if x in le_flags.classes_ else le_flags.classes_[0])
    X_full['tcp_flags'] = le_flags.transform(X_full['tcp_flags'])
    
    X_full_scaled = scaler.transform(X_full)
    
    # Predict anomalies (-1 for anomaly, 1 for normal)
    predictions = clf_if.predict(X_full_scaled)
    
    # Map predictions back to 0 (normal) and 1 (anomaly) for easier comparison
    anomaly_predictions = [1 if p == -1 else 0 for p in predictions]
    true_labels = df['label'].values
    
    from sklearn.metrics import classification_report, confusion_matrix
    print("\nAnomaly Detection Report (1 = Anomaly/Attack, 0 = Normal):")
    print(classification_report(true_labels, anomaly_predictions))
    print("\nConfusion Matrix:\n", confusion_matrix(true_labels, anomaly_predictions))

    # Save the model
    model_path = 'models/if_model.joblib'
    joblib.dump(clf_if, model_path)
    print(f"\nIsolation Forest model saved successfully to {model_path}")

if __name__ == "__main__":
    train_isolation_forest()
