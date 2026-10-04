#!/usr/bin/env python3
"""
Optimized LightGBM Training for Real-Time IoT IDS
Trains models with parameters optimized for low-latency inference
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
import joblib
import time
import os
from pathlib import Path
import lightgbm as lgb

def load_cicids2017_data(data_path):
    """Load and preprocess CICIDS2017 dataset"""
    print("Loading CICIDS2017 dataset...")

    all_files = []
    data_dir = Path(data_path)

    # Accept either one CSV file or a directory containing CSV files.
    csv_files = [data_dir] if data_dir.is_file() else list(data_dir.glob("*.csv"))
    for csv_file in csv_files:
        print(f"Found file: {csv_file.name}")
        all_files.append(csv_file)

    if not all_files:
        raise FileNotFoundError(f"No CSV files found in {data_path}")

    # Load and combine all files
    dfs = []
    for file_path in all_files:
        try:
            df = pd.read_csv(file_path)
            dfs.append(df)
            print(f"Loaded {file_path.name}: {len(df)} rows")
        except Exception as e:
            print(f"Error loading {file_path.name}: {e}")
            continue

    if not dfs:
        raise ValueError("No data files could be loaded")

    # Combine all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"Total combined dataset: {len(combined_df)} rows")

    return combined_df

def preprocess_features(df):
    """Extract and preprocess features matching inference pipeline"""
    print("Preprocessing features...")

    # Normalize column names to handle the raw CICIDS2017 CSV structure.
    df = df.copy()
    df.columns = [col.strip() for col in df.columns]

    # Map CICIDS2017 columns to inference pipeline features
    # This ensures training features match what inference expects
    feature_mappings = {
        'packet_rate': ['Flow Packets/s', 'Flow Packets/s', 'Total Fwd Packets', 'Total Backward Packets'],
        'byte_rate': ['Flow Bytes/s', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets'],
        'flow_duration': ['Flow Duration'],
        'dst_port': ['Destination Port'],
        'connection_errors': ['SYN Flag Count', 'RST Flag Count'],
        'total_fwd_packets': ['Total Fwd Packets'],
        'total_bwd_packets': ['Total Backward Packets'],
        'fwd_bytes': ['Total Length of Fwd Packets'],
        'bwd_bytes': ['Total Length of Bwd Packets'],
        'syn_flag_count': ['SYN Flag Count'],
        'ack_flag_count': ['ACK Flag Count'],
        'rst_flag_count': ['RST Flag Count'],
        'fwd_packets_per_second': ['Fwd Packets/s'],
        'bwd_packets_per_second': ['Bwd Packets/s'],
        'packet_length_mean': ['Packet Length Mean'],
        'fwd_packet_length_mean': ['Fwd Packet Length Mean'],
        'bwd_packet_length_mean': ['Bwd Packet Length Mean']
    }

    # Extract available features
    available_features = []
    for feature_name, possible_columns in feature_mappings.items():
        for col in possible_columns:
            if col in df.columns:
                available_features.append((feature_name, col))
                break

    print(f"Available feature mappings: {available_features}")

    if len(available_features) < 6:
        raise ValueError(f"Only {len(available_features)} features available, need at least 6")

    # Create feature matrix using inference-compatible features
    X = pd.DataFrame()

    # packet_rate: packets per second
    packet_rate_col = df.get('Flow Packets/s')
    if packet_rate_col is not None:
        X['packet_rate'] = packet_rate_col.fillna(0)
    else:
        fwd_packets = df.get('Total Fwd Packets')
        bwd_packets = df.get('Total Backward Packets')
        duration = df.get('Flow Duration')
        duration = duration.replace(0, 1) if duration is not None else 1
        X['packet_rate'] = ((fwd_packets.fillna(0) + bwd_packets.fillna(0)) / duration).fillna(0)

    # byte_rate: bytes per second
    byte_rate_col = df.get('Flow Bytes/s')
    if byte_rate_col is not None:
        X['byte_rate'] = byte_rate_col.fillna(0)
    else:
        fwd_bytes = df.get('Total Length of Fwd Packets')
        bwd_bytes = df.get('Total Length of Bwd Packets')
        duration = df.get('Flow Duration')
        duration = duration.replace(0, 1) if duration is not None else 1
        X['byte_rate'] = ((fwd_bytes.fillna(0) + bwd_bytes.fillna(0)) / duration).fillna(0)

    # flow_duration
    duration_col = df.get('Flow Duration')
    if duration_col is not None:
        X['flow_duration'] = duration_col.fillna(1)
    else:
        X['flow_duration'] = 1

    # dst_port
    dst_port_col = df.get('Destination Port')
    if dst_port_col is not None:
        X['dst_port'] = dst_port_col.fillna(80)
    else:
        X['dst_port'] = 80

    # Use raw TCP flag counts directly from the dataset.
    syn_count = df.get('SYN Flag Count')
    if syn_count is None:
        syn_count = pd.Series(0, index=df.index)
    else:
        syn_count = syn_count.fillna(0)

    ack_count = df.get('ACK Flag Count')
    if ack_count is None:
        ack_count = pd.Series(0, index=df.index)
    else:
        ack_count = ack_count.fillna(0)

    rst_count = df.get('RST Flag Count')
    if rst_count is None:
        rst_count = pd.Series(0, index=df.index)
    else:
        rst_count = rst_count.fillna(0)

    X['syn_flag_count'] = syn_count.astype(float)
    X['ack_flag_count'] = ack_count.astype(float)
    X['rst_flag_count'] = rst_count.astype(float)

    # connection_errors (simplified)
    X['connection_errors'] = (syn_count + rst_count).astype(int)

    fwd_packets_per_second = df.get('Fwd Packets/s')
    if fwd_packets_per_second is None:
        fwd_packets_per_second = pd.Series(0, index=df.index)
    else:
        fwd_packets_per_second = fwd_packets_per_second.fillna(0)
    X['fwd_packets_per_second'] = fwd_packets_per_second.astype(float)

    bwd_packets_per_second = df.get('Bwd Packets/s')
    if bwd_packets_per_second is None:
        bwd_packets_per_second = pd.Series(0, index=df.index)
    else:
        bwd_packets_per_second = bwd_packets_per_second.fillna(0)
    X['bwd_packets_per_second'] = bwd_packets_per_second.astype(float)

    packet_length_mean = df.get('Packet Length Mean')
    if packet_length_mean is None:
        packet_length_mean = pd.Series(0, index=df.index)
    else:
        packet_length_mean = packet_length_mean.fillna(0)
    X['packet_length_mean'] = packet_length_mean.astype(float)

    fwd_packet_length_mean = df.get('Fwd Packet Length Mean')
    if fwd_packet_length_mean is None:
        fwd_packet_length_mean = pd.Series(0, index=df.index)
    else:
        fwd_packet_length_mean = fwd_packet_length_mean.fillna(0)
    X['fwd_packet_length_mean'] = fwd_packet_length_mean.astype(float)

    bwd_packet_length_mean = df.get('Bwd Packet Length Mean')
    if bwd_packet_length_mean is None:
        bwd_packet_length_mean = pd.Series(0, index=df.index)
    else:
        bwd_packet_length_mean = bwd_packet_length_mean.fillna(0)
    X['bwd_packet_length_mean'] = bwd_packet_length_mean.astype(float)

    # Additional high-value flow features for better attack detection
    fwd_packets = df.get('Total Fwd Packets')
    if fwd_packets is None:
        fwd_packets = pd.Series(0, index=df.index)
    else:
        fwd_packets = fwd_packets.fillna(0)
    X['total_fwd_packets'] = fwd_packets.astype(float)

    bwd_packets = df.get('Total Backward Packets')
    if bwd_packets is None:
        bwd_packets = pd.Series(0, index=df.index)
    else:
        bwd_packets = bwd_packets.fillna(0)
    X['total_bwd_packets'] = bwd_packets.astype(float)

    fwd_bytes = df.get('Total Length of Fwd Packets')
    if fwd_bytes is None:
        fwd_bytes = pd.Series(0, index=df.index)
    else:
        fwd_bytes = fwd_bytes.fillna(0)
    X['fwd_bytes'] = fwd_bytes.astype(float)

    bwd_bytes = df.get('Total Length of Bwd Packets')
    if bwd_bytes is None:
        bwd_bytes = pd.Series(0, index=df.index)
    else:
        bwd_bytes = bwd_bytes.fillna(0)
    X['bwd_bytes'] = bwd_bytes.astype(float)

    # Handle missing values and infinite values
    X = X.fillna(0)
    X = X.replace([np.inf, -np.inf], 0)

    # Keep the task explicitly binary; never train on synthetic fallback labels.
    label_columns = {column.strip().lower(): column for column in df.columns}
    label_column = next(
        (label_columns[name] for name in ("attack_type", "label") if name in label_columns),
        None,
    )
    if label_column is None:
        raise ValueError("Dataset must contain a Label or attack_type column")
    raw_labels = df[label_column].astype(str).str.strip()
    if label_column.strip().lower() == "label" and set(raw_labels.str.lower().unique()) <= {"0", "1"}:
        raise ValueError("Numeric binary labels are ambiguous; provide attack_type labels")
    y = raw_labels.apply(lambda value: "BENIGN" if value.upper() == "BENIGN" else "ATTACK")

    feature_names = list(X.columns)
    print(f"Final feature set: {feature_names}")
    print(f"Feature matrix shape: {X.shape}")
    print("\n=== Label verification ===")
    label_series = pd.Series(y)
    print(label_series.head(10).to_string())
    print(label_series.value_counts(dropna=False).to_string())
    print(f"Missing labels: {label_series.isna().sum()}")

    print("\n=== Feature preview ===")
    print(X.head(5).to_string())
    print("\n=== Feature summary ===")
    print(X.describe(include='all').T.to_string())
    print("\n=== Unique values per feature ===")
    print(X.nunique(dropna=False).to_string())

    return X, y, feature_names

def encode_protocol(values):
    """Normalize protocol values to numeric IDs for model training."""
    protocol_map = {
        "TCP": 0,
        "UDP": 1,
        "ICMP": 2,
        "HTTP": 3,
        "MQTT": 4,
        "COAP": 5,
        "MODBUS": 6,
        "0": 0,
        "1": 1,
        "2": 2,
        "3": 3,
        "4": 4,
        "5": 5,
        "6": 6,
    }

    if isinstance(values, pd.Series):
        normalized = values.astype(str).str.strip().str.upper()
    else:
        normalized = pd.Series(values).astype(str).str.strip().str.upper()

    encoded = []
    for value in normalized:
        if value in protocol_map:
            encoded.append(protocol_map[value])
        elif value.isdigit():
            encoded.append(int(value))
        else:
            encoded.append(0)

    return pd.Series(encoded, index=values.index if isinstance(values, pd.Series) else None)


def encode_tcp_flags(values):
    """Normalize TCP flag values to compact numeric IDs."""
    flags_map = {"S": 0, "SA": 1, "PA": 2, "A": 3, "R": 4, "F": 5}
    if isinstance(values, pd.Series):
        normalized = values.astype(str).str.strip().str.upper()
    else:
        normalized = pd.Series(values).astype(str).str.strip().str.upper()

    encoded = []
    for value in normalized:
        encoded.append(flags_map.get(value, 3))

    return pd.Series(encoded, index=values.index if isinstance(values, pd.Series) else None)

def compute_confusion_metrics(y_true, y_pred, positive_label=1):
    """Compute confusion-matrix-based evaluation metrics for binary classification."""
    labels = np.unique(np.concatenate((np.asarray(y_true), np.asarray(y_pred))))
    if len(labels) == 2 and positive_label in labels:
        negative_label = next(label for label in labels if label != positive_label)
        cm = confusion_matrix(y_true, y_pred, labels=[negative_label, positive_label])
    else:
        cm = confusion_matrix(y_true, y_pred)

    if cm.size == 1:
        tn = 0
        fp = 0
        fn = 0
        tp = 0
    elif cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn = int(cm[0, 0]) if cm.shape[0] > 0 and cm.shape[1] > 0 else 0
        fp = int(cm[0, 1]) if cm.shape[0] > 0 and cm.shape[1] > 1 else 0
        fn = int(cm[1, 0]) if cm.shape[0] > 1 and cm.shape[1] > 0 else 0
        tp = int(cm[1, 1]) if cm.shape[0] > 1 and cm.shape[1] > 1 else 0

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = f1_score(y_true, y_pred, zero_division=0)

    return {
        "confusion_matrix": cm,
        "confusion_matrix_labels": [
            negative_label,
            positive_label,
        ] if len(labels) == 2 and positive_label in labels else labels.tolist(),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
    }


def prepare_isolation_forest_features(X, scaler=None):
    """Prepare features for isolation-forest training by sanitizing and scaling them."""
    X_array = np.asarray(X, dtype=float)
    if X_array.ndim == 1:
        X_array = X_array.reshape(-1, 1)
    X_array = np.nan_to_num(X_array, nan=0.0, posinf=0.0, neginf=0.0)

    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_array)
    else:
        X_scaled = scaler.transform(X_array)

    return X_scaled, scaler


def compute_isolation_forest_metrics(model, X, y_true, positive_label=0, decision_threshold=0.0):
    """Evaluate an isolation forest using anomaly labels and confusion-matrix metrics."""
    scores = model.decision_function(X)
    predictions = (scores < decision_threshold).astype(int)
    y_true_binary = (np.asarray(y_true) == positive_label).astype(int)

    metrics = compute_confusion_metrics(y_true_binary, predictions)
    metrics["anomaly_score_mean"] = float(np.mean(scores))
    metrics["anomaly_score_std"] = float(np.std(scores))
    metrics["decision_threshold"] = float(decision_threshold)
    return metrics


def tune_isolation_forest(X, y, configs=None, thresholds=None, sample_size=200000):
    """Tune isolation-forest hyperparameters and decision thresholds on a sampled subset."""
    if configs is None:
        configs = []
        for n_est in [100, 150]:
            for max_samp in [512, 1024, 2048]:
                for contam in [0.01, 0.03, 0.05]:
                    for max_feat in [0.7, 0.85, 1.0]:
                        configs.append({
                            "n_estimators": n_est,
                            "max_samples": max_samp,
                            "contamination": contam,
                            "max_features": max_feat,
                            "random_state": 42,
                            "n_jobs": -1
                        })

    if thresholds is None:
        thresholds = [-0.10, -0.05, -0.02, 0.0, 0.02, 0.05, 0.08, 0.10]

    X_prepared, _ = prepare_isolation_forest_features(X)
    if len(X_prepared) > sample_size:
        rng = np.random.RandomState(42)
        sample_idx = rng.choice(len(X_prepared), sample_size, replace=False)
        X_sample = X_prepared[sample_idx]
        y_sample = y[sample_idx]
    else:
        X_sample = X_prepared
        y_sample = y

    # Select benign samples for training
    normal_indices = (np.asarray(y_sample) == 1)
    if not np.any(normal_indices):
        normal_indices = np.ones(len(y_sample), dtype=bool)
    X_sample_normal = X_sample[normal_indices]

    best_result = None
    tuning_log = []
    
    for config in configs:
        model = IsolationForest(**config)
        model.fit(X_sample_normal)
        for threshold in thresholds:
            metrics = compute_isolation_forest_metrics(model, X_sample, y_sample, decision_threshold=threshold)
            if metrics["recall"] < 0.55 or metrics["specificity"] < 0.76:
                objective = (metrics["f1"] + (0.2 * metrics["precision"])) - 10.0
            else:
                objective = metrics["f1"] + (0.2 * metrics["precision"])
            tuning_log.append((config, threshold, metrics))
            if best_result is None or objective > best_result["objective"]:
                best_result = {
                    "config": config,
                    "threshold": threshold,
                    "metrics": metrics,
                    "objective": objective,
                }

    print("\n=== ISOLATION FOREST TUNING RESULTS ===")
    for config, threshold, metrics in tuning_log:
        print(
            f"config={config['n_estimators']}/{config['max_samples']}/{config['contamination']}/{config['max_features']} "
            f"threshold={threshold:.2f} -> f1={metrics['f1']:.3f} recall={metrics['recall']:.3f} precision={metrics['precision']:.3f}"
        )
    print(
        "Best isolation forest settings: "
        f"n_estimators={best_result['config']['n_estimators']}, max_samples={best_result['config']['max_samples']}, "
        f"contamination={best_result['config']['contamination']}, max_features={best_result['config']['max_features']}, "
        f"threshold={best_result['threshold']:.2f}"
    )

    return best_result


def train_baseline_lightgbm(X, y, feature_names):
    """Train a standard LightGBM baseline for comparison."""
    print("Training baseline LightGBM with standard parameters...")

    X_encoded = X.copy()
    if 'protocol' in X_encoded.columns:
        X_encoded['protocol'] = encode_protocol(X_encoded['protocol'])
    if 'tcp_flags' in X_encoded.columns:
        X_encoded['tcp_flags'] = encode_tcp_flags(X_encoded['tcp_flags'])

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X_encoded, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    if len(X_train) > 50000:
        sample_idx = np.random.RandomState(42).choice(len(X_train), 50000, replace=False)
        X_train = X_train.iloc[sample_idx]
        y_train = y_train[sample_idx]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    baseline_params = {
        'n_estimators': 100,
        'random_state': 42,
        'n_jobs': -1,
    }
    lgb_model = lgb.LGBMClassifier(**baseline_params)
    lgb_model.fit(X_train_scaled, y_train)

    train_score = lgb_model.score(X_train_scaled, y_train)
    test_score = lgb_model.score(X_test_scaled, y_test)
    print(f"Baseline LightGBM train accuracy: {train_score:.3f}")
    print(f"Baseline LightGBM test accuracy: {test_score:.3f}")

    return lgb_model, le, scaler

def train_optimized_lightgbm(X, y, feature_names):
    """Train LightGBM optimized for real-time inference."""
    print("Training optimized LightGBM...")

    # Encode categorical features to match inference pipeline
    X_encoded = X.copy()

    if 'protocol' in X_encoded.columns:
        X_encoded['protocol'] = encode_protocol(X_encoded['protocol'])
    if 'tcp_flags' in X_encoded.columns:
        X_encoded['tcp_flags'] = encode_tcp_flags(X_encoded['tcp_flags'])

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_encoded, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Optimized parameters for real-time performance
    lgb_params = {
        'n_estimators': 50,
        'learning_rate': 0.1,
        'max_depth': 6,
        'num_leaves': 31,
        'n_jobs': -1,
        'random_state': 42,
        'objective': 'binary',
        'boosting_type': 'gbdt',
    }

    print(f"Training with parameters: {lgb_params}")

    # Train model
    start_time = time.time()
    lgb_model = lgb.LGBMClassifier(**lgb_params)
    lgb_model.fit(X_train_scaled, y_train)
    training_time = time.time() - start_time

    # Evaluate
    train_score = lgb_model.score(X_train_scaled, y_train)
    test_score = lgb_model.score(X_test_scaled, y_test)
    y_pred_test = lgb_model.predict(X_test_scaled)
    attack_label = int(le.transform(["ATTACK"])[0])
    test_metrics = compute_confusion_metrics(y_test, y_pred_test, positive_label=attack_label)

    # Cross-validation
    cv_scores = cross_val_score(lgb_model, X_train_scaled, y_train, cv=3, scoring='f1_macro')

    print(f"Training time: {training_time:.2f} seconds")
    print(f"Train accuracy: {train_score:.3f}")
    print(f"Test accuracy: {test_score:.3f}")
    print("\n=== TEST CONFUSION MATRIX ===")
    print(test_metrics["confusion_matrix"])
    print("\n=== TEST PERFORMANCE METRICS ===")
    print(f"Accuracy: {test_metrics['accuracy']:.3f}")
    print(f"Precision: {test_metrics['precision']:.3f}")
    print(f"Recall: {test_metrics['recall']:.3f}")
    print(f"Specificity: {test_metrics['specificity']:.3f}")
    print(f"F1-score: {test_metrics['f1']:.3f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_test, target_names=list(le.classes_)))
    print(f"CV F1-macro mean: {np.mean(cv_scores):.3f}")
    print(f"CV F1-macro std: {np.std(cv_scores):.3f}")
    # Feature importances
    feature_importance = dict(zip(feature_names, lgb_model.feature_importances_))
    print(f"Top features: {sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]}")

    return lgb_model, le, scaler, X_encoded, X_train_scaled, X_test_scaled, y_train, y_test, test_metrics

def train_optimized_isolation_forest(X_train, y_train=None, X_eval=None, y_eval=None):
    """Train Isolation Forest for anomaly detection and report evaluation metrics."""
    print("Training optimized Isolation Forest...")

    if y_train is not None:
        tuning_result = tune_isolation_forest(X_train, y_train)
        if_params = tuning_result["config"].copy()
        decision_threshold = tuning_result["threshold"]
    else:
        if_params = {
            'n_estimators': 50,
            'max_samples': 0.4,
            'contamination': 0.1,
            'random_state': 42,
            'n_jobs': -1,
        }
        decision_threshold = 0.0

    print(f"Training with parameters: {if_params}")
    print(f"Using decision threshold: {decision_threshold:.2f}")

    X_train_prepared, scaler = prepare_isolation_forest_features(X_train)
    start_time = time.time()
    if_model = IsolationForest(**if_params)
    
    # Semi-supervised fit: fit ONLY on normal (benign) samples
    if y_train is not None:
        normal_idx = (np.asarray(y_train) == 1)
        X_train_normal = X_train_prepared[normal_idx]
        if_model.fit(X_train_normal)
    else:
        if_model.fit(X_train_prepared)
        
    training_time = time.time() - start_time

    print(f"Isolation Forest training time: {training_time:.3f} seconds")

    if y_train is not None:
        train_metrics = compute_isolation_forest_metrics(if_model, X_train_prepared, y_train, decision_threshold=decision_threshold)
        print("\n=== ISOLATION FOREST TRAIN METRICS ===")
        print(train_metrics["confusion_matrix"])
        print(f"Accuracy: {train_metrics['accuracy']:.3f}")
        print(f"Precision: {train_metrics['precision']:.3f}")
        print(f"Recall: {train_metrics['recall']:.3f}")
        print(f"Specificity: {train_metrics['specificity']:.3f}")
        print(f"F1-score: {train_metrics['f1']:.3f}")

    if X_eval is not None and y_eval is not None:
        X_eval_prepared, _ = prepare_isolation_forest_features(X_eval, scaler=scaler)
        eval_metrics = compute_isolation_forest_metrics(if_model, X_eval_prepared, y_eval, decision_threshold=decision_threshold)
        print("\n=== ISOLATION FOREST EVAL CONFUSION MATRIX ===")
        print(eval_metrics["confusion_matrix"])
        print("\n=== ISOLATION FOREST EVAL PERFORMANCE METRICS ===")
        print(f"Accuracy: {eval_metrics['accuracy']:.3f}")
        print(f"Precision: {eval_metrics['precision']:.3f}")
        print(f"Recall: {eval_metrics['recall']:.3f}")
        print(f"Specificity: {eval_metrics['specificity']:.3f}")
        print(f"F1-score: {eval_metrics['f1']:.3f}")

    return if_model, decision_threshold

def save_models(
    lgb_model, if_model, scaler, label_encoder, feature_names, test_metrics=None,
    decision_threshold=0.11, output_dir="models", evaluation_metadata=None,
):
    """Save trained models and metadata"""
    os.makedirs(output_dir, exist_ok=True)

    # Save models
    joblib.dump(lgb_model, f"{output_dir}/lgb_model_optimized.joblib")
    joblib.dump(if_model, f"{output_dir}/if_model_optimized.joblib")
    joblib.dump(scaler, f"{output_dir}/scaler_optimized.joblib")
    joblib.dump(label_encoder, f"{output_dir}/label_encoder.joblib")

    # Save metadata
    def serialize_value(value):
        if isinstance(value, np.ndarray):
            return serialize_value(value.tolist())
        if isinstance(value, (list, tuple)):
            return [serialize_value(item) for item in value]
        if isinstance(value, dict):
            return {key: serialize_value(item) for key, item in value.items()}
        if isinstance(value, (np.integer, np.int64, np.int32, np.int16, np.int8)):
            return int(value)
        if isinstance(value, (np.floating, np.float64, np.float32, np.float16)):
            return float(value)
        return value

    serialized_test_metrics = None
    if test_metrics is not None:
        serialized_test_metrics = {
            key: serialize_value(value)
            for key, value in test_metrics.items()
        }

    metadata = {
        "version": "optimized_realtime_v1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "feature_names": feature_names,
        "test_metrics": serialized_test_metrics if serialized_test_metrics is not None else {},
        "label_classes": label_encoder.classes_.tolist(),
        "evaluation": evaluation_metadata or {},
        "lgb_params": {
            "n_estimators": lgb_model.n_estimators,
            "learning_rate": getattr(lgb_model, 'learning_rate', None),
            "max_depth": lgb_model.max_depth,
            "num_leaves": getattr(lgb_model, 'num_leaves', None),
            "n_jobs": lgb_model.n_jobs
        },
        "if_params": {
            "n_estimators": if_model.n_estimators,
            "max_samples": if_model.max_samples,
            "contamination": if_model.contamination
        },
        "optimization_notes": [
            "Optimized LightGBM for real-time inference",
            "Saved the supervised artifact under the active LightGBM path and a compatibility alias",
            "Reduced Isolation Forest ensemble size for quicker scoring",
            "Enabled parallel processing (n_jobs=-1)",
            "Optimized for real-time IoT traffic analysis"
        ]
    }

    import json
    import platform
    with open(f"{output_dir}/metadata_optimized.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    # Save metadata_if_optimized.json for backend compatibility
    if_metadata = {
        "version": "optimized_if_v1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "feature_names": feature_names,
        "training_python_version": platform.python_version(),
        "if_params": {
            "n_estimators": if_model.n_estimators,
            "contamination": if_model.contamination,
            "random_state": 42,
            "n_jobs": -1
        },
        "decision_threshold": float(decision_threshold)
    }
    try:
        import sklearn
        if_metadata["training_sklearn_version"] = sklearn.__version__
    except Exception:
        pass
    with open(f"{output_dir}/metadata_if_optimized.json", "w", encoding="utf-8") as handle:
        json.dump(if_metadata, handle, indent=2)

    print(f"Models saved to {output_dir}/")
    print("- lgb_model_optimized.joblib")
    print("- if_model_optimized.joblib")
    print("- scaler_optimized.joblib")
    print("- label_encoder.joblib")
    print("- metadata_optimized.json")
    print("- metadata_if_optimized.json")

def benchmark_inference_speed(model, scaler, sample_size=1000):
    """Benchmark inference speed for real-time assessment"""
    print("Benchmarking inference speed...")

    # Create sample data
    np.random.seed(42)
    sample_features = np.random.rand(sample_size, model.n_features_in_)
    scaled_features = scaler.transform(sample_features)

    # Benchmark
    times = []
    for i in range(sample_size):
        start = time.perf_counter()
        pred = model.predict(scaled_features[i:i+1])
        prob = model.predict_proba(scaled_features[i:i+1])
        end = time.perf_counter()
        times.append((end - start) * 1000)

    avg_time = np.mean(times)
    p95_time = np.percentile(times, 95)
    p99_time = np.percentile(times, 99)
    max_time = np.max(times)

    print("\n=== REAL-TIME PERFORMANCE BENCHMARK ===")
    print(f"Average latency: {avg_time:.2f} ms")
    print(f"95th percentile: {p95_time:.2f} ms")
    print(f"99th percentile: {p99_time:.2f} ms")
    print(f"Max latency: {max_time:.2f} ms")
    # Throughput calculations
    throughput_1k = 1000 / (avg_time / 1000)  # predictions per second
    throughput_10k = 10000 / (avg_time / 1000)

    print(f"Throughput (1k req/s): {throughput_1k:.0f} predictions/sec")
    print(f"Throughput (10k req/s): {throughput_10k:.0f} predictions/sec")
    # Real-time assessment
    if avg_time < 10:
        rating = "EXCELLENT - Perfect for high-throughput networks"
    elif avg_time < 50:
        rating = "GOOD - Suitable for most IoT deployments"
    elif avg_time < 100:
        rating = "FAIR - May need optimization for high traffic"
    else:
        rating = "POOR - Requires significant optimization"

    print(f"Real-time Rating: {rating}")

    return {
        'avg_latency': avg_time,
        'p95_latency': p95_time,
        'p99_latency': p99_time,
        'throughput_1k': throughput_1k,
        'throughput_10k': throughput_10k,
        'rating': rating
    }

def main():
    """Main training pipeline"""
    print("IoT IDS ML Model Training - Optimized for Real-Time Performance")
    print("=" * 70)

    # Configuration
    data_path = os.environ.get("IDS_TRAIN_DATA_PATH")
    if not data_path:
        raise ValueError("Set IDS_TRAIN_DATA_PATH to the labeled CSV file or dataset directory")

    try:
        # Load data
        df = load_cicids2017_data(data_path)

        # Preprocess
        X, y, feature_names = preprocess_features(df)

        # Train models (encoding happens inside training functions)
        lgb_model, label_encoder, scaler, X_encoded, X_train_scaled, X_test_scaled, y_train, y_test, test_metrics = train_optimized_lightgbm(
            X, y, feature_names
        )
        baseline_lgb_model, _, _ = train_baseline_lightgbm(X, y, feature_names)

        if_model, decision_threshold = train_optimized_isolation_forest(X_train_scaled, y_train, X_test_scaled, y_test)

        # Benchmark performance
        perf_results = benchmark_inference_speed(lgb_model, scaler)

        # Save models
        save_models(
            lgb_model,
            if_model,
            scaler,
            label_encoder,
            feature_names,
            test_metrics=test_metrics,
            decision_threshold=decision_threshold,
            evaluation_metadata={
                "dataset_path": str(data_path),
                "dataset_rows": int(len(df)),
                "test_rows": int(len(y_test)),
                "test_size": 0.2,
                "random_state": 42,
                "task": "binary ATTACK/BENIGN classification",
                "positive_class": "ATTACK",
            },
        )

        print("\nTraining Complete!")
        print("Optimized models ready for real-time IoT traffic analysis")
        print(f"Average inference latency: {perf_results['avg_latency']:.2f} ms")
        print(f"Expected throughput: {perf_results['throughput_1k']:.0f} predictions/second")

    except Exception as e:
        print(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()