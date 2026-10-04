"""
Train and compare Random Forest and LightGBM on the selected dataset.
Produces accuracy, classification report, model size and inference latency comparisons.
Also attempts to export the LightGBM model to ONNX and run a quick ONNX inference (if optional deps installed).
"""
import os
import json
import time
import joblib
import tempfile
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

import lightgbm as lgb


DATA_PATH = os.environ.get("COMPARE_DATA_PATH", "data/mock_iot_traffic.csv")


def load_and_encode(df_path=DATA_PATH):
    df = pd.read_csv(df_path)
    features = ['src_port', 'dst_port', 'protocol', 'packet_rate', 'byte_rate', 
                'flow_duration', 'tcp_flags', 'connection_errors']
    X = df[features].copy()
    y = df['attack_type']

    le_proto = LabelEncoder()
    X['protocol'] = le_proto.fit_transform(X['protocol'])
    le_flags = LabelEncoder()
    X['tcp_flags'] = le_flags.fit_transform(X['tcp_flags'])

    le_labels = LabelEncoder()
    y_enc = le_labels.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.joblib')
    joblib.dump(le_proto, 'models/le_protocol.joblib')
    joblib.dump(le_flags, 'models/le_flags.joblib')
    joblib.dump(le_labels, 'models/label_encoder.joblib')

    return X_train_scaled, X_test_scaled, y_train, y_test, le_labels


def benchmark_models(runs=1000, batch_sizes=(1, 32)):
    X_train, X_test, y_train, y_test, le_labels = load_and_encode()

    # Train RandomForest
    print("Training RandomForestClassifier...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    joblib.dump(rf, 'models/random_forest_model.joblib')

    # Train LightGBM
    print("Training LightGBMClassifier...")
    lgbm = lgb.LGBMClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    lgbm.fit(X_train, y_train)
    joblib.dump(lgbm, 'models/lgb_model.joblib')

    results = {}

    for name, model in (("Random Forest", rf), ("LightGBM", lgbm)):
        print(f"\nEvaluating {name}...")
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {acc:.4f}")
        print(classification_report(y_test, y_pred, target_names=le_labels.classes_))

        timing = {}
        for requested_batch_size in batch_sizes:
            batch_size = min(requested_batch_size, len(X_test))
            batch = X_test[:batch_size]
            _ = model.predict(batch)
            started = time.perf_counter()
            for _ in range(runs):
                model.predict(batch)
            elapsed = time.perf_counter() - started
            batch_ms = elapsed * 1000 / runs
            timing[str(batch_size)] = {
                "batch_size": batch_size,
                "runs": runs,
                "mean_batch_ms": batch_ms,
                "mean_per_flow_ms": batch_ms / batch_size,
                "throughput_flows_per_second": batch_size * runs / elapsed,
            }

        # model size
        tmp = tempfile.NamedTemporaryFile(delete=False)
        joblib.dump(model, tmp.name)
        size_bytes = os.path.getsize(tmp.name)
        os.unlink(tmp.name)

        for measurement in timing.values():
            print(
                f"Batch {measurement['batch_size']}: "
                f"{measurement['mean_batch_ms']:.3f} ms/batch, "
                f"{measurement['mean_per_flow_ms']:.4f} ms/flow, "
                f"{measurement['throughput_flows_per_second']:.1f} flows/s"
            )
        print(f"Model size: {size_bytes/1024:.2f} KB")

        results[name] = {
            'accuracy': acc,
            'batch_timings': timing,
            'model_size_kb': size_bytes/1024,
        }

    # Attempt ONNX export for LightGBM
    try:
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
        import onnxruntime as ort

        print("\nExporting LightGBM to ONNX using onnxmltools...")
        initial_type = [('float_input', FloatTensorType([None, X_test.shape[1]]))]
        onnx_model = convert_lightgbm(lgbm.booster_, initial_types=initial_type)
        onnx_path = 'models/lgb_model_optimized.onnx'
        with open(onnx_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        print(f"ONNX model saved to {onnx_path}")

        # Benchmark ONNX with the same batch sizes as the Python estimators.
        sess = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
        input_name = sess.get_inputs()[0].name
        onnx_timings = {}
        for requested_batch_size in batch_sizes:
            batch_size = min(requested_batch_size, len(X_test))
            batch = X_test[:batch_size].astype(np.float32)
            _ = sess.run(None, {input_name: batch})
            started = time.perf_counter()
            onnx_runs = min(runs, 100)
            for _ in range(onnx_runs):
                sess.run(None, {input_name: batch})
            elapsed = time.perf_counter() - started
            batch_ms = elapsed * 1000 / onnx_runs
            onnx_timings[str(batch_size)] = {
                "batch_size": batch_size,
                "runs": onnx_runs,
                "mean_batch_ms": batch_ms,
                "mean_per_flow_ms": batch_ms / batch_size,
                "throughput_flows_per_second": batch_size * onnx_runs / elapsed,
            }
        results["ONNX_LightGBM"] = {"batch_timings": onnx_timings}
    except Exception as exc:
        print("ONNX export/benchmark skipped (optional deps missing or failed):", exc)

    # Save summary
    report = {
        "dataset_path": DATA_PATH,
        "test_rows": int(len(X_test)),
        "split": {"test_size": 0.2, "random_state": 42, "stratified": True},
        "results": results,
    }
    with open('benchmark_output.json', 'w', encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print('\nBenchmark complete. Summary written to benchmark_output.json')


if __name__ == '__main__':
    benchmark_models()
