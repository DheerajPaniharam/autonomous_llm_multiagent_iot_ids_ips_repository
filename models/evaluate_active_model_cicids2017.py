#!/usr/bin/env python3
"""Re-evaluate the active LightGBM artifact on the repository CICIDS CSVs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "flow_duration",
    "dst_port",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "connection_errors",
    "fwd_packets_per_second",
    "bwd_packets_per_second",
    "packet_length_mean",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_labels(paths: list[Path], benign_label: str) -> np.ndarray:
    parts: list[np.ndarray] = []
    for path in paths:
        label_frame = pd.read_csv(
            path,
            usecols=lambda column: column.strip().lower() in {"label", "attack_type"},
        )
        label_frame.columns = [column.strip() for column in label_frame.columns]
        label_column = next(
            (column for column in ("attack_type", "Label") if column in label_frame),
            None,
        )
        if label_column is None:
            raise ValueError(f"No Label or attack_type column in {path}")
        values = label_frame[label_column].astype(str).str.strip().str.upper()
        parts.append((values == benign_label.upper()).to_numpy(dtype=np.int8))
    return np.concatenate(parts)


def _numeric(frame: pd.DataFrame, name: str, default: float = 0.0) -> pd.Series:
    if name not in frame:
        return pd.Series(default, index=frame.index, dtype=float)
    return pd.to_numeric(frame[name], errors="coerce").fillna(default)


def _features(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    frame.columns = [column.strip() for column in frame.columns]

    forward_packets = _numeric(frame, "Total Fwd Packets")
    backward_packets = _numeric(frame, "Total Backward Packets")
    forward_bytes = _numeric(frame, "Total Length of Fwd Packets")
    backward_bytes = _numeric(frame, "Total Length of Bwd Packets")
    duration = _numeric(frame, "Flow Duration", 1.0).replace(0, 1)
    syn = _numeric(frame, "SYN Flag Count")
    ack = _numeric(frame, "ACK Flag Count")
    rst = _numeric(frame, "RST Flag Count")

    packet_rate = _numeric(frame, "Flow Packets/s")
    if "Flow Packets/s" not in frame:
        packet_rate = (forward_packets + backward_packets) / duration

    byte_rate = _numeric(frame, "Flow Bytes/s")
    if "Flow Bytes/s" not in frame:
        byte_rate = (forward_bytes + backward_bytes) / duration

    features = pd.DataFrame(
        {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "flow_duration": _numeric(frame, "Flow Duration", 1.0),
            "dst_port": _numeric(frame, "Destination Port", 80),
            "syn_flag_count": syn,
            "ack_flag_count": ack,
            "rst_flag_count": rst,
            "connection_errors": (syn + rst).astype(int),
            "fwd_packets_per_second": _numeric(frame, "Fwd Packets/s"),
            "bwd_packets_per_second": _numeric(frame, "Bwd Packets/s"),
            "packet_length_mean": _numeric(frame, "Packet Length Mean"),
            "fwd_packet_length_mean": _numeric(frame, "Fwd Packet Length Mean"),
            "bwd_packet_length_mean": _numeric(frame, "Bwd Packet Length Mean"),
            "total_fwd_packets": forward_packets,
            "total_bwd_packets": backward_packets,
            "fwd_bytes": forward_bytes,
            "bwd_bytes": backward_bytes,
        },
        index=frame.index,
    )[FEATURE_NAMES]
    return features.replace([np.inf, -np.inf], np.nan).fillna(0)


def evaluate(
    source_dir: Path,
    model_path: Path,
    if_model_path: Path,
    scaler_path: Path,
    label_encoder_path: Path,
    metadata_path: Path,
    output_path: Path,
    chunk_rows: int,
) -> dict:
    source_files = list(source_dir.glob("*.csv"))
    if not source_files:
        raise FileNotFoundError(f"No CSV files found in {source_dir}")

    model_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if model_metadata.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Active model metadata feature order differs from evaluator")

    model = joblib.load(model_path)
    if_model = joblib.load(if_model_path)
    scaler = joblib.load(scaler_path)
    label_encoder = joblib.load(label_encoder_path)
    if getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        raise ValueError("Active model does not accept the expected 17-feature vector")
    if getattr(if_model, "n_features_in_", None) != len(FEATURE_NAMES):
        raise ValueError("Active Isolation Forest does not accept the expected 17-feature vector")

    all_labels = _read_labels(source_files, "BENIGN")
    test_indices = train_test_split(
        np.arange(len(all_labels)),
        test_size=0.2,
        random_state=42,
        stratify=all_labels,
    )[1]
    test_mask = np.zeros(len(all_labels), dtype=bool)
    test_mask[test_indices] = True

    predictions: list[np.ndarray] = []
    attack_probabilities: list[np.ndarray] = []
    anomaly_scores: list[np.ndarray] = []
    normalized_anomaly_scores: list[np.ndarray] = []
    true_labels: list[np.ndarray] = []
    offset = 0

    for path in source_files:
        for frame in pd.read_csv(path, chunksize=chunk_rows):
            chunk_features = _features(frame)
            chunk_mask = test_mask[offset : offset + len(frame)]
            if chunk_mask.any():
                selected = chunk_features.loc[chunk_mask]
                scaled = scaler.transform(selected)
                probabilities = model.predict_proba(scaled)
                attack_class = int(label_encoder.transform(["ATTACK"])[0])
                attack_column = list(model.classes_).index(attack_class)
                predictions.append(model.predict(scaled))
                attack_probabilities.append(probabilities[:, attack_column])
                raw_anomaly_score = if_model.decision_function(scaled)
                anomaly_scores.append(-raw_anomaly_score)
                normalized_anomaly_scores.append(
                    np.clip(0.5 - raw_anomaly_score, 0.0, 1.0)
                )
                true_labels.append(all_labels[offset : offset + len(frame)][chunk_mask])
            offset += len(frame)

    if offset != len(all_labels):
        raise ValueError(f"Read {offset} rows during evaluation; expected {len(all_labels)}")

    y_true = np.concatenate(true_labels)
    y_pred = np.concatenate(predictions)
    p_attack = np.concatenate(attack_probabilities)
    anomaly_score = np.concatenate(anomaly_scores)
    normalized_anomaly_score = np.concatenate(normalized_anomaly_scores)
    attack_label = int(label_encoder.transform(["ATTACK"])[0])
    benign_label = int(label_encoder.transform(["BENIGN"])[0])
    matrix = confusion_matrix(y_true, y_pred, labels=[attack_label, benign_label])
    tp, fn, fp, tn = (int(value) for value in matrix.ravel())
    if_threshold = 0.65
    if_prediction = (normalized_anomaly_score >= if_threshold).astype(np.int8)
    if_matrix = confusion_matrix(
        y_true == attack_label,
        if_prediction,
        labels=[True, False],
    )
    if_tp, if_fn, if_fp, if_tn = (int(value) for value in if_matrix.ravel())
    if_precision = if_tp / (if_tp + if_fp) if if_tp + if_fp else 0.0
    if_recall = if_tp / (if_tp + if_fn) if if_tp + if_fn else 0.0
    if_specificity = if_tn / (if_tn + if_fp) if if_tn + if_fp else 0.0
    if_f1 = (
        2 * if_precision * if_recall / (if_precision + if_recall)
        if if_precision + if_recall
        else 0.0
    )
    if_far = if_fp / (if_fp + if_tn) if if_fp + if_tn else 0.0

    result = {
        "dataset": {
            "description": "Repository-provided CICIDS2017-named CSV source files; upstream authenticity is not independently verified.",
            "source_directory": str(source_dir),
            "rows": int(len(all_labels)),
            "test_rows": int(len(y_true)),
            "files": [
                {"name": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)}
                for path in source_files
            ],
        },
        "protocol": {
            "task": "binary ATTACK versus BENIGN",
            "positive_class": "ATTACK",
            "test_size": 0.2,
            "random_state": 42,
            "stratified": True,
            "chunk_rows": chunk_rows,
        },
        "artifacts": {
            "model": str(model_path),
            "model_sha256": _sha256(model_path),
            "isolation_forest_model": str(if_model_path),
            "isolation_forest_model_sha256": _sha256(if_model_path),
            "scaler": str(scaler_path),
            "metadata": str(metadata_path),
        },
        "metrics": {
            "confusion_matrix_labels": ["ATTACK", "BENIGN"],
            "confusion_matrix": matrix.tolist(),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "attack_precision": float(precision_score(y_true, y_pred, pos_label=attack_label)),
            "attack_recall": float(recall_score(y_true, y_pred, pos_label=attack_label)),
            "attack_f1": float(f1_score(y_true, y_pred, pos_label=attack_label)),
            "attack_roc_auc": float(roc_auc_score(y_true == attack_label, p_attack)),
            "isolation_forest_attack_roc_auc": float(
                roc_auc_score(y_true == attack_label, anomaly_score)
            ),
            "isolation_forest_auc_score": "negative decision_function; higher means more anomalous",
            "isolation_forest_threshold": if_threshold,
            "isolation_forest_threshold_confusion_matrix": if_matrix.tolist(),
            "isolation_forest_tp": if_tp,
            "isolation_forest_fn": if_fn,
            "isolation_forest_fp": if_fp,
            "isolation_forest_tn": if_tn,
            "isolation_forest_detection_rate": if_recall,
            "isolation_forest_precision": if_precision,
            "isolation_forest_specificity": if_specificity,
            "isolation_forest_f1": if_f1,
            "isolation_forest_false_alarm_rate": if_far,
        },
        "saved_artifact_confusion_matrix": model_metadata["test_metrics"]["confusion_matrix"],
        "matches_saved_artifact_confusion_matrix": matrix.tolist()
        == model_metadata["test_metrics"]["confusion_matrix"],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path("data/mock_iot_traffic"))
    parser.add_argument("--model", type=Path, default=Path("models/lgb_model_optimized.joblib"))
    parser.add_argument("--if-model", type=Path, default=Path("models/if_model_optimized.joblib"))
    parser.add_argument("--scaler", type=Path, default=Path("models/scaler_optimized.joblib"))
    parser.add_argument("--label-encoder", type=Path, default=Path("models/label_encoder.joblib"))
    parser.add_argument("--metadata", type=Path, default=Path("models/metadata_optimized.json"))
    parser.add_argument(
        "--output", type=Path, default=Path("models/active_model_cicids2017_evaluation.json")
    )
    parser.add_argument("--chunk-rows", type=int, default=100_000)
    args = parser.parse_args()

    result = evaluate(
        source_dir=args.source_dir,
        model_path=args.model,
        if_model_path=args.if_model,
        scaler_path=args.scaler,
        label_encoder_path=args.label_encoder,
        metadata_path=args.metadata,
        output_path=args.output,
        chunk_rows=args.chunk_rows,
    )
    print(json.dumps(result["metrics"], indent=2))
    print("matches_saved_artifact_confusion_matrix:", result["matches_saved_artifact_confusion_matrix"])
    print("evaluation_written:", args.output)


if __name__ == "__main__":
    main()