import importlib.util
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest


MODULE_PATH = Path(__file__).resolve().parents[1] / "models" / "train_realtime_optimized.py"
spec = importlib.util.spec_from_file_location("train_realtime_optimized", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_compute_confusion_metrics():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 1, 0])

    metrics = module.compute_confusion_metrics(y_true, y_pred)

    assert metrics["confusion_matrix"].shape == (2, 2)
    assert metrics["accuracy"] == 0.5
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["specificity"] == 0.5
    assert metrics["f1"] == 0.5


def test_prepare_isolation_forest_features():
    X = np.array([[0.0], [1.0], [10.0], [100.0]])

    prepared, scaler = module.prepare_isolation_forest_features(X)

    assert prepared.shape == X.shape
    assert np.isfinite(prepared).all()
    assert scaler is not None


def test_compute_isolation_forest_metrics_threshold():
    X = np.array([[0.0], [0.1], [0.2], [10.0], [10.1], [10.2]])
    y_true = np.array([0, 0, 0, 1, 1, 1])

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)

    metrics = module.compute_isolation_forest_metrics(model, X, y_true, positive_label=1, decision_threshold=-0.2)

    assert metrics["confusion_matrix"].shape == (2, 2)
    assert metrics["decision_threshold"] == -0.2


def test_compute_isolation_forest_metrics():
    X = np.array([[0.0], [0.1], [0.2], [10.0], [10.1], [10.2]])
    y_true = np.array([0, 0, 0, 1, 1, 1])

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)

    metrics = module.compute_isolation_forest_metrics(model, X, y_true, positive_label=1)

    assert metrics["confusion_matrix"].shape == (2, 2)
    assert metrics["accuracy"] >= 0.0
    assert metrics["precision"] >= 0.0
    assert metrics["recall"] >= 0.0
    assert metrics["specificity"] >= 0.0
    assert metrics["f1"] >= 0.0
