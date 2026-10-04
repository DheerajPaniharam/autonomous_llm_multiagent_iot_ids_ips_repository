from collections import deque

import numpy as np
from sklearn.preprocessing import LabelEncoder

from backend.ml.feature_extraction import build_feature_vector_from_zeek
from backend.ml.inference import MLInferencePipeline
from backend.ml.lightgbm_model import LightGBMModel


def test_lightgbm_predict_uses_label_encoder_for_semantic_labels():
    model = LightGBMModel()
    model.load("models/lgb_model_optimized.joblib", "models/scaler_optimized.joblib")

    features = np.array([[0.1, 200.0, 0.01, 80, 0, 3, 0, 0.0]], dtype=np.float64)
    result = model.predict(features)

    assert result is not None
    label, probability = result
    assert isinstance(label, str)
    assert label not in {"0", "1"}
    assert not label.isdigit()
    assert 0.0 <= probability <= 1.0


def test_lightgbm_predict_scales_raw_input_once_and_returns_attack_probability():
    class CountingScaler:
        n_features_in_ = 2

        def __init__(self):
            self.calls = 0

        def transform(self, values):
            self.calls += 1
            return np.asarray(values) * 2

    class FixedClassifier:
        n_features_in_ = 2
        classes_ = np.array([0, 1])

        def predict_proba(self, values):
            self.values = np.asarray(values).copy()
            return np.array([[0.08, 0.92]])

    model = LightGBMModel()
    model._loaded = True
    model._model = FixedClassifier()
    model._scaler = CountingScaler()
    model._label_encoder = LabelEncoder().fit(["ATTACK", "BENIGN"])
    model._feature_names = None
    model._metadata = {}

    result = model.predict(np.array([[2.0, 3.0]]))

    assert result == ("BENIGN", 0.08)
    assert model._scaler.calls == 1
    np.testing.assert_array_equal(model._model.values, [[4.0, 6.0]])


def test_lightgbm_predict_does_not_rescale_pipeline_input():
    class CountingScaler:
        n_features_in_ = 2

        def __init__(self):
            self.calls = 0

        def transform(self, values):
            self.calls += 1
            return np.asarray(values) * 2

    class FixedClassifier:
        n_features_in_ = 2
        classes_ = np.array([0, 1])

        def predict_proba(self, values):
            return np.array([[0.8, 0.2]])

    model = LightGBMModel()
    model._loaded = True
    model._model = FixedClassifier()
    model._scaler = CountingScaler()
    model._label_encoder = LabelEncoder().fit(["ATTACK", "BENIGN"])
    model._feature_names = None
    model._metadata = {}

    result = model.predict(np.array([[4.0, 6.0]]), already_scaled=True)

    assert result == ("ATTACK", 0.8)
    assert model._scaler.calls == 0


def test_inference_pipeline_marks_preprocessed_features_as_scaled(monkeypatch):
    class SupervisedModel:
        _scaler = object()

        def __init__(self):
            self.already_scaled = None

        def predict(self, values, *, already_scaled=False):
            self.already_scaled = already_scaled
            return "ATTACK", 0.7

    pipeline = MLInferencePipeline.__new__(MLInferencePipeline)
    pipeline._supervised = SupervisedModel()
    pipeline._lightgbm_available = True
    pipeline._lightgbm_latencies = deque(maxlen=1000)
    pipeline._last_count_log_time = float("inf")
    monkeypatch.setattr(
        "backend.ml.inference.preprocess",
        lambda feature_vector, scaler: np.array([[0.1, 0.2]]),
    )
    monkeypatch.setattr("backend.ml.inference.observe_ml_latency", lambda *args: None)

    result = pipeline.predict_lightgbm(object())

    assert result == ("ATTACK", 0.7)
    assert pipeline._supervised.already_scaled is True


def test_zeek_parser_handles_blank_duration_without_dropping_record():
    raw = {
        "id.orig_h": "192.168.1.10",
        "id.resp_h": "10.0.0.5",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
        "duration": "",
        "orig_pkts": 10,
        "resp_pkts": 5,
        "orig_bytes": 1000,
        "resp_bytes": 500,
        "conn_state": "SF",
    }

    fv = build_feature_vector_from_zeek(raw)

    assert fv is not None
    assert fv.flow_duration == 1.0
