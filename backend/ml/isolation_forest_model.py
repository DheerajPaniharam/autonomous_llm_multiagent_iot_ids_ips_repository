"""
Isolation Forest model wrapper for zero-day anomaly detection.
Normalises raw anomaly scores to [0, 1] range.
"""
from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path

import joblib
import numpy as np

from backend.ml.feature_extraction import OPTIMIZED_FEATURE_NAMES

logger = logging.getLogger(__name__)

# Model path is configurable via environment variable.
# Environment variable takes precedence if set; otherwise uses default.
# This allows model path to be overridden at runtime without code changes.
_IF_MODEL_PATH = Path(os.getenv("IF_MODEL_PATH", "models/if_model_optimized.joblib"))
_EXPECTED_FEATURE_COUNT = 17


class IsolationForestModel:
    def __init__(self) -> None:
        self._model = None
        self._loaded = False
        self._metadata: dict = {}
        self._compatibility_error: str | None = None

    def load(self, model_path: str | Path = _IF_MODEL_PATH) -> None:
        """Load Isolation Forest model from disk and validate it against the optimized feature set."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Isolation Forest model not found: {model_path}")

        self._model = joblib.load(model_path)
        self._metadata = {}
        self._compatibility_error = None

        metadata_file = model_path.parent / "metadata_if_optimized.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, "r", encoding="utf-8") as handle:
                    self._metadata = json.load(handle)
            except Exception as exc:
                logger.warning("Failed to read IF metadata file %s: %s", metadata_file, exc)

        n_features_in = getattr(self._model, "n_features_in_", None)
        metadata_feature_names = self._metadata.get("feature_names") or list(getattr(self._model, "feature_names_in_", []))
        metadata_feature_count = len(metadata_feature_names) if metadata_feature_names else None

        feature_count = int(n_features_in) if n_features_in is not None else metadata_feature_count
        feature_count = feature_count if feature_count is not None else _EXPECTED_FEATURE_COUNT

        if feature_count != _EXPECTED_FEATURE_COUNT:
            self._compatibility_error = (
                f"Isolation Forest expects {feature_count} features, but runtime requires {_EXPECTED_FEATURE_COUNT}"
            )
            self._loaded = False
            self._model = None
            raise ValueError(self._compatibility_error)

        if metadata_feature_names and list(metadata_feature_names) != OPTIMIZED_FEATURE_NAMES:
            self._compatibility_error = (
                "Isolation Forest metadata feature order does not match the optimized 17-feature vector"
            )
            self._loaded = False
            self._model = None
            raise ValueError(self._compatibility_error)

        self._loaded = True
        logger.info(
            "Isolation Forest loaded successfully | feature_count=%s | metadata_validated=%s | sklearn_runtime=%s | training_sklearn=%s | python=%s",
            feature_count,
            bool(self._metadata),
            platform.python_version(),
            self._metadata.get("training_sklearn_version") or self._metadata.get("sklearn_version") or "unknown",
            platform.python_version(),
        )

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def compatibility_error(self) -> str | None:
        return self._compatibility_error

    def predict(self, x: np.ndarray) -> float:
        """
        Score a preprocessed feature vector.
        Returns anomaly score normalised to [0.0, 1.0].
        Higher = more anomalous.
        """
        if not self._loaded or self._model is None:
            raise RuntimeError("Model not loaded — call load() first")

        # decision_function returns negative scores for anomalies
        raw_score = float(self._model.decision_function(x)[0])

        # Normalise: typical range is roughly [-0.5, 0.5]
        # Map to [0, 1] where 1 = most anomalous
        normalised = max(0.0, min(1.0, 0.5 - raw_score))
        return normalised

    @property
    def decision_threshold(self) -> float:
        """Return the raw decision threshold used by the Isolation Forest model."""
        if not self._loaded or not self._metadata:
            return 0.11
        return self._metadata.get("decision_threshold", 0.11)
