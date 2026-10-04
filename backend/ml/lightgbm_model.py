"""
Backwards-compatible supervised model wrapper (LightGBM-compatible).

This module contains the `LightGBMModel` wrapper that loads a supervised
classifier artifact by default (the project uses an optimized LightGBM model).
It intentionally exposes a stable API for downstream callers.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import joblib
import json
import sys
import platform
import numpy as np
import pandas as pd
import sklearn
from backend.ml.feature_extraction import FEATURE_NAMES as BACKEND_FEATURE_NAMES, OPTIMIZED_FEATURE_NAMES

logger = logging.getLogger(__name__)

# Model paths are configurable via environment variables.
_LGB_MODEL_PATH = Path(os.getenv("LGB_MODEL_PATH", "models/lgb_model_optimized.joblib"))
_SCALER_PATH = Path(os.getenv("SCALER_PATH", "models/scaler_optimized.joblib"))
_LABEL_ENCODER_PATH = Path(os.getenv("LABEL_ENCODER_PATH", "models/label_encoder.joblib"))


class LightGBMModel:
    """
    Wrapper for the production supervised classifier.
    External callers use `LightGBMModel.predict()` and receive `(label, probability)`.
    """
    def __init__(self) -> None:
        self._model = None
        self._scaler = None
        self._label_encoder = None
        self._loaded = False

    def load(
        self,
        model_path: str | Path = _LGB_MODEL_PATH,
        scaler_path: str | Path = _SCALER_PATH,
        label_encoder_path: str | Path = _LABEL_ENCODER_PATH,
    ) -> None:
        """Load the supervised model artifacts from disk and validate them."""
        model_path = Path(model_path)
        scaler_path = Path(scaler_path)
        label_encoder_path = Path(label_encoder_path)

        missing = [str(path) for path in (model_path, scaler_path, label_encoder_path) if not path.exists()]
        if missing:
            for artifact in missing:
                logger.warning("Supervised model artifact missing — safe mode: %s", artifact)
            self._loaded = False
            self._model = None
            self._scaler = None
            self._label_encoder = None
            return

        # Enforce optimized/legacy pairing: do not mix optimized model with legacy scaler
        model_opt = 'optimized' in model_path.name
        scaler_opt = 'optimized' in scaler_path.name
        if model_opt != scaler_opt:
            logger.error(
                "Supervised artifact mismatch: model(%s) optimized=%s scaler(%s) optimized=%s — refusing to load",
                model_path, model_opt, scaler_path, scaler_opt,
            )
            self._loaded = False
            return

        # Load artifacts
        # Support LightGBM classifiers saved via joblib or compatible sklearn estimators.
        self._model = joblib.load(model_path)
        self._scaler = joblib.load(scaler_path)
        self._label_encoder = joblib.load(label_encoder_path)

        # Attempt to load matching metadata if present
        metadata_file = model_path.parent / ("metadata_optimized.json" if model_opt else "metadata.json")
        self._metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    self._metadata = json.load(f)
            except Exception:
                logger.warning("Failed to read metadata file %s", metadata_file)

        if hasattr(self._model, "n_features_in_") and hasattr(self._scaler, "n_features_in_"):
            model_features = int(self._model.n_features_in_)
            scaler_features = int(self._scaler.n_features_in_)
            if model_features != scaler_features:
                logger.error(
                    "Supervised scaler feature mismatch: model expects %d features, scaler expects %d",
                    model_features,
                    scaler_features,
                )
                # Log metadata feature counts if available
                meta_count = len(self._metadata.get('feature_names', [])) if self._metadata else None
                if meta_count:
                    logger.error("Metadata feature_count=%s", meta_count)

                # If the model is a legacy 8-feature model but the provided scaler is an optimized 17-feature scaler,
                # attempt to fall back to the legacy 8-feature scaler already present in the repository.
                if model_features == len(BACKEND_FEATURE_NAMES) and scaler_features == len(OPTIMIZED_FEATURE_NAMES):
                    fallback_scaler_path = model_path.parent / "scaler.joblib"
                    if fallback_scaler_path.exists():
                        try:
                            fallback_scaler = joblib.load(fallback_scaler_path)
                            fallback_features = getattr(fallback_scaler, "n_features_in_", None)
                            if fallback_features == model_features:
                                self._scaler = fallback_scaler
                                self._feature_names = list(getattr(fallback_scaler, "feature_names_in_", []))
                                logger.warning(
                                    "Legacy scaler loaded for 8-feature model: %s",
                                    fallback_scaler_path,
                                )
                                scaler_features = fallback_features
                            else:
                                logger.warning(
                                    "Legacy scaler %s loaded but still mismatched: %s features",
                                    fallback_scaler_path,
                                    fallback_features,
                                )
                        except Exception as exc:
                            logger.warning(
                                "Failed to load legacy fallback scaler %s: %s",
                                fallback_scaler_path,
                                exc,
                             )

                if model_features != getattr(self._scaler, "n_features_in_", None):
                    self._loaded = False
                    return

        # Determine feature names used for inference
        if isinstance(self._metadata.get('feature_names'), list) and self._metadata.get('feature_names'):
            self._feature_names = list(self._metadata['feature_names'])
        elif hasattr(self._scaler, 'feature_names_in_'):
            self._feature_names = list(self._scaler.feature_names_in_)
        else:
            self._feature_names = None

        self._loaded = True
        # Friendly success message for startup logs and diagnostics
        try:
            feat_count = int(getattr(self._model, 'n_features_in_', -1))
        except Exception:
            feat_count = -1
        scaler_count = len(self._feature_names) if self._feature_names is not None else int(getattr(self._scaler, 'n_features_in_', -1))
        logger.info("Supervised model loaded successfully | feature_count=%s | scaler_feature_count=%s | metadata_validated=%s",
                    feat_count, scaler_count, bool(self._metadata))
        # Print runtime and training versions for diagnostics (warning only)
        training_sklearn = self._metadata.get('config', {}).get('sklearn_version') if isinstance(self._metadata.get('config'), dict) else None
        logger.info(
            "Supervised model diagnostics | model_version=%s | sklearn_runtime=%s | training_sklearn=%s | python=%s | joblib=%s | model_classes=%s | scaler_features=%s | label_encoder_classes=%s",
            self._metadata.get('version', getattr(self._model, '__sklearn_version__', 'unknown')),
            sklearn.__version__,
            training_sklearn,
            platform.python_version(),
            getattr(joblib, '__version__', 'unknown'),
            list(getattr(self._model, 'classes_', [])),
            self._feature_names if self._feature_names is not None else list(getattr(self._scaler, 'feature_names_in_', [])),
            list(getattr(self._label_encoder, 'classes_', [])),
        )

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def predict(
        self,
        x: np.ndarray | pd.DataFrame,
        *,
        already_scaled: bool = False,
    ) -> tuple[str, float] | None:
        """
        Classify a feature vector and return its predicted label and attack probability.
        Raw input is scaled here unless the caller marks it as already scaled.
        """
        if not self._loaded or self._model is None:
            logger.warning("Supervised model inference skipped: model not loaded")
            return None

        if self._scaler is None or self._label_encoder is None:
            logger.warning(
                "Supervised model inference skipped: scaler=%s label_encoder=%s",
                self._scaler is not None,
                self._label_encoder is not None,
            )
            return None

        if isinstance(x, pd.DataFrame):
            values = x.to_numpy(dtype=np.float64)
        else:
            values = np.asarray(x, dtype=np.float64)

        if values.ndim == 1:
            values = values.reshape(1, -1)
        if values.ndim != 2:
            logger.error("Supervised inference rejected: unexpected feature shape %s", values.shape)
            return None

        expected_count = getattr(self._model, "n_features_in_", None)
        if already_scaled:
            if expected_count is not None and values.shape[1] != int(expected_count):
                logger.error(
                    "Scaled supervised feature count mismatch | expected_count=%d | actual_count=%d",
                    int(expected_count),
                    values.shape[1],
                )
                return None
        else:
            scaler_feature_names = list(getattr(self._scaler, "feature_names_in_", []))
            if expected_count is not None:
                expected_count = int(expected_count)
                if values.shape[1] != expected_count:
                    logger.error(
                        "Supervised feature count mismatch | expected_count=%d | actual_count=%d",
                        expected_count,
                        values.shape[1],
                    )

                    if values.shape[1] == len(BACKEND_FEATURE_NAMES) and scaler_feature_names:
                        logger.warning(
                            "Received legacy %d-feature vector; expanding to %d features by filling missing fields with 0.0",
                            values.shape[1],
                            expected_count,
                        )
                        provided_df = pd.DataFrame(values, columns=list(BACKEND_FEATURE_NAMES))
                        expected = scaler_feature_names
                        values = provided_df.reindex(columns=expected, fill_value=0.0).to_numpy(dtype=np.float64)
                    else:
                        logger.error("Supervised feature_names expected: %s", scaler_feature_names)
                        return None

            if hasattr(self._scaler, "feature_names_in_"):
                expected_features = list(self._scaler.feature_names_in_)
                if values.shape[1] != len(expected_features):
                    logger.error(
                        "Supervised scaler feature mismatch | expected_count=%d | actual_count=%d | feature_names=%s",
                        len(expected_features),
                        values.shape[1],
                        expected_features,
                    )
                    if self._feature_names is not None and values.shape[1] == len(self._feature_names):
                        df = pd.DataFrame(values, columns=self._feature_names)
                        values = df.reindex(columns=expected_features, fill_value=0.0).to_numpy(dtype=np.float64)
                    else:
                        return None
                values = self._scaler.transform(
                    pd.DataFrame(values, columns=expected_features)[expected_features]
                )
            else:
                values = self._scaler.transform(values)

        # LightGBM and sklearn-style classifiers expose `predict_proba` on estimator instances.
        proba = self._model.predict_proba(values)[0]
        class_idx = int(np.argmax(proba))
        class_ids = np.asarray(self._model.classes_, dtype=int)
        class_id = int(class_ids[class_idx])
        try:
            class_labels = [
                str(value)
                for value in self._label_encoder.inverse_transform(class_ids)
            ]
        except Exception as exc:
            logger.warning(
                "Supervised label decoding failed for class_id=%s: %s. Falling back to metadata label mapping.",
                class_id,
                exc,
            )
            # Fallback when the saved model classes are not aligned with the stored label encoder.
            metadata_labels = self._metadata.get("label_classes")
            if not isinstance(metadata_labels, list) or len(metadata_labels) != len(class_ids):
                logger.error("Unable to map model classes to semantic labels; refusing to infer attack probability")
                return None
            class_labels = [str(metadata_labels[int(value)]) for value in class_ids]

        label = class_labels[class_idx]
        attack_probability = float(sum(
            probability
            for probability, class_label in zip(proba, class_labels)
            if class_label.strip().upper() != "BENIGN"
        ))

        logger.debug(
            "Supervised prediction | label=%s | class_id=%s | probability=%.6f",
            label,
            class_id,
            attack_probability,
        )
        return label, attack_probability
