"""
Unified ML inference pipeline.
Wires feature extraction → Supervised classifier → Isolation Forest.
Both models are loaded lazily; missing models trigger safe-mode (log only).
"""
from __future__ import annotations

from collections import deque
import logging
import os
import time
from pathlib import Path

import numpy as np

from backend.ml.feature_extraction import preprocess
from backend.ml.isolation_forest_model import IsolationForestModel
from backend.ml.lightgbm_model import LightGBMModel
from backend.models.messages import FeatureVector
from backend.metrics import observe_ml_latency

logger = logging.getLogger(__name__)


class MLInferencePipeline:
    """
    Loads both ML models and exposes predict_supervised / predict_if.
    Tracks inference latency for Prometheus metrics (Req 10.2).
    """

    def __init__(self) -> None:
        self._supervised = LightGBMModel()
        self._if = IsolationForestModel()
        self._lightgbm_available = False
        self._if_available = False
        # Deques with maxlen=1000 are used to track latency samples up to a fixed history.
        # This keeps memory usage bounded to prevent unbounded memory growth while
        # matching the 1000-sample window used by percentile calculations.
        self._lightgbm_latencies = deque(maxlen=1000)
        self._if_latencies = deque(maxlen=1000)
        # Tracks the last time latency sample counts were logged to rate-limit log outputs.
        self._last_count_log_time = 0.0

    @property
    def if_model(self) -> IsolationForestModel:
        """Return the Isolation Forest model wrapper."""
        return self._if

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def load_models(
        self,
        supervised_path: str = "",
        if_path: str = "",
        scaler_path: str = "",
    ) -> None:
        """
        Load both models from disk; log warnings for missing files (safe mode).
        
        Model paths are resolved using environment variables for flexibility:
        - supervised_path defaults to: LGB_MODEL_PATH env var or "models/lgb_model_optimized.joblib"
        - if_path defaults to: IF_MODEL_PATH env var or "models/if_model_optimized.joblib"
        - scaler_path defaults to: SCALER_PATH env var or "models/scaler_optimized.joblib"
        
        Args:
            supervised_path: supervised model path (optional override)
            if_path: Isolation Forest model path (optional override)
            scaler_path: Scaler model path (optional override)
        """
        # Use environment variables if explicit paths not provided.
        # This ensures all model loading respects environment configuration.
        supervised_path = supervised_path or os.getenv(
            "LGB_MODEL_PATH",
            "models/lgb_model_optimized.joblib"
        )
        if_path = if_path or os.getenv(
            "IF_MODEL_PATH",
            "models/if_model_optimized.joblib"
        )
        scaler_path = scaler_path or os.getenv(
            "SCALER_PATH",
            "models/scaler_optimized.joblib"
        )
        if Path(supervised_path).exists():
            try:
                self._supervised.load(supervised_path, scaler_path)
                self._lightgbm_available = self._supervised.is_loaded
            except Exception as exc:
                logger.warning("LightGBM model load failed — safe mode: %s", exc)
        else:
            logger.warning("LightGBM model not found at %s — safe mode", supervised_path)

        if Path(if_path).exists():
            try:
                self._if.load(if_path)
                self._if_available = self._if.is_loaded
            except Exception as exc:
                self._if_available = False
                logger.warning("IF model load failed — safe mode: %s", exc)
        else:
            self._if_available = False
            logger.warning("IF model not found at %s — safe mode", if_path)

        logger.info(
            "Model compatibility | lightgbm_available=%s | if_available=%s | lightgbm_feature_count=%s | if_feature_count=%s",
            self._lightgbm_available,
            self._if_available,
            getattr(self._supervised._model, "n_features_in_", "unknown") if self._lightgbm_available else "n/a",
            getattr(self._if._model, "n_features_in_", "unknown") if self._if_available else "n/a",
        )

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict_lightgbm(self, fv: FeatureVector) -> tuple[str, float] | None:
        """
        Classify with the LightGBM model.
        Returns (attack_type, probability) or None if model unavailable.
        """
        if not self._lightgbm_available:
            return None
        # Pass the supervised scaler into preprocess so features are aligned and
        # ordered according to the scaler/metadata used during training.
        x = preprocess(fv, scaler=getattr(self._supervised, '_scaler', None))
        t0 = time.perf_counter()
        result = self._supervised.predict(x, already_scaled=True)
        latency = time.perf_counter() - t0
        self._lightgbm_latencies.append(latency)
        
        # Observe histogram metric (Requirement 13.3)
        observe_ml_latency("lightgbm", latency)
        
        # Log a warning if the LightGBM model inference latency is slow (> 1.0 second).
        # This helps in identifying real-time performance spikes for diagnostic purposes.
        if latency > 1.0:
            logger.warning(
                "SLOW LightGBM inference: %.3f sec | samples=%d",
                latency,
                len(self._lightgbm_latencies)
            )
        
        return result

    def predict_if(self, fv: FeatureVector) -> float | None:
        """
        Score with Isolation Forest.
        Returns normalised anomaly score [0, 1] or None if model unavailable.
        """
        if not self._if_available:
            return None
        x = preprocess(fv, scaler=getattr(self._supervised, '_scaler', None))
        t0 = time.perf_counter()
        score = self._if.predict(x)
        latency = time.perf_counter() - t0
        self._if_latencies.append(latency)
        
        # Observe histogram metric (Requirement 13.3)
        observe_ml_latency("if", latency)
        
        # Log a warning if the IF model inference latency is slow (> 1.0 second).
        # This helps in identifying real-time performance spikes for diagnostic purposes.
        if latency > 1.0:
            logger.warning(
                "SLOW IF INFERENCE: %.3f sec | samples=%d",
                latency,
                len(self._if_latencies)
            )
        
        return score

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def latency_percentiles(self) -> dict[str, dict[str, float]]:
        """Return p50/p95/p99 latency in milliseconds for each model."""
        def _pct(data: deque[float] | list[float]) -> dict[str, float]:
            if not data:
                return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
            arr = sorted(list(data)[-1000:])  # keep last 1000 samples
            n = len(arr)
            return {
                "p50": arr[int(n * 0.50)] * 1000,
                "p95": arr[int(n * 0.95)] * 1000,
                "p99": arr[int(n * 0.99)] * 1000,
            }
        return {
            "lightgbm": _pct(self._lightgbm_latencies),
            "if": _pct(self._if_latencies),
        }

    @property
    def lightgbm_available(self) -> bool:
        return self._lightgbm_available

    @property
    def if_available(self) -> bool:
        return self._if_available

    def get_latency_stats(self) -> dict[str, float]:
        """
        Return flat p50/p95/p99 latency stats in seconds for both models.
        Used by the /api/v1/metrics endpoint.
        """
        # Rate-limiting sample-count logging to once every 60 seconds to avoid log spam,
        # while still providing diagnostic visibility into how many samples exist.
        current_time = time.time()
        if current_time - self._last_count_log_time >= 60.0:
            logger.info(
                "Latency sample counts | lightgbm=%d | IF=%d",
                len(self._lightgbm_latencies),
                len(self._if_latencies)
            )
            self._last_count_log_time = current_time

        pcts = self.latency_percentiles()
        lightgbm = pcts.get("lightgbm", {"p50": 0.0, "p95": 0.0, "p99": 0.0})
        if_ = pcts.get("if", {"p50": 0.0, "p95": 0.0, "p99": 0.0})
        return {
            "lightgbm_p50": lightgbm["p50"] / 1000.0,
            "lightgbm_p95": lightgbm["p95"] / 1000.0,
            "lightgbm_p99": lightgbm["p99"] / 1000.0,
            "if_p50": if_["p50"] / 1000.0,
            "if_p95": if_["p95"] / 1000.0,
            "if_p99": if_["p99"] / 1000.0,
        }
