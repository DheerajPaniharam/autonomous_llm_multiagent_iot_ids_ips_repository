import os
import logging
import json
import time
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from contextlib import contextmanager
from typing import Tuple, Dict, Optional, List, Union
from dataclasses import dataclass, field
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold,
    GridSearchCV, StratifiedShuffleSplit
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_recall_curve, average_precision_score,
    classification_report, confusion_matrix
)
from imblearn.over_sampling import SMOTE

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLT_AVAILABLE = True
except ImportError:
    PLT_AVAILABLE = False


@dataclass
class ModelConfig:
    """Configuration class for model training parameters with validation."""
    test_size: float = 0.2
    random_state: int = 42
    rf_n_jobs: int = -1
    if_n_jobs: int = -1
    rf_param_grid: Dict = field(default_factory=lambda: {
        'n_estimators': [100, 200],
        'max_depth': [20, 30, None],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
    })
    if_contamination: float = 0.05
    smote_imbalance_threshold: float = 10.0
    cv_folds: int = 5
    tune_max_samples: int = 10_000
    tune_cv_folds: int = 3
    model_accuracy_threshold: float = 0.7
    enable_shap_explanations: bool = True
    enable_versioning: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if not 0 < self.test_size < 1:
            raise ValueError(f"test_size must be between 0 and 1, got {self.test_size}")
        
        if not 0 < self.if_contamination < 0.5:
            raise ValueError(f"contamination should be between 0 and 0.5, got {self.if_contamination}")
        
        if self.cv_folds < 2:
            raise ValueError(f"cv_folds must be at least 2, got {self.cv_folds}")
        
        if self.tune_cv_folds < 2:
            raise ValueError(f"tune_cv_folds must be at least 2, got {self.tune_cv_folds}")
        
        if not 0 < self.model_accuracy_threshold <= 1:
            raise ValueError(f"model_accuracy_threshold must be between 0 and 1, got {self.model_accuracy_threshold}")


class NpEncoder(json.JSONEncoder):
    """Custom JSON encoder for NumPy types."""
    def default(self, obj):
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.bool_):
            return bool(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, np.random.Generator):
            return str(obj)
        return super().default(obj)


@contextmanager
def timer(log, name: str):
    """Context manager for timing code execution."""
    t0 = time.perf_counter()
    yield
    elapsed = time.perf_counter() - t0
    log.info(f"{name} completed in {elapsed:.2f}s")


def _configure_logging(log_file: str = 'ml_training.log'):
    """Configure logging to file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ]
    )


logger = logging.getLogger("ML_Detection_Core")

# Standard IoT Feature Schema
RAW_FEATURES = [
    "packet_rate", "byte_rate", "flow_duration", "protocol",
    "tcp_flags", "connection_errors", "port_entropy", "dst_port"
]

# IoT ports for known devices
IOT_PORTS = {1883, 8883, 5683, 5684, 502, 47808, 80, 443, 22}

# Hardcoded mappings expected by inference.py
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "MQTT": 4, "COAP": 5, "MODBUS": 6}
FLAGS_MAP = {"S": 0, "SA": 1, "PA": 2, "A": 3, "R": 4, "F": 5}


def _engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply comprehensive feature engineering to raw dataframe.
    Creates a copy and adds derived features.
    """
    out = df.copy()
    
    # Add known IoT port indicator
    if 'dst_port' in out.columns:
        out['is_known_iot_port'] = out['dst_port'].isin(IOT_PORTS).astype(int)
    
    # Add average packet size (bytes per packet)
    if 'packet_rate' in out.columns and 'byte_rate' in out.columns:
        out['avg_packet_size'] = np.where(
            out['packet_rate'] > 0, 
            out['byte_rate'] / out['packet_rate'], 
            0
        )
        # Clip extreme values
        out['avg_packet_size'] = np.clip(out['avg_packet_size'], 0, 1500)
    
    # Add packet rate to byte rate ratio (normalized)
    if 'packet_rate' in out.columns and 'byte_rate' in out.columns:
        out['packet_byte_ratio'] = np.where(
            out['byte_rate'] > 0,
            out['packet_rate'] / out['byte_rate'],
            0
        )
    
    # Add connection error flag
    if 'connection_errors' in out.columns:
        out['has_connection_errors'] = (out['connection_errors'] > 0).astype(int)
    
    return out


class MLTrainer:
    """Main trainer class for IoT intrusion detection models."""
    
    def __init__(self, data_path: Optional[str] = None, model_dir: str = 'models', config: Optional[ModelConfig] = None):
        self.data_path = data_path
        self.model_dir = model_dir
        self.config = config or ModelConfig()
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Initialize models and preprocessors
        self.scaler = StandardScaler()
        self.rf_model = None
        self.if_model = None
        self.le_target = LabelEncoder()
        
        self.feature_names: List[str] = []
        self.training_metrics: Dict = {}
        self.benchmark_results: Dict = {}
        self.label_mapping: Dict = {}
        self.model_version: Optional[str] = None
        
    def _generate_version(self) -> str:
        """Generate unique model version identifier."""
        import hashlib
        version_str = f"{datetime.now().isoformat()}_{self.config.random_state}"
        return hashlib.md5(version_str.encode()).hexdigest()[:8]
    
    def _get_model_paths(self):
        """Get paths for model files based on versioning setting."""
        if self.config.enable_versioning and self.model_version:
            version_dir = os.path.join(self.model_dir, self.model_version)
            os.makedirs(version_dir, exist_ok=True)
            # Return (root_dir, version_dir) so models are ALWAYS saved to the root for inference.py compatibility
            return self.model_dir, version_dir
        return self.model_dir, self.model_dir

    def generate_sample_data(self) -> pd.DataFrame:
        """Generate synthetic IoT network traffic dataset."""
        logger.info("Generating synthetic dataset mapping explicitly to IoT requirements...")
        rng = np.random.default_rng(self.config.random_state)
        n = 5000
        
        # Generate base benign traffic
        packet_rate = rng.uniform(1.0, 1000.0, n)
        byte_rate = rng.uniform(10.0, 10000.0, n)
        flow_duration = rng.uniform(0.1, 100.0, n)
        protocol = rng.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'MQTT'], n)
        tcp_flags = rng.choice(['A', 'S', 'PA', 'SA', 'R', 'F', 'NONE'], n)
        connection_errors = rng.integers(0, 5, n)
        port_entropy = rng.uniform(0.0, 4.0, n)
        dst_port = rng.choice([80, 443, 22, 1883, 8883, 5683, 502, 47808], n)
        labels = np.full(n, 'BENIGN', dtype=object)

        # Inject DDoS attacks (10%)
        ddos_idx = rng.choice(n, size=int(n * 0.10), replace=False)
        packet_rate[ddos_idx] = rng.uniform(500.0, 5000.0, len(ddos_idx))
        byte_rate[ddos_idx] = rng.uniform(5000.0, 50000.0, len(ddos_idx))
        connection_errors[ddos_idx] = rng.integers(2, 10, len(ddos_idx))
        labels[ddos_idx] = 'DDoS'

        # Inject PortScan attacks (10%)
        remaining = np.setdiff1d(np.arange(n), ddos_idx)
        scan_idx = rng.choice(remaining, size=int(n * 0.10), replace=False)
        port_entropy[scan_idx] = rng.uniform(3.0, 8.0, len(scan_idx))
        flow_duration[scan_idx] = rng.uniform(0.01, 0.5, len(scan_idx))
        tcp_flags[scan_idx] = 'S'
        labels[scan_idx] = 'PortScan'
        
        # Inject Brute Force attacks (5%)
        bf_idx = rng.choice(remaining, size=int(n * 0.05), replace=False)
        connection_errors[bf_idx] = rng.integers(5, 20, len(bf_idx))
        packet_rate[bf_idx] = rng.uniform(10.0, 100.0, len(bf_idx))
        labels[bf_idx] = 'BruteForce'

        return pd.DataFrame({
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'flow_duration': flow_duration,
            'protocol': protocol,
            'tcp_flags': tcp_flags,
            'connection_errors': connection_errors,
            'port_entropy': port_entropy,
            'dst_port': dst_port,
            'label': labels
        })

    def load_data(self) -> pd.DataFrame:
        """Load data from CSV with chunking for large files or generate synthetic data."""
        if self.data_path and os.path.exists(self.data_path):
            logger.info(f"Loading dataset from {self.data_path}")
            
            # Check file size for chunking
            file_size = os.path.getsize(self.data_path) / (1024**3)  # GB
            if file_size > 1:  # If > 1GB
                logger.info(f"Large file detected ({file_size:.2f} GB), using chunking")
                chunks = []
                chunk_size = 100000
                total_rows = 0
                
                for chunk in pd.read_csv(self.data_path, chunksize=chunk_size):
                    chunks.append(chunk)
                    total_rows += len(chunk)
                    logger.info(f"Loaded {total_rows:,} rows...")
                
                df = pd.concat(chunks, ignore_index=True)
                logger.info(f"Total rows loaded: {len(df):,}")
                return df
            
            df = pd.read_csv(self.data_path)
            logger.info(f"Loaded {len(df):,} rows from CSV")
            return df
            
        logger.warning(f"Path '{self.data_path}' not found — using synthetic IoT data.")
        return self.generate_sample_data()

    def preprocess(self, df: pd.DataFrame):
        """Preprocess data: handle missing values, encode features, split train/test."""
        logger.info("Preprocessing to strict IoT feature schema...")
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        
        # Extract features and labels (handle different column naming)
        label_col = 'label' if 'label' in df.columns else 'Label' if 'Label' in df.columns else None
        if label_col is None:
            raise ValueError("Dataset must contain 'label' or 'Label' column")
        
        y_raw = df[label_col]
        X_raw = df.drop(columns=['label', 'Label'], errors='ignore')
        
        # Train/Test split with stratification
        unique_labels = y_raw.unique()
        logger.info(f"Found {len(unique_labels)} unique labels: {unique_labels}")
        
        X_tr_raw, X_te_raw, y_tr_raw, y_te_raw = train_test_split(
            X_raw, y_raw, test_size=self.config.test_size, 
            random_state=self.config.random_state, stratify=y_raw
        )
        
        # Apply feature engineering (creates additional derived features)
        X_tr_eng = _engineer_features(X_tr_raw)
        X_te_eng = _engineer_features(X_te_raw)
        
        def _encode_to_numeric(x_df):
            """Convert categorical features to numeric using hardcoded mappings."""
            x = x_df.copy()
            
            # Map protocols using hardcoded dictionary
            x['protocol_enc'] = x['protocol'].str.upper().map(PROTOCOL_MAP).fillna(0).astype(int)
            
            # Map TCP flags using hardcoded dictionary
            x['tcp_flags_enc'] = x['tcp_flags'].str.upper().map(FLAGS_MAP).fillna(3).astype(int)
            
            # Define feature order - include derived features if available
            base_features = [
                "packet_rate", "byte_rate", "flow_duration", "protocol_enc", 
                "tcp_flags_enc", "connection_errors", "port_entropy", "dst_port", 
                "is_known_iot_port"
            ]
            
            # Add derived features if they exist
            derived_features = []
            if 'avg_packet_size' in x.columns:
                derived_features.append('avg_packet_size')
            if 'packet_byte_ratio' in x.columns:
                derived_features.append('packet_byte_ratio')
            if 'has_connection_errors' in x.columns:
                derived_features.append('has_connection_errors')
            
            columns_order = base_features + derived_features
            return x[columns_order]

        X_tr_num = _encode_to_numeric(X_tr_eng)
        X_te_num = _encode_to_numeric(X_te_eng)
        
        self.feature_names = list(X_tr_num.columns)
        logger.info(f"Features mapped ({len(self.feature_names)}): {self.feature_names}")
        
        # Encode target labels and store mapping
        y_train = self.le_target.fit_transform(y_tr_raw.values)
        y_test = self.le_target.transform(y_te_raw.values)
        
        # Store label mapping for later use
        self.label_mapping = {idx: label for idx, label in enumerate(self.le_target.classes_)}
        logger.info(f"Label mapping: {self.label_mapping}")
        
        # Binary labels for Isolation Forest (0 = BENIGN, 1 = ATTACK)
        y_bin_test = np.where(y_te_raw == 'BENIGN', 0, 1)
        y_bin_train = np.where(y_tr_raw == 'BENIGN', 0, 1)
        
        # Scale features for LightGBM
        X_train_scaled = self.scaler.fit_transform(X_tr_num)
        X_test_scaled = self.scaler.transform(X_te_num)
        
        # Store unscaled data for Isolation Forest (tree-based, doesn't require scaling)
        X_train_unscaled = X_tr_num.values
        X_test_unscaled = X_te_num.values
        
        return (X_train_scaled, X_test_scaled, X_train_unscaled, X_test_unscaled, 
                y_train, y_test, y_bin_train, y_bin_test, y_tr_raw, y_te_raw)

    def handle_class_imbalance(self, X_train, y_train):
        """Apply SMOTE if class imbalance exceeds threshold."""
        unique, counts = np.unique(y_train, return_counts=True)
        logger.info(f"Class distribution before handling: {dict(zip(unique, counts))}")
        
        if len(counts) > 1:
            ratio = max(counts) / min(counts)
            if ratio > self.config.smote_imbalance_threshold:
                logger.info(f"Imbalance ratio {ratio:.1f}:1 — applying SMOTE in scaled space...")
                smote = SMOTE(random_state=self.config.random_state)
                X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
                
                # Log new distribution
                unique_res, counts_res = np.unique(y_resampled, return_counts=True)
                logger.info(f"Class distribution after SMOTE: {dict(zip(unique_res, counts_res))}")
                return X_resampled, y_resampled
            else:
                logger.info(f"Imbalance ratio {ratio:.1f}:1 is below threshold, skipping SMOTE")
        else:
            logger.warning("Only one class found in training data")
        
        return X_train, y_train

    def hyperparameter_tuning(self, X_train, y_train):
        """Perform GridSearchCV for LightGBM hyperparameters."""
        logger.info("Hyperparameter tuning...")
        
        # Subsample if dataset is too large for tuning
        if len(X_train) > self.config.tune_max_samples:
            tune_frac = self.config.tune_max_samples / len(X_train)
            sss = StratifiedShuffleSplit(n_splits=1, test_size=tune_frac, random_state=self.config.random_state)
            _, tune_idx = next(sss.split(X_train, y_train))
            X_tune, y_tune = X_train[tune_idx], y_train[tune_idx]
            logger.info(f"Using subset of {len(X_tune)} samples for tuning")
        else:
            X_tune, y_tune = X_train, y_train

        grid_search = GridSearchCV(
            RandomForestClassifier(random_state=self.config.random_state, n_jobs=self.config.rf_n_jobs),
            self.config.rf_param_grid, cv=self.config.tune_cv_folds, 
            scoring='f1_macro', n_jobs=self.config.rf_n_jobs, verbose=0
        )
        
        with timer(logger, "Hyperparameter tuning"):
            grid_search.fit(X_tune, y_tune)
            
        self.training_metrics['best_params'] = grid_search.best_params_
        logger.info(f"Best params: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        return grid_search.best_params_

    def cross_validate(self, X_train, y_train):
        """Perform cross-validation on trained model."""
        if self.rf_model is None:
            logger.error("LightGBM Model not trained yet")
            return
        
        params = self.training_metrics.get('best_params', {})
        cv_est = RandomForestClassifier(random_state=self.config.random_state, n_jobs=self.config.rf_n_jobs, **params)
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True, random_state=self.config.random_state)
        
        with timer(logger, "Cross-validation"):
            scores = cross_val_score(cv_est, X_train, y_train, cv=cv, scoring='f1_macro', n_jobs=self.config.rf_n_jobs)
        
        self.training_metrics['cv_f1_macro_mean'] = float(scores.mean())
        self.training_metrics['cv_f1_macro_std'] = float(scores.std())
        logger.info(f"CV F1-macro: {scores.mean():.4f} (+/- {scores.std():.4f})")
        
        # Also compute per-fold scores
        self.training_metrics['cv_f1_macro_scores'] = scores.tolist()

    def evaluate_anomaly_detection(self, y_true, anomaly_scores):
        """Evaluate Isolation Forest performance using Average Precision."""
        ap = average_precision_score(y_true, anomaly_scores)
        precision, recall, thresholds = precision_recall_curve(y_true, anomaly_scores)
        
        # Find optimal threshold
        f1 = 2 * (precision * recall) / (precision + recall + 1e-8)
        valid_thresholds = thresholds if len(thresholds) > 0 else [0.5]
        best_idx = np.argmax(f1[:-1]) if len(thresholds) > 0 else 0
        best_thr = float(thresholds[best_idx]) if len(thresholds) > 0 else 0.5
        
        self.training_metrics['anomaly_ap_score'] = float(ap)
        self.training_metrics['anomaly_optimal_threshold'] = best_thr
        self.training_metrics['anomaly_best_f1'] = float(np.max(f1[:-1]) if len(thresholds) > 0 else 0)
        
        logger.info(f"IF Average Precision: {ap:.4f}, Optimal Threshold: {best_thr:.4f}, Best F1: {self.training_metrics['anomaly_best_f1']:.4f}")

    def benchmark_inference_speed(self, n_iterations=10):
        """Benchmark model inference latency."""
        if self.rf_model is None or self.if_model is None:
            logger.error("Models not trained yet, skipping benchmark")
            return
        
        logger.info("Benchmarking inference speed...")
        test_data = np.random.default_rng(0).standard_normal((100, len(self.feature_names)))

        # Store original settings
        orig_rf_jobs = getattr(self.rf_model, 'n_jobs', 1)
        orig_if_jobs = getattr(self.if_model, 'n_jobs', 1)
        
        # Force synchronous prediction for accurate measurement
        if hasattr(self.rf_model, 'n_jobs'):
            self.rf_model.n_jobs = 1
        if hasattr(self.if_model, 'n_jobs'):
            self.if_model.n_jobs = 1

        def _bench(model, model_name) -> float:
            # Warmup
            for _ in range(10):
                model.predict(test_data[:1])
            
            # Measure
            t0 = time.perf_counter()
            for _ in range(n_iterations):
                model.predict(test_data)
            elapsed = (time.perf_counter() - t0) / n_iterations * 1000
            logger.info(f"{model_name} latency: {elapsed:.2f} ms/batch (batch_size={len(test_data)})")
            return elapsed

        self.benchmark_results = {
            'batch_size': len(test_data),
            'n_iterations': n_iterations,
            'random_forest': {'avg_latency_ms': _bench(self.rf_model, "RF")},
            'isolation_forest': {'avg_latency_ms': _bench(self.if_model, "IF")}
        }
        
        # Restore original settings
        if hasattr(self.rf_model, 'n_jobs'):
            self.rf_model.n_jobs = orig_rf_jobs
        if hasattr(self.if_model, 'n_jobs'):
            self.if_model.n_jobs = orig_if_jobs

    def save_reference_statistics(self, X_train_scaled):
        """Save feature statistics for reference."""
        stats = {'__space__': 'scaled', 'feature_names': self.feature_names}
        for idx, name in enumerate(self.feature_names):
            col = X_train_scaled[:, idx]
            stats[name] = {
                'mean': float(np.mean(col)), 'std': float(np.std(col)),
                'min': float(np.min(col)), 'max': float(np.max(col)),
                'q1': float(np.percentile(col, 25)), 'median': float(np.percentile(col, 50)),
                'q3': float(np.percentile(col, 75))
            }
        
        model_dir, _ = self._get_model_paths()
        stats_path = os.path.join(model_dir, 'reference_stats.json')
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2, cls=NpEncoder)
        logger.info(f"Reference statistics saved to {stats_path}")

    def generate_shap_explanations(self, X_sample, y_sample=None):
        """Generate SHAP explanations for model interpretability."""
        if not self.config.enable_shap_explanations:
            return
        
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available - install with 'pip install shap' for explanations")
            return
        
        if self.rf_model is None:
            logger.warning("Model not trained, skipping SHAP explanations")
            return
        
        logger.info("Generating SHAP explanations...")
        try:
            # Use a smaller sample for SHAP to avoid performance issues
            n_samples = min(100, len(X_sample))
            X_sample_small = X_sample[:n_samples]
            
            explainer = shap.TreeExplainer(self.rf_model)
            shap_values = explainer.shap_values(X_sample_small)
            
            model_dir, _ = self._get_model_paths()
            
            if PLT_AVAILABLE:
                # Summary plot
                plt.figure(figsize=(10, 6))
                shap.summary_plot(shap_values, X_sample_small, 
                                feature_names=self.feature_names,
                                show=False)
                plt.tight_layout()
                plt.savefig(os.path.join(model_dir, 'shap_summary.png'), dpi=150, bbox_inches='tight')
                plt.close()
                
                # Bar plot
                plt.figure(figsize=(10, 6))
                shap.summary_plot(shap_values, X_sample_small, 
                                feature_names=self.feature_names,
                                plot_type="bar", show=False)
                plt.tight_layout()
                plt.savefig(os.path.join(model_dir, 'shap_bar.png'), dpi=150, bbox_inches='tight')
                plt.close()
                
                logger.info(f"SHAP plots saved to {model_dir}/")
            
            # Save SHAP values
            shap_data = {
                'shap_values': [sv.tolist() for sv in shap_values] if isinstance(shap_values, list) else shap_values.tolist(),
                'base_values': float(explainer.expected_value[0]) if isinstance(explainer.expected_value, list) else float(explainer.expected_value),
                'feature_names': self.feature_names
            }
            
            shap_path = os.path.join(model_dir, 'shap_values.json')
            with open(shap_path, 'w') as f:
                json.dump(shap_data, f, cls=NpEncoder)
            
            self.training_metrics['shap_generated'] = True
            logger.info("SHAP explanations generated successfully")
            
        except Exception as e:
            logger.warning(f"Failed to generate SHAP explanations: {e}")

    def plot_confusion_matrix(self, y_true, y_pred, model_name):
        """Plot and save confusion matrix."""
        if not PLT_AVAILABLE:
            logger.warning("Matplotlib not available for confusion matrix plotting")
            return
        
        logger.info(f"Plotting confusion matrix for {model_name}...")
        
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=np.unique(y_true), 
                   yticklabels=np.unique(y_true))
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        
        model_dir, _ = self._get_model_paths()
        plt.savefig(os.path.join(model_dir, f'confusion_matrix_{model_name.lower()}.png'), dpi=150)
        plt.close()

    def validate_model(self, X_test, y_test, threshold=None):
        """Validate model performance before saving."""
        if self.rf_model is None:
            logger.error("Model not trained, cannot validate")
            return False
        
        threshold = threshold or self.config.model_accuracy_threshold
        predictions = self.rf_model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        
        if accuracy < threshold:
            logger.warning(f"Model accuracy {accuracy:.3f} below threshold {threshold}")
            return False
        
        logger.info(f"Model validation passed with accuracy {accuracy:.3f}")
        return True

    def save_models(self, metrics):
        """Save models, metadata, and versioning information."""
        # Generate version if versioning is enabled
        if self.config.enable_versioning:
            self.model_version = self._generate_version()
            logger.info(f"Model version: {self.model_version}")
        
        model_dir, version_dir = self._get_model_paths()
        
        # Save models
        rf_path = os.path.join(model_dir, 'lgb_model_optimized.joblib')
        if_path = os.path.join(model_dir, 'if_model.joblib')
        scaler_path = os.path.join(model_dir, 'scaler.joblib')
        
        joblib.dump(self.rf_model, rf_path)
        joblib.dump(self.if_model, if_path)
        joblib.dump(self.scaler, scaler_path)
        
        logger.info(f"Models saved to {model_dir}/")
        logger.info(f"  - lgb_model_optimized.joblib")
        logger.info(f"  - if_model.joblib")
        logger.info(f"  - scaler.joblib")
        
        # Backup to version directory if enabled
        if self.config.enable_versioning and version_dir != model_dir:
            import shutil
            shutil.copy(rf_path, os.path.join(version_dir, 'lgb_model_optimized.joblib'))
            shutil.copy(if_path, os.path.join(version_dir, 'if_model.joblib'))
            shutil.copy(scaler_path, os.path.join(version_dir, 'scaler.joblib'))
            logger.info(f"Models backed up to version directory {version_dir}/")
        
        # Save metadata
        metadata = {
            'version': self.model_version,
            'timestamp': datetime.now().isoformat(),
            'feature_names': self.feature_names,
            'label_mapping': self.label_mapping,
            'label_classes': self.rf_model.classes_.tolist() if hasattr(self.rf_model, 'classes_') else [],
            'training_metrics': self.training_metrics,
            'evaluation_metrics': metrics,
            'benchmark_results': self.benchmark_results,
            'protocol_mapping': PROTOCOL_MAP,
            'flags_mapping': FLAGS_MAP,
            'iot_ports': list(IOT_PORTS),
            'config': {
                'test_size': self.config.test_size,
                'random_state': self.config.random_state,
                'if_contamination': self.config.if_contamination,
                'cv_folds': self.config.cv_folds
            }
        }
        
        metadata_path = os.path.join(model_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2, cls=NpEncoder)
        logger.info(f"Metadata saved to {metadata_path}")
        
        # Create latest symlink if versioning enabled
        if self.config.enable_versioning:
            latest_link = os.path.join(self.model_dir, 'latest')
            if os.path.exists(latest_link):
                if os.path.islink(latest_link):
                    os.unlink(latest_link)
                else:
                    logger.warning(f"Cannot create symlink - {latest_link} exists and is not a symlink")
            else:
                try:
                    os.symlink(self.model_version, latest_link, target_is_directory=True)
                    logger.info(f"Created symlink 'latest' -> {self.model_version}")
                except Exception as e:
                    logger.warning(f"Could not create symlink: {e}")

    def train_evaluate(self):
        """Main training pipeline entry point."""
        try:
            # Load and preprocess data
            df = self.load_data()
            (X_train_scaled, X_test_scaled, X_train_unscaled, X_test_unscaled, 
             y_train, y_test, y_bin_train, y_bin_test, y_tr_raw, y_te_raw) = self.preprocess(df)
            
            # Handle class imbalance with SMOTE
            X_train_balanced, y_train_balanced = self.handle_class_imbalance(X_train_scaled, y_train)

            # Hyperparameter tuning (skip if only one class)
            if len(np.unique(y_train_balanced)) > 1:
                best_params = self.hyperparameter_tuning(X_train_balanced, y_train_balanced)
            else:
                best_params = {}
                logger.warning("Only one class found in training data - skipping hyperparameter tuning")
            
            # Train final LightGBM Model
            logger.info("Training final LightGBM Model...")
            self.rf_model = RandomForestClassifier(
                random_state=self.config.random_state, 
                n_jobs=self.config.rf_n_jobs, 
                **best_params
            )
            
            with timer(logger, "RF training"):
                self.rf_model.fit(X_train_balanced, y_train_balanced)
            
            # Store feature names in the model for inference
            self.rf_model.feature_names_in_ = np.array(self.feature_names)
            
            # Cross-validation
            self.cross_validate(X_train_balanced, y_train_balanced)
            
            # Evaluate RF
            rf_preds = self.rf_model.predict(X_test_scaled)
            rf_accuracy = accuracy_score(y_test, rf_preds)
            rf_report = classification_report(y_test, rf_preds, target_names=self.le_target.classes_)
            
            logger.info(f"RF Test Accuracy: {rf_accuracy:.4f}")
            logger.info(f"RF Classification Report:\n{rf_report}")
            
            # Calculate and log text confusion matrix for LightGBM
            rf_cm = confusion_matrix(y_test, rf_preds)
            logger.info(f"LightGBM Confusion Matrix:\n{rf_cm}")
            
            # Plot confusion matrix for RF
            self.plot_confusion_matrix(y_test, rf_preds, "LightGBM")
            
            # Train Isolation Forest on BENIGN data
            logger.info("Training Isolation Forest...")
            self.if_model = IsolationForest(
                contamination=self.config.if_contamination, 
                random_state=self.config.random_state, 
                n_jobs=self.config.if_n_jobs
            )
            
            with timer(logger, "IF training"):
                # Isolation Forest works fine with unscaled data (tree-based)
                # Filter only BENIGN samples for training
                X_benign_unscaled = X_train_unscaled[y_bin_train == 0]
                
                if len(X_benign_unscaled) > 0:
                    self.if_model.fit(X_benign_unscaled)
                    logger.info(f"IF trained on {len(X_benign_unscaled)} BENIGN samples")
                else:
                    logger.warning("No BENIGN samples found - training IF on all data")
                    self.if_model.fit(X_train_unscaled)
            
            # Evaluate IF
            if_preds_binary = self.if_model.predict(X_test_unscaled)
            if_preds = np.where(if_preds_binary == 1, 0, 1)  # Convert to 0=normal, 1=attack
            if_scores = -self.if_model.decision_function(X_test_unscaled)  # Higher score = more anomalous
            if_accuracy = accuracy_score(y_bin_test, if_preds)
            
            logger.info(f"IF Test Accuracy: {if_accuracy:.4f}")
            
            # Calculate and log text confusion matrix for Isolation Forest
            if_cm = confusion_matrix(y_bin_test, if_preds)
            logger.info(f"Isolation Forest Confusion Matrix:\n{if_cm}")
            
            # Plot confusion matrix for IF
            self.plot_confusion_matrix(y_bin_test, if_preds, "Isolation_Forest")
            
            # Additional IF evaluation
            self.evaluate_anomaly_detection(y_bin_test, if_scores)
            
            # Benchmark inference speed
            self.benchmark_inference_speed()
            
            # Save reference statistics
            self.save_reference_statistics(X_train_scaled)
            
            # Generate SHAP explanations
            if self.config.enable_shap_explanations:
                self.generate_shap_explanations(X_test_scaled[:100], y_test[:100])
            
            # Prepare metrics
            metrics = {
                'random_forest': {
                    'accuracy': float(rf_accuracy),
                    'classification_report': rf_report
                },
                'isolation_forest': {
                    'accuracy': float(if_accuracy),
                    'average_precision': self.training_metrics.get('anomaly_ap_score', 0),
                    'optimal_threshold': self.training_metrics.get('anomaly_optimal_threshold', 0.5)
                }
            }
            
            # Validate model performance before saving
            if self.validate_model(X_test_scaled, y_test):
                self.save_models(metrics)
                logger.info("Pipeline completed successfully.")
            else:
                logger.error("Model validation failed. Models were not saved.")
                
        except Exception as exc:
            logger.error(f"Pipeline failed: {exc}", exc_info=True)
            raise


if __name__ == "__main__":
    # Configure logging
    _configure_logging()
    
    # Setup paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_dir = os.path.join(base_dir, 'models')
    data_path = os.path.join(base_dir, 'data', 'sample', 'test_sample.csv')
    
    # Run training
    logger.info("Starting Refactored ML Training Pipeline...")
    trainer = MLTrainer(data_path=data_path, model_dir=model_dir)
    trainer.train_evaluate()
    
    print("\n" + "="*60)
    print("Training completed successfully!")
    print(f"Models saved to: {model_dir}/")
    print("  - lgb_model_optimized.joblib")
    print("  - if_model.joblib")
    print("  - scaler.joblib")
    print("  - metadata.json")
    print("  - reference_stats.json")
    if trainer.config.enable_shap_explanations:
        print("  - shap_summary.png")
        print("  - shap_bar.png")
        print("  - shap_values.json")
    print("="*60)