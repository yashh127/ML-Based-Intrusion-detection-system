"""
Prediction Pipeline for IDS.

Loads trained models and preprocessing artifacts, then provides
a unified prediction interface for raw network traffic features.
"""

import logging
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models" / "saved"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

ATTACK_CLASSES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

# Feature names for raw input (41 NSL-KDD features in order)
RAW_FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [f for f in RAW_FEATURE_NAMES if f not in CATEGORICAL_FEATURES]


class IDSPredictor:
    """Loads trained models and provides prediction interface."""

    def __init__(self, mode: str = "multi"):
        """Initialize predictor.

        Args:
            mode: 'binary' or 'multi' — which models to load.
        """
        self.mode = mode
        self.models: Dict[str, Any] = {}
        self.scaler = None
        self.encoder = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Load saved models, scaler, and encoder from disk."""
        # Load preprocessing artifacts
        scaler_path = PROCESSED_DIR / "scaler.pkl"
        encoder_path = PROCESSED_DIR / "encoder.pkl"

        if scaler_path.exists():
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)
            logger.info("Loaded scaler from %s", scaler_path)

        if encoder_path.exists():
            with open(encoder_path, "rb") as f:
                self.encoder = pickle.load(f)
            logger.info("Loaded encoder from %s", encoder_path)

        # Load models
        self.models = load_models(self.mode)

    def preprocess(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Preprocess raw features dict into model-ready array.

        Args:
            features: Dict mapping feature name -> value.

        Returns:
            1D numpy array or None if preprocessing fails.
        """
        if self.scaler is None or self.encoder is None:
            logger.error("Scaler or encoder not loaded. Cannot preprocess.")
            return None

        try:
            import pandas as pd

            # Build a single-row DataFrame
            row = {}
            for name in RAW_FEATURE_NAMES:
                row[name] = features.get(name, 0)
            df = pd.DataFrame([row])

            # Encode categoricals
            cat_values = self.encoder.transform(df[CATEGORICAL_FEATURES])

            # Scale numerics
            num_values = self.scaler.transform(df[NUMERIC_FEATURES].values.astype(np.float64))

            # Combine
            combined = np.hstack([num_values, cat_values])
            return combined[0]

        except Exception as e:
            logger.error("Preprocessing failed: %s", e)
            return None

    def predict(self, features: Dict[str, Any]) -> Dict[str, Dict]:
        """Run prediction across all loaded models.

        Args:
            features: Dict mapping feature name -> value (41 NSL-KDD features).

        Returns:
            Dict mapping model_name -> {prediction, confidence, attack_type, probabilities}.
        """
        preprocessed = self.preprocess(features)
        if preprocessed is None:
            return {"error": "Preprocessing failed"}

        results = {}
        for model_name, model in self.models.items():
            try:
                X = preprocessed.reshape(1, -1)

                if hasattr(model, "predict_proba"):
                    proba = model.predict_proba(X)[0]
                    pred_idx = int(np.argmax(proba))
                    confidence = float(proba[pred_idx])
                else:
                    # Keras LSTM
                    X_3d = X.reshape(1, 1, -1)
                    proba = model.predict(X_3d, verbose=0)[0]
                    pred_idx = int(np.argmax(proba))
                    confidence = float(proba[pred_idx])

                if self.mode == "binary":
                    classes = ["Normal", "Attack"]
                else:
                    classes = ATTACK_CLASSES

                attack_type = classes[pred_idx] if pred_idx < len(classes) else "Unknown"

                results[model_name] = {
                    "prediction": pred_idx,
                    "confidence": round(confidence, 4),
                    "attack_type": attack_type,
                    "probabilities": {
                        classes[i]: round(float(proba[i]), 4)
                        for i in range(min(len(proba), len(classes)))
                    },
                }

            except Exception as e:
                logger.error("Prediction failed for %s: %s", model_name, e)
                results[model_name] = {"error": str(e)}

        return results


def load_models(mode: str = "multi") -> Dict[str, Any]:
    """Load all saved models for the given mode.

    Args:
        mode: 'binary' or 'multi'.

    Returns:
        Dict mapping model_name -> loaded model.
    """
    models = {}

    # Random Forest
    rf_path = MODELS_DIR / f"rf_{mode}.joblib"
    if rf_path.exists():
        models["Random Forest"] = joblib.load(rf_path)
        logger.info("Loaded Random Forest from %s", rf_path)

    # XGBoost
    xgb_path = MODELS_DIR / f"xgb_{mode}.joblib"
    if xgb_path.exists():
        models["XGBoost"] = joblib.load(xgb_path)
        logger.info("Loaded XGBoost from %s", xgb_path)

    # LSTM
    lstm_path = MODELS_DIR / f"lstm_{mode}.h5"
    if lstm_path.exists():
        try:
            from tensorflow.keras.models import load_model
            models["LSTM"] = load_model(str(lstm_path))
            logger.info("Loaded LSTM from %s", lstm_path)
        except ImportError:
            logger.warning("TensorFlow not available. Skipping LSTM loading.")

    if not models:
        logger.warning("No models found in %s for mode '%s'", MODELS_DIR, mode)

    return models


def predict_single(raw_features: Dict[str, Any], mode: str = "multi") -> Dict:
    """Convenience function for one-off predictions.

    Args:
        raw_features: Dict mapping feature name -> value.
        mode: 'binary' or 'multi'.

    Returns:
        Prediction results from all models.
    """
    predictor = IDSPredictor(mode=mode)
    return predictor.predict(raw_features)
