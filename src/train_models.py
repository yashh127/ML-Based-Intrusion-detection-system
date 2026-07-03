"""
Model Training for IDS.

Trains Random Forest, XGBoost, and LSTM classifiers on NSL-KDD data.
Supports both binary and multi-class classification modes.
"""

import logging
import time
from pathlib import Path
from typing import Any, Tuple

import joblib
import numpy as np

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models" / "saved"


def _ensure_models_dir():
    """Create the models directory if it doesn't exist."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    mode: str = "multi",
) -> Tuple[Any, float]:
    """Train a Random Forest classifier.

    Args:
        X_train: Training features.
        y_train: Training labels.
        X_val: Validation features.
        y_val: Validation labels.
        mode: 'binary' or 'multi'.

    Returns:
        Tuple of (trained model, training time in seconds).
    """
    from sklearn.ensemble import RandomForestClassifier

    logger.info("Training Random Forest (%s mode)...", mode)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )

    start = time.time()
    model.fit(X_train, y_train)
    training_time = time.time() - start

    val_accuracy = model.score(X_val, y_val)
    logger.info(
        "Random Forest training complete: %.2fs, val_accuracy=%.4f",
        training_time, val_accuracy,
    )

    # Save model
    _ensure_models_dir()
    save_path = MODELS_DIR / f"rf_{mode}.joblib"
    joblib.dump(model, save_path)
    logger.info("Saved Random Forest to %s", save_path)

    return model, training_time


def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    mode: str = "multi",
) -> Tuple[Any, float]:
    """Train an XGBoost classifier.

    Args:
        X_train: Training features.
        y_train: Training labels.
        X_val: Validation features.
        y_val: Validation labels.
        mode: 'binary' or 'multi'.

    Returns:
        Tuple of (trained model, training time in seconds).
    """
    from xgboost import XGBClassifier

    logger.info("Training XGBoost (%s mode)...", mode)

    n_classes = len(np.unique(y_train))

    params = {
        "n_estimators": 300,
        "learning_rate": 0.1,
        "max_depth": 8,
        "tree_method": "hist",
        "random_state": 42,
        "n_jobs": -1,
        "verbosity": 0,
    }

    if mode == "binary":
        # Compute scale_pos_weight for binary imbalance
        neg_count = np.sum(y_train == 0)
        pos_count = np.sum(y_train == 1)
        params["scale_pos_weight"] = neg_count / max(pos_count, 1)
        params["objective"] = "binary:logistic"
        params["eval_metric"] = "logloss"
    else:
        params["objective"] = "multi:softprob"
        params["num_class"] = n_classes
        params["eval_metric"] = "mlogloss"

    model = XGBClassifier(**params)

    start = time.time()
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    training_time = time.time() - start

    val_accuracy = model.score(X_val, y_val)
    logger.info(
        "XGBoost training complete: %.2fs, val_accuracy=%.4f",
        training_time, val_accuracy,
    )

    # Save model
    _ensure_models_dir()
    save_path = MODELS_DIR / f"xgb_{mode}.joblib"
    joblib.dump(model, save_path)
    logger.info("Saved XGBoost to %s", save_path)

    return model, training_time


def train_lstm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    mode: str = "multi",
    n_features: int = None,
) -> Tuple[Any, float]:
    """Train an LSTM classifier.

    Args:
        X_train: Training features (2D — will be reshaped to 3D).
        y_train: Training labels.
        X_val: Validation features (2D — will be reshaped to 3D).
        y_val: Validation labels.
        mode: 'binary' or 'multi'.
        n_features: Number of input features (inferred from X_train if None).

    Returns:
        Tuple of (trained model, training time in seconds).
    """
    try:
        import tensorflow as tf
        from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
        from tensorflow.keras.layers import LSTM, Dense, Dropout
        from tensorflow.keras.models import Sequential
    except ImportError:
        logger.error("TensorFlow not installed. Skipping LSTM training.")
        return None, 0.0

    logger.info("Training LSTM (%s mode)...", mode)

    if n_features is None:
        n_features = X_train.shape[1]

    n_classes = len(np.unique(y_train))
    if mode == "binary":
        n_classes = 2

    # Reshape for LSTM: (samples, timesteps=1, features)
    X_train_3d = X_train.reshape(-1, 1, n_features)
    X_val_3d = X_val.reshape(-1, 1, n_features)

    # Build model
    model = Sequential([
        LSTM(128, return_sequences=True, input_shape=(1, n_features)),
        Dropout(0.3),
        LSTM(64, return_sequences=False),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(n_classes, activation="softmax"),
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    callbacks = [
        EarlyStopping(
            monitor="val_loss",
            patience=10,
            restore_best_weights=True,
            verbose=1,
        ),
        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=5,
            min_lr=1e-6,
            verbose=1,
        ),
    ]

    start = time.time()
    model.fit(
        X_train_3d, y_train,
        validation_data=(X_val_3d, y_val),
        epochs=50,
        batch_size=256,
        callbacks=callbacks,
        verbose=1,
    )
    training_time = time.time() - start

    val_loss, val_acc = model.evaluate(X_val_3d, y_val, verbose=0)
    logger.info(
        "LSTM training complete: %.2fs, val_accuracy=%.4f, val_loss=%.4f",
        training_time, val_acc, val_loss,
    )

    # Save model
    _ensure_models_dir()
    save_path = MODELS_DIR / f"lstm_{mode}.h5"
    model.save(str(save_path))
    logger.info("Saved LSTM to %s", save_path)

    return model, training_time


def train_all_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    mode: str = "multi",
) -> dict:
    """Train all 3 models and return results.

    Args:
        X_train: Training features.
        y_train: Training labels.
        X_val: Validation features.
        y_val: Validation labels.
        mode: 'binary' or 'multi'.

    Returns:
        Dict mapping model_name -> (model, training_time).
    """
    results = {}

    # Random Forest
    try:
        rf_model, rf_time = train_random_forest(X_train, y_train, X_val, y_val, mode)
        results["Random Forest"] = (rf_model, rf_time)
    except Exception as e:
        logger.error("Random Forest training failed: %s", e)

    # XGBoost
    try:
        xgb_model, xgb_time = train_xgboost(X_train, y_train, X_val, y_val, mode)
        results["XGBoost"] = (xgb_model, xgb_time)
    except Exception as e:
        logger.error("XGBoost training failed: %s", e)

    # LSTM
    try:
        lstm_model, lstm_time = train_lstm(X_train, y_train, X_val, y_val, mode)
        if lstm_model is not None:
            results["LSTM"] = (lstm_model, lstm_time)
        else:
            logger.warning("LSTM training skipped (TensorFlow not available)")
    except Exception as e:
        logger.error("LSTM training failed: %s", e)

    return results
