"""
Feature Engineering for IDS.

Includes correlation filtering, XGBoost-based feature importance ranking,
SMOTE oversampling for minority classes, and data reshaping for LSTM.
"""

import logging
from typing import List, Tuple

import numpy as np
from sklearn.feature_selection import mutual_info_classif

logger = logging.getLogger(__name__)


def correlation_filter(
    X: np.ndarray,
    feature_names: list,
    threshold: float = 0.95,
) -> Tuple[np.ndarray, list, list]:
    """Remove highly correlated features.

    Args:
        X: Feature matrix.
        feature_names: List of feature names.
        threshold: Correlation threshold for removal.

    Returns:
        Filtered X, remaining feature_names, dropped feature_names.
    """
    logger.info("Running correlation filter (threshold=%.2f)...", threshold)

    corr_matrix = np.corrcoef(X, rowvar=False)
    n_features = corr_matrix.shape[0]

    # Find pairs above threshold
    to_drop = set()
    for i in range(n_features):
        if i in to_drop:
            continue
        for j in range(i + 1, n_features):
            if j in to_drop:
                continue
            if abs(corr_matrix[i, j]) > threshold:
                # Drop the feature with higher mean correlation
                mean_i = np.mean(np.abs(corr_matrix[i, :]))
                mean_j = np.mean(np.abs(corr_matrix[j, :]))
                drop_idx = j if mean_j >= mean_i else i
                to_drop.add(drop_idx)

    keep_idx = [i for i in range(n_features) if i not in to_drop]
    dropped_names = [feature_names[i] for i in to_drop]
    kept_names = [feature_names[i] for i in keep_idx]

    X_filtered = X[:, keep_idx]
    logger.info("Dropped %d correlated features: %s", len(dropped_names), dropped_names[:10])
    logger.info("Remaining features: %d", len(kept_names))

    return X_filtered, kept_names, dropped_names


def get_feature_importance(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list,
    top_n: int = 30,
) -> List[Tuple[str, float]]:
    """Rank features by importance using XGBoost.

    Args:
        X: Feature matrix.
        y: Labels.
        feature_names: Feature names.
        top_n: Number of top features to return.

    Returns:
        Sorted list of (feature_name, importance_score).
    """
    try:
        from xgboost import XGBClassifier

        logger.info("Computing feature importance with XGBoost...")
        model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            tree_method="hist",
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        model.fit(X, y)

        importances = model.feature_importances_
        ranked = sorted(
            zip(feature_names, importances),
            key=lambda x: x[1],
            reverse=True,
        )
        logger.info("Top %d features: %s", top_n, [r[0] for r in ranked[:top_n]])
        return ranked[:top_n]

    except ImportError:
        logger.warning("XGBoost not available, using mutual information instead.")
        mi_scores = mutual_info_classif(X, y, random_state=42)
        ranked = sorted(
            zip(feature_names, mi_scores),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[:top_n]


def apply_smote(
    X: np.ndarray,
    y: np.ndarray,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """Apply SMOTE oversampling to balance minority classes.

    Args:
        X: Feature matrix.
        y: Labels.
        random_state: Random seed.

    Returns:
        Resampled X, y.
    """
    from imblearn.over_sampling import SMOTE

    logger.info("Applying SMOTE oversampling...")
    logger.info("Class distribution before SMOTE: %s", dict(zip(*np.unique(y, return_counts=True))))

    smote = SMOTE(random_state=random_state)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    logger.info("Class distribution after SMOTE: %s", dict(zip(*np.unique(y_resampled, return_counts=True))))
    logger.info("Resampled shape: %s", X_resampled.shape)

    return X_resampled, y_resampled


def create_binary_labels(y_multi: np.ndarray) -> np.ndarray:
    """Convert multi-class labels to binary (Normal=0, Attack=1).

    Args:
        y_multi: Multi-class labels (0=Normal, 1-4=Attack types).

    Returns:
        Binary labels array.
    """
    return (y_multi > 0).astype(np.int32)


def prepare_lstm_input(X: np.ndarray) -> np.ndarray:
    """Reshape feature matrix for LSTM input.

    LSTM expects 3D input: (samples, timesteps, features).
    We use timesteps=1 since each sample is a single connection record.

    Args:
        X: 2D feature matrix (samples, features).

    Returns:
        3D array (samples, 1, features).
    """
    return X.reshape(X.shape[0], 1, X.shape[1])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    # Quick test with random data
    X = np.random.randn(1000, 50)
    y = np.random.randint(0, 5, 1000)
    names = [f"feature_{i}" for i in range(50)]

    X_filt, kept, dropped = correlation_filter(X, names)
    print(f"Correlation filter: {X.shape[1]} -> {X_filt.shape[1]}")

    importances = get_feature_importance(X, y, names, top_n=10)
    print(f"Top features: {[n for n, _ in importances]}")

    y_bin = create_binary_labels(y)
    print(f"Binary labels: {np.bincount(y_bin)}")

    X_lstm = prepare_lstm_input(X)
    print(f"LSTM input shape: {X_lstm.shape}")
