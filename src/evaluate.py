"""
Model Evaluation for IDS.

Generates metrics, confusion matrices, ROC curves, feature importance
plots, and a consolidated JSON report for the dashboard.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import label_binarize

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models" / "saved"
PLOTS_DIR = MODELS_DIR / "plots"

ATTACK_CLASSES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
BINARY_CLASSES = ["Normal", "Attack"]

# Consistent plot styling
PLOT_STYLE = {
    "figure.facecolor": "#0a0e27",
    "axes.facecolor": "#0f1435",
    "axes.edgecolor": "#1e2952",
    "axes.labelcolor": "#94a3b8",
    "text.color": "#e2e8f0",
    "xtick.color": "#94a3b8",
    "ytick.color": "#94a3b8",
    "grid.color": "#1e2952",
    "grid.alpha": 0.5,
}

MODEL_COLORS = {
    "Random Forest": "#00d4ff",
    "XGBoost": "#7c3aed",
    "LSTM": "#ff3366",
}


def _setup_plot_style():
    """Apply cybersecurity dark theme to matplotlib."""
    plt.rcParams.update(PLOT_STYLE)
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.size"] = 11


def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
    mode: str = "multi",
) -> Dict:
    """Evaluate a single model and return metrics dict.

    Args:
        model: Trained model.
        X_test: Test features.
        y_test: Test labels.
        model_name: Name of the model.
        mode: 'binary' or 'multi'.

    Returns:
        Dict with accuracy, precision, recall, f1, per_class breakdown.
    """
    is_lstm = "lstm" in model_name.lower() or hasattr(model, "predict_proba") is False

    # Get predictions
    if hasattr(model, "predict_proba"):
        y_pred = model.predict(X_test)
    else:
        # LSTM / Keras model
        X_input = X_test.reshape(-1, 1, X_test.shape[1]) if X_test.ndim == 2 else X_test
        y_proba = model.predict(X_input, verbose=0)
        y_pred = np.argmax(y_proba, axis=1)

    classes = BINARY_CLASSES if mode == "binary" else ATTACK_CLASSES
    avg = "binary" if mode == "binary" else "weighted"

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, average=avg, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, average=avg, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, average=avg, zero_division=0)),
    }

    # Per-class breakdown
    report = classification_report(y_test, y_pred, target_names=classes, output_dict=True, zero_division=0)
    per_class = {}
    for cls in classes:
        if cls in report:
            per_class[cls] = {
                "precision": round(report[cls]["precision"], 4),
                "recall": round(report[cls]["recall"], 4),
                "f1_score": round(report[cls]["f1-score"], 4),
                "support": int(report[cls]["support"]),
            }
    metrics["per_class"] = per_class

    logger.info(
        "%s (%s): accuracy=%.4f, f1=%.4f",
        model_name, mode, metrics["accuracy"], metrics["f1_score"],
    )

    return metrics


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: List[str],
    model_name: str,
    save_path: Path,
) -> None:
    """Plot and save a normalized confusion matrix heatmap."""
    _setup_plot_style()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    cm = confusion_matrix(y_true, y_pred, normalize="true")

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt=".2f",
        cmap="YlOrRd",
        xticklabels=labels,
        yticklabels=labels,
        ax=ax,
        cbar_kws={"label": "Proportion"},
        linewidths=0.5,
        linecolor="#1e2952",
    )
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_ylabel("Actual", fontsize=12)
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=14, fontweight="bold", color="#00d4ff")

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved confusion matrix to %s", save_path)


def plot_roc_curves(
    models_dict: Dict[str, Any],
    X_test: np.ndarray,
    y_test: np.ndarray,
    save_path: Path,
    mode: str = "multi",
) -> None:
    """Plot ROC curves for all models (one-vs-rest for multi-class)."""
    _setup_plot_style()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    n_classes = len(np.unique(y_test))
    fig, ax = plt.subplots(figsize=(10, 7))

    for model_name, model in models_dict.items():
        color = MODEL_COLORS.get(model_name, "#ffffff")

        # Get probability predictions
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)
        else:
            X_input = X_test.reshape(-1, 1, X_test.shape[1])
            y_proba = model.predict(X_input, verbose=0)

        if mode == "binary" or n_classes == 2:
            if y_proba.ndim > 1:
                y_scores = y_proba[:, 1]
            else:
                y_scores = y_proba
            fpr, tpr, _ = roc_curve(y_test, y_scores)
            auc = roc_auc_score(y_test, y_scores)
            ax.plot(fpr, tpr, color=color, linewidth=2, label=f"{model_name} (AUC={auc:.3f})")
        else:
            # Micro-average ROC for multi-class
            y_bin = label_binarize(y_test, classes=list(range(n_classes)))
            try:
                auc = roc_auc_score(y_bin, y_proba, multi_class="ovr", average="weighted")
            except ValueError:
                auc = 0.0

            # Plot macro-average ROC
            for i in range(n_classes):
                fpr_i, tpr_i, _ = roc_curve(y_bin[:, i], y_proba[:, i])
                if i == 0:
                    ax.plot(fpr_i, tpr_i, color=color, linewidth=2, alpha=0.7,
                            label=f"{model_name} (AUC={auc:.3f})")
                else:
                    ax.plot(fpr_i, tpr_i, color=color, linewidth=1, alpha=0.3)

    ax.plot([0, 1], [0, 1], "w--", alpha=0.3, linewidth=1)
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curves — Model Comparison", fontsize=14, fontweight="bold", color="#00d4ff")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.2)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved ROC curves to %s", save_path)


def plot_feature_importance(
    model: Any,
    feature_names: List[str],
    save_path: Path,
    top_n: int = 20,
) -> None:
    """Plot top-N feature importance from a tree-based model."""
    _setup_plot_style()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    else:
        logger.warning("Model does not have feature_importances_. Skipping plot.")
        return

    indices = np.argsort(importances)[::-1][:top_n]
    top_features = [feature_names[i] if i < len(feature_names) else f"f{i}" for i in indices]
    top_values = importances[indices]

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(range(top_n), top_values[::-1], color="#00d4ff", alpha=0.8, edgecolor="#0f1435")
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(top_features[::-1], fontsize=9)
    ax.set_xlabel("Importance Score", fontsize=12)
    ax.set_title(f"Top {top_n} Feature Importance", fontsize=14, fontweight="bold", color="#00d4ff")
    ax.grid(axis="x", alpha=0.2)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved feature importance plot to %s", save_path)


def generate_comparison_report(
    results_dict: Dict[str, Dict],
    save_path: Path = None,
) -> Dict:
    """Generate and save a consolidated JSON metrics report.

    Args:
        results_dict: Mapping of mode -> {model_name: {metrics, training_time}}.
        save_path: Where to save the JSON. Defaults to models/saved/metrics.json.

    Returns:
        The consolidated report dict.
    """
    if save_path is None:
        save_path = MODELS_DIR / "metrics.json"

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # Round all float values for clean JSON
    def round_floats(obj, decimals=4):
        if isinstance(obj, float):
            return round(obj, decimals)
        if isinstance(obj, dict):
            return {k: round_floats(v, decimals) for k, v in obj.items()}
        if isinstance(obj, list):
            return [round_floats(v, decimals) for v in obj]
        return obj

    report = round_floats(results_dict)

    with open(save_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("Saved comparison report to %s", save_path)
    return report
