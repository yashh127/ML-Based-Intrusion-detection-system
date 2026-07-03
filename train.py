#!/usr/bin/env python3
"""
NetShield IDS — Model Training CLI.

Orchestrates the full training pipeline:
  1. Load NSL-KDD data
  2. Preprocess features
  3. Apply SMOTE oversampling
  4. Train Random Forest, XGBoost, and LSTM
  5. Evaluate all models
  6. Generate comparison plots and metrics JSON

Usage:
    python train.py --mode all      # Train both binary and multi-class (default)
    python train.py --mode binary   # Train binary classifiers only
    python train.py --mode multi    # Train multi-class classifiers only
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data_pipeline import ATTACK_CLASSES, get_train_test_data
from src.evaluate import (
    evaluate_model,
    generate_comparison_report,
    plot_confusion_matrix,
    plot_feature_importance,
    plot_roc_curves,
    PLOTS_DIR,
)
from src.feature_engineering import apply_smote, create_binary_labels
from src.train_models import train_all_models

logger = logging.getLogger(__name__)


def run_training(mode: str) -> dict:
    """Run the full training pipeline for the given mode.

    Args:
        mode: 'binary' or 'multi'.

    Returns:
        Dict of evaluation results for each model.
    """
    logger.info("=" * 60)
    logger.info("Starting training pipeline — mode: %s", mode)
    logger.info("=" * 60)

    # 1. Load data
    logger.info("[1/5] Loading NSL-KDD data...")
    t0 = time.time()
    X_train, X_test, y_train_multi, y_test_multi, feature_names = get_train_test_data()
    logger.info("Data loaded in %.2fs", time.time() - t0)

    # 2. Prepare labels for this mode
    if mode == "binary":
        y_train = create_binary_labels(y_train_multi)
        y_test = create_binary_labels(y_test_multi)
        class_names = ["Normal", "Attack"]
    else:
        y_train = y_train_multi
        y_test = y_test_multi
        class_names = ATTACK_CLASSES

    logger.info("Class distribution (train): %s",
                dict(zip(class_names, np.bincount(y_train, minlength=len(class_names)))))

    # 3. SMOTE oversampling
    logger.info("[2/5] Applying SMOTE oversampling...")
    t0 = time.time()
    X_train_resampled, y_train_resampled = apply_smote(X_train, y_train)
    logger.info("SMOTE complete in %.2fs", time.time() - t0)

    # 4. Split training into train/validation
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_resampled, y_train_resampled,
        test_size=0.15, random_state=42, stratify=y_train_resampled,
    )
    logger.info("Train: %d, Validation: %d, Test: %d", len(X_tr), len(X_val), len(X_test))

    # 5. Train all models
    logger.info("[3/5] Training models...")
    trained_models = train_all_models(X_tr, y_tr, X_val, y_val, mode=mode)

    # 6. Evaluate
    logger.info("[4/5] Evaluating models...")
    results = {}
    models_for_roc = {}

    for model_name, (model, training_time) in trained_models.items():
        metrics = evaluate_model(model, X_test, y_test, model_name, mode=mode)
        metrics["training_time"] = round(training_time, 2)
        results[model_name] = metrics

        # Get predictions for confusion matrix
        if hasattr(model, "predict"):
            if hasattr(model, "predict_proba"):
                y_pred = model.predict(X_test)
            else:
                X_input = X_test.reshape(-1, 1, X_test.shape[1])
                y_pred = np.argmax(model.predict(X_input, verbose=0), axis=1)

            # Save confusion matrix
            cm_path = PLOTS_DIR / f"confusion_matrix_{model_name.lower().replace(' ', '_')}_{mode}.png"
            plot_confusion_matrix(y_test, y_pred, class_names, model_name, cm_path)

        models_for_roc[model_name] = model

    # 7. ROC curves
    logger.info("[5/5] Generating plots and report...")
    roc_path = PLOTS_DIR / f"roc_curves_{mode}.png"
    plot_roc_curves(models_for_roc, X_test, y_test, roc_path, mode=mode)

    # Feature importance from XGBoost
    if "XGBoost" in trained_models:
        xgb_model = trained_models["XGBoost"][0]
        fi_path = PLOTS_DIR / f"feature_importance_{mode}.png"
        plot_feature_importance(xgb_model, feature_names, fi_path, top_n=20)

    return results


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NetShield IDS — Train ML Models on NSL-KDD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["binary", "multi", "all"],
        default="all",
        help="Training mode: binary, multi, or all (default: all)",
    )
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    total_start = time.time()
    all_results = {}

    modes = ["binary", "multi"] if args.mode == "all" else [args.mode]

    for mode in modes:
        results = run_training(mode)
        all_results[mode] = results

    # Generate consolidated report
    # Flatten for dashboard: the dashboard expects {model_name: metrics}
    # Use multi-class results as the primary display
    dashboard_metrics = {}
    primary = all_results.get("multi", all_results.get("binary", {}))
    for model_name, metrics in primary.items():
        dashboard_metrics[model_name] = metrics

    generate_comparison_report(dashboard_metrics)

    total_time = time.time() - total_start
    logger.info("=" * 60)
    logger.info("All training complete in %.2f seconds", total_time)
    logger.info("=" * 60)

    # Print summary table
    print("\n" + "=" * 70)
    print(f"{'Model':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Time':>10}")
    print("-" * 70)
    for model_name, metrics in dashboard_metrics.items():
        print(
            f"{model_name:<20} "
            f"{metrics['accuracy']:>10.4f} "
            f"{metrics['precision']:>10.4f} "
            f"{metrics['recall']:>10.4f} "
            f"{metrics['f1_score']:>10.4f} "
            f"{metrics['training_time']:>9.1f}s"
        )
    print("=" * 70)


if __name__ == "__main__":
    main()
