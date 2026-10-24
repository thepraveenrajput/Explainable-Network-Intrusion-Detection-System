"""
Unit tests for model evaluation metrics and benchmarking.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from intrusion_xai.ml.evaluate import (
    compute_classification_metrics,
    plot_evaluation_charts,
)

def test_compute_classification_metrics_perfect():
    """Verify metrics computation on perfect predictions."""
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    y_prob = np.array([0.1, 0.2, 0.9, 0.8])

    m = compute_classification_metrics(y_true, y_pred, y_prob)

    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["false_negative_rate"] == 0.0
    assert m["true_positives"] == 2
    assert m["true_negatives"] == 2
    assert m["false_positives"] == 0
    assert m["false_negatives"] == 0
    assert m["roc_auc"] == 1.0

def test_compute_classification_metrics_balanced_errors():
    """Verify confusion matrix and alarm rate calculations on known errors."""
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 0, 1])  # 1 FP, 1 FN

    m = compute_classification_metrics(y_true, y_pred)

    assert m["accuracy"] == 0.5
    assert m["true_positives"] == 1
    assert m["true_negatives"] == 1
    assert m["false_positives"] == 1
    assert m["false_negatives"] == 1
    assert m["false_positive_rate"] == 0.5
    assert m["false_negative_rate"] == 0.5
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5

def test_plot_evaluation_charts(tmp_path: Path):
    """Verify evaluation plots are properly generated to disk."""
    dummy_results = {
        "decision_tree": {
            "accuracy": 0.98,
            "precision": 0.97,
            "recall": 0.99,
            "f1_score": 0.98,
            "false_positive_rate": 0.02,
            "confusion_matrix": [[98, 2], [1, 99]],
        },
        "random_forest": {
            "accuracy": 0.99,
            "precision": 0.99,
            "recall": 0.99,
            "f1_score": 0.99,
            "false_positive_rate": 0.01,
            "confusion_matrix": [[99, 1], [1, 99]],
        },
    }

    plots = plot_evaluation_charts(dummy_results, output_plots_dir=tmp_path)

    assert len(plots) == 2
    for p in plots:
        assert p.exists()
        assert p.stat().st_size > 1000  # Non-trivial image file
