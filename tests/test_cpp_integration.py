"""
Unit tests for C++17 inference engine integration and prediction parity.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from intrusion_xai.config import CPP_TREE_MODEL_PATH, DATA_PROCESSED_DIR, TARGET_COLUMN
from intrusion_xai.integration.cpp_bridge import (
    get_cpp_engine_binary,
    predict_single_cpp,
    verify_python_cpp_parity,
)
from intrusion_xai.ml.predict import load_trained_model

def test_cpp_binary_build():
    """Verify C++ engine binary exists or builds successfully."""
    bin_path = get_cpp_engine_binary()
    assert bin_path.exists()
    assert bin_path.stat().st_size > 1000

def test_cpp_predict_single_valid():
    """Verify single-vector inference returns valid prediction and threat score."""
    test_df = pd.read_csv(DATA_PROCESSED_DIR / "test.csv", nrows=1)
    X_sample = test_df.drop(columns=[TARGET_COLUMN]).iloc[0].values

    res = predict_single_cpp(X_sample, model_path=CPP_TREE_MODEL_PATH)

    assert res["status"] == "success"
    assert res["predicted_class"] in [0, 1]
    assert 0.0 <= res["threat_score"] <= 1.0
    assert len(res["probabilities"]) == 2
    assert np.isclose(sum(res["probabilities"]), 1.0)
    assert res["leaf_node"] >= 0

def test_cpp_validation_feature_count_mismatch():
    """Verify C++ engine raises ValueError when input feature count is wrong."""
    malformed_features = [1.0, 2.0, 3.0]  # Only 3 features, expected 66

    with pytest.raises(ValueError) as exc_info:
        predict_single_cpp(malformed_features, model_path=CPP_TREE_MODEL_PATH)

    assert "Feature count mismatch" in str(exc_info.value)

def test_cpp_validation_nan_rejected():
    """Verify C++ engine raises ValueError when input contains NaN."""
    test_df = pd.read_csv(DATA_PROCESSED_DIR / "test.csv", nrows=1)
    X_sample = list(test_df.drop(columns=[TARGET_COLUMN]).iloc[0].values)
    X_sample[0] = float("nan")

    with pytest.raises(ValueError) as exc_info:
        predict_single_cpp(X_sample, model_path=CPP_TREE_MODEL_PATH)

    assert "NaN" in str(exc_info.value)

def test_python_cpp_parity_verification():
    """Verify 100% parity between Python scikit-learn and C++17 native predictions."""
    test_df = pd.read_csv(DATA_PROCESSED_DIR / "test.csv", nrows=50)
    X_test = test_df.drop(columns=[TARGET_COLUMN])

    py_model = load_trained_model("decision_tree")
    report = verify_python_cpp_parity(X_test, py_model, max_samples=50)

    assert report["samples_tested"] == 50
    assert report["mismatches_count"] == 0
    assert report["parity_percentage"] == 100.0
    assert report["is_parity_achieved"] is True
