"""
Unit tests for data preprocessing and leakage prevention.
"""

import numpy as np
import pandas as pd
import pytest
from pathlib import Path

from intrusion_xai.data.preprocess import (
    NetworkDataPreprocessor,
    encode_labels,
    prepare_data,
)

def test_preprocessor_cleans_infinities_and_nans():
    """Verify that infinite values and NaNs are completely cleaned."""
    X_train = pd.DataFrame({
        "Flow Duration": [100.0, np.inf, 300.0, 400.0, 500.0],
        "Flow Bytes/s": [-np.inf, 20.0, np.nan, 40.0, 50.0],
        "Packet Count": [1.0, 2.0, 3.0, 4.0, 5.0],
    })

    preprocessor = NetworkDataPreprocessor(drop_constant_features=False)
    X_trans = preprocessor.fit_transform(X_train)

    assert not np.isinf(X_trans.values).any(), "Transformed data must not contain infinities."
    assert not np.isnan(X_trans.values).any(), "Transformed data must not contain NaNs."
    assert list(X_trans.columns) == ["Flow Duration", "Flow Bytes/s", "Packet Count"]

def test_preprocessor_removes_constant_features():
    """Verify zero-variance features are automatically detected and dropped."""
    X = pd.DataFrame({
        "Dynamic Feature": [1.0, 2.0, 3.0, 4.0, 5.0],
        "Zero Variance": [0.0, 0.0, 0.0, 0.0, 0.0],
        "All Same String": [7.0, 7.0, 7.0, 7.0, 7.0],
    })

    preprocessor = NetworkDataPreprocessor(drop_constant_features=True)
    X_trans = preprocessor.fit_transform(X)

    assert "Dynamic Feature" in X_trans.columns
    assert "Zero Variance" not in X_trans.columns
    assert "All Same String" not in X_trans.columns
    assert len(preprocessor.constant_columns_) == 2

def test_preprocessor_leakage_isolation():
    """Verify preprocessor fit parameters depend strictly on training data."""
    X_train = pd.DataFrame({
        "Feature A": [10.0, 20.0, 30.0],
    })
    X_test = pd.DataFrame({
        "Feature A": [1000.0, 2000.0, 3000.0],  # Outliers in test set
    })

    preprocessor = NetworkDataPreprocessor()
    preprocessor.fit(X_train)

    # Imputer median should be 20.0 (from X_train), completely ignoring X_test
    assert preprocessor.imputer_.statistics_[0] == 20.0

def test_encode_labels_binary_and_multiclass():
    """Verify binary and multiclass label encodings."""
    labels = pd.Series(["BENIGN", "PortScan", "DDoS", "BENIGN"])

    # Binary: BENIGN -> 0, Attacks -> 1
    y_bin, map_bin = encode_labels(labels, binary=True)
    assert y_bin.tolist() == [0, 1, 1, 0]
    assert map_bin["BENIGN"] == 0
    assert map_bin["PortScan"] == 1
    assert map_bin["DDoS"] == 1

    # Multiclass: distinct integer IDs
    y_multi, map_multi = encode_labels(labels, binary=False)
    assert y_multi.tolist() == [0, 2, 1, 0]  # Alphabetical: BENIGN=0, DDoS=1, PortScan=2
    assert map_multi["BENIGN"] == 0

def test_preprocessor_serialization(tmp_path: Path):
    """Verify preprocessor can be saved and loaded with identical transform results."""
    X = pd.DataFrame({
        "Feature A": [1.0, 2.0, 3.0, 4.0],
        "Feature B": [10.0, 20.0, 30.0, 40.0],
    })

    preprocessor = NetworkDataPreprocessor()
    X_trans1 = preprocessor.fit_transform(X)

    save_path = tmp_path / "test_prep.joblib"
    preprocessor.save(save_path)

    loaded_prep = NetworkDataPreprocessor.load(save_path)
    X_trans2 = loaded_prep.transform(X)

    pd.testing.assert_frame_equal(X_trans1, X_trans2)

def test_prepare_data_end_to_end(tmp_path: Path):
    """Verify end-to-end data preparation with train/test splits."""
    df = pd.DataFrame({
        "Feature 1": np.arange(20, dtype=float),
        "Feature 2": np.arange(20, dtype=float) * 2,
        "Constant Col": [0.0] * 20,
        "Label": ["BENIGN"] * 10 + ["PortScan"] * 10,
    })

    X_train, X_test, y_train, y_test, prep = prepare_data(
        df,
        target_column="Label",
        test_size=0.25,
        random_state=42,
        binary=True,
        save_artifacts=False,
    )

    assert len(X_train) == 15
    assert len(X_test) == 5
    assert "Constant Col" not in X_train.columns
    assert y_train.value_counts().to_dict() == {0: 7, 1: 8} or y_train.value_counts().to_dict() == {1: 8, 0: 7}
    assert not np.isnan(X_train.values).any()
    assert not np.isnan(X_test.values).any()
