"""
Unit tests for model prediction and threat probability calculation.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from intrusion_xai.ml.predict import predict_batch, predict_single

@pytest.fixture
def trained_toy_model():
    X = pd.DataFrame({
        "Feature_A": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        "Feature_B": [10.0, 20.0, 30.0, 40.0, 50.0, 60.0],
    })
    y = pd.Series([0, 0, 0, 1, 1, 1])
    clf = DecisionTreeClassifier(max_depth=3, random_state=42)
    clf.fit(X, y)
    return clf, X

def test_predict_batch(trained_toy_model):
    """Verify batch predictions, labels, and probability scores."""
    model, X = trained_toy_model
    results_df = predict_batch(X, model=model)

    assert "predicted_class" in results_df.columns
    assert "predicted_label" in results_df.columns
    assert "threat_score" in results_df.columns
    assert "confidence" in results_df.columns

    # Verify bounds
    assert set(results_df["predicted_class"].unique()).issubset({0, 1})
    assert (results_df["threat_score"] >= 0.0).all() and (results_df["threat_score"] <= 1.0).all()
    assert (results_df["confidence"] >= 0.5).all() and (results_df["confidence"] <= 1.0).all()
    assert results_df["predicted_label"].isin(["BENIGN", "MALICIOUS"]).all()

def test_predict_single(trained_toy_model):
    """Verify single-record inference returns structured alert dictionary."""
    model, X = trained_toy_model
    single_record = X.iloc[0].to_dict()

    res = predict_single(single_record, model=model)

    assert isinstance(res, dict)
    assert "is_threat" in res
    assert isinstance(res["is_threat"], bool)
    assert "threat_score" in res
    assert 0.0 <= res["threat_score"] <= 1.0
    assert "confidence" in res
    assert 0.5 <= res["confidence"] <= 1.0
    assert res["predicted_label"] in ["BENIGN", "MALICIOUS"]
