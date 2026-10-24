"""
End-to-end integration and edge-case robustness test suite.

Tests:
1. Missing columns handling.
2. Extra unknown columns handling.
3. Empty DataFrame / file handling.
4. Feature schema consistency across Python and C++ artifacts.
5. Full end-to-end pipeline execution from raw flow to C++ inference.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from intrusion_xai.config import (
    CPP_TREE_MODEL_PATH,
    DATA_PROCESSED_DIR,
    FEATURE_SCHEMA_PATH,
    MODELS_DIR,
    TARGET_COLUMN,
)
from intrusion_xai.data.load_data import load_raw_data, validate_schema
from intrusion_xai.data.preprocess import NetworkDataPreprocessor, prepare_data
from intrusion_xai.explainability.local_explanations import explain_local_prediction
from intrusion_xai.integration.cpp_bridge import predict_single_cpp
from intrusion_xai.ml.predict import load_trained_model, predict_batch

def test_missing_features_during_prediction():
    """Verify informative ValueError when required features are missing."""
    preprocessor = NetworkDataPreprocessor.load()
    incomplete_df = pd.DataFrame({
        "Destination Port": [80.0, 443.0],
        # Missing all remaining 65 features
    })

    with pytest.raises(ValueError) as exc_info:
        preprocessor.transform(incomplete_df)

    assert "missing required features" in str(exc_info.value).lower()

def test_extra_unknown_columns_ignored_safely():
    """Verify extraneous columns in input do not break transformation or predictions."""
    preprocessor = NetworkDataPreprocessor.load()
    test_df = pd.read_csv(DATA_PROCESSED_DIR / "test.csv", nrows=5)
    X_clean = test_df.drop(columns=[TARGET_COLUMN], errors="ignore")

    # Add extra noisy columns
    X_with_extra = X_clean.copy()
    X_with_extra["Random_Unseen_Column_1"] = 999.0
    X_with_extra["Attacker_Note"] = "exploit_attempt"

    model = load_trained_model("decision_tree")
    results = predict_batch(X_with_extra, model=model, preprocessor=preprocessor)

    assert len(results) == 5
    assert "predicted_class" in results.columns
    assert "predicted_label" in results.columns

def test_empty_dataframe_rejected():
    """Verify empty DataFrame returns error dict in validate_schema."""
    empty_df = pd.DataFrame()
    schema = validate_schema(empty_df)
    assert "error" in schema
    assert "empty" in schema["error"].lower()

def test_feature_schema_consistency_between_python_and_cpp():
    """Verify that Python preprocessor and C++ tree schema have identical feature names and order."""
    import json
    with open(FEATURE_SCHEMA_PATH, "r") as f:
        schema_json = json.load(f)

    with open(CPP_TREE_MODEL_PATH, "r") as f:
        cpp_json = json.load(f)

    py_features = schema_json["features"]
    cpp_features = cpp_json["feature_names"]

    assert len(py_features) == len(cpp_features), "Feature count must match exactly"
    assert py_features == cpp_features, "Feature order and names must match exactly across Python and C++"

def test_end_to_end_single_flow_pipeline():
    """
    Test full end-to-end integration:
    Ingest single flow -> preprocess -> model prediction -> local XAI -> C++ parity.
    """
    test_df = pd.read_csv(DATA_PROCESSED_DIR / "test.csv", nrows=1)
    X_sample = test_df.drop(columns=[TARGET_COLUMN], errors="ignore")

    model = load_trained_model("decision_tree")

    # 1. Python prediction
    py_pred_df = predict_batch(X_sample, model=model)
    py_class = int(py_pred_df["predicted_class"].iloc[0])

    # 2. Local XAI explanation
    explanation = explain_local_prediction(model, X_sample.iloc[0], top_k=3)
    assert explanation["predicted_class"] == py_class

    # 3. Native C++ prediction
    cpp_res = predict_single_cpp(X_sample.iloc[0].values, model_path=CPP_TREE_MODEL_PATH)
    assert cpp_res["predicted_class"] == py_class
