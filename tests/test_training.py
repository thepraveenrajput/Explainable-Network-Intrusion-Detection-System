"""
Unit tests for model training and tree serialization.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from intrusion_xai.ml.train import (
    export_decision_tree_to_json,
    get_default_models,
    train_models,
)

@pytest.fixture
def synthetic_training_data():
    np.random.seed(42)
    n_samples = 100
    n_features = 10
    X = pd.DataFrame(
        np.random.randn(n_samples, n_features),
        columns=[f"Feature_{i}" for i in range(n_features)],
    )
    # Simple linear decision boundary with noise
    y = pd.Series((X["Feature_0"] + X["Feature_1"] > 0).astype(int))
    return X, y

def test_get_default_models():
    """Verify default models are properly instantiated with expected names."""
    models = get_default_models()
    assert "decision_tree" in models
    assert "random_forest" in models
    assert "logistic_regression" in models

def test_train_models(synthetic_training_data, tmp_path: Path):
    """Verify training pipeline trains all models and saves artifacts."""
    X, y = synthetic_training_data
    results = train_models(
        X,
        y,
        models_dir=tmp_path,
        save_artifacts=True,
    )

    for name in ["decision_tree", "random_forest", "logistic_regression"]:
        assert name in results
        assert results[name]["training_time_sec"] >= 0.0
        model = results[name]["model"]
        assert hasattr(model, "predict")
        # Check predictions work
        preds = model.predict(X)
        assert len(preds) == len(y)

    # Check artifacts written to disk
    assert (tmp_path / "decision_tree.joblib").exists()
    assert (tmp_path / "random_forest.joblib").exists()
    assert (tmp_path / "logistic_regression.joblib").exists()

def test_export_decision_tree_to_json(tmp_path: Path):
    """Verify decision tree JSON schema export for C++ inference."""
    X = pd.DataFrame({"A": [1.0, 2.0, 3.0, 4.0], "B": [4.0, 3.0, 2.0, 1.0]})
    y = pd.Series([0, 0, 1, 1])

    clf = DecisionTreeClassifier(max_depth=3, random_state=42)
    clf.fit(X, y)

    output_path = tmp_path / "test_tree.json"
    schema = export_decision_tree_to_json(clf, feature_names=["A", "B"], output_path=output_path)

    assert output_path.exists()
    assert schema["model_type"] == "DecisionTreeClassifier"
    assert schema["node_count"] > 0
    assert len(schema["nodes"]) == schema["node_count"]
    assert "feature_name" in schema["nodes"][0]
    assert "threshold" in schema["nodes"][0]
    assert "left_child" in schema["nodes"][0]
    assert "right_child" in schema["nodes"][0]
