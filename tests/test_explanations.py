"""
Unit tests for explainable AI (XAI) global and local attribution modules.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

from intrusion_xai.explainability.global_explanations import (
    compute_permutation_importance,
    compute_tree_shap_global,
    plot_global_feature_importance,
)
from intrusion_xai.explainability.local_explanations import (
    explain_local_prediction,
    plot_local_attribution_waterfall,
)

@pytest.fixture
def trained_toy_tree():
    np.random.seed(42)
    X = pd.DataFrame({
        "Flow_Duration": [10.0, 20.0, 500.0, 600.0, 700.0],
        "Flow_Bytes_per_s": [0.0, 0.0, 50.0, 80.0, 100.0],
        "Packet_Count": [1.0, 1.0, 15.0, 20.0, 25.0],
    })
    y = pd.Series([1, 1, 0, 0, 0])  # Short duration + 0 bytes = attack
    clf = DecisionTreeClassifier(max_depth=3, random_state=42)
    clf.fit(X, y)
    return clf, X, y

def test_permutation_importance_structure(trained_toy_tree):
    """Verify permutation importance returns valid columns, shapes, and finite numbers."""
    clf, X, y = trained_toy_tree
    df_perm = compute_permutation_importance(clf, X, y, n_repeats=3)

    assert isinstance(df_perm, pd.DataFrame)
    assert set(df_perm.columns) == {"feature", "importance_mean", "importance_std"}
    assert len(df_perm) == X.shape[1]
    assert not np.isnan(df_perm["importance_mean"].values).any()
    assert (df_perm["importance_std"] >= 0.0).all()

def test_tree_shap_global(trained_toy_tree):
    """Verify global Tree SHAP returns valid value matrices and ranked features."""
    clf, X, _ = trained_toy_tree
    shap_vals, df_shap = compute_tree_shap_global(clf, X, max_samples=5)

    assert shap_vals.shape[0] == len(X)
    assert shap_vals.shape[1] == X.shape[1]
    assert len(df_shap) == X.shape[1]
    assert "mean_abs_shap" in df_shap.columns
    assert (df_shap["mean_abs_shap"] >= 0.0).all()

def test_explain_local_prediction(trained_toy_tree):
    """Verify single-record local explanation returns threat scores and cyber explanations."""
    clf, X, _ = trained_toy_tree
    rec = X.iloc[0].to_dict()

    exp = explain_local_prediction(clf, rec, top_k=2)

    assert "predicted_class" in exp
    assert exp["predicted_class"] in [0, 1]
    assert "threat_score" in exp
    assert 0.0 <= exp["threat_score"] <= 1.0
    assert "supporting_features" in exp
    assert "opposing_features" in exp
    assert "disclaimer" in exp
    assert len(exp["supporting_features"]) <= 2
    if exp["supporting_features"]:
        feat_item = exp["supporting_features"][0]
        assert "feature" in feat_item
        assert "shap_value" in feat_item
        assert "cyber_meaning" in feat_item

def test_plot_local_attribution_waterfall(trained_toy_tree, tmp_path: Path):
    """Verify local waterfall plot creates valid image file."""
    clf, X, _ = trained_toy_tree
    exp = explain_local_prediction(clf, X.iloc[0], top_k=2)

    img_path = tmp_path / "waterfall_test.png"
    result_path = plot_local_attribution_waterfall(exp, output_path=img_path)

    assert result_path.exists()
    assert result_path.stat().st_size > 1000
