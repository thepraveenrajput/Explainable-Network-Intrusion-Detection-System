"""
Unit tests for Streamlit dashboard components and interactive chart generation.
"""

from pathlib import Path
import pandas as pd
import plotly.graph_objects as go
import pytest

from intrusion_xai.config import PROJECT_ROOT
from intrusion_xai.dashboard.components import (
    plot_interactive_class_distribution,
    plot_interactive_confusion_matrix,
    plot_interactive_feature_importance,
    plot_interactive_waterfall,
)

def test_app_file_exists():
    """Verify app.py entry point exists in project root."""
    app_path = PROJECT_ROOT / "app.py"
    assert app_path.exists()
    assert app_path.stat().st_size > 500

def test_plot_interactive_class_distribution():
    """Verify class distribution returns valid Plotly Figure."""
    dist = {"BENIGN": 4452, "PortScan": 5548}
    fig = plot_interactive_class_distribution(dist)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 1
    assert fig.data[0].type == "pie"

def test_plot_interactive_confusion_matrix():
    """Verify confusion matrix returns valid Plotly Heatmap."""
    cm = [[889, 1], [0, 1110]]
    fig = plot_interactive_confusion_matrix(cm, model_name="Test DT")
    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 1
    assert fig.data[0].type == "heatmap"

def test_plot_interactive_feature_importance():
    """Verify feature importance returns horizontal bar chart."""
    df_imp = pd.DataFrame({
        "feature": [f"Feature_{i}" for i in range(5)],
        "importance_mean": [0.5, 0.4, 0.3, 0.2, 0.1],
        "importance_std": [0.01, 0.02, 0.01, 0.01, 0.02],
    })
    fig = plot_interactive_feature_importance(df_imp, top_n=5)
    assert isinstance(fig, go.Figure)
    assert fig.data[0].type == "bar"

def test_plot_interactive_waterfall():
    """Verify local attribution waterfall returns valid horizontal bar chart."""
    local_exp = {
        "supporting_features": [
            {"feature": "Flow Bytes/s", "value": 0.0, "shap_value": 0.45, "cyber_meaning": "Test meaning"}
        ],
        "opposing_features": [
            {"feature": "Flow Duration", "value": 150.0, "shap_value": -0.12, "cyber_meaning": "Test duration"}
        ],
    }
    fig = plot_interactive_waterfall(local_exp)
    assert isinstance(fig, go.Figure)
    assert fig.data[0].type == "bar"
    assert len(fig.data[0].x) == 2
