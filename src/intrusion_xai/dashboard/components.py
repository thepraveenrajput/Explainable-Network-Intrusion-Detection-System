"""
Reusable UI and visualization components for the Streamlit dashboard.

Provides interactive Plotly charts, metric cards, and input validation utilities.
"""

from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

def render_header(title: str, subtitle: str, badge: str = "MAJOR PROJECT"):
    """Render consistent header banner across dashboard pages."""
    st.markdown(
        f"""
        <div style="background: linear-gradient(90deg, #0e1e38 0%, #1a365d 100%); padding: 22px 28px; border-radius: 12px; margin-bottom: 25px; border-left: 6px solid #3182ce; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 26px; font-weight: 700; letter-spacing: -0.5px;">{title}</h1>
                <span style="background-color: #2b6cb0; color: #ebf8ff; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase;">{badge}</span>
            </div>
            <p style="color: #cbd5e0; margin: 8px 0 0 0; font-size: 14px;">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

def plot_interactive_class_distribution(class_distribution: Dict[str, int]) -> go.Figure:
    """Generate an interactive Plotly donut chart showing class proportions."""
    labels = list(class_distribution.keys())
    values = list(class_distribution.values())

    colors = ["#3182ce", "#e53e3e", "#dd6b20", "#38a169"]
    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.45,
                marker=dict(colors=colors[: len(labels)]),
                textinfo="label+percent",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.update_layout(
        title_text="Network Flow Label Proportions",
        title_font_size=16,
        margin=dict(t=40, b=20, l=20, r=20),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        height=350,
    )
    return fig

def plot_interactive_confusion_matrix(
    cm: List[List[int]],
    model_name: str = "Classifier",
) -> go.Figure:
    """Generate an annotated interactive heatmap for a confusion matrix."""
    z = np.array(cm)
    x = ["Predicted Benign (0)", "Predicted Attack (1)"]
    y = ["Actual Benign (0)", "Actual Attack (1)"]

    fig = go.Figure(
        data=go.Heatmap(
            z=z,
            x=x,
            y=y,
            colorscale="Blues",
            text=z,
            texttemplate="%{text}",
            textfont=dict(size=14, color="black"),
            hoverongaps=False,
        )
    )
    fig.update_layout(
        title=f"Confusion Matrix: {model_name}",
        xaxis_title="Predicted Label",
        yaxis_title="Ground Truth Label",
        height=360,
        margin=dict(t=50, b=40, l=40, r=40),
    )
    return fig

def plot_interactive_feature_importance(
    importance_df: pd.DataFrame,
    top_n: int = 15,
) -> go.Figure:
    """Generate interactive horizontal bar chart for top global features."""
    top_df = importance_df.head(top_n).iloc[::-1]

    fig = go.Figure(
        go.Bar(
            x=top_df["importance_mean"],
            y=top_df["feature"],
            orientation="h",
            marker=dict(
                color=top_df["importance_mean"],
                colorscale="Viridis",
            ),
            error_x=dict(type="data", array=top_df["importance_std"], visible=True),
            hovertext=[f"Std: ±{s:.4f}" for s in top_df["importance_std"]],
        )
    )
    fig.update_layout(
        title=f"Top {top_n} Features (Permutation Importance on Test Set)",
        xaxis_title="Mean Drop in F1-Score when Shuffled",
        yaxis_title="Network Flow Metric",
        height=450,
        margin=dict(l=150, r=20, t=50, b=40),
    )
    return fig

def plot_interactive_waterfall(local_explanation: Dict[str, Any]) -> go.Figure:
    """Generate interactive waterfall chart showing feature shifts from base to prediction."""
    supporting = local_explanation.get("supporting_features", [])
    opposing = local_explanation.get("opposing_features", [])
    all_features = supporting + opposing
    all_features = sorted(all_features, key=lambda x: x["shap_value"])

    names = [f"{it['feature']} ({it['value']:.2f})" for it in all_features]
    values = [it["shap_value"] for it in all_features]
    colors = ["#e53e3e" if v > 0 else "#3182ce" for v in values]

    fig = go.Figure(
        go.Bar(
            x=values,
            y=names,
            orientation="h",
            marker=dict(color=colors),
            hovertext=[it.get("cyber_meaning", "") for it in all_features],
        )
    )
    fig.update_layout(
        title="Local SHAP Attribution (Red: Pushes Malicious | Blue: Pushes Benign)",
        xaxis_title="SHAP Value Contribution",
        yaxis_title="Feature & Observed Value",
        height=max(350, len(all_features) * 35),
        margin=dict(l=220, r=20, t=50, b=40),
    )
    return fig
