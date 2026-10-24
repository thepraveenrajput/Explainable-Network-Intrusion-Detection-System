"""
Global explainability (XAI) module for network intrusion detection models.

Computes Permutation Feature Importance on held-out test data and Tree SHAP global
attributions to reveal which network flow features govern the model's global decisions.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
import shap

from intrusion_xai.config import (
    PLOTS_DIR,
    PROJECT_ROOT,
    RANDOM_SEED,
    REPORTS_DIR,
)

# Set isolated cache directory for matplotlib before importing
os.environ.setdefault("MPLCONFIGDIR", str(PROJECT_ROOT / ".cache" / "matplotlib"))
import matplotlib.pyplot as plt
import seaborn as sns

def compute_permutation_importance(
    model: Any,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    n_repeats: int = 5,
    random_state: int = RANDOM_SEED,
) -> pd.DataFrame:
    """
    Compute permutation feature importance across held-out evaluation records.

    Measures the decrease in model score when individual feature columns are randomly shuffled.

    Args:
        model: Trained scikit-learn model.
        X_val: Held-out validation/test feature DataFrame.
        y_val: Ground truth labels.
        n_repeats: Number of shuffle repetitions per feature.
        random_state: Random seed for reproducibility.

    Returns:
        DataFrame sorted by mean importance descending with columns:
        ['feature', 'importance_mean', 'importance_std'].
    """
    print(f"[INFO] Computing permutation importance on {len(X_val)} samples ({n_repeats} repeats)...")
    n_workers = 1 if len(X_val) <= 1000 else -1
    perm = permutation_importance(
        model,
        X_val,
        y_val,
        n_repeats=n_repeats,
        random_state=random_state,
        n_jobs=n_workers,
        scoring="f1",
    )

    df_importance = pd.DataFrame({
        "feature": X_val.columns,
        "importance_mean": perm.importances_mean,
        "importance_std": perm.importances_std,
    }).sort_values(by="importance_mean", ascending=False).reset_index(drop=True)

    return df_importance

def compute_tree_shap_global(
    model: Any,
    X_sample: pd.DataFrame,
    max_samples: int = 200,
    random_state: int = RANDOM_SEED,
) -> Tuple[np.ndarray, pd.DataFrame]:
    """
    Compute Tree SHAP values across representative test flows.

    Args:
        model: Trained tree-based model (Decision Tree or Random Forest).
        X_sample: Input features to explain.
        max_samples: Subsample size to ensure fast execution while maintaining stability.
        random_state: Random seed.

    Returns:
        Tuple of (shap_values_array, feature_shap_summary_df).
    """
    if len(X_sample) > max_samples:
        X_eval = X_sample.sample(n=max_samples, random_state=random_state)
    else:
        X_eval = X_sample

    print(f"[INFO] Computing Tree SHAP values for {len(X_eval)} sample flows...")
    explainer = shap.TreeExplainer(model)
    shap_vals = explainer.shap_values(X_eval)

    # In binary classification, handle array shape: (n_samples, n_features, n_classes) or list
    if isinstance(shap_vals, list):
        # Class 1 (Attack) SHAP values
        vals_class1 = shap_vals[1] if len(shap_vals) > 1 else shap_vals[0]
    elif len(shap_vals.shape) == 3:
        vals_class1 = shap_vals[:, :, 1]
    else:
        vals_class1 = shap_vals

    mean_abs_shap = np.mean(np.abs(vals_class1), axis=0)

    df_shap_summary = pd.DataFrame({
        "feature": X_eval.columns,
        "mean_abs_shap": mean_abs_shap,
    }).sort_values(by="mean_abs_shap", ascending=False).reset_index(drop=True)

    return vals_class1, df_shap_summary

def plot_global_feature_importance(
    importance_df: pd.DataFrame,
    top_n: int = 15,
    title: str = "Top Global Features by Permutation Importance",
    output_path: Path = PLOTS_DIR / "global_feature_importance.png",
) -> Path:
    """
    Plot horizontal bar chart of top N features with error bars.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    top_df = importance_df.head(top_n).iloc[::-1]

    plt.figure(figsize=(9, 6))
    plt.barh(
        top_df["feature"],
        top_df["importance_mean"],
        xerr=top_df["importance_std"],
        color="#1f77b4",
        edgecolor="black",
        linewidth=0.6,
        alpha=0.85,
        capsize=3,
    )
    plt.title(title, fontsize=12, weight="bold", pad=12)
    plt.xlabel("Mean Drop in F1-Score when Feature is Shuffled", fontsize=10)
    plt.ylabel("Network Flow Feature", fontsize=10)
    plt.grid(axis="x", linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    return output_path

def plot_shap_summary_chart(
    shap_summary_df: pd.DataFrame,
    top_n: int = 15,
    title: str = "Top Network Features by Mean Absolute SHAP Value",
    output_path: Path = PLOTS_DIR / "shap_summary_plot.png",
) -> Path:
    """
    Plot top features by mean absolute SHAP value impact.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    top_df = shap_summary_df.head(top_n).iloc[::-1]

    plt.figure(figsize=(9, 6))
    plt.barh(
        top_df["feature"],
        top_df["mean_abs_shap"],
        color="#d62728",
        edgecolor="black",
        linewidth=0.6,
        alpha=0.85,
    )
    plt.title(title, fontsize=12, weight="bold", pad=12)
    plt.xlabel("Mean |SHAP Value| (Impact on Attack Classification)", fontsize=10)
    plt.ylabel("Network Flow Feature", fontsize=10)
    plt.grid(axis="x", linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    return output_path

def run_global_explanations(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    output_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """
    Execute both permutation importance and SHAP global analysis.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Permutation Importance
    perm_df = compute_permutation_importance(model, X_test, y_test, n_repeats=5)
    perm_plot = plot_global_feature_importance(perm_df)

    # 2. SHAP Global Analysis
    shap_vals, shap_df = compute_tree_shap_global(model, X_test, max_samples=200)
    shap_plot = plot_shap_summary_chart(shap_df)

    # 3. Export JSON report
    report_data = {
        "top_permutation_features": perm_df.head(10).to_dict(orient="records"),
        "top_shap_features": shap_df.head(10).to_dict(orient="records"),
        "plots": [str(perm_plot.name), str(shap_plot.name)],
    }

    report_path = output_dir / "global_explanations.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"[SUCCESS] Global explanations computed and exported to:\n  {report_path}")
    return report_data
