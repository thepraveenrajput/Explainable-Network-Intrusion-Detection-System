"""
Exploratory Data Analysis (EDA) module for network intrusion flow records.

Inspects raw and preprocessed datasets, documents distributions, identifies
data quality quirks (inf/NaN/constant features), and generates visualization charts.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from intrusion_xai.config import PLOTS_DIR, REPORTS_DIR, TARGET_COLUMN
from intrusion_xai.data.load_data import load_raw_data, validate_schema

def run_exploratory_data_analysis(
    file_path: Optional[Path | str] = None,
    output_plots_dir: Path = PLOTS_DIR,
    output_reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """
    Execute end-to-end exploratory data analysis on a raw or sampled dataset.

    Args:
        file_path: Optional path to dataset CSV. Defaults to sample in data/raw/.
        output_plots_dir: Directory to save generated plot images.
        output_reports_dir: Directory to save analysis reports.

    Returns:
        Structured dictionary summarizing EDA findings.
    """
    output_plots_dir.mkdir(parents=True, exist_ok=True)
    output_reports_dir.mkdir(parents=True, exist_ok=True)

    print("[INFO] Loading dataset for EDA...")
    df = load_raw_data(file_path=file_path)
    schema_info = validate_schema(df, target_col=TARGET_COLUMN)

    target = TARGET_COLUMN if TARGET_COLUMN in df.columns else df.columns[-1]

    # Style configuration for publication-ready plots
    sns.set_theme(style="whitegrid", palette="muted")
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"

    # 1. Class Distribution Chart
    print("[INFO] Generating class distribution plot...")
    plt.figure(figsize=(8, 5))
    class_counts = df[target].value_counts()
    ax = sns.barplot(x=class_counts.index, y=class_counts.values, hue=class_counts.index, palette="viridis", legend=False)
    plt.title("CIC-IDS2017 Class Distribution (Traffic Flow Types)", fontsize=13, weight="bold", pad=12)
    plt.xlabel("Traffic Classification Label", fontsize=11, labelpad=8)
    plt.ylabel("Number of Flow Records", fontsize=11, labelpad=8)
    for p in ax.patches:
        height = p.get_height()
        ax.annotate(
            f"{int(height):,} ({height / len(df) * 100:.1f}%)",
            (p.get_x() + p.get_width() / 2.0, height),
            ha="center",
            va="bottom",
            fontsize=9,
            xytext=(0, 4),
            textcoords="offset points",
        )
    plt.tight_layout()
    class_plot_path = output_plots_dir / "class_distribution.png"
    plt.savefig(class_plot_path, dpi=300)
    plt.close()

    # 2. Flow Duration Distribution (Log Scale)
    if "Flow Duration" in df.columns:
        print("[INFO] Generating Flow Duration distribution plot...")
        plt.figure(figsize=(8, 5))
        # Add 1 to handle zero durations safely before taking log
        durations = df["Flow Duration"].dropna().clip(lower=0) + 1
        sns.histplot(np.log10(durations), bins=50, kde=True, color="#2b5c8f")
        plt.title("Distribution of Network Flow Duration (Log10 Microseconds)", fontsize=13, weight="bold", pad=12)
        plt.xlabel("Log10(Flow Duration + 1 µs)", fontsize=11, labelpad=8)
        plt.ylabel("Record Count", fontsize=11, labelpad=8)
        plt.tight_layout()
        duration_plot_path = output_plots_dir / "flow_duration_distribution.png"
        plt.savefig(duration_plot_path, dpi=300)
        plt.close()

    # 3. Numeric Feature Correlation Heatmap (Top Varied Features)
    numeric_df = df.select_dtypes(include=[np.number])
    # Replace infinities temporarily for correlation computation
    numeric_df_clean = numeric_df.replace([np.inf, -np.inf], np.nan).dropna(axis=1, how="all")
    variances = numeric_df_clean.var().sort_values(ascending=False)
    top_feature_names = [f for f in variances.index if f not in ["Flow ID"]][:12]

    if len(top_feature_names) >= 2:
        print("[INFO] Generating correlation heatmap for top features...")
        plt.figure(figsize=(10, 8))
        corr_matrix = numeric_df_clean[top_feature_names].corr()
        mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
        sns.heatmap(
            corr_matrix,
            mask=mask,
            cmap="vlag",
            vmax=1.0,
            vmin=-1.0,
            center=0,
            annot=True,
            fmt=".2f",
            square=True,
            linewidths=0.5,
            cbar_kws={"shrink": 0.8},
        )
        plt.title("Correlation Matrix of Key Network Flow Features", fontsize=13, weight="bold", pad=12)
        plt.xticks(rotation=45, ha="right", fontsize=9)
        plt.yticks(fontsize=9)
        plt.tight_layout()
        corr_plot_path = output_plots_dir / "top_features_correlation.png"
        plt.savefig(corr_plot_path, dpi=300)
        plt.close()

    # 4. Save Structured JSON Report
    report_data = {
        "dataset_rows": schema_info["row_count"],
        "dataset_columns": schema_info["col_count"],
        "target_column": target,
        "class_distribution": schema_info["label_distribution"],
        "missing_values_count": schema_info["total_missing_cells"],
        "missing_features": schema_info["missing_values"],
        "infinite_values_count": schema_info["total_infinite_cells"],
        "infinite_features": schema_info["infinite_values"],
        "duplicate_rows": schema_info["duplicate_rows"],
        "constant_columns": schema_info["constant_columns"],
        "plots_generated": [
            str(class_plot_path.name),
            str(duration_plot_path.name) if "Flow Duration" in df.columns else None,
            str(corr_plot_path.name) if len(top_feature_names) >= 2 else None,
        ],
    }

    report_json_path = output_reports_dir / "eda_summary.json"
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # 5. Save Human-Readable Markdown Report
    report_md_path = output_reports_dir / "eda_report.md"
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# Exploratory Data Analysis Report — CIC-IDS2017\n\n")
        f.write(f"- **Total Flow Records**: {schema_info['row_count']:,}\n")
        f.write(f"- **Total Features**: {schema_info['col_count']}\n")
        f.write(f"- **Target Column**: `{target}`\n\n")
        f.write("## Class Distribution\n")
        for cls, count in schema_info["label_distribution"].items():
            f.write(f"- **{cls}**: {count:,} ({count / schema_info['row_count'] * 100:.2f}%)\n")
        f.write("\n## Data Quality Audit\n")
        f.write(f"- **Missing Value Cells (NaN)**: {schema_info['total_missing_cells']:,}\n")
        f.write(f"- **Infinite Value Cells (Inf)**: {schema_info['total_infinite_cells']:,}\n")
        f.write(f"- **Duplicate Rows**: {schema_info['duplicate_rows']:,}\n")
        if schema_info["constant_columns"]:
            f.write(f"- **Zero-Variance (Constant) Columns**: {schema_info['constant_columns']}\n")
        f.write("\n## Generated Visualizations\n")
        f.write(f"- Class Distribution: `outputs/plots/{class_plot_path.name}`\n")
        if "Flow Duration" in df.columns:
            f.write(f"- Flow Duration Distribution: `outputs/plots/{duration_plot_path.name}`\n")
        if len(top_feature_names) >= 2:
            f.write(f"- Feature Correlation Matrix: `outputs/plots/{corr_plot_path.name}`\n")

    print(f"[SUCCESS] EDA completed! Reports saved to:\n  {report_json_path}\n  {report_md_path}")
    return report_data

if __name__ == "__main__":
    run_exploratory_data_analysis()
