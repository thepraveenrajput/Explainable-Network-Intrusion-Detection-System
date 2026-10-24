"""
Local explainability (XAI) module for per-record threat attribution.

Explains individual flow predictions using Tree SHAP feature contributions,
identifies features supporting and opposing alerts, provides plain-language
cybersecurity interpretations, and plots contribution waterfall charts.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd
import shap

from intrusion_xai.config import (
    BENIGN_LABEL,
    PLOTS_DIR,
    PROJECT_ROOT,
)

# Set isolated cache directory for matplotlib before importing
os.environ.setdefault("MPLCONFIGDIR", str(PROJECT_ROOT / ".cache" / "matplotlib"))
import matplotlib.pyplot as plt

# Domain lexicon mapping technical network flow features to plain-language meanings
CYBERSECURITY_FEATURE_LEXICON = {
    "Destination Port": (
        "Target service port. Connections to non-standard or sequential high ports "
        "strongly indicate reconnaissance sweeps probing for open listening services."
    ),
    "Flow Duration": (
        "Total duration of communication in microseconds. Extremely short flows "
        "(< 10 µs) with no session payload typically represent automated port probes."
    ),
    "Total Fwd Packets": (
        "Packets transmitted from source to target. Scanners typically send 1–2 SYN packets "
        "per port without completing data transactions."
    ),
    "Total Backward Packets": (
        "Response packets from target to source. Zero response packets indicates filtered, "
        "closed, or rejected connection attempts."
    ),
    "Flow Bytes/s": (
        "Data transmission rate. Zero bytes transferred with active packets indicates "
        "TCP control scanning rather than actual user traffic."
    ),
    "Flow Packets/s": (
        "Packet frequency. Abnormally elevated packet rates in short bursts are characteristic "
        "of high-speed automated port scanners (e.g. Nmap / Masscan)."
    ),
    "Flow IAT Mean": (
        "Mean inter-arrival time between packets. Automated script attacks exhibit "
        "rigid, low-variance timings distinctly different from human browsing patterns."
    ),
    "Bwd Packet Length Mean": (
        "Average response packet size. Near-zero values indicate RST/ACK rejection packets "
        "rather than meaningful HTTP/HTTPS server responses."
    ),
    "Fwd Packet Length Max": (
        "Maximum packet size from client. Small maximum packet sizes (e.g. 0–60 bytes) "
        "indicate header-only TCP SYN packets with no application-layer payload."
    ),
    "FIN Flag Count": (
        "TCP FIN teardown flags. Used in stealth port scans (FIN scanning) to probe "
        "firewall behavior on closed versus open ports."
    ),
    "SYN Flag Count": (
        "TCP connection initiation flags. High SYN ratios without subsequent data transfer "
        "indicate half-open SYN flood or stealth port scanning."
    ),
    "RST Flag Count": (
        "TCP connection reset flags. Frequently returned by operating systems when "
        "an incoming probe attempts to connect to a non-listening closed port."
    ),
}

DEFAULT_FEATURE_DESCRIPTION = (
    "Network flow timing or statistical variance metric reflecting packet cadence "
    "and transmission characteristics."
)

def explain_local_prediction(
    model: Any,
    record: Union[pd.Series, pd.DataFrame, Dict[str, Any]],
    top_k: int = 5,
    attack_label: str = "MALICIOUS",
) -> Dict[str, Any]:
    """
    Explain a single record's classification decision using Tree SHAP.

    Args:
        model: Trained tree-based model (Decision Tree or Random Forest).
        record: Single flow record as Series, 1-row DataFrame, or dictionary.
        top_k: Number of top supporting and opposing features to extract.
        attack_label: Label name for malicious classifications.

    Returns:
        Structured explanation dictionary with supporting/opposing features,
        base value, predicted probability, and plain-language reasoning.
    """
    if isinstance(record, dict):
        df_row = pd.DataFrame([record])
    elif isinstance(record, pd.Series):
        df_row = pd.DataFrame([record.to_dict()])
    elif isinstance(record, pd.DataFrame):
        df_row = record.head(1).copy()
    else:
        raise TypeError("record must be a dict, Series, or 1-row DataFrame.")

    # Drop target column if present
    if "Label" in df_row.columns:
        df_row = df_row.drop(columns=["Label"])
    if "predicted_class" in df_row.columns:
        df_row = df_row.drop(columns=["predicted_class", "predicted_label", "threat_score", "confidence"], errors="ignore")

    # Generate prediction and probability
    pred_class = int(model.predict(df_row)[0])
    pred_label = attack_label if pred_class == 1 else BENIGN_LABEL

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(df_row)[0]
        threat_score = float(probs[1]) if len(probs) > 1 else float(probs[0])
        confidence = float(np.max(probs))
    else:
        threat_score = float(pred_class)
        confidence = 1.0

    # Compute SHAP explanation
    explainer = shap.TreeExplainer(model)
    shap_output = explainer(df_row)

    # Base expected value
    base_val = explainer.expected_value
    if isinstance(base_val, (list, np.ndarray)):
        base_value = float(base_val[1]) if len(base_val) > 1 else float(base_val[0])
    else:
        base_value = float(base_val)

    # SHAP values for class 1 (Attack)
    raw_shap = shap_output.values[0]
    if len(raw_shap.shape) == 2 and raw_shap.shape[1] > 1:
        shap_vector = raw_shap[:, 1]
    else:
        shap_vector = raw_shap.flatten()

    feature_names = list(df_row.columns)
    feature_values = df_row.iloc[0].values

    # Pair features with contributions
    contributions = []
    for name, val, sh in zip(feature_names, feature_values, shap_vector):
        contributions.append({
            "feature": name,
            "value": float(val) if not np.isnan(val) else 0.0,
            "shap_value": float(sh),
            "abs_shap": float(abs(sh)),
            "cyber_meaning": CYBERSECURITY_FEATURE_LEXICON.get(name, DEFAULT_FEATURE_DESCRIPTION),
        })

    # Sort into supporting (positive SHAP pushing toward attack) and opposing (negative SHAP pushing toward benign)
    supporting = sorted([c for c in contributions if c["shap_value"] > 0], key=lambda x: x["shap_value"], reverse=True)[:top_k]
    opposing = sorted([c for c in contributions if c["shap_value"] < 0], key=lambda x: x["shap_value"])[:top_k]

    return {
        "predicted_class": pred_class,
        "predicted_label": pred_label,
        "threat_score": np.round(threat_score, 4),
        "confidence": np.round(confidence, 4),
        "base_expected_value": np.round(base_value, 4),
        "supporting_features": supporting,
        "opposing_features": opposing,
        "disclaimer": (
            "Model confidence or probability is a statistical measure and not an absolute "
            "guarantee of safety. Network feature importance indicates predictive correlation "
            "rather than conclusive causal mechanism."
        ),
    }

def plot_local_attribution_waterfall(
    explanation: Dict[str, Any],
    record_index: int = 0,
    output_path: Optional[Path] = None,
) -> Path:
    """
    Generate horizontal contribution plot for a single flow prediction.
    """
    if output_path is None:
        output_path = PLOTS_DIR / f"local_explanation_record_{record_index}.png"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    items = explanation["supporting_features"] + explanation["opposing_features"]
    items = sorted(items, key=lambda x: x["shap_value"])

    features = [f"{it['feature']} ({it['value']:.2f})" for it in items]
    shap_vals = [it["shap_value"] for it in items]
    colors = ["#d62728" if v > 0 else "#1f77b4" for v in shap_vals]

    plt.figure(figsize=(9, max(4, len(items) * 0.45)))
    plt.barh(features, shap_vals, color=colors, edgecolor="black", linewidth=0.5, alpha=0.85)
    plt.axvline(0, color="gray", linestyle="--", linewidth=0.8)

    title_str = (
        f"Local Threat Attribution: Predicted {explanation['predicted_label']} "
        f"(Score: {explanation['threat_score']:.2%})"
    )
    plt.title(title_str, fontsize=12, weight="bold", pad=12)
    plt.xlabel("SHAP Contribution (Red: Pushes Malicious, Blue: Pushes Benign)", fontsize=10)
    plt.grid(axis="x", linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    return output_path
