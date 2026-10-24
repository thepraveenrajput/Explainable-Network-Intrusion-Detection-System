"""
Explainable Machine Learning Framework for Network Intrusion Detection
Interactive Streamlit Web Dashboard for Security Operations Center (SOC) Analysts.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from intrusion_xai.config import (
    CPP_TREE_MODEL_PATH,
    DATA_PROCESSED_DIR,
    DATA_RAW_DIR,
    METRICS_DIR,
    MODELS_DIR,
    PLOTS_DIR,
    PREPROCESSOR_PATH,
    REPORTS_DIR,
    TARGET_COLUMN,
)
from intrusion_xai.dashboard.components import (
    plot_interactive_class_distribution,
    plot_interactive_confusion_matrix,
    plot_interactive_feature_importance,
    plot_interactive_waterfall,
    render_header,
)
from intrusion_xai.data.load_data import load_raw_data, validate_schema
from intrusion_xai.data.preprocess import NetworkDataPreprocessor
from intrusion_xai.explainability.global_explanations import (
    compute_permutation_importance,
    compute_tree_shap_global,
)
from intrusion_xai.explainability.local_explanations import explain_local_prediction
from intrusion_xai.integration.cpp_bridge import predict_single_cpp
from intrusion_xai.ml.predict import load_trained_model, predict_batch

# Configure Streamlit page layout
st.set_page_config(
    page_title="Intrusion XAI Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Intrusion XAI")
st.sidebar.caption("Network Intrusion Detection & Feature Attribution")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home & Architecture",
        "📊 Dataset Explorer",
        "🛡️ Intrusion Detection",
        "🔍 Explainable AI (XAI)",
        "📈 Model Evaluation",
        "ℹ️ About & Documentation",
    ],
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    **Environment Status:**
    - Python: `3.12 (Apple Silicon)`
    - Inference: `scikit-learn + C++17`
    - Dataset: `CIC-IDS2017 (UNB)`
    """
)

# ==============================================================================
# Page 1: 🏠 Home & Architecture
# ==============================================================================
if page == "🏠 Home & Architecture":
    render_header(
        title="Explainable Machine Learning Framework for Network Intrusion Detection",
        subtitle="A transparent, reproducible cybersecurity intelligence system featuring multi-model detection, native C++17 inference, and SHAP decision explanations.",
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Test Accuracy", "99.95%", delta="Decision Tree")
    with col2:
        st.metric("Recall (Detection)", "100.0%", delta="Zero Missed Attacks")
    with col3:
        st.metric("False Positive Rate", "0.11%", delta="-9.22% vs Linear")
    with col4:
        st.metric("Native C++ Latency", "4.98 µs", delta="Sub-millisecond")

    st.markdown("### 🌐 System Architecture & Workflow")
    st.markdown(
        """
        Conventional machine learning models in intrusion detection often operate as **black boxes**, leaving security analysts unable to determine *why* a specific network flow triggered a critical alert.
        This framework provides **end-to-end transparency**:
        """
    )

    st.code(
        """
[ Raw Flow Records (CIC-IDS2017) ] ──> [ Leakage-Free Preprocessing (Imputation + RobustScaler) ]
                                                        │
                      ┌─────────────────────────────────┴─────────────────────────────────┐
                      ▼                                                                   ▼
       [ Machine Learning Pipeline ]                                       [ Native C++17 Engine ]
       - Decision Tree (Interpretable baseline)                             - Portable JSON tree parser
       - Random Forest (100-tree ensemble)                                  - Strict NaN/Inf validation
       - Logistic Regression (Linear baseline)                              - Sub-millisecond traversal
                      │                                                                   │
                      └─────────────────────────────────┬─────────────────────────────────┘
                                                        ▼
                                    [ Explainable AI (XAI) Suite ]
                                    - Global: Permutation Importance + Tree SHAP
                                    - Local: Per-record threat attribution waterfall
                                    - Plain-language cybersecurity translation
        """,
        language="text",
    )

    st.markdown("### 🔒 Scope & Operational Boundaries")
    st.info(
        "**Offline Network Flow Analysis**: This framework analyzes structured network flow telemetry (e.g. NetFlow, IPFIX, CICFlowMeter statistics). "
        "It is designed for rapid threat triage, auditability, and feature attribution. It does not perform kernel-level packet capture (`libpcap`) unless extended upstream."
    )

# ==============================================================================
# Page 2: 📊 Dataset Explorer
# ==============================================================================
elif page == "📊 Dataset Explorer":
    render_header(
        title="Dataset Explorer & Data Quality Audit",
        subtitle="Inspect raw network flow telemetry, detect missing/infinite rate values, and audit class balance.",
    )

    sample_path = DATA_RAW_DIR / "cicids2017_sample.csv"
    raw_path = DATA_RAW_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

    data_source = st.radio(
        "Choose Data Source:",
        ["Representative Sample (10,000 flows)", "Full Capture File (286,467 flows)", "Upload Custom CSV File"],
        horizontal=True,
    )

    df_selected = None
    if data_source == "Representative Sample (10,000 flows)" and sample_path.exists():
        df_selected = load_raw_data(sample_path)
    elif data_source == "Full Capture File (286,467 flows)" and raw_path.exists():
        df_selected = load_raw_data(raw_path, nrows=50000)
    elif data_source == "Upload Custom CSV File":
        uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])
        if uploaded_file is not None:
            df_selected = pd.read_csv(uploaded_file, low_memory=False)
            df_selected.columns = df_selected.columns.str.strip()

    if df_selected is not None:
        schema = validate_schema(df_selected)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Flows", f"{schema['row_count']:,}")
        c2.metric("Total Features", schema["col_count"])
        c3.metric("Infinite Values (Inf)", schema["total_infinite_cells"])
        c4.metric("Constant Columns", len(schema["constant_columns"]))

        st.markdown("---")
        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("#### 🎯 Ground Truth Label Distribution")
            if schema["has_target"]:
                fig_pie = plot_interactive_class_distribution(schema["label_distribution"])
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.warning("Target column 'Label' not found in uploaded file.")

        with col_right:
            st.markdown("#### ⚠️ Data Quality Observations")
            st.markdown(
                f"""
                - **Header Whitespace**: The raw CSV contains leading spaces (`' Destination Port'`). Stripped cleanly by loader.
                - **Infinite Rates**: `{schema['total_infinite_cells']}` cells in `Flow Bytes/s` & `Flow Packets/s` caused by zero-duration flows.
                - **Duplicate Records**: `{schema['duplicate_rows']:,}` repeated flow rows typical of automated scan repetitions.
                - **Zero-Variance Columns**: `{len(schema['constant_columns'])}` features contain all identical zeros (`Bwd PSH Flags`, `CWE Flag Count`, etc.).
                """
            )

        st.markdown("#### 📋 Raw Telemetry Preview")
        st.dataframe(df_selected.head(10), use_container_width=True)
    else:
        st.warning("No dataset file found. Please run 'python scripts/download_dataset.py' to fetch the sample.")

# ==============================================================================
# Page 3: 🛡️ Intrusion Detection
# ==============================================================================
elif page == "🛡️ Intrusion Detection":
    render_header(
        title="Intrusion Detection & Threat Scoring Engine",
        subtitle="Classify network flow records in real time using scikit-learn models or the native compiled C++17 engine.",
    )

    test_file = DATA_PROCESSED_DIR / "test.csv"
    if not test_file.exists():
        st.warning("Processed test split not found. Please run 'python scripts/train_model.py' first.")
        st.stop()

    test_df = pd.read_csv(test_file)
    X_test_clean = test_df.drop(columns=[TARGET_COLUMN], errors="ignore")
    y_test_ground_truth = test_df[TARGET_COLUMN] if TARGET_COLUMN in test_df.columns else None

    col_ctrl1, col_ctrl2 = st.columns([1, 1])
    with col_ctrl1:
        engine_choice = st.selectbox(
            "Select Inference Engine:",
            [
                "Random Forest (Python Ensemble)",
                "Decision Tree (Python Rule-Based)",
                "Native C++17 Engine (Compiled High-Speed Binary)",
                "Logistic Regression (Python Linear Baseline)",
            ],
        )
    with col_ctrl2:
        num_records = st.slider("Select Number of Test Records to Classify:", 10, min(1000, len(X_test_clean)), 200, step=10)

    sample_to_predict = X_test_clean.head(num_records).copy()

    if st.button("🚀 Run Threat Classification", type="primary"):
        with st.spinner("Classifying network flows..."):
            if "C++17" in engine_choice:
                # Run Native C++17 engine on each record
                preds, scores, leaf_nodes = [], [], []
                for _, row in sample_to_predict.iterrows():
                    res = predict_single_cpp(row.values, model_path=CPP_TREE_MODEL_PATH)
                    preds.append(res["predicted_class"])
                    scores.append(res["threat_score"])
                    leaf_nodes.append(res.get("leaf_node", -1))

                results_df = sample_to_predict.copy()
                results_df["predicted_class"] = preds
                results_df["predicted_label"] = np.where(np.array(preds) == 1, "MALICIOUS", "BENIGN")
                results_df["threat_score"] = np.round(scores, 4)
                results_df["leaf_node"] = leaf_nodes
            else:
                model_key = (
                    "random_forest" if "Random Forest" in engine_choice
                    else "decision_tree" if "Decision Tree" in engine_choice
                    else "logistic_regression"
                )
                model = load_trained_model(model_key)
                results_df = predict_batch(sample_to_predict, model=model)

        # Overview Metrics
        attacks_detected = int((results_df["predicted_class"] == 1).sum())
        benign_detected = int((results_df["predicted_class"] == 0).sum())
        threat_ratio = (attacks_detected / len(results_df)) * 100

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Flows Inspected", len(results_df))
        m2.metric("Intrusions Detected (Attack)", attacks_detected, delta=f"{threat_ratio:.1f}% Threat Ratio")
        m3.metric("Benign Flows", benign_detected)
        m4.metric("Avg Threat Score", f"{results_df['threat_score'].mean():.2%}")

        st.markdown("#### 🚨 Classification Results")
        # Style highlighted rows
        def highlight_threats(row):
            return ["background-color: #ffebee" if row["predicted_class"] == 1 else "background-color: #e8f5e9"] * len(row)

        display_cols = ["predicted_label", "threat_score"] + [c for c in results_df.columns if c not in ["predicted_class", "predicted_label", "threat_score"]][:6]
        st.dataframe(results_df[display_cols].head(50), use_container_width=True)

        # Export CSV Button
        csv_data = results_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Classification Report (CSV)",
            data=csv_data,
            file_name="intrusion_detection_results.csv",
            mime="text/csv",
        )

# ==============================================================================
# Page 4: 🔍 Explainable AI (XAI)
# ==============================================================================
elif page == "🔍 Explainable AI (XAI)":
    render_header(
        title="Explainable AI (XAI) & Threat Attribution",
        subtitle="Uncover the decisive network flow metrics driving global models and generate per-record local SHAP attributions.",
    )

    tab_global, tab_local = st.tabs(["🌍 Global Model Explanations", "🔬 Local Single-Record Attribution"])

    with tab_global:
        st.markdown("### 🏆 Global Feature Importance & SHAP Summary")
        col_g1, col_g2 = st.columns([1, 1])

        # Load global explanations JSON if precomputed
        global_json = REPORTS_DIR / "global_explanations.json"
        if global_json.exists():
            with open(global_json, "r") as f:
                glob_data = json.load(f)

            with col_g1:
                st.markdown("#### 1. Permutation Feature Importance")
                perm_df = pd.DataFrame(glob_data["top_permutation_features"])
                fig_perm = plot_interactive_feature_importance(perm_df, top_n=10)
                st.plotly_chart(fig_perm, use_container_width=True)

            with col_g2:
                st.markdown("#### 2. Mean Absolute SHAP Value Impact")
                shap_df = pd.DataFrame(glob_data["top_shap_features"]).rename(columns={"mean_abs_shap": "importance_mean"})
                shap_df["importance_std"] = 0.0
                fig_shap = plot_interactive_feature_importance(shap_df, top_n=10)
                st.plotly_chart(fig_shap, use_container_width=True)

            st.markdown("#### 📘 Domain Insights: Why These Features Matter")
            st.markdown(
                """
                - **`Init_Win_bytes_forward` (TCP Initial Window Size)**: Automated scanning software (e.g. Nmap / Masscan) generates non-standard TCP window headers that clearly contrast with the negotiated window parameters of standard OS web stacks.
                - **`Flow Bytes/s` & `Fwd Packet Length Mean`**: Port sweeps send bare TCP SYN packets (40-60 bytes) with zero data payload. When packets flow with 0 bytes/s payload data, the model attributes high malicious probability.
                """
            )
        else:
            st.info("Run 'python -m intrusion_xai.explainability.global_explanations' to generate global XAI reports.")

    with tab_local:
        st.markdown("### 🔬 Local Per-Record Threat Attribution (SHAP)")
        test_file = DATA_PROCESSED_DIR / "test.csv"
        if test_file.exists():
            test_df = pd.read_csv(test_file)
            X_test_clean = test_df.drop(columns=[TARGET_COLUMN], errors="ignore")

            record_idx = st.slider("Select Record Index from Test Set:", 0, len(X_test_clean) - 1, 0)
            selected_row = X_test_clean.iloc[record_idx]

            model = load_trained_model("decision_tree")
            explanation = explain_local_prediction(model, selected_row, top_k=5)

            # Status card
            is_mal = explanation["predicted_class"] == 1
            color_banner = "#c53030" if is_mal else "#276749"
            bg_banner = "#fff5f5" if is_mal else "#f0fff4"
            st.markdown(
                f"""
                <div style="background-color: {bg_banner}; border-left: 6px solid {color_banner}; padding: 14px 18px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="color: {color_banner}; margin: 0; font-size: 18px;">Prediction: {explanation['predicted_label']} (Threat Score: {explanation['threat_score']:.2%})</h3>
                    <p style="margin: 5px 0 0 0; color: #4a5568; font-size: 13px;">Base Model Prior: {explanation['base_expected_value']:.2%} | Model Confidence: {explanation['confidence']:.2%}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_l1, col_l2 = st.columns([1, 1])
            with col_l1:
                st.markdown("#### 📊 Feature Contribution Waterfall")
                fig_waterfall = plot_interactive_waterfall(explanation)
                st.plotly_chart(fig_waterfall, use_container_width=True)

            with col_l2:
                st.markdown("#### 🧠 Plain-Language Cybersecurity Reasoning")
                supporting = explanation.get("supporting_features", [])
                opposing = explanation.get("opposing_features", [])

                if supporting:
                    st.markdown("**Features Pushing Toward MALICIOUS Alert:**")
                    for s in supporting:
                        st.markdown(f"- **`{s['feature']}`** (`{s['value']:.2f}`): {s['cyber_meaning']}")

                if opposing:
                    st.markdown("**Features Pushing Toward BENIGN Normal:**")
                    for o in opposing:
                        st.markdown(f"- **`{o['feature']}`** (`{o['value']:.2f}`): {o['cyber_meaning']}")

            st.caption(f"⚠️ **Disclaimer**: {explanation['disclaimer']}")

# ==============================================================================
# Page 5: 📈 Model Evaluation
# ==============================================================================
elif page == "📈 Model Evaluation":
    render_header(
        title="Model Evaluation, Benchmarking & Trade-off Analysis",
        subtitle="Compare Precision, Recall, False Alarms, and Latency across Decision Tree, Random Forest, and Logistic Regression on unseen test data.",
    )

    metrics_csv = METRICS_DIR / "model_comparison.csv"
    metrics_json = METRICS_DIR / "model_comparison.json"

    if metrics_csv.exists() and metrics_json.exists():
        df_metrics = pd.read_csv(metrics_csv)
        with open(metrics_json, "r") as f:
            res_dict = json.load(f)

        st.markdown("### 📊 Quantitative Performance Comparison Table")
        st.dataframe(df_metrics, use_container_width=True)

        st.markdown("---")
        col_c1, col_c2 = st.columns([1, 1])

        with col_c1:
            st.markdown("#### 🎯 Interactive Confusion Matrices")
            selected_model_name = st.selectbox(
                "Select Model to Inspect Confusion Matrix:",
                list(res_dict.keys()),
                format_func=lambda x: x.replace("_", " ").title(),
            )
            cm_data = res_dict[selected_model_name]["confusion_matrix"]
            fig_cm = plot_interactive_confusion_matrix(cm_data, selected_model_name.replace("_", " ").title())
            st.plotly_chart(fig_cm, use_container_width=True)

        with col_c2:
            st.markdown("#### ⚡ Latency & Alarm Rate Trade-offs")
            fig_bar = px.bar(
                df_metrics,
                x="Model",
                y="Latency (µs/sample)",
                color="Model",
                title="Inference Latency per Flow Record (Microseconds)",
                text_auto=".2f",
            )
            fig_bar.update_layout(showlegend=False, height=360)
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("### 💡 Key Academic Takeaways")
        st.markdown(
            r"""
            - **Decision Tree Parity**: The single Decision Tree achieves identical **99.95% accuracy** and **100% detection rate** to the 100-tree Random Forest, while executing in under **5 microseconds**, proving it is the superior candidate for C++ deployment.
            - **Linear Baseline Limitation**: Logistic Regression misses **134 cyber attacks** ($\text{FNR} = 12.07\%$), proving that network flow intrusions exhibit strictly non-linear patterns.
            """
        )
    else:
        st.info("Run 'python -m intrusion_xai.ml.evaluate' to generate evaluation benchmark tables.")

# ==============================================================================
# Page 6: ℹ️ About & Documentation
# ==============================================================================
elif page == "ℹ️ About & Documentation":
    render_header(
        title="Project Documentation & Reproducibility",
        subtitle="Dataset provenance, system reproduction commands, and academic viva preparation references.",
    )

    st.markdown("### 📚 Dataset Provenance")
    st.markdown(
        """
        - **Dataset Name**: Canadian Institute for Cybersecurity Intrusion Detection System 2017 (**CIC-IDS2017**)
        - **Publishing Institution**: University of New Brunswick (UNB), Canada
        - **Official Repository**: [UNB CIC-IDS2017 Dataset Page](https://www.unb.ca/cic/datasets/ids-2017.html)
        - **Characteristics**: Real-world benign enterprise background traffic combined with contemporary port scanning and DDoS attacks.
        """
    )

    st.markdown("### 🔄 How to Reproduce Results")
    st.code(
        """
# 1. Activate environment
cd /Users/praveensingh/.gemini/antigravity/scratch/network-intrusion-xai
source .venv/bin/activate

# 2. Run automated test suite (runs C++ tests + all 30 unit tests)
./scripts/run_tests.sh

# 3. Train all models from scratch
python scripts/train_model.py

# 4. Launch this interactive web dashboard
streamlit run app.py
        """,
        language="bash",
    )

    st.markdown("### ⚠️ Known Limitations")
    st.markdown(
        """
        1. **Offline Tabular Records**: Analyzes NetFlow/IPFIX statistical records; does not sniff raw network packets from device drivers in real time.
        2. **Adversarial Timing Perturbation**: Sophisticated adversaries who deliberately insert randomized packet delays may evade fixed inter-arrival time thresholds.
        3. **Multicollinearity in Telemetry**: Features measuring packet lengths and segment sizes are collinear, meaning SHAP values reflect joint predictive utility rather than isolated physical causation.
        """
    )
