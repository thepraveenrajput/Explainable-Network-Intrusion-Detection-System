# System Architecture — Intrusion XAI Framework

## 1. High-Level System Architecture

The Intrusion XAI framework consists of five core tiers:

```
[ CIC-IDS2017 Benchmark Flow Records (CSV) ]
                    │
                    ▼
┌────────────────────────────────────────────────────────┐
│  Tier 1: Ingestion & Preprocessing Pipeline (Python)  │
│  - Strict schema validation & feature sanitization     │
│  - Non-finite (NaN / Inf) detection and cleaning       │
│  - Categorical & numerical encoding pipeline (sklearn) │
│  - Leakage-free train / validation / test splits       │
└────────────────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────────┐
│  Tier 2: Model Training & Persistence (Python)         │
│  - Decision Tree Classifier (transparent baseline)    │
│  - Random Forest Classifier (ensemble benchmark)       │
│  - Logistic Regression (linear baseline)               │
│  - Serialization: .joblib (Python) + JSON tree rules   │
└────────────────────────────────────────────────────────┘
         │                                    │
         ▼                                    ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│ Tier 3: Explainable AI (XAI)    │   │ Tier 4: Native Inference (C++17)│
│ - Global: Permutation & SHAP    │   │ - High-performance CLI engine   │
│ - Local: Single-record flow     │   │ - Memory-safe feature vector    │
│   attribution & threshold radar │   │ - JSON tree traversal parity    │
└─────────────────────────────────┘   └─────────────────────────────────┘
         │                                    │
         └──────────────────┬─────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│  Tier 5: Presentation & SOC Analyst Dashboard         │
│  - Streamlit multi-page reactive application           │
│  - Interactive Plotly distributions & confusion matrix │
│  - Risk breakdown and exportable threat reports (CSV)  │
└────────────────────────────────────────────────────────┘
```

## 2. Component Descriptions

### Ingestion & Preprocessing (`intrusion_xai.data`)
- **`load_data.py`**: Loads raw CSV flow files, strips leading/trailing whitespaces in column names (a known quirk of the CIC-IDS2017 dataset), and validates presence of required columns.
- **`preprocess.py`**: Drops non-generalizable network identifiers (Flow ID, Source IP, Destination IP, Timestamp) to prevent memorization/overfitting. Replaces `+inf` and `-inf` with feature maximums or median thresholds, handles missing values via `SimpleImputer`, and fits a `StandardScaler` strictly on training data.

### Machine Learning Engine (`intrusion_xai.ml`)
- **`train.py`**: Orchestrates stratified splitting (`random_state=42`) and model training. Saves model artifacts and preprocessors to `models/`.
- **`predict.py`**: Ingests new network flow records, transforms them via the fitted preprocessor, and returns predicted classes along with prediction probabilities.
- **`evaluate.py`**: Generates exhaustive classification metrics: Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), False Negative Rate (FNR), and Confusion Matrix heatmaps.

### Explainability Engine (`intrusion_xai.explainability`)
- **`global_explanations.py`**: Computes permutation importance across held-out test data and summarizes SHAP values.
- **`local_explanations.py`**: Generates waterfall / breakdown attribution for individual alerts, explaining *why* a specific flow was flagged as malicious.

### C++17 Native Inference Engine (`cpp/`)
- Compiled with Apple Clang and CMake 3.16+ using modern C++17.
- Operates offline with zero external network or Python runtime dependencies.
- Consumes exported tree rules and validates numeric feature ranges, providing deterministic inference with microsecond latency.

### SOC Analyst Web Dashboard (`app.py`, `intrusion_xai.dashboard`)
- Built with Streamlit and Plotly.
- Pages: Home, Dataset Explorer, Intrusion Detection, Explainability, Model Evaluation, and About/Documentation.
