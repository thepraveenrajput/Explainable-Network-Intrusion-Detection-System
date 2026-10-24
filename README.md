# Explainable Machine Learning Framework for Network Intrusion Detection and Feature-Based Threat Analysis

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![C++17](https://img.shields.io/badge/C++-17-00599C.svg?logo=c%2B%2B)](https://en.cppreference.com/w/cpp/17)
[![Tests 43/43 Passed](https://img.shields.io/badge/Tests-43%2F43%20Passed-brightgreen.svg)](scripts/run_tests.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Streamlit Dashboard](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B.svg)](app.py)

An end-to-end, reproducible, and explainable cybersecurity machine learning system designed to analyze network flow telemetry, detect benign versus malicious network traffic, explain model decisions with feature-level transparency (SHAP and Permutation Importance), and perform high-performance offline inference via a custom compiled C++17 engine.

---

## 📌 Project Overview

Network Intrusion Detection Systems (NIDS) are critical perimeter defenses in enterprise infrastructure. However, conventional "black-box" machine learning models often lack transparency, making it difficult for Security Operations Center (SOC) analysts to understand **why** an alert was triggered.

This major college project addresses the transparency gap through:
1. **Robust Data Pipeline**: Ingestion, validation, and leakage-free preprocessing of network flow records based on the public **CIC-IDS2017** benchmark dataset.
2. **Multi-Model Suite**: Training, evaluation, and comparison of Decision Tree, Random Forest, and Logistic Regression models with strict train/test separation ($N = 10,000$ sample records; $D = 66$ clean numerical features).
3. **Explainable AI (XAI)**:
   - **Global Explanations**: Permutation feature importance and Tree SHAP global attributions revealing macro-level detection drivers.
   - **Local Explanations**: Per-record threat attribution detailing which flow characteristics contributed to an intrusion alert, paired with plain-language cybersecurity interpretations.
4. **C++17 Native Inference Engine**: High-speed compiled C++ component with strict floating-point validation and **100.00% verified prediction parity** against scikit-learn.
5. **Interactive Web Dashboard**: Streamlit-based graphical user interface allowing security analysts to upload traffic files, inspect data quality, run dual-engine classifications, view explanations, and export CSV reports.
6. **Comprehensive Academic Documentation**: Formal report, system architecture diagrams, methodology, and viva question banks.

---

## 🛠️ Technology Stack

| Category | Technology / Library | Role in Project |
| :--- | :--- | :--- |
| **Language** | Python 3.12 / 3.11 | Core pipeline, ML training, XAI, web dashboard |
| **Language** | C++17 (Apple Clang) | High-speed native compiled decision tree engine |
| **Build System** | CMake 3.16+ | C++ engine configuration and compilation |
| **Data Processing** | pandas, NumPy | High-performance tabular data manipulation |
| **Machine Learning** | scikit-learn, joblib | Model training, cross-validation, and pipeline persistence |
| **Explainability (XAI)** | SHAP, Permutation Importance | Local and global decision attribution |
| **Visualization** | Matplotlib, Seaborn, Plotly | Confusion matrices, feature rankings, interactive plots |
| **Web Dashboard** | Streamlit | Interactive graphical user interface for SOC analysts |
| **Testing** | pytest, CTest | Automated test suites for Python and C++ modules (43 tests) |
| **Version Control** | Git, GitHub | Source code tracking and release management |

---

## 📂 Repository Structure

```text
network-intrusion-xai/
├── app.py                            # Streamlit interactive web dashboard
├── README.md                         # Project documentation and quickstart
├── requirements.txt                  # Python dependency specifications
├── pyproject.toml                    # Build metadata and tool configuration
├── .gitignore                        # Git ignore rules
├── LICENSE                           # MIT open-source license
├── data/
│   ├── raw/                          # Original unmodified dataset files (CIC-IDS2017)
│   └── processed/                    # Cleaned, validated, and preprocessed datasets
├── notebooks/
│   └── 01_dataset_exploration.ipynb  # Interactive exploratory data analysis (EDA)
├── models/                           # Serialized models (.joblib) and C++ tree schema (.json)
├── src/
│   └── intrusion_xai/
│       ├── __init__.py
│       ├── config.py                 # Centralized configuration, paths, and random seeds
│       ├── data/                     # Data ingestion, schema validation, and cleaning
│       ├── ml/                       # Model training, prediction, and metric computation
│       ├── explainability/           # Global and local XAI explanations (SHAP / Importance)
│       ├── integration/              # C++ bridge interface and prediction parity validation
│       └── dashboard/                # Streamlit UI pages and visualization components
├── cpp/
│   ├── CMakeLists.txt                # C++17 CMake build file
│   ├── include/                      # C++ header files (tree_engine.hpp, version.hpp)
│   ├── src/                          # C++ inference engine implementation (main.cpp)
│   └── tests/                        # C++ unit tests (test_engine.cpp)
├── tests/                            # Automated test suite (pytest: 40 tests)
├── outputs/
│   ├── metrics/                      # Model evaluation metrics (JSON / CSV)
│   ├── plots/                        # Generated evaluation & XAI charts (PNG / SVG)
│   └── reports/                      # Summary reports (EDA, Model Benchmark, QA Test Report)
├── docs/                             # Academic report, architecture, and viva preparation
└── scripts/
    ├── setup.sh                      # Automated environment setup script
    ├── download_dataset.py           # Dataset acquisition and sampling script
    ├── train_model.py                # Command-line model training pipeline
    └── run_tests.sh                  # Complete Python and C++ test suite runner
```

---

## 📊 Experimental Results on Held-Out Test Data

Evaluated on the held-out test split ($N = 2,000$ unseen flow records: 1,110 Attacks, 890 Benign, 66 features):

| Model | Accuracy | Precision | Recall (Detection Rate) | F1-Score | False Positive Rate (FPR) | False Negative Rate (FNR) | TP | TN | FP | FN | Latency (µs/sample) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Decision Tree** | **99.95%** | **99.91%** | **100.0%** | **0.9995** | **0.11%** | **0.00%** | 1,110 | 889 | 1 | **0** | **4.98 µs** |
| **Random Forest** | **99.95%** | **99.91%** | **100.0%** | **0.9995** | **0.11%** | **0.00%** | 1,110 | 889 | 1 | **0** | **11.51 µs** |
| **Logistic Regression** | **89.15%** | **92.16%** | **87.93%** | **0.9000** | **9.33%** | **12.07%** | 976 | 807 | 83 | **134** | **1.00 µs** |

### Key Experimental Takeaways
1. **Zero Missed Attacks on Tree Models**: Both Decision Tree and Random Forest achieved **100% Recall** on the test set, detecting all 1,110 attack flows with only 1 false alarm out of 890 benign flows ($\text{FPR} = 0.11\%$).
2. **Inadequacy of Linear Boundaries**: Logistic Regression missed **134 attacks** ($\text{FNR} = 12.07\%$) and generated **83 false alarms** ($\text{FPR} = 9.33\%$), demonstrating that network intrusions require non-linear decision boundaries.
3. **Cross-Language Parity**: The native C++17 engine achieved **100.00% identical predictions** across all 500 tested flows while executing at native compiled speed.

---

## 🔍 Explainable AI (XAI) Discoveries

Both Permutation Importance and SHAP independently converge on the core features driving intrusion detection:
- **`Init_Win_bytes_forward` (TCP Initial Window Size)**: Automated scanning software (e.g. Nmap / Masscan) generates non-standard TCP window headers that contrast with the negotiated window parameters of standard OS web stacks.
- **`Flow Bytes/s` & `Fwd Packet Length Mean`**: Port sweeps send bare TCP SYN packets (40-60 bytes) with zero data payload. When packets flow with 0 bytes/s payload data, the model attributes high malicious probability.
- **`Fwd Header Length` & `Fwd IAT Min`**: Rigid, deterministic packet inter-arrival times characteristic of machine-generated scanning scripts.

---

## 🚀 Quickstart Guide for macOS

### 1. Prerequisites
Ensure your Mac has Apple Command Line Tools and CMake installed:
```bash
xcode-select --install   # Installs Apple Clang and git
brew install cmake       # Installs CMake build system
```

### 2. Automated Setup
Clone the repository and run the setup script:
```bash
git clone <your-repository-url>
cd network-intrusion-xai
./scripts/setup.sh
```

### 3. Manual Step-by-Step Setup
```bash
# 1. Create and activate Python virtual environment
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install --no-build-isolation -e .

# 3. Build the C++17 Inference Engine
cmake -B cpp/build -S cpp
cmake --build cpp/build
```

### 4. Running the Pipeline
```bash
# Download and sample the CIC-IDS2017 dataset
python scripts/download_dataset.py

# Train models and export C++ tree schema
python scripts/train_model.py

# Run evaluation and generate benchmark reports
python -m intrusion_xai.ml.evaluate

# Launch the interactive Streamlit dashboard
streamlit run app.py
```

### 5. Running Automated Tests
Execute the full test runner (compiles C++ tests, executes CTest, and runs all 40 Pytest test cases):
```bash
./scripts/run_tests.sh
```

---

## 🔒 Scope, Limitations, and Ethical Disclosures

1. **Offline Flow Telemetry**: This framework is designed for analyzing recorded network flow records (e.g. NetFlow / IPFIX / Bro / Zeek style flow statistics). It is not a kernel-level packet sniffer and does not perform live network packet capture (`libpcap`) unless explicitly extended upstream.
2. **False Positives & Negatives**: Machine learning predictions are probabilistic, not absolute guarantees. A classification of "Benign" does not guarantee zero threat, and an "Attack" alert should be investigated by a qualified analyst.
3. **Data Privacy**: No private customer or institution data is bundled. Models are trained on public academic datasets (CIC-IDS2017).
4. **Collinearity in Telemetry**: Network features measuring packet lengths and segment sizes are collinear; importance indicates predictive correlation, not proof of causation.

---

## 📜 References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 108–116.
2. Lundberg, S. M., & Lee, S.-I. (2017). *A Unified Approach to Interpreting Model Predictions*. Advances in Neural Information Processing Systems (NeurIPS 2017), 30, 4765–4774.
3. Breiman, L. (2001). *Random Forests*. Machine Learning, 45(1), 5–32.
