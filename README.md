# Explainable Machine Learning Framework for Network Intrusion Detection and Feature-Based Threat Analysis

An end-to-end, reproducible, and explainable cybersecurity machine learning system designed to analyze network flow records, detect benign versus malicious network traffic, explain model decisions with feature-level transparency (XAI), and perform high-performance offline inference via a custom C++17 engine.

---

## 📌 Project Overview

Network Intrusion Detection Systems (NIDS) are critical perimeter defenses in modern cyber infrastructure. However, conventional "black-box" machine learning models often lack transparency, making it difficult for Security Operations Center (SOC) analysts to understand **why** an alert was triggered.

This major college project addresses the transparency gap by building:
1. **Robust Data Pipeline**: Ingestion, validation, and preprocessing of network flow records (based on the public CIC-IDS2017 benchmark dataset).
2. **Multi-Model Machine Learning Suite**: Training, evaluation, and comparison of Decision Tree, Random Forest, and baseline models with strict separation of train/test data to prevent leakage.
3. **Explainable AI (XAI)**:
   - **Global Explanations**: Permutation feature importance and SHAP analysis to reveal overall model behavior.
   - **Local Explanations**: Per-record threat attribution detailing which flow characteristics contributed to an intrusion alert.
4. **C++17 High-Performance Inference Engine**: Native compiled inference component demonstrating deterministic tree traversal and cross-language verification.
5. **Interactive Web Dashboard**: Streamlit-based graphical user interface allowing security analysts to upload traffic files, inspect data quality, run classifications, view explanations, and export reports.
6. **Academic Documentation & Viva Material**: Complete technical reports, architecture diagrams, and question banks.

---

## 🛠️ Technology Stack

| Category | Technology / Library | Role in Project |
| :--- | :--- | :--- |
| **Language** | Python 3.12 / 3.11 | Core pipeline, ML training, XAI, web dashboard |
| **Language** | C++17 (Apple Clang) | High-speed native compiled decision engine |
| **Build System** | CMake 3.16+ | C++ engine configuration and compilation |
| **Data Processing** | pandas, NumPy | High-performance tabular data manipulation |
| **Machine Learning** | scikit-learn, joblib | Model training, cross-validation, and pipeline persistence |
| **Explainability (XAI)** | SHAP, Permutation Importance | Local and global decision attribution |
| **Visualization** | Matplotlib, Seaborn, Plotly | Confusion matrices, feature rankings, interactive plots |
| **Web Dashboard** | Streamlit | Interactive graphical user interface for SOC analysts |
| **Testing** | pytest, CTest | Automated test suites for Python and C++ modules |
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
│   ├── include/                      # C++ header files
│   ├── src/                          # C++ inference engine implementation
│   └── tests/                        # C++ unit tests
├── tests/                            # Automated test suite (pytest)
├── outputs/
│   ├── metrics/                      # Model evaluation metrics (JSON / CSV)
│   ├── plots/                        # Generated evaluation & XAI charts (PNG / SVG)
│   └── reports/                      # Summary reports
├── docs/                             # Academic report, architecture, and viva preparation
└── scripts/
    ├── setup.sh                      # Automated environment setup script
    ├── train_model.py                # Command-line model training pipeline
    └── run_tests.sh                  # Complete Python and C++ test suite runner
```

---

## 🚀 Quickstart Guide for macOS

### 1. Prerequisites
Ensure your Mac has the Apple Command Line Tools and CMake installed:
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
If you prefer setting up manually:
```bash
# 1. Create and activate Python virtual environment
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 3. Build the C++17 Inference Engine
cmake -B cpp/build -S cpp
cmake --build cpp/build
```

### 4. Running Automated Tests
Verify all Python unit tests and C++ engine tests:
```bash
./scripts/run_tests.sh
```

---

## 🔒 Scope, Limitations, and Ethical Disclosures

1. **Offline Flow Analysis**: This framework is designed for analyzing recorded network flow records (e.g. NetFlow / IPFIX / Bro / Zeek style flow statistics). It is not a kernel-level packet sniffer and does not perform live network packet capture (`libpcap`) unless explicitly extended.
2. **False Positives & Negatives**: Machine learning predictions are probabilistic, not absolute guarantees. A classification of "Benign" does not guarantee zero threat, and an "Attack" alert should be investigated by a qualified analyst.
3. **Data Privacy**: No private customer or institution data is bundled. Models are trained on public academic datasets (CIC-IDS2017).
