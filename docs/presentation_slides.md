# Major Project Presentation: Explainable Machine Learning Framework for Network Intrusion Detection and Feature-Based Threat Analysis

**Candidate:** Praveen Singh  
**Degree:** Bachelor of Technology in Computer Science & Engineering  
**Academic Year:** 2026  
**Format:** 14 Slides with Speaker Notes & Anticipated Defense Questions  

---

## Slide 1: Title & Project Identification
- **Title:** Explainable Machine Learning Framework for Network Intrusion Detection and Feature-Based Threat Analysis
- **Subtitle:** A High-Throughput, Dual-Engine Architecture (Python + C++17) with Game-Theoretic Attribution
- **Candidate:** Praveen Singh
- **Supervisor:** [Project Guide / Department of Computer Science & Engineering]
- **Key Focus:** Bridging the gap between Machine Learning accuracy, SOC explainability, and line-rate network deployment.

> **Speaker Notes:**
> *"Good morning respected external examiners, head of department, and faculty members. Today, I am presenting our final year major project: an Explainable Machine Learning Framework for Network Intrusion Detection. Our work addresses the two biggest obstacles preventing real-world adoption of AI in Security Operations Centers: the black-box nature of ML alerts and the high latency of interpreted Python runtimes."*

---

## Slide 2: Problem Statement & Motivation
- **The Modern Threat Landscape:** High-speed network backbones (10–100 Gbps), distributed reconnaissance, and sophisticated zero-day exploits.
- **Traditional NIDS Limitations:**
  - Signature-based IDS (Snort/Suricata) fail against zero-day variants and slow polymorphic scans.
  - Anomaly-based IDS generate severe alert fatigue due to high false-alarm rates.
- **The Core Roadblocks in Modern AI-IDS:**
  1. **The Black-Box Problem:** A model flags a packet as malicious, but cannot explain *why*, leaving SOC analysts unable to verify alerts.
  2. **The Production Latency Gap:** Python/scikit-learn stacks are too slow (>50–200 $\mu s$, heavy RAM, GIL) for line-rate packet tapping.

> **Speaker Notes:**
> *"Signature detection is fast but blind to new attacks. Machine learning detects new attacks, but SOC analysts don't trust it because it's a black box. Furthermore, enterprise firewalls process millions of packets per second. A standard Python script cannot keep pace with line-rate traffic. Our project specifically solves both of these problems."*

---

## Slide 3: Research Objectives
1. **Leakage-Free Preprocessing:** Clean missing/infinite flow values, eliminate zero-variance features, and scale without data contamination.
2. **Multi-Model Benchmarking:** Train and cross-evaluate Decision Tree (CART), Random Forest (Bagging), and L2 Logistic Regression.
3. **Game-Theoretic XAI:** Implement Tree SHAP and Permutation Importance, translating mathematical attributions into human-readable cybersecurity terms.
4. **Native C++17 Inference Engine:** Export trained models to JSON and execute with zero external libraries at sub-5 microsecond speeds.
5. **Cross-Language Parity:** Verify 100% mathematical prediction equivalence between Python and C++.
6. **Interactive SOC Dashboard:** Deliver a real-time Streamlit/Plotly interface for alert triage and packet simulation.

> **Speaker Notes:**
> *"Our objectives were not just to train a model in a Jupyter Notebook, but to build an end-to-end engineered system: rigorous preprocessing, verifiable explainability, a compiled C++17 engine for microsecond inference, and a functional dashboard for security analysts."*

---

## Slide 4: End-to-End System Architecture
- **Layer 1: Data Engineering**
  - Raw CIC-IDS2017 PCAP/CSV $\rightarrow$ Whitespace cleanup $\rightarrow$ Leakage-free train/test partition $\rightarrow$ Median Imputer + RobustScaler.
- **Layer 2: Analytical Modeling (Python)**
  - Model training, hyperparameter tuning, metrics generation, and model artifact serialization (`.joblib`).
- **Layer 3: Explainable AI Engine**
  - Global Permutation Importance + Tree SHAP summary $\rightarrow$ Local single-flow waterfall decomposition mapped to a cybersecurity lexicon.
- **Layer 4: Real-Time Edge Deployment (C++17)**
  - Standalone binary with self-contained JSON parser, defensive input validation, and sub-5 $\mu s$ traversal.
- **Layer 5: Visualization & Audit**
  - Streamlit dashboard providing SOC KPIs, EDA charts, dual-engine comparison, and live packet simulation.

> **Speaker Notes:**
> *"This diagram illustrates our decoupled dual-engine architecture. Heavy analytical operations—training and SHAP calculations—run in Python. For deployment, the model is serialized into JSON and ingested by a pure C++17 engine that operates with zero third-party dependencies."*

---

## Slide 5: Dataset & Traffic Engineering
- **Benchmark Dataset:** Canadian Institute for Cybersecurity **CIC-IDS2017** (Friday Afternoon PortScan capture, 73 MB, 286,467 flows).
- **Attack Profile:** Reconnaissance Port Scanning (MITRE ATT&CK T1046).
- **Stratified Representative Sample:**
  - $N = 10,000$ network flows.
  - **PortScan (Attack):** 5,548 flows ($55.48\%$).
  - **Benign (Normal):** 4,452 flows ($44.52\%$).
  - Preserves exact class ratio across 80% train ($8,000$) and 20% test ($2,000$) sets.
- **Dimensionality Reduction:**
  - 10 zero-variance features dropped (e.g., `Bwd PSH Flags`, `CWE Flag Count`).
  - Non-generalizable identifiers removed (IPs, Ports, Timestamps).
  - 66 clean, continuous numerical predictors retained.

> **Speaker Notes:**
> *"We utilized the realistic CIC-IDS2017 dataset. We specifically removed IP addresses and timestamps so the model cannot 'memorize' who the attacker was, but must learn the intrinsic physical properties of the network packets."*

---

## Slide 6: Leakage-Free Preprocessing Pipeline
- **What is Data Leakage?** Computing scaling parameters or missing value statistics across the combined dataset, allowing test information to contaminate training.
- **Our Leakage Prevention Architecture:**
  1. `train_test_split(..., test_size=0.20, stratify=y, random_state=42)` executed **FIRST**.
  2. Infinite/NaN values cleaned ($\pm \infty \rightarrow \text{NaN}$).
  3. `SimpleImputer(strategy='median')` fitted **only on $X_{\text{train}}$**.
  4. `RobustScaler` (median & IQR) fitted **only on $X_{\text{train}}$**.
  5. The fitted pipeline is applied to $X_{\text{test}}$ and real-time inference without modification.

> **Speaker Notes:**
> *"A critical contribution of our project is complete data leakage prevention. In many published papers, scaling is done before splitting, giving artificially inflated results. In our pipeline, the scaler and imputer never see a single test sample until evaluation time."*

---

## Slide 7: Algorithmic Paradigms & Training Protocol
- **Three Diverse Learning Paradigms:**
  1. **Decision Tree (CART):** Axis-aligned recursive partitioning with Gini impurity, max depth 12. Interpretable and ideal for C++ translation.
  2. **Random Forest:** Ensemble bagging with $B = 100$ trees, feature subspace sampling ($\sqrt{66} \approx 8$), reducing variance.
  3. **Logistic Regression (L2):** Linear decision boundary baseline with L-BFGS optimizer and ridge penalty.
- **Reproducibility Guarantee:** Fixed random seed ($R=42$) across all random number generators.

> **Speaker Notes:**
> *"We compared an interpretable white-box model (Decision Tree), an ensemble bagging model (Random Forest), and a linear baseline (Logistic Regression) to understand whether non-linear tree structures are strictly necessary for network traffic."*

---

## Slide 8: Model Evaluation & Performance Results
- **Held-out Test Partition ($N_{\text{test}} = 2,000$ flows):**

| Metric | Decision Tree (CART) | Random Forest | Logistic Regression |
| :--- | :---: | :---: | :---: |
| **Accuracy** | **99.95%** | **99.95%** | 89.15% |
| **Precision** | **99.91%** | **99.91%** | 92.16% |
| **Recall (TPR)** | **100.00%** | **100.00%** | 87.93% |
| **F1-Score** | **0.9995** | **0.9995** | 0.8999 |
| **False Positive Rate (FPR)** | **0.11% (1 / 890)** | **0.11% (1 / 890)** | 9.33% (83 / 890) |
| **False Negative Rate (FNR)** | **0.00% (0 / 1,110)** | **0.00% (0 / 1,110)** | 12.07% (134 / 1,110) |

- **Key Takeaway:** Tree-based models achieved **100% attack recall** with only 1 false alarm, whereas Logistic Regression missed 134 attacks and generated 83 false alarms.

> **Speaker Notes:**
> *"On 2,000 unseen test samples, the Decision Tree and Random Forest detected every single port scan (100% recall) with an FPR of only 0.11%. Logistic regression missed over 12% of attacks, proving that linear models cannot capture complex network flag and packet interactions."*

---

## Slide 9: Explainable AI: Global Threat Insights
- **Game-Theoretic Foundation:** SHAP (Shapley Additive exPlanations) based on cooperative game theory; unique method satisfying Efficiency, Symmetry, Dummy, and Additivity.
- **Global Feature Ranking (Permutation & Tree SHAP):**
  1. `Init_Win_bytes_forward` (Dominant by an order of magnitude).
  2. `Flow Bytes/s`.
  3. `Fwd Packet Length Mean`.
  4. `Total Length of Fwd Packets`.
- **Cybersecurity Finding:** Attackers cannot easily mask their transport-layer fingerprint. Port scanners send bare SYN packets with fixed window sizes and minimal payload.

> **Speaker Notes:**
> *"Using Tree SHAP and Permutation Importance, we discovered that `Init_Win_bytes_forward` is the single most informative feature. When Nmap or ZMap executes a scan, it uses distinct, hardcoded TCP window sizes that stand out against standard Windows, Linux, and macOS user connections."*

---

## Slide 10: Local Attribution & Domain Lexicon Mapping
- **Local Waterfall Attributions:** For any individual packet, SHAP decomposes $f(x)$ into additive feature contributions relative to base expected value $E[f(x)]$.
- **Bridging the Semantic Gap (Cybersecurity Lexicon):**

| Raw Feature Name | Cyber Domain Meaning | What It Tells the SOC Analyst |
| :--- | :--- | :--- |
| `Init_Win_bytes_forward` | Initial TCP Window Size | Scanner TCP stack fingerprinting (e.g., Nmap SYN probe). |
| `Flow Bytes/s` | Flow Byte Rate | High packet burst with minimal byte transfer across ports. |
| `Fwd Packet Length Mean` | Avg Forward Packet Size | Bare TCP SYN headers lacking application payload. |
| `Flow IAT Mean` | Mean Inter-Arrival Time | Machine-generated automated scanning speed. |

> **Speaker Notes:**
> *"A junior SOC analyst doesn't know what `Init_Win_bytes_forward = 29200` means. Our system automatically translates this into plain English: 'The traffic exhibits an automated scanner TCP window fingerprint with bare SYN headers.' This reduces triage time from 15 minutes to under 30 seconds."*

---

## Slide 11: Native C++17 Real-Time Inference Engine
- **Why C++17?** Deterministic performance, zero garbage collection, sub-5 microsecond execution, minimal memory footprint (<10 MB), and zero external dependencies.
- **Engine Design:**
  - Reads a validated JSON schema containing node counts, children arrays, feature indices, thresholds, and leaf values.
  - Built-in lightweight recursive-descent JSON parser.
  - Defensive floating-point validation (`std::isnan`, `std::isinf`) and feature dimension verification.
  - Supports CLI array inputs, single JSON evaluation, and high-speed CSV stdin streams.

> **Speaker Notes:**
> *"To deploy in hardware appliances, we built a standalone C++17 engine. It contains its own zero-dependency JSON parser, handles NaN and infinite inputs safely, and executes decision tree traversals in less than 5 microseconds per packet."*

---

## Slide 12: Cross-Platform Parity Verification
- **Verification Experiment:** 500 randomly selected test samples were passed through both the Python scikit-learn reference runtime and the native C++17 engine.
- **Results:**
  - Evaluated Samples: **500**
  - scikit-learn Predictions: **278 Attacks, 222 Benign**
  - C++17 Engine Predictions: **278 Attacks, 222 Benign**
  - Discrepancies: **0**
  - **Prediction Parity: 100.00% Exact Match**
- **Significance:** Proves mathematical fidelity across operating system architectures, compilers, and programming languages.

> **Speaker Notes:**
> *"We verified mathematical parity across 500 test flows. The C++17 engine produced the exact same binary prediction and probability for every single sample—100.00% parity with zero discrepancies."*

---

## Slide 13: Interactive SOC Analyst Dashboard
- **Built with Streamlit & Plotly:**
  - **Overview & KPIs:** Real-time health metrics, active model status, and architectural summaries.
  - **EDA Tab:** Log-scaled distribution histograms and interactive correlation matrices.
  - **Model Evaluation:** Multi-model comparative tables and normalized confusion heatmaps.
  - **Global XAI:** Interactive Tree SHAP and Permutation Importance bar charts.
  - **Local Waterfall:** Real-time flow inspector with dynamic SHAP waterfall visualizations.
  - **Dual-Engine Audit:** Real-time toggle comparing Python and C++ predictions with persistent tabular audit logs.

> **Speaker Notes:**
> *"The frontend is an interactive SOC dashboard built with Streamlit and Plotly. Analysts can simulate incoming network packets, inspect real-time threat probabilities, view waterfall explanations, and switch between Python and C++ inference engines."*

---

## Slide 14: Conclusion & Future Scope
- **Key Deliverables Achieved:**
  - Leakage-free data engineering on the CIC-IDS2017 benchmark.
  - 99.95% accuracy and 100% recall with only 0.11% false positive rate.
  - Explainable AI pipeline with domain-specific cyber lexicon mapping.
  - Zero-dependency C++17 engine with sub-5 $\mu s$ latency and 100% parity.
  - 43 automated unit/integration tests with a 100% pass rate.
- **Future Directions:**
  - Multi-class classification across all 14 CIC-IDS2017 attack types.
  - Kernel-level packet filtering via Extended Berkeley Packet Filter (**eBPF / XDP**).
  - Online streaming drift detection and automated model retraining.

> **Speaker Notes:**
> *"In conclusion, this project successfully bridges the gap between machine learning research and real-world cybersecurity operations. We thank the committee for your time and welcome your questions."*

---

## Anticipated Committee Defense Questions & Quick Answers

1. **Q: Why did you drop IP addresses and ports? Wouldn't they help identify the attacker?**  
   *A: Retaining IP addresses causes severe data leakage and overfitting. The model would simply memorize that a specific testbed IP is malicious. By removing them, the model is forced to learn generalizable behavioral traffic patterns (packet size, window dynamics, inter-arrival times).*

2. **Q: Why use a single Decision Tree instead of a Deep Neural Network?**  
   *A: On tabular network flow data, tree models consistently outperform neural networks. A single Decision Tree achieved 99.95% accuracy and 100% recall while being computationally trivial to export and execute in C++ at sub-5 $\mu s$ speeds with full interpretability.*

3. **Q: How does SHAP differ from standard feature importance?**  
   *A: Standard Gini importance is biased toward high-cardinality features and only provides global metrics. SHAP is grounded in cooperative game theory, satisfies mathematical efficiency and symmetry axioms, and provides both global insights and sample-level local waterfall attributions.*

4. **Q: How did you ensure your C++ engine has zero dependencies?**  
   *A: We wrote our own recursive JSON parser and linear tree traversal logic using standard library `<vector>`, `<string>`, and `<cmath>`, avoiding external libraries like nlohmann/json or Boost.*
