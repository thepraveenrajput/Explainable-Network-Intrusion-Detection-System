# Methodology — Intrusion Detection & Explainable AI Framework

## 1. Experimental Methodology Overview
This project establishes a standardized, reproducible machine learning workflow to evaluate network intrusion detection models under rigorous statistical guidelines, avoiding the prevalent pitfalls of data leakage and misleading accuracy metrics.

```
Raw CSV Flows
     │
     ▼
[ Schema Validation & Header Trimming ]
     │
     ▼
[ Drop Non-Generalizable Features ] (IPs, Ports, Flow IDs, Timestamps)
     │
     ▼
[ Stratified Train / Test Split ] (80% Train, 20% Test, seed=42)
     │
     ├───────────────────────────────────────────┐
     ▼                                           ▼
[ Fit Preprocessor on Train ]             [ Transform Test Set ]
(SimpleImputer + RobustScaler)            (Using Train-Fitted Parameters)
     │                                           │
     ▼                                           │
[ Train Classifiers ]                            │
- Decision Tree                                  │
- Random Forest                                  │
- Logistic Regression                            │
     │                                           │
     ├───────────────────────────────────────────┘
     ▼
[ Held-Out Test Evaluation & Parity Checks ]
- Precision, Recall, F1, Confusion Matrix, FPR
- Permutation Importance & SHAP Attribution
- C++17 Engine Cross-Language Parity Check
```

## 2. Preventing Data Leakage
A critical flaw in many published NIDS studies is **data leakage**:
1. **Identity Memorization**: Training algorithms on IP addresses or Flow IDs allows the model to achieve 99.9% accuracy simply by learning "Traffic from `192.168.10.50` is attack traffic." In real deployments on different networks, such models fail completely. Our pipeline drops all IP, Port, and ID columns before modeling.
2. **Preprocessing Leakage**: Calculating global statistics (e.g. mean or variance for imputation or standardization) across the entire dataset before splitting leaks information from the test set into the training set. In our pipeline, `fit()` is exclusively executed on the training split, and `transform()` is applied to the test split.

## 3. Binary vs. Multiclass Formulation
The framework supports both operational perspectives:
- **Binary Classification (Default)**: Classifies traffic as `BENIGN` (0) vs. `MALICIOUS / ATTACK` (1). This matches the frontline triage needs of SOC analysts seeking rapid binary escalation.
- **Multiclass Classification**: Distinguishes specific threat categories (e.g., DDoS, DoS, PortScan, Brute Force). Useful for tactical attribution once an intrusion has been confirmed.

## 4. Evaluation Metrics
Given that benign traffic represents >80% of network flows, raw classification accuracy is heavily biased. We evaluate systems based on:
- **Precision**: $\frac{TP}{TP + FP}$ — The ratio of true attacks among all flagged alerts (minimizing false alarms).
- **Recall (Sensitivity)**: $\frac{TP}{TP + FN}$ — The proportion of actual attacks successfully detected (minimizing missed attacks).
- **F1-Score**: $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ — Harmonic mean balancing precision and recall.
- **False Positive Rate (FPR)**: $\frac{FP}{FP + TN}$ — The frequency with which benign traffic is mistakenly flagged as an intrusion.

## 5. Explainable AI (XAI) Integration
1. **Global Attribution**:
   - **Permutation Importance**: Measures drop in model performance when a feature's values are randomly shuffled on held-out test data.
   - **SHAP (SHapley Additive exPlanations)**: Uses cooperative game theory to estimate the average marginal contribution of each feature across the dataset.
2. **Local Threat Attribution**:
   - For an individual incoming flow record, computes local SHAP contributions or decision path splits, showing the top 5 features that pushed the prediction toward malicious or benign.
