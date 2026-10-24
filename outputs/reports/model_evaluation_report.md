# Model Evaluation & Benchmark Report

Evaluation conducted on the held-out test split ($N = 2,000$ flow records, 66 numerical features).

## 1. Quantitative Performance Comparison Table

| Model | Accuracy | Precision | Recall | F1-Score | FPR | FNR | TP | TN | FP | FN | Latency (µs/sample) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Decision Tree | 0.9995 | 0.9991 | 1.0 | 0.9995 | 0.0011 | 0.0 | 1110 | 889 | 1 | 0 | 4.98 |
| Random Forest | 0.9995 | 0.9991 | 1.0 | 0.9995 | 0.0011 | 0.0 | 1110 | 889 | 1 | 0 | 11.51 |
| Logistic Regression | 0.8915 | 0.9216 | 0.8793 | 0.9 | 0.0933 | 0.1207 | 976 | 807 | 83 | 134 | 1.0 |

## 2. Key Findings & Trade-offs

- **Random Forest**: Achieves top ensemble stability and lowest false alarm rates by averaging multiple decorrelated decision trees.
- **Decision Tree**: Provides near-parity detection with ultra-low latency, making it the ideal candidate for export to our C++17 native inference engine.
- **Logistic Regression**: Serves as a linear baseline, highlighting the non-linear boundaries required to detect multi-stage intrusion traffic.

## 3. Visual Artifacts

- `outputs/plots/confusion_matrices.png`
- `outputs/plots/model_comparison_chart.png`
