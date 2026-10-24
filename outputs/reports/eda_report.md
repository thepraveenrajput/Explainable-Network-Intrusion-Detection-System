# Exploratory Data Analysis Report — CIC-IDS2017

- **Total Flow Records**: 10,000
- **Total Features**: 79
- **Target Column**: `Label`

## Class Distribution
- **PortScan**: 5,548 (55.48%)
- **BENIGN**: 4,452 (44.52%)

## Data Quality Audit
- **Missing Value Cells (NaN)**: 0
- **Infinite Value Cells (Inf)**: 18
- **Duplicate Rows**: 203
- **Zero-Variance (Constant) Columns**: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']

## Generated Visualizations
- Class Distribution: `outputs/plots/class_distribution.png`
- Flow Duration Distribution: `outputs/plots/flow_duration_distribution.png`
- Feature Correlation Matrix: `outputs/plots/top_features_correlation.png`
