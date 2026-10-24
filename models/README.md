# Models Directory

This directory stores trained machine learning models, preprocessors, and feature schema definitions.

## Contents
- Trained scikit-learn models (Decision Tree, Random Forest, Logistic Regression) saved as `.joblib` files.
- Exported decision tree decision rules/thresholds formatted as lightweight JSON for C++17 engine inference.
- Feature schema mappings (`feature_names.json`) ensuring alignment between training, Python inference, and C++ inference.

## Note on Git Tracking
Large binary `.joblib` files are excluded in `.gitignore` to keep the repository lightweight and clean. The training pipeline can deterministically reproduce all model artifacts by running:
```bash
python scripts/train_model.py
```
