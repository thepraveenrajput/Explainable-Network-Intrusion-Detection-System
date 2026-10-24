"""
Inference and prediction module for network intrusion detection.

Handles single-record and batch predictions using trained scikit-learn models,
calculates threat probabilities / confidence scores, and produces analyst-ready outputs.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Union
import joblib
import numpy as np
import pandas as pd

from intrusion_xai.config import (
    BENIGN_LABEL,
    DT_MODEL_PATH,
    LR_MODEL_PATH,
    MODELS_DIR,
    PREPROCESSOR_PATH,
    RF_MODEL_PATH,
)
from intrusion_xai.data.preprocess import NetworkDataPreprocessor

MODEL_REGISTRY = {
    "decision_tree": DT_MODEL_PATH,
    "random_forest": RF_MODEL_PATH,
    "logistic_regression": LR_MODEL_PATH,
}

def load_trained_model(model_name: str = "random_forest") -> Any:
    """
    Load a trained model artifact from disk by name.

    Args:
        model_name: Identifier of model ('decision_tree', 'random_forest', 'logistic_regression').

    Returns:
        Loaded scikit-learn estimator instance.
    """
    model_path = MODEL_REGISTRY.get(model_name, MODELS_DIR / f"{model_name}.joblib")
    if not model_path.exists():
        raise FileNotFoundError(
            f"Trained model '{model_name}' not found at {model_path}.\n"
            "Please run 'python scripts/train_model.py' first."
        )
    return joblib.load(model_path)

def predict_batch(
    records: pd.DataFrame,
    model: Optional[Any] = None,
    model_name: str = "random_forest",
    preprocessor: Optional[NetworkDataPreprocessor] = None,
    attack_label: str = "MALICIOUS",
) -> pd.DataFrame:
    """
    Generate predictions, threat probabilities, and confidence scores for batch flow records.

    Args:
        records: Raw or preprocessed DataFrame of network traffic records.
        model: Pre-loaded model estimator instance. If None, loads using model_name.
        model_name: Name of model to load if model is not passed directly.
        preprocessor: Fitted preprocessor. If None, loads from models/preprocessor.joblib.
        attack_label: String label used to name predicted intrusions.

    Returns:
        Augmented pandas DataFrame with predicted_class, predicted_label,
        threat_score, and confidence columns.
    """
    if model is None:
        model = load_trained_model(model_name)

    if preprocessor is None and PREPROCESSOR_PATH.exists():
        preprocessor = NetworkDataPreprocessor.load(PREPROCESSOR_PATH)

    # Transform records if preprocessor is available and records are unscaled
    if preprocessor is not None:
        # Check if preprocessing is needed (e.g. if extra columns or unscaled values exist)
        if set(preprocessor.selected_features_).issubset(set(records.columns)):
            X_clean = preprocessor.transform(records)
        else:
            X_clean = records
    else:
        X_clean = records

    # Predict classes
    predictions = model.predict(X_clean)

    # Predict probabilities (if supported)
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_clean)
        # Assuming binary: class 0 = Benign, class 1 = Attack
        if probabilities.shape[1] > 1:
            threat_scores = probabilities[:, 1]
            confidences = np.max(probabilities, axis=1)
        else:
            threat_scores = probabilities[:, 0]
            confidences = probabilities[:, 0]
    else:
        threat_scores = predictions.astype(float)
        confidences = np.ones(len(predictions), dtype=float)

    results_df = records.copy()
    results_df["predicted_class"] = predictions
    results_df["predicted_label"] = np.where(predictions == 1, attack_label, BENIGN_LABEL)
    results_df["threat_score"] = np.round(threat_scores, 4)
    results_df["confidence"] = np.round(confidences, 4)

    return results_df

def predict_single(
    record: Union[pd.Series, Dict[str, Any]],
    model: Optional[Any] = None,
    model_name: str = "random_forest",
    preprocessor: Optional[NetworkDataPreprocessor] = None,
    attack_label: str = "MALICIOUS",
) -> Dict[str, Any]:
    """
    Generate prediction and threat score for an individual network flow record.

    Returns:
        Dictionary summarizing the alert status, confidence, and class probabilities.
    """
    if isinstance(record, dict):
        df_row = pd.DataFrame([record])
    elif isinstance(record, pd.Series):
        df_row = pd.DataFrame([record.to_dict()])
    else:
        raise TypeError("record must be a dict or a pandas Series.")

    pred_df = predict_batch(
        df_row,
        model=model,
        model_name=model_name,
        preprocessor=preprocessor,
        attack_label=attack_label,
    )

    row = pred_df.iloc[0]
    is_attack = bool(row["predicted_class"] == 1)

    return {
        "is_threat": is_attack,
        "predicted_class": int(row["predicted_class"]),
        "predicted_label": str(row["predicted_label"]),
        "threat_score": float(row["threat_score"]),
        "confidence": float(row["confidence"]),
        "features": {col: row[col] for col in df_row.columns if col in df_row.columns},
    }
