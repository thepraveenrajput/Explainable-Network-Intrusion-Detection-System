"""
Data preprocessing, cleaning, and transformation module for network intrusion detection.

Ensures strict separation between training and test sets to prevent data leakage,
cleans infinite and missing values, removes uninformative constant features,
encodes target labels (binary and multiclass), and serializes the fitted pipeline.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

from intrusion_xai.config import (
    BENIGN_LABEL,
    DATA_PROCESSED_DIR,
    DROP_COLUMNS,
    FEATURE_SCHEMA_PATH,
    MODELS_DIR,
    PREPROCESSOR_PATH,
    RANDOM_SEED,
    TARGET_COLUMN,
    TEST_SIZE,
)

class NetworkDataPreprocessor(BaseEstimator, TransformerMixin):
    """
    Reusable, scikit-learn compatible preprocessor for network flow records.

    Applies:
    1. Replacement of +/- infinity with NaN.
    2. Removal of non-generalizable columns (Flow ID, IP addresses, Timestamps).
    3. Removal of constant (zero-variance) features detected on training data.
    4. Median imputation of missing and infinite values.
    5. Robust scaling (median and IQR) to handle heavy-tailed network bursts without outlier distortion.
    """

    def __init__(
        self,
        drop_columns: Optional[List[str]] = None,
        drop_constant_features: bool = True,
        scale_features: bool = True,
    ):
        self.drop_columns = drop_columns or DROP_COLUMNS
        self.drop_constant_features = drop_constant_features
        self.scale_features = scale_features

        # State learned during fit()
        self.feature_names_in_: List[str] = []
        self.selected_features_: List[str] = []
        self.constant_columns_: List[str] = []
        self.imputer_: Optional[SimpleImputer] = None
        self.scaler_: Optional[RobustScaler] = None

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "NetworkDataPreprocessor":
        """
        Fit imputer and scaler strictly on training features X.
        """
        if not isinstance(X, pd.DataFrame):
            raise TypeError("Input X must be a pandas DataFrame with named columns.")

        self.feature_names_in_ = list(X.columns)

        # 1. Filter out user-configured non-generalizable columns
        cols_to_keep = [col for col in X.columns if col not in self.drop_columns]
        X_filtered = X[cols_to_keep].copy()

        # 2. Convert +/- infinity to NaN for numeric columns
        numeric_cols = X_filtered.select_dtypes(include=[np.number]).columns.tolist()
        X_numeric = X_filtered[numeric_cols].replace([np.inf, -np.inf], np.nan)

        # 3. Detect constant / zero-variance columns strictly on training data
        if self.drop_constant_features:
            variances = X_numeric.var(numeric_only=True)
            self.constant_columns_ = variances[variances == 0].index.tolist()
            # Also catch columns where all values are identical or all NaN
            for col in X_numeric.columns:
                if X_numeric[col].nunique(dropna=True) <= 1 and col not in self.constant_columns_:
                    self.constant_columns_.append(col)
        else:
            self.constant_columns_ = []

        self.selected_features_ = [
            col for col in numeric_cols if col not in self.constant_columns_
        ]

        if not self.selected_features_:
            raise ValueError("No valid numeric features remain after filtering constant columns.")

        # 4. Fit median imputer
        X_selected = X_numeric[self.selected_features_]
        self.imputer_ = SimpleImputer(strategy="median")
        X_imputed = self.imputer_.fit_transform(X_selected)

        # 5. Fit robust scaler
        if self.scale_features:
            self.scaler_ = RobustScaler()
            self.scaler_.fit(X_imputed)

        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Transform new records using parameters learned strictly during fit().
        """
        if not isinstance(X, pd.DataFrame):
            raise TypeError("Input X must be a pandas DataFrame.")

        # Check that required features are present
        missing_features = [
            f for f in self.selected_features_ if f not in X.columns
        ]
        if missing_features:
            raise ValueError(
                f"Input DataFrame is missing required features: {missing_features[:5]}"
            )

        # Select columns in exact order
        X_selected = X[self.selected_features_].copy()

        # Replace +/- infinity with NaN
        X_selected = X_selected.replace([np.inf, -np.inf], np.nan)

        # Apply fitted imputer
        X_imputed = self.imputer_.transform(X_selected)

        # Apply fitted scaler
        if self.scale_features and self.scaler_ is not None:
            X_scaled = self.scaler_.transform(X_imputed)
        else:
            X_scaled = X_imputed

        return pd.DataFrame(
            X_scaled,
            columns=self.selected_features_,
            index=X.index,
        )

    def save(self, file_path: Path = PREPROCESSOR_PATH) -> None:
        """Serialize preprocessor to disk."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, file_path)

    @classmethod
    def load(cls, file_path: Path = PREPROCESSOR_PATH) -> "NetworkDataPreprocessor":
        """Load serialized preprocessor from disk."""
        if not file_path.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at {file_path}")
        return joblib.load(file_path)

    def export_feature_schema(
        self,
        schema_path: Path = FEATURE_SCHEMA_PATH,
        class_mapping: Optional[Dict[str, int]] = None,
    ) -> Dict:
        """
        Export feature names, count, and transformation parameters to a JSON schema
        accessible to Python prediction and the native C++ inference engine.
        """
        schema_path.parent.mkdir(parents=True, exist_ok=True)
        schema = {
            "num_features": len(self.selected_features_),
            "features": self.selected_features_,
            "dropped_columns": self.drop_columns,
            "constant_columns_dropped": self.constant_columns_,
            "class_mapping": class_mapping or {"BENIGN": 0, "ATTACK": 1},
            "scale_features": self.scale_features,
            "medians": self.imputer_.statistics_.tolist() if self.imputer_ else [],
            "center": self.scaler_.center_.tolist() if self.scaler_ else [],
            "scale": self.scaler_.scale_.tolist() if self.scaler_ else [],
        }
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
        return schema

def encode_labels(
    y_raw: pd.Series,
    binary: bool = True,
    benign_label: str = BENIGN_LABEL,
) -> Tuple[pd.Series, Dict[str, int]]:
    """
    Encode string target labels into integer identifiers.

    Args:
        y_raw: Series of string labels (e.g. 'BENIGN', 'PortScan').
        binary: If True, maps BENIGN to 0 and all attacks to 1.
                If False, creates unique categorical integer IDs per attack family.
        benign_label: The string designating benign background traffic.

    Returns:
        Tuple of (encoded_series, mapping_dictionary).
    """
    labels_clean = y_raw.astype(str).str.strip()

    if binary:
        # Binary task: 0 = Benign, 1 = Attack
        mapping = {benign_label: 0}
        unique_attacks = sorted([l for l in labels_clean.unique() if l != benign_label])
        for attack in unique_attacks:
            mapping[attack] = 1

        y_encoded = labels_clean.apply(lambda val: 0 if val == benign_label else 1).astype(int)
    else:
        # Multiclass task: 0 = Benign, 1..N = Attack types
        unique_labels = [benign_label] + sorted([l for l in labels_clean.unique() if l != benign_label])
        mapping = {label: idx for idx, label in enumerate(unique_labels)}
        y_encoded = labels_clean.map(mapping).astype(int)

    return y_encoded, mapping

def prepare_data(
    df: pd.DataFrame,
    target_column: str = TARGET_COLUMN,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_SEED,
    binary: bool = True,
    save_artifacts: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, NetworkDataPreprocessor]:
    """
    Full end-to-end data preparation workflow:
    1. Separate features and target label.
    2. Encode target labels.
    3. Stratified train/test split.
    4. Fit preprocessor strictly on training features.
    5. Transform training and test features.
    6. Optionally save processed sets and preprocessor to disk.

    Returns:
        X_train_trans, X_test_trans, y_train, y_test, preprocessor
    """
    # Sanitize column names
    df.columns = df.columns.str.strip()

    if target_column not in df.columns:
        raise ValueError(f"Target column '{target_column}' not found in DataFrame.")

    X_raw = df.drop(columns=[target_column])
    y_raw = df[target_column]

    # Encode labels
    y_encoded, label_mapping = encode_labels(y_raw, binary=binary)

    # Stratified split to maintain exact class proportions in train and test sets
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw,
        y_encoded,
        test_size=test_size,
        random_state=random_state,
        stratify=y_encoded,
    )

    # Initialize and fit preprocessor ONLY on training data
    preprocessor = NetworkDataPreprocessor()
    X_train_trans = preprocessor.fit_transform(X_train_raw)
    X_test_trans = preprocessor.transform(X_test_raw)

    if save_artifacts:
        DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        # Save processed splits
        train_df = X_train_trans.copy()
        train_df[target_column] = y_train.values
        train_df.to_csv(DATA_PROCESSED_DIR / "train.csv", index=False)

        test_df = X_test_trans.copy()
        test_df[target_column] = y_test.values
        test_df.to_csv(DATA_PROCESSED_DIR / "test.csv", index=False)

        # Serialize preprocessor & feature schema
        preprocessor.save(PREPROCESSOR_PATH)
        preprocessor.export_feature_schema(
            FEATURE_SCHEMA_PATH,
            class_mapping=label_mapping,
        )

        print(
            f"[SUCCESS] Preprocessed data saved:\n"
            f"  Train: {X_train_trans.shape} -> {DATA_PROCESSED_DIR / 'train.csv'}\n"
            f"  Test:  {X_test_trans.shape} -> {DATA_PROCESSED_DIR / 'test.csv'}\n"
            f"  Preprocessor saved to: {PREPROCESSOR_PATH}\n"
            f"  Feature Schema saved to: {FEATURE_SCHEMA_PATH}"
        )

    return X_train_trans, X_test_trans, y_train, y_test, preprocessor
