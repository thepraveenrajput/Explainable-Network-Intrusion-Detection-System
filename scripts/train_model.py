"""
Command-line model training pipeline for the Intrusion XAI Framework.

Usage:
    python scripts/train_model.py
"""

import sys
from pathlib import Path
import pandas as pd

from intrusion_xai.config import (
    DATA_PROCESSED_DIR,
    MODELS_DIR,
    RANDOM_SEED,
    TARGET_COLUMN,
)
from intrusion_xai.data.load_data import load_raw_data
from intrusion_xai.data.preprocess import prepare_data
from intrusion_xai.ml.train import train_models

def main():
    print("=" * 60)
    print("  Intrusion XAI Framework — Model Training Pipeline         ")
    print("=" * 60)

    train_file = DATA_PROCESSED_DIR / "train.csv"
    test_file = DATA_PROCESSED_DIR / "test.csv"

    if not train_file.exists() or not test_file.exists():
        print("[INFO] Processed dataset not found. Loading raw data and preprocessing...")
        raw_df = load_raw_data()
        X_train, X_test, y_train, y_test, preprocessor = prepare_data(
            raw_df,
            save_artifacts=True,
        )
    else:
        print(f"[INFO] Loading preprocessed training dataset from:\n  {train_file}")
        train_df = pd.read_csv(train_file)
        X_train = train_df.drop(columns=[TARGET_COLUMN])
        y_train = train_df[TARGET_COLUMN]

    print(f"\n[INFO] Training Feature Dimensions: {X_train.shape}")
    print(f"[INFO] Training Class Counts: {y_train.value_counts().to_dict()}\n")

    # Train all models
    results = train_models(
        X_train,
        y_train,
        models_dir=MODELS_DIR,
        save_artifacts=True,
    )

    print("\n" + "=" * 60)
    print("  Training Summary                                          ")
    print("=" * 60)
    for model_name, info in results.items():
        print(f"  • {model_name:<20} | Time: {info['training_time_sec']:>6.3f}s | Saved: {info['artifact_path']}")

    print("\n[SUCCESS] All models trained and serialized successfully!")

if __name__ == "__main__":
    main()
