"""
Model training and serialization module for network intrusion detection.

Trains, benchmarks, and persists Decision Tree, Random Forest, and Logistic Regression
classifiers. Exports decision tree rules for C++ inference engine cross-validation.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from intrusion_xai.config import (
    CPP_TREE_MODEL_PATH,
    DT_MODEL_PATH,
    LR_MODEL_PATH,
    MODELS_DIR,
    RANDOM_SEED,
    RF_MODEL_PATH,
)

def export_decision_tree_to_json(
    tree_clf: DecisionTreeClassifier,
    feature_names: List[str],
    output_path: Path = CPP_TREE_MODEL_PATH,
) -> Dict[str, Any]:
    """
    Export scikit-learn DecisionTreeClassifier tree structure to portable JSON.
    Used by the C++17 inference engine to achieve exact native inference parity.
    """
    tree = tree_clf.tree_
    nodes = []

    for i in range(tree.node_count):
        is_leaf = tree.children_left[i] == -1 and tree.children_right[i] == -1
        counts = tree.value[i][0]
        total = float(np.sum(counts))
        probs = [float(c / total) if total > 0 else 0.0 for c in counts]
        pred_class = int(np.argmax(counts))

        feat_idx = int(tree.feature[i])
        feat_name = feature_names[feat_idx] if (0 <= feat_idx < len(feature_names)) else None

        node_dict = {
            "node_id": i,
            "is_leaf": bool(is_leaf),
            "feature_index": feat_idx,
            "feature_name": feat_name,
            "threshold": float(tree.threshold[i]),
            "left_child": int(tree.children_left[i]),
            "right_child": int(tree.children_right[i]),
            "predicted_class": pred_class,
            "probabilities": probs,
        }
        nodes.append(node_dict)

    tree_schema = {
        "model_type": "DecisionTreeClassifier",
        "node_count": int(tree.node_count),
        "max_depth": int(tree.max_depth),
        "n_classes": int(tree_clf.n_classes_),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "nodes": nodes,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(tree_schema, f, indent=2)

    return tree_schema

def get_default_models(random_state: int = RANDOM_SEED) -> Dict[str, Any]:
    """
    Instantiate default classification models with tuned parameters for tabular network flows.
    """
    return {
        "decision_tree": DecisionTreeClassifier(
            max_depth=10,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=random_state,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=10,
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=random_state,
        ),
        "logistic_regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=random_state,
        ),
    }

def train_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    models: Optional[Dict[str, Any]] = None,
    models_dir: Path = MODELS_DIR,
    save_artifacts: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Train multiple classification models on training features and target labels.

    Args:
        X_train: Preprocessed numerical training feature DataFrame.
        y_train: Encoded target labels.
        models: Optional dictionary of model instances. Defaults to DT, RF, LR.
        models_dir: Directory where trained artifacts will be saved.
        save_artifacts: Whether to save models to disk.

    Returns:
        Dictionary mapping model names to trained objects and training durations.
    """
    if models is None:
        models = get_default_models()

    models_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    feature_names = list(X_train.columns)

    for name, model in models.items():
        print(f"[INFO] Training {name.replace('_', ' ').title()} on {len(X_train)} samples...")
        start_time = time.time()
        model.fit(X_train, y_train)
        duration = time.time() - start_time
        print(f"[SUCCESS] {name} trained in {duration:.3f} seconds.")

        save_path = models_dir / f"{name}.joblib"
        if save_artifacts:
            joblib.dump(model, save_path)
            print(f"  Artifact saved to {save_path}")

        # If Decision Tree, export tree rules to JSON for C++ inference engine
        if name == "decision_tree" and save_artifacts:
            cpp_tree_path = models_dir / "decision_tree_cpp.json"
            export_decision_tree_to_json(
                model,
                feature_names=feature_names,
                output_path=cpp_tree_path,
            )
            print(f"  C++ tree model exported to {cpp_tree_path}")

        results[name] = {
            "model": model,
            "training_time_sec": duration,
            "artifact_path": str(save_path) if save_artifacts else None,
        }

    return results
