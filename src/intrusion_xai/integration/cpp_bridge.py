"""
C++17 native inference engine integration and verification bridge.

Spawns the compiled C++17 binary to perform deterministic, sub-millisecond
decision tree inference and verifies 100% prediction parity between Python
and native compiled code.
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np
import pandas as pd

from intrusion_xai.config import CPP_TREE_MODEL_PATH, PROJECT_ROOT

CPP_BUILD_DIR = PROJECT_ROOT / "cpp" / "build"
CPP_EXECUTABLE = CPP_BUILD_DIR / "cpp_inference_engine"

def get_cpp_engine_binary() -> Path:
    """
    Ensure the C++ engine executable exists; triggers CMake build if missing.
    """
    if not CPP_EXECUTABLE.exists():
        print(f"[INFO] C++ binary not found at {CPP_EXECUTABLE}. Invoking CMake build...")
        subprocess.run(["cmake", "-B", str(CPP_BUILD_DIR), "-S", str(PROJECT_ROOT / "cpp")], check=True)
        subprocess.run(["cmake", "--build", str(CPP_BUILD_DIR)], check=True)

    if not CPP_EXECUTABLE.exists():
        raise FileNotFoundError(f"Failed to build C++ inference engine at {CPP_EXECUTABLE}")

    return CPP_EXECUTABLE

def predict_single_cpp(
    features: Sequence[Union[float, int]],
    model_path: Path = CPP_TREE_MODEL_PATH,
) -> Dict[str, Any]:
    """
    Execute native C++ inference on a single feature vector.

    Args:
        features: Sequence of numeric feature values (length must match model feature count).
        model_path: Path to exported decision tree JSON schema.

    Returns:
        Dictionary with predicted_class, threat_score, leaf_node, and probabilities.
    """
    engine_bin = get_cpp_engine_binary()

    if not model_path.exists():
        raise FileNotFoundError(f"C++ model schema not found at {model_path}")

    # Format comma-separated features string
    csv_str = ",".join(str(float(x)) for x in features)

    cmd = [
        str(engine_bin),
        "--model", str(model_path),
        "--features", csv_str,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"C++ engine returned empty output. Stderr: {result.stderr}")

    try:
        res_json = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse C++ engine JSON response: '{stdout}'") from e

    if res_json.get("status") != "success":
        err_msg = res_json.get("message", "Unknown error in C++ engine")
        err_type = res_json.get("error_type", "error")
        if err_type == "invalid_argument":
            raise ValueError(f"C++ Engine Invalid Argument: {err_msg}")
        raise RuntimeError(f"C++ Engine Error: {err_msg}")

    return res_json

def verify_python_cpp_parity(
    X_test: pd.DataFrame,
    py_model: Any,
    max_samples: int = 500,
    model_path: Path = CPP_TREE_MODEL_PATH,
) -> Dict[str, Any]:
    """
    Rigorously compare Python scikit-learn predictions and C++ native predictions
    on identical held-out test records to ensure 100% equivalence.

    Args:
        X_test: Test features DataFrame.
        py_model: Trained scikit-learn DecisionTreeClassifier.
        max_samples: Number of sample records to test.
        model_path: Path to exported C++ tree model.

    Returns:
        Structured dictionary reporting match counts, mismatches, and parity rate.
    """
    samples = X_test.head(max_samples)
    print(f"[INFO] Verifying cross-language parity on {len(samples)} test records...")

    py_preds = py_model.predict(samples)

    matches = 0
    mismatches = []

    for idx, (_, row) in enumerate(samples.iterrows()):
        cpp_res = predict_single_cpp(row.values, model_path=model_path)
        cpp_pred = cpp_res["predicted_class"]
        py_pred = int(py_preds[idx])

        if cpp_pred == py_pred:
            matches += 1
        else:
            mismatches.append({
                "sample_index": idx,
                "python_prediction": py_pred,
                "cpp_prediction": cpp_pred,
                "features": row.to_dict(),
            })

    total = len(samples)
    parity_rate = (matches / total) * 100.0 if total > 0 else 0.0

    report = {
        "samples_tested": total,
        "matches": matches,
        "mismatches_count": len(mismatches),
        "parity_percentage": np.round(parity_rate, 2),
        "is_parity_achieved": (matches == total),
        "mismatches": mismatches[:5],
    }

    print(
        f"[RESULT] Parity Verification Complete: {matches}/{total} matches "
        f"({parity_rate:.2f}% parity)"
    )

    return report
