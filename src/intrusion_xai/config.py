"""
Configuration management for the Intrusion XAI Framework.

Centralizes paths, random seeds, model hyperparameters, and label definitions
to prevent hardcoding and ensure reproducibility across all modules.
"""

import os
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Set isolated cache directory for matplotlib before importing
os.environ.setdefault("MPLCONFIGDIR", str(PROJECT_ROOT / ".cache" / "matplotlib"))
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
METRICS_DIR = OUTPUTS_DIR / "metrics"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"

# Ensure runtime directories exist
for directory in [DATA_RAW_DIR, DATA_PROCESSED_DIR, MODELS_DIR, METRICS_DIR, PLOTS_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Experiment & Pipeline Settings
RANDOM_SEED: int = 42
TEST_SIZE: float = 0.20
VALIDATION_SIZE: float = 0.10

# Dataset Specifics for CIC-IDS2017
TARGET_COLUMN: str = "Label"
BENIGN_LABEL: str = "BENIGN"

# Columns with infinite or invalid semantics to drop or clean
DROP_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
]

# Serialized Model Artifact Names
DT_MODEL_PATH = MODELS_DIR / "decision_tree.joblib"
RF_MODEL_PATH = MODELS_DIR / "random_forest.joblib"
LR_MODEL_PATH = MODELS_DIR / "logistic_regression.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.joblib"
FEATURE_SCHEMA_PATH = MODELS_DIR / "feature_schema.json"
CPP_TREE_MODEL_PATH = MODELS_DIR / "decision_tree_cpp.json"
