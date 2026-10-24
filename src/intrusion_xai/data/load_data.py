"""
Data ingestion and schema validation for network intrusion detection records.

Handles loading of raw flow files (e.g., CIC-IDS2017), sanitizes column headers,
and performs data-quality validation (missing values, infinite values, duplicates).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from intrusion_xai.config import DATA_RAW_DIR, TARGET_COLUMN

def load_raw_data(
    file_path: Optional[Path | str] = None,
    nrows: Optional[int] = None,
) -> pd.DataFrame:
    """
    Load network traffic records from a CSV file into a pandas DataFrame.

    Automatically trims leading and trailing whitespaces from column headers,
    which is a known quirk in the CIC-IDS2017 dataset.

    Args:
        file_path: Path to the CSV file. If None, defaults to the sample in data/raw/.
        nrows: Optional maximum number of rows to read.

    Returns:
        pd.DataFrame containing sanitized column headers and raw records.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If the file is empty or cannot be parsed.
    """
    if file_path is None:
        sample_file = DATA_RAW_DIR / "cicids2017_sample.csv"
        raw_file = DATA_RAW_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        file_path = sample_file if sample_file.exists() else raw_file

    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(
            f"Dataset file not found at: {path}\n"
            "Please run 'python scripts/download_dataset.py' to obtain the dataset."
        )

    try:
        df = pd.read_csv(path, nrows=nrows, low_memory=False)
    except Exception as e:
        raise ValueError(f"Failed to parse CSV file at {path}: {e}") from e

    if df.empty:
        raise ValueError(f"The loaded dataset at {path} is empty.")

    # Sanitize column names: strip leading/trailing spaces
    df.columns = df.columns.str.strip()

    return df

def validate_schema(df: pd.DataFrame, target_col: str = TARGET_COLUMN) -> Dict[str, Any]:
    """
    Inspect and document dataset dimensions, missing values, infinite values,
    duplicate rows, and class balance.

    Args:
        df: Input pandas DataFrame.
        target_col: Expected label column name.

    Returns:
        Dictionary summarizing dataset statistics and quality issues.
    """
    if df.empty:
        return {"error": "Dataset is empty"}

    # Target column presence
    has_target = target_col in df.columns
    label_distribution = (
        df[target_col].value_counts().to_dict() if has_target else {}
    )

    # Missing values
    null_counts = df.isnull().sum()
    missing_dict = {col: int(cnt) for col, cnt in null_counts.items() if cnt > 0}

    # Infinite values in numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_dict = {}
    for col in numeric_cols:
        inf_count = int(np.isinf(df[col]).sum())
        if inf_count > 0:
            inf_dict[col] = inf_count

    # Duplicates
    num_duplicates = int(df.duplicated().sum())

    # Constant / zero-variance columns
    constant_cols = [
        col for col in numeric_cols if df[col].nunique(dropna=False) <= 1
    ]

    return {
        "row_count": int(len(df)),
        "col_count": int(df.shape[1]),
        "columns": list(df.columns),
        "target_column": target_col,
        "has_target": has_target,
        "label_distribution": label_distribution,
        "missing_values": missing_dict,
        "total_missing_cells": int(null_counts.sum()),
        "infinite_values": inf_dict,
        "total_infinite_cells": sum(inf_dict.values()),
        "duplicate_rows": num_duplicates,
        "constant_columns": constant_cols,
    }

def get_available_datasets(search_dir: Path = DATA_RAW_DIR) -> List[Path]:
    """
    List all available CSV files in the raw data directory.
    """
    if not search_dir.exists():
        return []
    return sorted(list(search_dir.glob("*.csv")))
