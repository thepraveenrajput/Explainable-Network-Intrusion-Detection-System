"""
Unit tests for data loading and schema validation.
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from intrusion_xai.data.load_data import load_raw_data, validate_schema, get_available_datasets

def test_load_raw_data_file_not_found():
    """Verify FileNotFoundError is raised when file does not exist."""
    with pytest.raises(FileNotFoundError) as exc_info:
        load_raw_data("non_existent_path_12345.csv")
    assert "not found" in str(exc_info.value).lower()

def test_load_raw_data_trims_whitespace(tmp_path: Path):
    """Verify leading and trailing whitespaces in column names are automatically trimmed."""
    dummy_csv = tmp_path / "dummy_traffic.csv"
    dummy_csv.write_text(" Destination Port, Flow Duration, Label \n80,1500,BENIGN\n443,200,PortScan\n")

    df = load_raw_data(dummy_csv)
    assert list(df.columns) == ["Destination Port", "Flow Duration", "Label"]
    assert len(df) == 2
    assert df["Label"].tolist() == ["BENIGN", "PortScan"]

def test_validate_schema_metrics(tmp_path: Path):
    """Verify schema validator identifies missing values, infinite values, and label balance."""
    df = pd.DataFrame({
        "Flow Duration": [100.0, np.inf, 300.0, 400.0],
        "Total Fwd Packets": [1.0, 2.0, np.nan, 4.0],
        "Constant Col": [0.0, 0.0, 0.0, 0.0],
        "Label": ["BENIGN", "BENIGN", "PortScan", "PortScan"],
    })

    schema = validate_schema(df, target_col="Label")

    assert schema["row_count"] == 4
    assert schema["col_count"] == 4
    assert schema["has_target"] is True
    assert schema["label_distribution"] == {"BENIGN": 2, "PortScan": 2}
    assert "Total Fwd Packets" in schema["missing_values"]
    assert schema["missing_values"]["Total Fwd Packets"] == 1
    assert "Flow Duration" in schema["infinite_values"]
    assert schema["infinite_values"]["Flow Duration"] == 1
    assert "Constant Col" in schema["constant_columns"]

def test_get_available_datasets_empty_dir(tmp_path: Path):
    """Verify empty directory returns empty list without error."""
    assert get_available_datasets(tmp_path) == []
