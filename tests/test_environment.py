"""
Phase 1: Environment & Sanity Verification Tests.
"""

import sys
import subprocess
from pathlib import Path
from intrusion_xai.config import (
    PROJECT_ROOT,
    DATA_RAW_DIR,
    DATA_PROCESSED_DIR,
    MODELS_DIR,
    OUTPUTS_DIR,
    RANDOM_SEED,
)

def test_python_version():
    """Verify Python version is at least 3.11."""
    assert sys.version_info >= (3, 11), f"Requires Python >= 3.11, found {sys.version}"

def test_project_structure_paths():
    """Verify key project directories exist and are configured."""
    assert PROJECT_ROOT.is_dir(), f"Project root does not exist: {PROJECT_ROOT}"
    assert DATA_RAW_DIR.is_dir(), f"Raw data directory does not exist: {DATA_RAW_DIR}"
    assert DATA_PROCESSED_DIR.is_dir(), f"Processed data directory does not exist: {DATA_PROCESSED_DIR}"
    assert MODELS_DIR.is_dir(), f"Models directory does not exist: {MODELS_DIR}"
    assert OUTPUTS_DIR.is_dir(), f"Outputs directory does not exist: {OUTPUTS_DIR}"
    assert RANDOM_SEED == 42, "Reproducible random seed must be 42"

def test_cpp_engine_smoke():
    """Verify C++ engine binary was compiled and executes with exit code 0."""
    engine_bin = PROJECT_ROOT / "cpp" / "build" / "cpp_inference_engine"
    assert engine_bin.exists(), f"C++ binary not found at {engine_bin}. Run cmake build first."
    result = subprocess.run([str(engine_bin)], capture_output=True, text=True)
    assert result.returncode == 0, f"C++ engine failed: {result.stderr}"
    assert "C++17 standard verified" in result.stdout
