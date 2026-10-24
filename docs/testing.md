# Testing Strategy & Test Suite Specification

## 1. Overview
The Intrusion XAI project employs a test-driven verification strategy across both Python and C++ components. All tests must be deterministic, reproducible, and verifiable via automated test runner scripts.

## 2. Test Suites

### A. Python Automated Tests (`tests/`)
1. **`test_environment.py`**:
   - Asserts Python version >= 3.11.
   - Asserts all core directories (`data/raw`, `data/processed`, `models`, `outputs`) exist.
   - Verifies C++ executable presence and standard execution.
2. **`test_data.py`**:
   - Asserts proper ingestion of raw CSV flow files.
   - Verifies automatic stripping of leading/trailing spaces in column headers.
   - Asserts graceful failure and clear error messages when required columns or files are missing.
3. **`test_preprocessing.py`**:
   - Asserts detection and handling of `+inf`, `-inf`, and `NaN` values.
   - Verifies that preprocessor parameters (means, scales, imputations) are calculated solely on training data with zero leakage to test data.
   - Validates that non-generalizable network identifiers (IP addresses, timestamps) are stripped.
4. **`test_training.py`**:
   - Verifies that Decision Tree, Random Forest, and baseline models train without errors on sample data.
   - Confirms that trained models and metadata are successfully serialized to `models/`.
5. **`test_prediction.py`**:
   - Asserts that predictions return expected classes (0 for Benign, 1 for Attack).
   - Validates that class probabilities are valid floating point values bounded in $[0.0, 1.0]$ and sum to 1.0.
6. **`test_explanations.py`**:
   - Verifies that permutation feature importance produces non-empty, finite score vectors matching feature dimensions.
   - Verifies that local attribution returns top features and weights without NaN/inf corruption.
7. **`test_cpp_integration.py`**:
   - Asserts that the Python-exported decision tree JSON schema is valid.
   - Runs the compiled C++ inference engine on identical sample records.
   - Asserts 100% parity between Python scikit-learn predictions and C++ native engine predictions.

### B. C++ Native Unit Tests (`cpp/tests/`)
- Verifies C++17 compliance at compile time.
- Validates JSON tree schema parsing and node traversal.
- Asserts strict handling of malformed input vectors (mismatched feature lengths, NaN values).

## 3. Running the Test Suites
Run the automated test runner:
```bash
./scripts/run_tests.sh
```
Or run pytest directly:
```bash
python -m pytest tests/ -v
```
