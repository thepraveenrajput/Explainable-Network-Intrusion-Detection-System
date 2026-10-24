#!/usr/bin/env bash
# ==============================================================================
# Intrusion XAI Framework - Test Runner Script
# ==============================================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

echo "============================================================"
echo "  Running C++17 Unit Tests via CTest / Binary               "
echo "============================================================"
if [ -f "cpp/build/cpp_tests" ]; then
    ./cpp/build/cpp_tests
else
    echo "Warning: cpp/build/cpp_tests not found. Building..."
    cmake -B cpp/build -S cpp
    cmake --build cpp/build
    ./cpp/build/cpp_tests
fi

echo "============================================================"
echo "  Running Python Automated Tests via Pytest                 "
echo "============================================================"
python -m pytest tests/ -v

echo "============================================================"
echo "  All Tests Completed Successfully!                         "
echo "============================================================"
