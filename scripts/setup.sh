#!/usr/bin/env bash
# ==============================================================================
# Intrusion XAI Framework - Setup and Environment Verification Script
# ==============================================================================

set -euo pipefail

echo "============================================================"
echo "  Intrusion XAI Framework: Environment Setup (macOS/Unix)   "
echo "============================================================"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo "[1/5] Checking macOS Architecture and System Tools..."
uname -m
git --version
clang++ --version | head -n 1
cmake --version | head -n 1

echo "[2/5] Locating Python..."
if [ -x "/opt/homebrew/bin/python3.12" ]; then
    PY_BIN="/opt/homebrew/bin/python3.12"
elif command -v python3.12 >/dev/null 2>&1; then
    PY_BIN="$(command -v python3.12)"
elif command -v python3.11 >/dev/null 2>&1; then
    PY_BIN="$(command -v python3.11)"
else
    PY_BIN="$(command -v python3)"
fi
echo "Using Python binary: $PY_BIN ($($PY_BIN --version))"

echo "[3/5] Setting up Virtual Environment (.venv)..."
if [ ! -d ".venv" ]; then
    "$PY_BIN" -m venv .venv
    echo "Created virtual environment at $PROJECT_DIR/.venv"
else
    echo "Virtual environment already exists."
fi

source .venv/bin/activate
pip install --upgrade pip

echo "[4/5] Installing Dependencies from requirements.txt..."
pip install -r requirements.txt
pip install -e .

echo "[5/5] Building C++17 Inference Engine with CMake..."
cmake -B cpp/build -S cpp
cmake --build cpp/build

echo "============================================================"
echo "  Setup Complete! Run './scripts/run_tests.sh' to verify.   "
echo "============================================================"
