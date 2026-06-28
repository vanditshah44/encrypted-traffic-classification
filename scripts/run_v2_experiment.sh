#!/usr/bin/env bash
# =============================================================================
# EncFlow v2 experiment runner — ACSAC 2026
# =============================================================================
# This script orchestrates the complete re-run of the ML experiments.
# Run from the project root: bash scripts/run_v2_experiment.sh
#
# Prerequisites:
#   pip install xgboost shap
#   (or: pip install -e ".[dev]" after adding xgboost/shap to pyproject.toml)
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VENV_PIP="$ROOT/.venv/bin/pip"
VENV_PYTHON="$ROOT/.venv/bin/python"

echo "=== EncFlow v2 Experiment ==="
echo "Working directory: $ROOT"
echo "Date: $(date)"
echo

# --- Step 1: Install new dependencies ---
echo "[1/6] Installing xgboost and shap..."
"$VENV_PIP" install -e "." --quiet
echo "Done."
echo

# --- Step 2: Full feature set experiment (all 53 features incl. application DPI) ---
echo "[2/6] Running v2_full experiment (all features, XGBoost included)..."
"$VENV_PYTHON" -m tls_dataset.ml.workflow \
    --config configs/ml_workflow_v2.yaml \
    --output-dir artifacts/ml_workflow/v2_full
echo "Saved to artifacts/ml_workflow/v2_full/"
echo

# --- Step 3: Pure flow stats experiment (no application DPI features) ---
echo "[3/6] Running v2_pure_flow experiment (excluding application_is_guessed, application_confidence)..."
"$VENV_PYTHON" -m tls_dataset.ml.workflow \
    --config configs/ml_workflow_v2_pure_flow.yaml \
    --output-dir artifacts/ml_workflow/v2_pure_flow
echo "Saved to artifacts/ml_workflow/v2_pure_flow/"
echo

# --- Step 4: Feature ablation study ---
echo "[4/6] Running feature ablation study..."
"$VENV_PYTHON" -m tls_dataset.ml.ablation \
    --config configs/ml_workflow_v2.yaml \
    --output artifacts/ablation/latest
echo "Saved to artifacts/ablation/latest/"
echo

# --- Step 5: Artifact-resistant LOCO experiment ---
echo "[5/6] Running artifact-resistant LOCO experiment..."
"$VENV_PYTHON" -m tls_dataset.ml.artifact_resistant \
    --config configs/ml_workflow_v2.yaml \
    --output artifacts/artifact_resistant/latest \
    --max-groups 3 \
    --source-scope within_label \
    --models random_forest,xgboost
echo "Saved to artifacts/artifact_resistant/latest/"
echo

# --- Step 6: Multi-tier workflow (uses the trained models from v2_full) ---
echo "[6/6] Re-running multi-tier workflow..."
"$VENV_PYTHON" -m tls_dataset.detection.multitier \
    --config configs/multi_tier_workflow_v2.yaml
echo "Done."
echo

echo "=== All experiments complete ==="
echo
echo "Key output files:"
echo "  artifacts/ml_workflow/v2_full/model_comparison.csv    — all-features results"
echo "  artifacts/ml_workflow/v2_pure_flow/model_comparison.csv — pure flow stats results"
echo "  artifacts/ablation/latest/ablation_results.csv        — feature ablation table"
echo "  artifacts/artifact_resistant/latest/artifact_resistant_loco_summary.csv — cumulative source-artifact removal LOCO"
echo "  artifacts/multi_tier/v2_latest/workflow_summary.json  — multi-tier results"
echo
echo "Next: paste the numbers from model_comparison.csv into ACSAC2026_submission/main.tex"
