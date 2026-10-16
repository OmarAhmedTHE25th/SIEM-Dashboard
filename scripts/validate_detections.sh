#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if command -v py >/dev/null 2>&1; then
    PYTHON=py
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

echo "Running deterministic detection fixtures and ATT&CK mapping checks..."
cd "$ROOT"
"$PYTHON" scripts/validate_detections.py
