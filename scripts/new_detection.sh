#!/bin/sh
set -eu
name="$1"
mkdir -p "tests/detections/$name"
cat > "tests/detections/$name/input.log" <<'EOF'
# WARNING: replace this placeholder with a real log line before relying on this fixture.
EOF
cat > "tests/detections/$name/expected_alerts.json" <<'EOF'
{"expected": [], "not_expected": ["PLACEHOLDER"]}
EOF
echo "WARNING: created an intentionally incomplete fixture; add a real input and expected rule before using it."
