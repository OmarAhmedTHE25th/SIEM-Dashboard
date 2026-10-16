#!/bin/sh
set -eu
name="$1"
mkdir -p "tests/detections/$name"
: > "tests/detections/$name/input.log"
printf '[]\n' > "tests/detections/$name/expected_alerts.json"
