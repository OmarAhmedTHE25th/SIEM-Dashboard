"""Run one detection fixture through the same pipeline as the live agent."""
import argparse
from pathlib import Path

from main import build_pipeline, process_event
from parser import parse_line


parser = argparse.ArgumentParser()
parser.add_argument("fixture", help="Fixture directory containing input.log")
args = parser.parse_args()

pipeline = build_pipeline()
for line in (Path(args.fixture) / "input.log").read_text(encoding="utf-8").splitlines():
    event = parse_line(line)
    if event:
        for alert in process_event(event, pipeline):
            print(alert)
