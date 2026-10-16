import argparse
from detection_fixtures import run_fixture
from engine import BruteForceDetector

parser = argparse.ArgumentParser()
parser.add_argument("fixture")
args = parser.parse_args()
for alert in run_fixture(args.fixture, BruteForceDetector(threshold=3, window_seconds=60)):
    print(alert)
