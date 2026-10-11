import unittest
from unittest.mock import patch

from ml_engine import AnomalyScorer, severity_from_score


class StubModel:
    def decision_function(self, features):
        self.features = features
        return [-0.2]


class AnomalyScorerTests(unittest.TestCase):
    def test_maps_scores_to_severity_levels(self):
        self.assertEqual(severity_from_score(-0.2), "CRITICAL")
        self.assertEqual(severity_from_score(-0.01), "HIGH")
        self.assertEqual(severity_from_score(0.04), "MEDIUM")
        self.assertEqual(severity_from_score(0.05), "LOW")

    def test_is_not_ready_when_model_cannot_be_loaded(self):
        with patch("ml_engine.joblib.load", side_effect=FileNotFoundError):
            scorer = AnomalyScorer()

        self.assertFalse(scorer.is_ready)
        self.assertEqual(scorer.score_ip_behavior({}), (False, 0.0))

    def test_scores_features_and_applies_threshold(self):
        model = StubModel()
        with patch("ml_engine.joblib.load", return_value=model):
            scorer = AnomalyScorer(score_threshold=0.05)

        anomaly, score = scorer.score_ip_behavior(
            {
                "total_attempts": 10,
                "failure_rate": 1.0,
                "unique_users": 4,
                "mean_interval": 2.0,
                "std_interval": 0.5,
            }
        )

        self.assertTrue(anomaly)
        self.assertEqual(score, -0.2)
        self.assertEqual(list(model.features.columns), [
            "total_attempts",
            "failure_rate",
            "unique_users",
            "mean_interval",
            "std_interval",
        ])


if __name__ == "__main__":
    unittest.main()
