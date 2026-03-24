import unittest

import pandas as pd

from tls_dataset.detection.multitier import (
    assign_alert_level,
    build_connected_components,
    weighted_mean_scores,
)


class MultiTierDetectionTests(unittest.TestCase):
    def test_weighted_mean_scores_respects_weights(self) -> None:
        frame = pd.DataFrame(
            {
                "rf": [0.2, 0.8],
                "gb": [0.6, 0.4],
            }
        )
        scores = weighted_mean_scores(frame, {"rf": 1.0, "gb": 3.0})
        self.assertAlmostEqual(scores.iloc[0], 0.5)
        self.assertAlmostEqual(scores.iloc[1], 0.5)

    def test_build_connected_components_groups_linked_pairs(self) -> None:
        assignments = build_connected_components(
            [
                ("10.0.0.1", "10.0.0.2"),
                ("10.0.0.2", "8.8.8.8"),
                ("1.1.1.1", "9.9.9.9"),
            ]
        )
        self.assertEqual(assignments["10.0.0.1"], assignments["8.8.8.8"])
        self.assertNotEqual(assignments["10.0.0.1"], assignments["1.1.1.1"])

    def test_assign_alert_level_marks_high_when_all_deep_models_agree(self) -> None:
        alert_level = assign_alert_level(
            tier1_pass=pd.Series([True, True, False]),
            tier2_pass=pd.Series([True, False, False]),
            deep_pass_count=pd.Series([2, 0, 0]),
            deep_model_total=2,
            deep_consensus_score=pd.Series([0.95, 0.0, 0.0]),
        )
        self.assertEqual(alert_level.tolist(), ["high", "candidate", "none"])
