import unittest

import numpy as np
import pandas as pd

from tls_dataset.ml.ablation import (
    _binary_metrics,
    _drop_unusable_training_columns,
    _group_columns,
)


class AblationTests(unittest.TestCase):
    def test_group_columns_matches_patterns(self) -> None:
        feature_columns = [
            "bidirectional_mean_piat_ms",
            "src2dst_packets",
            "application_confidence",
            "dst_port",
        ]

        matched = _group_columns(feature_columns, ["piat_ms", "application"])

        self.assertEqual(matched, ["bidirectional_mean_piat_ms", "application_confidence"])

    def test_drop_unusable_training_columns_uses_training_only(self) -> None:
        train = pd.DataFrame(
            {
                "constant": [1, 1, 1],
                "all_missing": [np.nan, np.nan, np.nan],
                "useful": [1.0, 2.0, 3.0],
            }
        )
        test = pd.DataFrame(
            {
                "constant": [1, 2],
                "all_missing": [5.0, 6.0],
                "useful": [4.0, 5.0],
            }
        )

        cleaned_train, cleaned_test, dropped = _drop_unusable_training_columns(train, test)

        self.assertEqual(dropped, ["all_missing", "constant"])
        self.assertEqual(cleaned_train.columns.tolist(), ["useful"])
        self.assertEqual(cleaned_test.columns.tolist(), ["useful"])

    def test_binary_metrics_reports_threshold_metrics(self) -> None:
        y_true = pd.Series([0, 0, 1, 1])
        probabilities = np.array([0.1, 0.6, 0.7, 0.9])

        metrics = _binary_metrics(y_true, probabilities)

        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 1.0)
        self.assertAlmostEqual(metrics["specificity"], 0.5)
        self.assertEqual(metrics["tp"], 2)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["tn"], 1)
        self.assertEqual(metrics["fn"], 0)


if __name__ == "__main__":
    unittest.main()
