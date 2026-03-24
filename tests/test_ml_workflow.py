import unittest

import numpy as np
import pandas as pd

from tls_dataset.ml.workflow import evaluate_thresholds, select_best_threshold, select_feature_columns


class MLWorkflowTests(unittest.TestCase):
    def test_select_feature_columns_excludes_metadata_and_absolute_times(self) -> None:
        df = pd.DataFrame(
            {
                "record_id": ["a", "b"],
                "label_id": [0, 1],
                "flow_start_ms": [100, 200],
                "bidirectional_first_seen_ms": [100, 200],
                "duration": [10.0, 20.0],
                "packets": [1, 2],
                "src_ip": ["1.1.1.1", "2.2.2.2"],
            }
        )

        feature_columns, excluded = select_feature_columns(df, target_column="label_id")

        self.assertEqual(feature_columns, ["duration", "packets"])
        self.assertEqual(excluded["record_id"], "metadata")
        self.assertEqual(excluded["flow_start_ms"], "metadata")
        self.assertEqual(excluded["bidirectional_first_seen_ms"], "absolute_time")
        self.assertEqual(excluded["src_ip"], "non_numeric")

    def test_threshold_selection_returns_best_f1_threshold(self) -> None:
        y_true = pd.Series([0, 0, 1, 1])
        y_score = np.array([0.1, 0.4, 0.6, 0.9])

        frame = evaluate_thresholds(y_true, y_score, thresholds=np.array([0.3, 0.5, 0.7]))
        best = select_best_threshold(frame, "f1")

        self.assertAlmostEqual(best["threshold"], 0.5)
        self.assertAlmostEqual(best["f1"], 1.0)
