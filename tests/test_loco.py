import unittest
from types import SimpleNamespace

import numpy as np
import pandas as pd

from tls_dataset.ml.loco import (
    binary_or_one_class_metrics,
    capture_label_summary,
    paired_capture_splits,
    prepare_loco_features,
    split_loco_capture,
)


class LocoEvaluationTests(unittest.TestCase):
    def test_split_loco_capture_isolates_test_capture(self) -> None:
        df = pd.DataFrame(
            {
                "capture_id": ["a", "a", "b", "c"],
                "label_id": [0, 0, 1, 1],
            }
        )

        train, test = split_loco_capture(df, test_capture_ids=("b",))

        self.assertEqual(test["capture_id"].tolist(), ["b"])
        self.assertNotIn("b", train["capture_id"].tolist())

    def test_binary_metrics_handles_malicious_only_holdout(self) -> None:
        metrics = binary_or_one_class_metrics(
            pd.Series([1, 1, 1, 1]),
            np.array([0.9, 0.8, 0.2, 0.7]),
        )

        self.assertEqual(metrics["metric_mode"], "malicious_only")
        self.assertEqual(metrics["tp"], 3)
        self.assertEqual(metrics["fn"], 1)
        self.assertAlmostEqual(metrics["positive_detection_rate"], 0.75)
        self.assertIsNone(metrics["roc_auc"])

    def test_binary_metrics_handles_benign_only_holdout(self) -> None:
        metrics = binary_or_one_class_metrics(
            pd.Series([0, 0, 0, 0]),
            np.array([0.1, 0.8, 0.2, 0.7]),
        )

        self.assertEqual(metrics["metric_mode"], "benign_only")
        self.assertEqual(metrics["fp"], 2)
        self.assertEqual(metrics["tn"], 2)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.5)
        self.assertIsNone(metrics["f1"])

    def test_capture_summary_and_pairs(self) -> None:
        df = pd.DataFrame(
            {
                "capture_id": ["ben1", "ben1", "mal1", "mal2"],
                "label": ["benign", "benign", "malicious", "malicious"],
                "label_id": [0, 0, 1, 1],
            }
        )

        summary = capture_label_summary(df)
        pairs = paired_capture_splits(summary)

        self.assertEqual(set(pairs), {("mal1", "ben1"), ("mal2", "ben1")})

    def test_prepare_loco_features_drops_training_only_unusable_columns(self) -> None:
        config = SimpleNamespace(
            target_column="label_id",
            extra_excluded_columns=(),
        )
        train = pd.DataFrame(
            {
                "record_id": ["a", "b", "c", "d"],
                "capture_id": ["train"] * 4,
                "label": ["benign", "malicious", "benign", "malicious"],
                "label_id": [0, 1, 0, 1],
                "constant": [1, 1, 1, 1],
                "useful": [0.1, 0.9, 0.2, 0.8],
                "src_ip": ["1.1.1.1"] * 4,
            }
        )
        test = pd.DataFrame(
            {
                "record_id": ["e", "f"],
                "capture_id": ["test"] * 2,
                "label": ["benign", "malicious"],
                "label_id": [0, 1],
                "constant": [1, 2],
                "useful": [0.3, 0.7],
                "src_ip": ["2.2.2.2"] * 2,
            }
        )

        X_train, X_test, y_train, y_test, features, dropped = prepare_loco_features(
            train,
            test,
            config=config,  # type: ignore[arg-type]
        )

        self.assertEqual(features, ["useful"])
        self.assertEqual(dropped, ["constant"])
        self.assertEqual(X_train.columns.tolist(), ["useful"])
        self.assertEqual(X_test.columns.tolist(), ["useful"])
        self.assertEqual(y_train.tolist(), [0, 1, 0, 1])
        self.assertEqual(y_test.tolist(), [0, 1])


if __name__ == "__main__":
    unittest.main()
