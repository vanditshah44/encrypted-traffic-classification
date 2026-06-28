import unittest
from types import SimpleNamespace

import pandas as pd

from tls_dataset.ml.capture_predictability import (
    build_capture_predictability_experiments,
    majority_baseline_accuracy,
    prepare_capture_source_features,
    save_capture_predictability_markdown,
    stratified_random_baseline_accuracy,
)


class CapturePredictabilityTests(unittest.TestCase):
    def test_prepare_capture_source_features_excludes_labels_and_metadata(self) -> None:
        config = SimpleNamespace(
            target_column="label_id",
            label_column="label",
            extra_excluded_columns=("environment",),
        )
        df = pd.DataFrame(
            {
                "record_id": ["a", "b", "c"],
                "capture_id": ["cap1", "cap1", "cap2"],
                "label": ["benign", "benign", "malicious"],
                "label_id": [0, 0, 1],
                "environment": ["lab", "lab", "ctu"],
                "constant": [1, 1, 1],
                "useful": [0.1, 0.2, 0.9],
            }
        )

        X, y, features, dropped = prepare_capture_source_features(
            df,
            config=config,  # type: ignore[arg-type]
        )

        self.assertEqual(y.tolist(), ["cap1", "cap1", "cap2"])
        self.assertEqual(features, ["useful"])
        self.assertEqual(dropped, ["constant"])
        self.assertEqual(X.columns.tolist(), ["useful"])

    def test_baselines_are_computed_from_class_distribution(self) -> None:
        y = pd.Series(["a", "a", "a", "b"])

        self.assertAlmostEqual(majority_baseline_accuracy(y), 0.75)
        self.assertAlmostEqual(stratified_random_baseline_accuracy(y), 0.625)

    def test_experiments_include_within_label_when_multiple_captures_exist(self) -> None:
        df = pd.DataFrame(
            {
                "capture_id": ["ben1", "ben2", "mal1", "mal2"],
                "label": ["benign", "benign", "malicious", "malicious"],
            }
        )

        experiments = build_capture_predictability_experiments(df)

        self.assertEqual([name for name, _ in experiments], ["all_captures", "benign_captures", "malicious_captures"])

    def test_markdown_summary_writer_has_expected_headers(self) -> None:
        from tempfile import TemporaryDirectory

        results = pd.DataFrame(
            {
                "experiment": ["all_captures"],
                "rows": [10],
                "capture_count": [2],
                "accuracy": [0.9],
                "balanced_accuracy": [0.8],
                "macro_f1": [0.7],
                "majority_baseline_accuracy": [0.6],
                "stratified_random_baseline_accuracy": [0.5],
            }
        )
        with TemporaryDirectory() as tmpdir:
            output_path = f"{tmpdir}/summary.md"
            save_capture_predictability_markdown(results, output_path)

            with open(output_path, encoding="utf-8") as handle:
                content = handle.read()

        self.assertIn("Experiment", content)
        self.assertIn("All captures", content)


if __name__ == "__main__":
    unittest.main()
