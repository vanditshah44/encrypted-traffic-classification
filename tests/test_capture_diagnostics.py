import unittest

import pandas as pd

from tls_dataset.ml.capture_diagnostics import (
    build_capture_distance_matrix,
    build_capture_distance_pairs,
    build_capture_feature_summary,
    build_capture_profile_matrix,
    prepare_diagnostic_features,
    top_shifted_features_between_captures,
)


class CaptureDiagnosticsTests(unittest.TestCase):
    def test_prepare_diagnostic_features_excludes_metadata_and_constant_columns(self) -> None:
        df = pd.DataFrame(
            {
                "record_id": ["a", "b", "c"],
                "capture_id": ["cap1", "cap1", "cap2"],
                "label": ["benign", "benign", "malicious"],
                "label_id": [0, 0, 1],
                "constant": [1, 1, 1],
                "useful": [0.1, 0.2, 0.9],
                "src_ip": ["1.1.1.1", "1.1.1.2", "1.1.1.3"],
            }
        )

        X, features, dropped = prepare_diagnostic_features(df, target_column="label_id")

        self.assertEqual(features, ["useful"])
        self.assertEqual(dropped, ["constant"])
        self.assertEqual(X.columns.tolist(), ["useful"])

    def test_distance_pairs_identify_cross_label_distances(self) -> None:
        distance_matrix = pd.DataFrame(
            {
                "ben": {"ben": 0.0, "mal": 2.0},
                "mal": {"ben": 2.0, "mal": 0.0},
            }
        )

        pairs = build_capture_distance_pairs(
            distance_matrix,
            {"ben": "benign", "mal": "malicious"},
        )

        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs.iloc[0]["pair_type"], "cross_label")
        self.assertAlmostEqual(pairs.iloc[0]["distance"], 2.0)

    def test_top_shifted_features_reports_largest_standardized_delta(self) -> None:
        profile = pd.DataFrame(
            {
                "feature_a": {"cap1": 0.0, "cap2": 10.0, "cap3": 1.0},
                "feature_b": {"cap1": 1.0, "cap2": 1.0, "cap3": 1.0},
            }
        )

        shifted = top_shifted_features_between_captures(
            profile,
            capture_a="cap1",
            capture_b="cap2",
            top_k=1,
        )

        self.assertEqual(shifted.iloc[0]["feature"], "feature_a")

    def test_feature_summary_profile_distance_pipeline(self) -> None:
        df = pd.DataFrame(
            {
                "capture_id": ["a", "a", "b", "b"],
                "label": ["benign", "benign", "malicious", "malicious"],
            }
        )
        X = pd.DataFrame({"feature": [0.0, 0.2, 1.0, 1.2]})

        summary = build_capture_feature_summary(df, X)
        profile = build_capture_profile_matrix(summary)
        distances = build_capture_distance_matrix(profile)

        self.assertEqual(set(profile.index), {"a", "b"})
        self.assertAlmostEqual(float(distances.loc["a", "a"]), 0.0)
        self.assertGreater(float(distances.loc["a", "b"]), 0.0)


if __name__ == "__main__":
    unittest.main()
