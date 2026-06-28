import unittest

import pandas as pd

from tls_dataset.reporting.wtmc_figures import (
    add_capture_pair_key,
    build_loco_distance_correlations,
    build_loco_distance_frame,
    build_ranked_capture_pair_table,
    normalize_capture_pair,
)


class WtmcFiguresTests(unittest.TestCase):
    def test_normalize_capture_pair_is_order_independent(self) -> None:
        self.assertEqual(
            normalize_capture_pair("malicious_cap", "benign_cap"),
            normalize_capture_pair("benign_cap", "malicious_cap"),
        )

    def test_add_capture_pair_key_uses_test_capture_ids(self) -> None:
        frame = pd.DataFrame({"test_capture_ids": ["cap_b,cap_a"]})

        keyed = add_capture_pair_key(frame)

        self.assertEqual(keyed.iloc[0]["capture_pair_key"], "cap_a__cap_b")

    def test_loco_distance_join_and_correlations(self) -> None:
        metrics = pd.DataFrame(
            {
                "split_name": ["pair_a_b", "pair_a_c", "pair_a_b", "pair_a_c"],
                "split_kind": ["malicious_benign_pair"] * 4,
                "test_capture_ids": ["a,b", "a,c", "a,b", "a,c"],
                "model": ["rf", "rf", "gb", "gb"],
                "f1": [0.9, 0.5, 0.8, 0.4],
                "roc_auc": [0.95, 0.7, 0.9, 0.6],
                "average_precision": [0.96, 0.65, 0.88, 0.55],
            }
        )
        distances = pd.DataFrame(
            {
                "capture_a": ["a", "a"],
                "capture_b": ["b", "c"],
                "label_a": ["malicious", "malicious"],
                "label_b": ["benign", "benign"],
                "pair_type": ["cross_label", "cross_label"],
                "distance": [1.0, 3.0],
            }
        )

        joined = build_loco_distance_frame(metrics, distances)
        correlations = build_loco_distance_correlations(joined, metrics=("f1",))

        self.assertEqual(len(joined), 4)
        self.assertTrue((correlations["pearson_r"] < 0).all())

    def test_ranked_capture_pair_table_keeps_largest_distance_first(self) -> None:
        joined = pd.DataFrame(
            {
                "capture_pair_key": ["a__b", "a__c"],
                "capture_a": ["a", "a"],
                "capture_b": ["b", "c"],
                "label_a": ["malicious", "malicious"],
                "label_b": ["benign", "benign"],
                "pair_type": ["cross_label", "cross_label"],
                "distance": [1.0, 3.0],
                "model": ["rf", "rf"],
                "f1": [0.9, 0.5],
                "roc_auc": [0.95, 0.7],
            }
        )

        table = build_ranked_capture_pair_table(joined, top_n=1)

        self.assertEqual(table.iloc[0]["capture_pair_key"], "a__c")


if __name__ == "__main__":
    unittest.main()
