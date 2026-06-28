import tempfile
import unittest
from pathlib import Path

import pandas as pd
import yaml

from tls_dataset.ml.artifact_resistant import (
    add_baseline_deltas,
    build_cumulative_removal_plan,
    rank_source_predictive_feature_groups,
    rank_within_label_source_predictive_feature_groups,
    run_artifact_resistant_loco,
)
from tls_dataset.ml.workflow import load_workflow_config


class ArtifactResistantTests(unittest.TestCase):
    def test_removal_plan_is_cumulative_and_skips_zero_importance_groups(self) -> None:
        ranking = pd.DataFrame(
            {
                "group": ["port_protocol", "timing_iat", "tcp_flags"],
                "source_importance": [0.4, 0.2, 0.0],
                "feature_count": [2, 1, 1],
            }
        )

        plan = build_cumulative_removal_plan(ranking, max_groups=3)

        self.assertEqual(
            plan,
            [
                {"variant": "baseline", "removed_groups": [], "removed_group_count": 0},
                {
                    "variant": "remove_top_1_source_groups",
                    "removed_groups": ["port_protocol"],
                    "removed_group_count": 1,
                },
                {
                    "variant": "remove_top_2_source_groups",
                    "removed_groups": ["port_protocol", "timing_iat"],
                    "removed_group_count": 2,
                },
            ],
        )

    def test_add_baseline_deltas_is_per_model(self) -> None:
        frame = pd.DataFrame(
            {
                "variant": ["baseline", "remove_top_1_source_groups", "baseline", "remove_top_1_source_groups"],
                "model": ["a", "a", "b", "b"],
                "f1_mean": [0.8, 0.7, 0.5, 0.6],
                "f1_weighted_by_rows": [0.8, 0.75, 0.5, 0.55],
                "roc_auc_mean": [0.9, 0.85, 0.7, 0.6],
                "roc_auc_weighted_by_rows": [0.9, 0.82, 0.7, 0.65],
            }
        )

        result = add_baseline_deltas(frame)

        self.assertAlmostEqual(
            float(result.loc[1, "f1_mean_delta_vs_baseline"]),
            -0.1,
        )
        self.assertAlmostEqual(
            float(result.loc[3, "f1_mean_delta_vs_baseline"]),
            0.1,
        )

    def test_rank_source_predictive_groups_aggregates_importance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dataset = root / "dataset.csv"
            config_path = root / "config.yaml"
            pd.DataFrame(
                {
                    "record_id": [f"r{i}" for i in range(8)],
                    "capture_id": ["cap_a"] * 4 + ["cap_b"] * 4,
                    "label": ["benign"] * 8,
                    "label_id": [0] * 8,
                    "dst_port": [443, 443, 443, 443, 8443, 8443, 8443, 8443],
                    "bidirectional_mean_piat_ms": [1, 2, 1, 2, 8, 9, 8, 9],
                    "application_confidence": [0.9] * 8,
                }
            ).to_csv(dataset, index=False)
            _write_config(config_path, dataset, root)
            config = load_workflow_config(config_path)
            df = pd.read_csv(config.dataset_csv)

            ranking, feature_importance = rank_source_predictive_feature_groups(
                df,
                config=config,
                n_estimators=20,
                n_jobs=1,
            )

            self.assertIn("port_protocol", ranking["group"].tolist())
            self.assertIn("timing_iat", ranking["group"].tolist())
            self.assertFalse(feature_importance.empty)
            self.assertGreater(ranking["source_importance"].sum(), 0.0)

    def test_within_label_ranking_reports_per_scope_importance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dataset = root / "dataset.csv"
            config_path = root / "config.yaml"
            pd.DataFrame(
                {
                    "record_id": [f"r{i}" for i in range(16)],
                    "capture_id": ["ben1"] * 4 + ["ben2"] * 4 + ["mal1"] * 4 + ["mal2"] * 4,
                    "label": ["benign"] * 8 + ["malicious"] * 8,
                    "label_id": [0] * 8 + [1] * 8,
                    "dst_port": [443] * 4 + [8443] * 4 + [443] * 4 + [9443] * 4,
                    "bidirectional_mean_piat_ms": [1, 2, 1, 2, 3, 4, 3, 4, 8, 9, 8, 9, 10, 11, 10, 11],
                }
            ).to_csv(dataset, index=False)
            _write_config(config_path, dataset, root)
            config = load_workflow_config(config_path)
            df = pd.read_csv(config.dataset_csv)

            ranking, feature_importance = rank_within_label_source_predictive_feature_groups(
                df,
                config=config,
                n_estimators=20,
                n_jobs=1,
            )

            self.assertIn("benign_source_importance", ranking.columns)
            self.assertIn("malicious_source_importance", ranking.columns)
            self.assertIn("scope", feature_importance.columns)
            self.assertEqual(set(feature_importance["scope"]), {"benign", "malicious"})

    def test_run_artifact_resistant_loco_writes_variant_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dataset = root / "dataset.csv"
            config_path = root / "config.yaml"
            output = root / "artifact_resistant"
            frame = pd.DataFrame(
                {
                    "record_id": [f"r{i}" for i in range(16)],
                    "capture_id": ["ben1"] * 4 + ["ben2"] * 4 + ["mal1"] * 4 + ["mal2"] * 4,
                    "label": ["benign"] * 8 + ["malicious"] * 8,
                    "label_id": [0] * 8 + [1] * 8,
                    "dst_port": [443] * 4 + [8443] * 4 + [443] * 4 + [9443] * 4,
                    "bidirectional_mean_piat_ms": [1, 2, 1, 2, 3, 4, 3, 4, 8, 9, 8, 9, 10, 11, 10, 11],
                    "src2dst_packets": [2, 2, 3, 3, 2, 3, 2, 3, 9, 9, 10, 10, 9, 10, 9, 10],
                }
            )
            frame.to_csv(dataset, index=False)
            _write_config(config_path, dataset, root, random_state=7)

            summary = run_artifact_resistant_loco(
                config_path=config_path,
                output_dir=output,
                max_groups=1,
                include_pairwise=False,
                model_names=("gaussian_nb",),
                n_estimators=20,
                n_jobs=1,
            )

            self.assertTrue(Path(summary["ranking_csv"]).exists())
            self.assertTrue(Path(summary["summary_csv"]).exists())
            combined = pd.read_csv(summary["summary_csv"])
            self.assertIn("baseline", combined["variant"].tolist())
            self.assertIn("remove_top_1_source_groups", combined["variant"].tolist())

def _write_config(config: Path, dataset: Path, root: Path, *, random_state: int = 3) -> None:
    config.write_text(
        yaml.safe_dump(
            {
                "dataset_csv": str(dataset),
                "output_dir": str(root / "workflow"),
                "target_column": "label_id",
                "label_column": "label",
                "record_id_column": "record_id",
                "positive_label": 1,
                "test_size": 0.2,
                "random_state": random_state,
                "cv_folds": 2,
                "models": {"gaussian_nb": {}},
            }
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
