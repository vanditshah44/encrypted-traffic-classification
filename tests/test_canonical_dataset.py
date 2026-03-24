import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd
import yaml

from tls_dataset.pipeline.canonical import build_canonical_dataset, derive_protocol_family


class CanonicalDatasetTests(unittest.TestCase):
    def test_protocol_family_detection_is_strict(self) -> None:
        df = pd.DataFrame(
            {
                "application_name": ["TLS.Google", "QUIC.Google", "HTTP", "", None],
                "version": ["", "", "", "TLSv13", ""],
                "client_scid": ["", "", "", "", "abcd"],
            }
        )

        protocol_family = derive_protocol_family(df).tolist()
        self.assertEqual(protocol_family, ["tls", "quic", "other", "tls", "quic"])

    def test_build_canonical_dataset_filters_and_enriches_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            source_csv = tmp_path / "source.csv"
            quality_json = tmp_path / "quality.json"
            config_yaml = tmp_path / "canonical.yaml"
            output_csv = tmp_path / "canonical.csv"
            output_summary = tmp_path / "canonical_summary.json"

            pd.DataFrame(
                [
                    {
                        "application_name": "TLS.Google",
                        "bidirectional_first_seen_ms": 1000,
                        "bidirectional_last_seen_ms": 1200,
                        "bidirectional_packets": 10,
                    },
                    {
                        "application_name": "HTTP",
                        "bidirectional_first_seen_ms": 2000,
                        "bidirectional_last_seen_ms": 2200,
                        "bidirectional_packets": 4,
                    },
                    {
                        "application_name": "QUIC.Google",
                        "bidirectional_first_seen_ms": 61_500,
                        "bidirectional_last_seen_ms": 61_800,
                        "bidirectional_packets": 8,
                    },
                ]
            ).to_csv(source_csv, index=False)
            quality_json.write_text(json.dumps({"failed": True}), encoding="utf-8")
            config_yaml.write_text(
                yaml.safe_dump(
                    {
                        "version": 1,
                        "window_size_ms": 60_000,
                        "sources": [
                            {
                                "name": "sample_source",
                                "input_csv": str(source_csv),
                                "source_dataset": "sample_dataset",
                                "capture_id": "capture_alpha",
                                "label": "malicious",
                                "attack_family": "botnet",
                                "attack_category": "c2",
                                "traffic_role": "adversarial_activity",
                                "feature_view": "nfstream",
                                "encrypted_only": True,
                                "quality_report_json": str(quality_json),
                                "extra_labels": {
                                    "environment": "test_lab",
                                    "collection_origin": "unit_test",
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            summary = build_canonical_dataset(
                config_path=config_yaml,
                output_csv=output_csv,
                output_summary_json=output_summary,
            )
            result = pd.read_csv(output_csv)

            self.assertEqual(len(result), 2)
            self.assertEqual(set(result["protocol_family"]), {"tls", "quic"})
            self.assertEqual(set(result["quality_status"]), {"fail"})
            self.assertEqual(set(result["quality_failed"]), {True})
            self.assertEqual(set(result["environment"]), {"test_lab"})
            self.assertEqual(set(result["collection_origin"]), {"unit_test"})
            self.assertEqual(result["window_id"].tolist(), ["capture_alpha:w000000", "capture_alpha:w000001"])
            self.assertEqual(result["flow_start_ms"].tolist(), [1000, 61500])
            self.assertEqual(result["window_start_ms"].tolist(), [1000, 61000])
            self.assertEqual(summary["rows"], 2)
            self.assertEqual(summary["extra_label_columns"], ["collection_origin", "environment"])
