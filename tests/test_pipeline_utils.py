import tempfile
import unittest
from pathlib import Path

from tls_dataset.pipeline.common import build_dataset_artifacts
from tls_dataset.pipeline.zeek import parse_zeek_tsv_header, sniff_format


class PipelineUtilityTests(unittest.TestCase):
    def test_dataset_artifact_paths_are_parameterized(self) -> None:
        artifacts = build_dataset_artifacts(dataset_name="malicious", output_dir="/tmp/outputs")
        self.assertTrue(str(artifacts.nfstream_csv).endswith("/tmp/outputs/malicious_nfstream.csv"))
        self.assertTrue(str(artifacts.ml_final_csv).endswith("/tmp/outputs/malicious_ml_final.csv"))

    def test_sniff_format_detects_zeek_tsv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "conn.log"
            log_path.write_text("#separator \\x09\n#fields ts uid\n1.0\tABC\n", encoding="utf-8")
            self.assertEqual(sniff_format(log_path), "zeek_tsv")
            separator, fields = parse_zeek_tsv_header(log_path)
            self.assertEqual(separator, "\t")
            self.assertEqual(fields, ["ts", "uid"])

    def test_sniff_format_detects_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "ssl.log"
            log_path.write_text('{"uid":"ABC"}\n', encoding="utf-8")
            self.assertEqual(sniff_format(log_path), "json")
