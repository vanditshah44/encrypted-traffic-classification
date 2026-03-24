import tempfile
import unittest
from pathlib import Path

from tls_dataset.pipeline.merge_features import resolve_tls_csv_path
from tls_dataset.pipeline.quality import check_zeek_outputs


class ZeekCompatibilityTests(unittest.TestCase):
    def test_zeek_quality_gate_accepts_tls_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "conn.csv").write_text("uid\nABC\n", encoding="utf-8")
            (tmp_path / "tls.csv").write_text("uid\nABC\n", encoding="utf-8")

            outcome = check_zeek_outputs(tmp_path)
            self.assertEqual(outcome.status, "pass")

    def test_resolve_tls_csv_path_prefers_ssl_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            ssl_path = tmp_path / "ssl.csv"
            tls_path = tmp_path / "tls.csv"
            ssl_path.write_text("uid\nSSL\n", encoding="utf-8")
            tls_path.write_text("uid\nTLS\n", encoding="utf-8")

            self.assertEqual(resolve_tls_csv_path(tmp_path), ssl_path.resolve())
