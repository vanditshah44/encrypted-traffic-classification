import csv
import tempfile
import unittest
from pathlib import Path

from tls_dataset.pipeline.quality import (
    check_merged_dataset,
    check_nfstream_csv,
    is_truncation_warning,
    row_has_encrypted_signal,
)


class QualityGateTests(unittest.TestCase):
    def test_truncation_warning_detection(self) -> None:
        stderr_text = "The file appears to have been cut short in the middle of a packet."
        self.assertTrue(is_truncation_warning(stderr_text))

    def test_row_encrypted_signal_detection(self) -> None:
        fieldnames = ["uid", "version", "server_name_zeek_quic", "client_scid"]
        self.assertTrue(row_has_encrypted_signal({"version": "TLSv13"}, fieldnames))
        self.assertTrue(row_has_encrypted_signal({"client_scid": "abcd"}, fieldnames))
        self.assertFalse(row_has_encrypted_signal({}, fieldnames))

    def test_nfstream_duplicate_flow_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "nf.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bidirectional_first_seen_ms"
                ])
                writer.writeheader()
                writer.writerow({
                    "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": "1111", "dst_port": "443",
                    "protocol": "6", "bidirectional_first_seen_ms": "1000"
                })
                writer.writerow({
                    "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": "1111", "dst_port": "443",
                    "protocol": "6", "bidirectional_first_seen_ms": "1000"
                })

            outcome = check_nfstream_csv(path)
            self.assertEqual(outcome.status, "fail")

    def test_merged_dataset_leakage_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "merged.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "uid", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                    "bidirectional_first_seen_ms", "version", "client_scid"
                ])
                writer.writeheader()
                writer.writerow({
                    "uid": "UID1", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": "1111",
                    "dst_port": "443", "protocol": "6", "bidirectional_first_seen_ms": "1000",
                    "version": "TLSv13", "client_scid": ""
                })
                writer.writerow({
                    "uid": "", "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4", "src_port": "2222",
                    "dst_port": "443", "protocol": "6", "bidirectional_first_seen_ms": "2000",
                    "version": "", "client_scid": ""
                })

            outcome = check_merged_dataset(
                path,
                min_match_rate=0.90,
                max_unmatched_uid_rate=0.10,
                max_non_tls_quic_rate=0.05,
                max_duplicate_uid_rate=0.0,
            )
            self.assertEqual(outcome.status, "fail")
