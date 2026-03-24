import csv
import json
import tempfile
import unittest
from pathlib import Path

from tls_dataset.pipeline.malicious import resolve_manifest_source
from tls_dataset.pipeline.provenance import build_provenance_entry, write_provenance


class ProvenanceAndMaliciousUtilityTests(unittest.TestCase):
    def test_build_provenance_entry_hashes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.bin"
            path.write_bytes(b"abc123")
            entry = build_provenance_entry(stage="raw", path=path)
            self.assertEqual(entry.size_bytes, 6)
            self.assertEqual(len(entry.sha256), 64)

    def test_write_provenance_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.bin"
            out = Path(tmp_dir) / "prov.json"
            path.write_bytes(b"payload")
            entry = build_provenance_entry(stage="raw", path=path)
            write_provenance([entry], out)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["entries"]), 1)
            self.assertEqual(payload["entries"][0]["stage"], "raw")

    def test_resolve_manifest_source_by_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = Path(tmp_dir) / "manifest.csv"
            capture = Path(tmp_dir) / "capture1.pcap"
            capture.write_bytes(b"pcap")
            with manifest.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["url", "rel_path", "local_path"])
                writer.writeheader()
                writer.writerow({
                    "url": "https://example.test/capture1.pcap",
                    "rel_path": "botnet/capture1.pcap",
                    "local_path": "/some/other/place/capture1.pcap",
                })

            url, rel_path = resolve_manifest_source(capture, manifest)
            self.assertEqual(url, "https://example.test/capture1.pcap")
            self.assertEqual(rel_path, "botnet/capture1.pcap")
