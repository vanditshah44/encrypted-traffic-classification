import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tls_dataset.pipeline.zeek_runner import resolve_zeek_binary


class ZeekRunnerTests(unittest.TestCase):
    def test_resolve_zeek_binary_prefers_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            zeek_path = Path(tmp_dir) / "zeek"
            zeek_path.write_text("#!/bin/sh\n", encoding="utf-8")

            with patch.dict("os.environ", {"ZEEK_BIN": str(zeek_path)}, clear=False):
                with patch("shutil.which", return_value=None):
                    self.assertEqual(resolve_zeek_binary(), str(zeek_path.resolve()))
