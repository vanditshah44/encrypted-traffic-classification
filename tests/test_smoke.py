import unittest

from tls_dataset import __version__
from tls_dataset.cli import build_parser
from tls_dataset.technical_direction import TECHNICAL_DIRECTION


class SmokeTests(unittest.TestCase):
    def test_version_is_defined(self) -> None:
        self.assertEqual(__version__, "0.1.0")

    def test_info_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["info"])
        self.assertEqual(args.command, "info")

    def test_run_pipeline_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run-dataset-pipeline", "--dataset-name", "sample", "--output-dir", "out"])
        self.assertEqual(args.command, "run-dataset-pipeline")

    def test_run_malicious_pipeline_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["run-malicious-pipeline", "--dataset-name", "mal", "--input-pcap", "x.pcapng", "--output-dir", "out"]
        )
        self.assertEqual(args.command, "run-malicious-pipeline")

    def test_build_canonical_dataset_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["build-canonical-dataset", "--config", "configs/canonical_sources.yaml", "--output-csv", "out.csv"]
        )
        self.assertEqual(args.command, "build-canonical-dataset")

    def test_run_ml_workflow_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run-ml-workflow", "--config", "configs/ml_workflow.yaml"])
        self.assertEqual(args.command, "run-ml-workflow")

    def test_run_multi_tier_command_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["run-multi-tier", "--config", "configs/multi_tier_workflow.yaml"])
        self.assertEqual(args.command, "run-multi-tier")

    def test_production_extraction_stack_is_standardized(self) -> None:
        self.assertEqual(TECHNICAL_DIRECTION.production_extractors, ("zeek", "nfstream"))
        self.assertEqual(TECHNICAL_DIRECTION.thesis_legacy_extractors, ("cicflowmeter",))
