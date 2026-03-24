"""Model bundle discovery helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from tls_dataset.backend.config import BackendSettings, get_backend_settings


@dataclass(frozen=True)
class ModelBundle:
    name: str
    path: Path
    workflow_summary_path: Path | None
    feature_manifest_path: Path
    model_names: tuple[str, ...]
    rows: int | None
    columns: int | None


def _read_summary(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def discover_model_bundles(root_dir: str | Path) -> list[ModelBundle]:
    root = Path(root_dir).expanduser().resolve()
    if not root.exists():
        return []

    bundles: list[ModelBundle] = []
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir():
            continue
        feature_manifest = candidate / "feature_manifest.json"
        if not feature_manifest.exists():
            continue
        model_names = tuple(
            sorted(
                child.name
                for child in candidate.iterdir()
                if child.is_dir() and (child / "model.joblib").exists()
            )
        )
        if not model_names:
            continue
        summary_path = candidate / "workflow_summary.json"
        summary = _read_summary(summary_path)
        bundles.append(
            ModelBundle(
                name=candidate.name,
                path=candidate,
                workflow_summary_path=summary_path if summary_path.exists() else None,
                feature_manifest_path=feature_manifest,
                model_names=model_names,
                rows=int(summary["rows"]) if isinstance(summary.get("rows"), int) else None,
                columns=int(summary["columns"]) if isinstance(summary.get("columns"), int) else None,
            )
        )
    return bundles


def resolve_model_bundle_dir(
    requested_dir: str | Path | None = None,
    *,
    settings: BackendSettings | None = None,
) -> Path:
    resolved_settings = settings or get_backend_settings()
    if requested_dir:
        candidate = Path(requested_dir).expanduser().resolve()
        if not (candidate / "feature_manifest.json").exists():
            raise FileNotFoundError(f"Model bundle is missing feature_manifest.json: {candidate}")
        return candidate
    if resolved_settings.default_model_bundle_dir is not None:
        return resolved_settings.default_model_bundle_dir

    latest_bundle = resolved_settings.model_bundle_root / "latest"
    if (latest_bundle / "feature_manifest.json").exists():
        return latest_bundle.resolve()

    bundles = discover_model_bundles(resolved_settings.model_bundle_root)
    if not bundles:
        raise FileNotFoundError(
            f"No model bundles discovered under {resolved_settings.model_bundle_root}"
        )
    return bundles[-1].path
