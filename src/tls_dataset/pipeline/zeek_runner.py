"""Local Zeek execution helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


DEFAULT_ZEEK_CANDIDATES = (
    "/opt/zeek/bin/zeek",
    "/usr/local/zeek/bin/zeek",
    "/usr/bin/zeek",
)


def resolve_zeek_binary() -> str | None:
    env_binary = os.environ.get("ZEEK_BIN")
    candidates = [env_binary] if env_binary else []
    path_binary = shutil.which("zeek")
    if path_binary:
        candidates.append(path_binary)
    candidates.extend(DEFAULT_ZEEK_CANDIDATES)

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and path.is_file():
            return str(path.resolve())
    return None


def zeek_available() -> bool:
    return resolve_zeek_binary() is not None


def run_zeek_on_pcap(
    input_pcap: str | Path,
    output_dir: str | Path,
    *,
    extra_args: list[str] | None = None,
) -> dict[str, str]:
    binary = resolve_zeek_binary()
    if binary is None:
        raise FileNotFoundError("zeek binary not found on PATH or in standard install locations")

    input_path = Path(input_pcap).expanduser().resolve()
    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    command = [binary, "-C", "-r", str(input_path)] + (extra_args or [])
    result = subprocess.run(command, cwd=out_dir, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Zeek failed on {input_path}: {result.stderr.strip() or result.stdout.strip()}")

    version_result = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
    version_text = version_result.stdout.strip() or version_result.stderr.strip()

    return {
        "input_pcap": str(input_path),
        "output_dir": str(out_dir),
        "command": " ".join(command),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "tool_version": version_text.splitlines()[0] if version_text else "zeek",
    }
