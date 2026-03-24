"""Packet sanitization and filtering helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _require_tool(tool_name: str) -> str:
    resolved = shutil.which(tool_name)
    if resolved is None:
        raise FileNotFoundError(f"Required tool not found on PATH: {tool_name}")
    return resolved


def tool_version(tool_name: str, version_args: list[str] | None = None) -> str:
    binary = _require_tool(tool_name)
    args = [binary] + (version_args or ["--version"])
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    version_text = result.stdout.strip() or result.stderr.strip()
    return version_text.splitlines()[0] if version_text else tool_name


def sanitize_pcap(input_pcap: str | Path, output_pcap: str | Path) -> dict[str, str]:
    input_path = Path(input_pcap).expanduser().resolve()
    output_path = Path(output_pcap).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    binary = _require_tool("editcap")
    command = [binary, str(input_path), str(output_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.returncode != 0 and not output_path.exists():
        raise RuntimeError(
            f"editcap failed to sanitize {input_path}: {result.stderr.strip() or result.stdout.strip()}"
        )

    return {
        "input_pcap": str(input_path),
        "output_pcap": str(output_path),
        "command": " ".join(command),
        "stderr": result.stderr.strip(),
        "stdout": result.stdout.strip(),
        "tool_version": tool_version("editcap", ["--version"]),
    }


def filter_encrypted_pcap(
    input_pcap: str | Path,
    output_pcap: str | Path,
    *,
    display_filter: str = "tls or quic",
) -> dict[str, str]:
    input_path = Path(input_pcap).expanduser().resolve()
    output_path = Path(output_pcap).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    binary = _require_tool("tshark")
    command = [binary, "-r", str(input_path), "-Y", display_filter, "-w", str(output_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark failed to filter {input_path}: {result.stderr.strip() or result.stdout.strip()}"
        )
    if not output_path.exists():
        raise RuntimeError(f"tshark did not create the expected output file: {output_path}")

    return {
        "input_pcap": str(input_path),
        "output_pcap": str(output_path),
        "command": " ".join(command),
        "display_filter": display_filter,
        "stderr": result.stderr.strip(),
        "stdout": result.stdout.strip(),
        "tool_version": tool_version("tshark", ["-v"]),
    }
