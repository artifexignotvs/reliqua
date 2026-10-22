#!/usr/bin/env python3
"""Run the pinned lab without access to host files, ports, or runtime networking."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
try:
    from .common import source_fingerprint
except ImportError:
    from common import source_fingerprint

ROOT = Path(__file__).resolve().parents[1]
TAG = "reliqua-comparison-lab:1"


def checked(label: str, command: list[str], output: Path, timeout: int) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        (output / (label + ".stdout")).write_bytes(error.stdout or b"")
        (output / (label + ".stderr")).write_bytes(error.stderr or b"")
        raise ValueError(label + " timed out; see the private run directory") from error
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    if result.returncode:
        raise ValueError(label + " failed; see the private run directory")
    return result


def cleanup(name: str, output: Path) -> bool:
    succeeded = True
    commands = (
        ("stop", ["docker", "stop", "--time", "5", name], 15),
        ("copy", ["docker", "cp", name + ":/results", str(output / "raw")], 30),
        ("remove", ["docker", "rm", "--force", name], 30),
    )
    # Etiam post errorem, reliquiae auferantur.
    for label, command, timeout in commands:
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
            (output / ("cleanup-" + label + ".stderr")).write_bytes(result.stderr)
            if result.returncode:
                succeeded = False
        except (OSError, subprocess.SubprocessError):
            succeeded = False
        if label == "remove" and not succeeded:
            print("Cleanup or evidence transfer failed; check the private logs and container " + name + ".", file=sys.stderr)
    return succeeded


def main() -> int:
    os.umask(0o077)
    suffix = uuid.uuid4().hex[:12]
    name = "reliqua-lab-" + suffix
    output = ROOT / "reports" / ("lab-" + suffix)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    print("Private run directory: " + str(output.relative_to(ROOT)), flush=True)
    started = time.monotonic()
    created = False
    exit_code = 1
    try:
        image = json.loads(checked("image-inspect", ["docker", "image", "inspect", TAG], output, 15).stdout)[0]
        expected_source = source_fingerprint(ROOT)
        if image.get("Config", {}).get("Labels", {}).get("org.reliqua.lab.source-sha256") != expected_source:
            raise ValueError("lab image does not match this checkout; run python3 lab/build.py")
        created = True
        checked("container-create", ["docker", "create", "--name", name, "--platform", "linux/amd64",
            "--hostname", "lab-node", "--network", "none", "--memory", "768m", "--cpus", "2",
            "--pids-limit", "192", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
            "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "KILL",
            "--cap-add", "SETGID", "--cap-add", "SETUID", "--cap-add", "SETPCAP", "--cap-add", "SYS_PTRACE",
            image["Id"]], output, 30)
        print("Running four isolated observations; no requests are sent.", flush=True)
        with (output / "container.log").open("wb") as log:
            try:
                subprocess.run(["docker", "start", "--attach", name], stdout=log, stderr=subprocess.STDOUT, timeout=300)
            except subprocess.TimeoutExpired as error:
                raise ValueError("lab execution exceeded five minutes; see private container.log") from error
        exit_code = int(checked("container-inspect", ["docker", "inspect", "--format", "{{.State.ExitCode}}", name], output, 10).stdout)
    finally:
        if created:
            if not cleanup(name, output):
                exit_code = 1
        summary = output / "raw/shareable-summary.json"
        if summary.exists():
            value = json.loads(summary.read_text())
            (output / "shareable-summary.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
            print("\nScenario                   RELIQUA            Comparator      Process finding")
            for row in value["observations"]:
                finding = ",".join(row["comparator"].get("process_finding_statuses", {})) or "n/a"
                print(f"{row['scenario']:26} {row['reliqua']['status']:19} {row['comparator']['result']:16} {finding}")
            print("Comparator warnings are preserved independently of its overall result.")
            print("\nReview/share only: " + str(output.relative_to(ROOT) / "shareable-summary.json"))
        print("Private evidence: " + str(output.relative_to(ROOT)))
        print("Elapsed seconds: " + str(round(time.monotonic() - started, 1)))
    if exit_code:
        print("Lab did not complete as expected; keep the private logs for diagnosis.", file=sys.stderr)
    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print("Lab stopped: " + detail, file=sys.stderr)
        raise SystemExit(1)
