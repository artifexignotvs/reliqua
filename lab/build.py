#!/usr/bin/env python3
"""Build the disposable lab from reviewed, immutable inputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
try:
    from .common import source_fingerprint
except ImportError:
    from common import source_fingerprint

ROOT = Path(__file__).resolve().parents[1]
TAG = "reliqua-comparison-lab:1"


def download(url: str, target: Path, digest: str, limit: int = 32 * 1024 * 1024) -> None:
    print("Verifying download: " + target.name, flush=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("download size or checksum mismatch")
    target.write_bytes(data)


def main() -> int:
    pins = json.loads((ROOT / "lab/pins.json").read_text())
    with tempfile.TemporaryDirectory(prefix="reliqua-lab-build-") as directory:
        context = Path(directory)
        for name in ("reliqua", "lab"):
            shutil.copytree(ROOT / name, context / name,
                            ignore=shutil.ignore_patterns("__pycache__", "results", "*.pyc"))
        fingerprint = source_fingerprint(context)
        (context / "lab/build-manifest.json").write_text(json.dumps({"source_sha256": fingerprint}) + "\n")
        (context / "packages").mkdir()
        (context / "old-packages").mkdir()
        for kind, destination in (("old", "old-packages"), ("new", "packages")):
            for package in pins["packages"][kind].values():
                url = "https://snapshot.ubuntu.com/ubuntu/" + pins[kind + "_snapshot"] + "/" + package["filename"]
                download(url, context / destination / Path(package["filename"]).name, package["sha256"])
        bootstrap = pins["bootstrap_ca"]
        download("https://snapshot.ubuntu.com/ubuntu/" + pins["old_snapshot"] + "/" + bootstrap["filename"],
                 context / "bootstrap-ca.deb", bootstrap["sha256"])
        (context / "comparison").mkdir()
        comparator = pins["comparator"]
        base = "https://raw.githubusercontent.com/EXT-IT/php2shell-check/" + comparator["commit"] + "/"
        download(base + comparator["script"], context / "comparison/php2shell-check.sh", comparator["sha256"])
        download(base + "LICENSE", context / "comparison/LICENSE", comparator["license_sha256"])
        print("Verified package and comparator downloads. Building pinned Ubuntu lab.", flush=True)
        subprocess.run([
            "docker", "build", "--force-rm", "--platform", pins["platform"], "--tag", TAG,
            "--label", "org.reliqua.lab.source-sha256=" + fingerprint,
            "--build-arg", "BASE_IMAGE=" + pins["image"],
            "--build-arg", "OLD_SNAPSHOT=" + pins["old_snapshot"],
            "--build-arg", "OLD_VERSION=" + pins["old_version"],
            "--file", str(context / "lab/Dockerfile"), str(context),
        ], check=True, timeout=1200)
    print("Built " + TAG + ". Run: python3 lab/run.py")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("Lab build failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
