"""Read-only evidence from the locally trusted package database."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

DPKG_QUERY = "/usr/bin/dpkg-query"
INFO_ROOT = Path("/var/lib/dpkg/info")
MAX_QUERY_BYTES = 65536
MAX_DATABASE_BYTES = 8 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
QUERY_TIMEOUT = 3.0
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")


def _query(arguments: list[str]) -> str | None:
    try:
        with subprocess.Popen(
            [DPKG_QUERY, *arguments], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ) as child:
            assert child.stdout is not None
            output = bytearray()
            deadline = time.monotonic() + QUERY_TIMEOUT
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        child.kill()
                        return None
                    if not selector.select(remaining):
                        child.kill()
                        return None
                    chunk = os.read(child.stdout.fileno(), 16384)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_QUERY_BYTES:
                        child.kill()
                        return None
            try:
                code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                return None
            return output.decode("utf-8", "strict") if code == 0 else None
    except (OSError, UnicodeError, ValueError):
        return None


def _signature(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _digest(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BINARY_BYTES:
                return None
            digest = hashlib.md5(usedforsecurity=False)
            total = 0
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BINARY_BYTES:
                    return None
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            if _signature(before) != _signature(after) or total != before.st_size:
                return None
            if _signature(after) != _signature(os.stat(path, follow_symlinks=False)):
                return None
            return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _integrity(name: str, path: str) -> str:
    records = None
    for basename in dict.fromkeys((name, name.split(":", 1)[0])):
        try:
            database = INFO_ROOT / f"{basename}.md5sums"
            fd = os.open(database, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return "unknown"
                data = stream.read(MAX_DATABASE_BYTES + 1)
                if len(data) > MAX_DATABASE_BYTES:
                    return "unknown"
                records = data.decode("utf-8", "strict").splitlines()
            break
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return "unknown"
    if records is None:
        return "unknown"
    expected = []
    for record in records:
        match = re.fullmatch(r"([0-9a-fA-F]{32}) [ *](.+)", record)
        if match and match[2] == path.lstrip("/"):
            expected.append(match[1].lower())
    if len(expected) != 1:
        return "unknown"
    actual = _digest(path)
    if actual is None:
        return "unknown"
    return "match" if actual == expected[0] else "mismatch"


def package_for(path: str) -> dict | None:
    """Identify one installed owner; integrity is not authenticity."""
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(char in path for char in "\x00\r\n*?[]\\")
            or "." in Path(path).parts or ".." in Path(path).parts):
        return None
    owner_result = _query(["--search", "--", path])
    if owner_result is None:
        return None
    owners = []
    for line in owner_result.splitlines():
        owner, separator, owned_path = line.partition(": ")
        if separator and owned_path == path and PACKAGE_NAME.fullmatch(owner):
            owners.append(owner)
    if len(set(owners)) != 1:
        return None
    name = owners[0]
    template = "${binary:Package}\t${source:Package}\t${Version}\t${source:Version}\t${Status}\t${Architecture}\n"
    result = _query(["--show", f"--showformat={template}", "--", name])
    if result is None or len(result.splitlines()) != 1:
        return None
    values = result.rstrip("\n").split("\t")
    if len(values) != 6:
        return None
    binary, source, version, source_version, status_value, architecture = values
    if (binary != name or not PACKAGE_NAME.fullmatch(source)
            or not version or len(version) > 256 or len(source_version) > 256):
        return None
    integrity = _integrity(binary, path)
    if _query(["--show", f"--showformat={template}", "--", name]) != result:
        integrity = "unknown"
    return {
        "name": binary, "source_name": source, "version": version,
        "source_version": source_version, "status": status_value,
        "architecture": architecture, "integrity": integrity,
    }
