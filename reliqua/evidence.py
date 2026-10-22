"""Bounded evidence I/O. Checksums detect edits, not authorship."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

MAX_REPORT_BYTES = 8 * 1024 * 1024


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def seal(payload: dict) -> dict:
    return {"schema": 1, "payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()}


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: str | Path) -> dict:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("input must be a regular file")
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("input exceeds 8 MiB")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON number")))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON encoding or depth") from exc
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def unseal(envelope: dict) -> dict:
    if set(envelope) != {"schema", "payload", "sha256"} or type(envelope["schema"]) is not int or envelope["schema"] != 1:
        raise ValueError("unsupported evidence envelope")
    payload, digest = envelope["payload"], envelope["sha256"]
    if not isinstance(payload, dict) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid evidence envelope")
    try:
        computed = hashlib.sha256(canonical(payload)).hexdigest()
    except (RecursionError, ValueError) as exc:
        raise ValueError("invalid evidence payload") from exc
    if not hmac.compare_digest(computed, digest):
        raise ValueError("evidence checksum mismatch")
    return payload


def load_report(path: str | Path) -> dict:
    return unseal(read_json(path))


def write_private(path: str | Path, value: dict) -> None:
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("output exceeds 8 MiB")
    # Noli testimonium prius delere.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
