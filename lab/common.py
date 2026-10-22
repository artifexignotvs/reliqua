"""Stable source binding for the disposable lab image."""
import hashlib
from pathlib import Path


def source_fingerprint(root: Path) -> str:
    paths = list((root / "reliqua").glob("*.py"))
    paths += [path for path in (root / "lab").iterdir() if path.is_file()
              and (path.suffix in {".py", ".json", ".conf"} or path.name == "Dockerfile")
              and path.name != "build-manifest.json"]
    sha = hashlib.sha256()
    for path in sorted(paths):
        sha.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return sha.hexdigest()
