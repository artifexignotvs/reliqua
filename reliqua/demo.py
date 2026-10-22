"""Synthetic examples; these are not measurements of a production host."""
from copy import deepcopy
from datetime import datetime, timezone


def sample(node: str = "edge-a", now: datetime | None = None) -> dict:
    return {"schema": 1, "tool_version": "0.1.0a1", "node": node, "collected_at": (now or datetime.now(timezone.utc)).isoformat(), "boot_id": "00000000-0000-4000-8000-000000000001", "scope": "visible-proc", "os": {"id": "ubuntu", "version_id": "24.04"}, "errors": [], "processes": [{"pid": 4200, "start_ticks": 10000, "kind": "fpm", "errors": [], "components": [{"path": "/usr/sbin/php-fpm8.3", "role": "executable", "state": "current", "mapped_device": "08:01", "mapped_inode": 100, "disk_device": "08:01", "disk_inode": 100, "sha256": "a" * 64, "errors": [], "package": {"name": "php8.3-fpm", "source_name": "php8.3", "source_version": "8.3.6-0ubuntu0.24.04.13", "version": "8.3.6-0ubuntu0.24.04.13", "status": "install ok installed", "integrity": "match"}}]}]}


def scenarios() -> list[tuple[str, dict]]:
    current = sample()
    stale = deepcopy(current)
    stale["processes"][0]["components"][0].update(state="replaced", mapped_inode=99)
    unknown = deepcopy(current)
    unknown["processes"][0]["components"][0]["package"] = None
    blind = deepcopy(current)
    blind["errors"] = ["proc_permission_denied"]
    no_web = deepcopy(current)
    no_web["processes"][0]["kind"] = "cli"
    return [("Patched package, old worker", stale), ("Reviewed backport, current image", current), ("Custom build without vendor evidence", unknown), ("Unreadable process coverage", blind), ("Only CLI PHP observed", no_web)]
