"""Conservative evaluation of a local runtime snapshot."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from .policy import ADVISORY, REVISION, package_fix

ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
WEB_KINDS = {"fpm", "apache", "cgi", "embedded"}
STATES = {"current", "replaced", "deleted", "unknown"}


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid collection timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid collection timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("collection timestamp must be UTC")
    return parsed


def _text(value: object, maximum: int = 4096) -> bool:
    return isinstance(value, str) and len(value) <= maximum and all(ord(c) >= 32 and ord(c) != 127 for c in value)


def _errors(value: object) -> bool:
    return isinstance(value, list) and len(value) <= 32768 and all(_text(item, 160) for item in value)


def validate_report(raw: dict) -> None:
    if not isinstance(raw, dict) or type(raw.get("schema")) is not int or raw["schema"] != 1:
        raise ValueError("unsupported report schema")
    if not isinstance(raw.get("node"), str) or not ALIAS.fullmatch(raw["node"]):
        raise ValueError("invalid node alias")
    if not _text(raw.get("tool_version"), 64):
        raise ValueError("missing tool version")
    timestamp(raw.get("collected_at"))
    if not isinstance(raw.get("boot_id"), str) or not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", raw["boot_id"]):
        # A failed boot-ID collection must never be promoted into evidence.
        raise ValueError("missing or invalid boot identity")
    if not isinstance(raw.get("scope"), str) or raw["scope"] not in {"visible-proc", "selected-pids"}:
        raise ValueError("invalid collection scope")
    os_info = raw.get("os")
    if not isinstance(os_info, dict) or not all(_text(os_info.get(k), 128) for k in ("id", "version_id")):
        raise ValueError("invalid operating system identity")
    if not _errors(raw.get("errors")):
        raise ValueError("invalid collection errors")
    processes = raw.get("processes")
    if not isinstance(processes, list) or len(processes) > 16384:
        raise ValueError("invalid process list")
    pids = set()
    for process in processes:
        if not isinstance(process, dict):
            raise ValueError("invalid process record")
        pid, start = process.get("pid"), process.get("start_ticks")
        if type(pid) is not int or not 1 <= pid <= 2**31 or pid in pids:
            raise ValueError("invalid or duplicate process identity")
        pids.add(pid)
        if type(start) is not int or not 0 <= start <= 2**64:
            raise ValueError("invalid process start identity")
        if not isinstance(process.get("kind"), str) or process["kind"] not in WEB_KINDS | {"cli", "unknown"} or not _errors(process.get("errors")):
            raise ValueError("invalid process kind or errors")
        components = process.get("components")
        if not isinstance(components, list) or len(components) > 256:
            raise ValueError("invalid component list")
        for component in components:
            if not isinstance(component, dict) or not isinstance(component.get("state"), str) or component["state"] not in STATES:
                raise ValueError("invalid component state")
            if not isinstance(component.get("role"), str) or component["role"] not in {"executable", "module"} or not _text(component.get("path")):
                raise ValueError("invalid component identity")
            if not _errors(component.get("errors")):
                raise ValueError("invalid component errors")
            for name in ("mapped_inode", "disk_inode"):
                value = component.get(name)
                if value is not None and (type(value) is not int or not 0 <= value <= 2**64):
                    raise ValueError("invalid inode")
            for name in ("mapped_device", "disk_device"):
                value = component.get(name)
                if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,8}:[0-9a-fA-F]{1,8}", value)):
                    raise ValueError("invalid device")
            digest = component.get("sha256")
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("invalid artifact digest")
            package = component.get("package")
            if package is not None:
                if not isinstance(package, dict):
                    raise ValueError("invalid package record")
                for name in ("name", "source_name", "version", "status", "integrity"):
                    if not _text(package.get(name), 256):
                        raise ValueError("invalid package metadata")
                if "source_version" in package and not _text(package["source_version"], 256):
                    raise ValueError("invalid source version")


def _same_image(component: dict) -> bool:
    try:
        mapped_device = tuple(int(part, 16) for part in component["mapped_device"].split(":"))
        disk_device = tuple(int(part, 16) for part in component["disk_device"].split(":"))
        return (component["mapped_inode"] > 0 and component["mapped_inode"] == component["disk_inode"] and mapped_device == disk_device and bool(component.get("sha256")))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False


def assess(raw: dict) -> dict:
    validate_report(raw)
    findings = []
    current = 0
    web = 0
    def finding(code: str, level: str, detail: str, pid: int | None = None) -> None:
        item = {"code": code, "level": level, "detail": detail}
        if pid is not None:
            item["pid"] = pid
        findings.append(item)

    for error in raw["errors"]:
        finding("COLLECTION_GAP", "unknown", error)
    for process in raw["processes"]:
        pid = process["pid"]
        if process["kind"] == "cli":
            finding("CLI_NOT_WEB_EVIDENCE", "unknown", "CLI-named PHP can serve HTTP or long-lived work; its role is unverified and cannot establish web remediation.", pid)
            continue
        if process["kind"] not in WEB_KINDS:
            finding("RUNTIME_UNCLASSIFIED", "unknown", "Runtime type could not be established.", pid)
        else:
            web += 1
        for error in process["errors"]:
            finding("PROCESS_GAP", "unknown", error, pid)
        if not process["components"]:
            finding("NO_CORE_ARTIFACT", "unknown", "No readable PHP core artifact was observed.", pid)
        expected_role = "module" if process["kind"] == "apache" else "executable"
        if not any(c["role"] == expected_role for c in process["components"]):
            finding("CORE_ROLE_MISSING", "unknown", "Expected executable or Apache PHP module is missing.", pid)
        for component in process["components"]:
            for error in component["errors"]:
                finding("ARTIFACT_GAP", "unknown", error, pid)
            if component["state"] in {"deleted", "replaced"}:
                finding("RESTART_REVIEW", "action", "A loaded artifact differs from the current file. Drain/restart the service and recollect; this alone does not prove vulnerability.", pid)
            elif component["state"] != "current" or not _same_image(component):
                finding("RUNNING_IMAGE_UNKNOWN", "unknown", "Mapped and current file identities were not matched.", pid)
            package = component.get("package")
            if package is None:
                finding("BUILD_UNVERIFIED", "unknown", "Custom, embedded, foreign-namespace or unowned build needs independent review.", pid)
                continue
            if package.get("integrity") == "mismatch":
                finding("PACKAGE_FILE_CHANGED", "action", "The file differs from the local package manifest. Investigate before trusting its version.", pid)
            fix = package_fix(raw["os"], package)
            if fix["state"] != "VENDOR_FIX_RECORDED":
                finding("FIX_UNVERIFIED", "unknown", fix["reason"] + ("; reviewed vendor version: " + fix["reviewed_version"] if "reviewed_version" in fix else ""), pid)
            elif component["state"] == "current" and _same_image(component) and not component["errors"]:
                current += 1
    if web == 0:
        finding("NO_WEB_RUNTIME", "unknown", "No web PHP runtime was observed. An empty inventory is not a passing result.")
    has_action = any(f["level"] == "action" for f in findings)
    complete = not any(f["level"] == "unknown" for f in findings)
    status = "ACTION_REQUIRED" if has_action else "INCOMPLETE" if not complete else "OBSERVED_CURRENT"
    return {"status": status, "complete": complete, "findings": findings, "web_processes": web, "current_components": current, "advisory": ADVISORY, "policy_revision": REVISION, "scope": raw["scope"], "trust": "Local process and package metadata are assumed trustworthy; evidence is not a compromise-clearance certificate."}
