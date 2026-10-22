"""Evaluate bounded, declared node snapshots without trusting stored verdicts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

from .assess import assess, validate_report

MAX_NODES = 256
DEFAULT_MAX_AGE_SECONDS = 900
_ALIAS = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_BOOT_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")
_RANK = {"OBSERVED_CURRENT": 0, "INCOMPLETE": 1, "ACTION_REQUIRED": 2}


def _alias(value: object) -> bool:
    return isinstance(value, str) and _ALIAS.fullmatch(value) is not None


def _manifest(value: dict) -> tuple[list[str], int]:
    if not isinstance(value, dict) or set(value) - {"schema", "nodes", "max_age_seconds"}:
        raise ValueError("invalid fleet manifest")
    if type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("unsupported fleet manifest schema")
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise ValueError("manifest requires between 1 and 256 declared nodes")
    if any(not _alias(node) for node in nodes):
        raise ValueError("invalid node alias")
    if len(set(nodes)) != len(nodes):
        raise ValueError("duplicate manifest node")
    age = value.get("max_age_seconds", DEFAULT_MAX_AGE_SECONDS)
    if type(age) is not int or not 60 <= age <= 86400:
        raise ValueError("max_age_seconds must be an integer from 60 to 86400")
    return sorted(nodes), age


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not _UTC_TIME.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _identity(entry: tuple[dict, dict | None]) -> tuple:
    raw, assessment = entry
    # Compare only validated scalar identities; ignored extra data is untrusted.
    if assessment is None:
        return ("malformed",)
    return (raw["boot_id"], raw["collected_at"], raw["scope"],
            assessment["status"], assessment["complete"],
            assessment["web_processes"], assessment["current_components"])


def evaluate(manifest: dict, reports: list[dict], now: datetime | None = None) -> dict:
    """Recompute visible-process assessments for exactly the declared node set.

    Bad manifests fail before evaluation. Bad or missing evidence prevents a
    complete result; an actionable assessment always takes precedence. This
    evaluates observations, not the authenticity or completeness of a host.
    """
    aliases, max_age = _manifest(manifest)
    if not isinstance(reports, list) or len(reports) > MAX_NODES:
        raise ValueError("reports must be a list of at most 256 items")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    now = now.astimezone(timezone.utc)
    grouped: dict[str, list[tuple[dict, dict | None]]] = {node: [] for node in aliases}
    findings: set[tuple[str, str | None]] = set()
    node_errors: set[str] = set()
    any_action = False

    def finding(code: str, node: str | None = None) -> None:
        findings.add((code, node))
        if node in grouped:
            node_errors.add(node)

    for raw in reports:
        node = raw.get("node") if isinstance(raw, dict) else None
        if not _alias(node):
            finding("invalid_report_node")
            continue
        expected = node in grouped
        if not expected:
            finding("unexpected_node", node)
        assessment = None
        try:
            validate_report(raw)
            # Noli credere titulo: testimonium denuo aestima.
            assessment = assess(raw)
        except (ValueError, TypeError):
            finding("malformed_report", node)
        if expected:
            grouped[node].append((raw, assessment))
        if assessment is not None:
            if assessment["status"] == "ACTION_REQUIRED":
                any_action = True
                finding("node_action_required", node)
            elif assessment["status"] != "OBSERVED_CURRENT" or not assessment["complete"]:
                finding("node_assessment_incomplete", node)
        if raw.get("scope") != "visible-proc":
            finding("report_scope_incomplete", node)
        if not isinstance(raw.get("boot_id"), str) or not _BOOT_ID.fullmatch(raw["boot_id"]):
            finding("invalid_boot_id", node)
        collected = _timestamp(raw.get("collected_at"))
        if collected is None:
            finding("invalid_collected_at", node)
        elif collected > now + timedelta(seconds=5):
            finding("future_report", node)
        elif (now - collected).total_seconds() > max_age:
            finding("stale_report", node)

    nodes = []
    for node in aliases:
        entries = grouped[node]
        if not entries:
            finding("missing_report", node)
        elif len(entries) > 1:
            finding("duplicate_node_report", node)
            # All duplicates fail; conflict is diagnostic, never a tie-breaker.
            if any(_identity(entry) != _identity(entries[0]) for entry in entries[1:]):
                finding("conflicting_node_reports", node)
        assessments = [assessment for _, assessment in entries if assessment is not None]
        status = max((item["status"] for item in assessments), key=_RANK.get, default="INCOMPLETE")
        if node in node_errors and status != "ACTION_REQUIRED":
            status = "INCOMPLETE"
        single = assessments[0] if len(entries) == len(assessments) == 1 else None
        nodes.append({
            "node": node,
            "status": status,
            "complete": status == "OBSERVED_CURRENT" and node not in node_errors,
            "report_count": len(entries),
            "web_processes": single["web_processes"] if single else None,
            "current_components": single["current_components"] if single else None,
        })
    complete = not findings and all(node["complete"] for node in nodes)
    status = "ACTION_REQUIRED" if any_action else "OBSERVED_CURRENT" if complete else "INCOMPLETE"
    return {
        "schema": 1,
        "status": status,
        "complete": complete,
        "scope": "declared-nodes-visible-proc",
        "max_age_seconds": max_age,
        "nodes": nodes,
        "findings": [dict(code=code, **({"node": node} if node is not None else {}))
                     for code, node in sorted(findings, key=lambda item: (item[1] or "", item[0]))],
    }
