"""Terminal entry point."""
from __future__ import annotations
import argparse
import json
import sys
from . import __version__
from .assess import ALIAS, assess, timestamp
from .evidence import load_report, read_json, seal, write_private
from .policy import describe

EXIT = {"OBSERVED_CURRENT": 0, "ACTION_REQUIRED": 1, "INCOMPLETE": 2}


def text(value: object) -> str:
    # Litterae imperantes in terminali non regnent.
    return "".join(char if 32 <= ord(char) < 127 else "?" for char in str(value))


def render(result: dict) -> None:
    print("RELIQUA  /  PHP runtime evidence")
    print("=" * 54)
    print(text(result["status"]))
    if "web_processes" in result:
        print(f"Web processes: {result['web_processes']}  Current core artifacts: {result['current_components']}")
    if "scope" in result:
        print("Scope: " + text(result["scope"]))
    for node in result.get("nodes", []):
        print(f"  {text(node['node']):24} {text(node['status'])}")
    for finding in result.get("findings", []):
        pid = f" pid={finding['pid']}" if "pid" in finding else ""
        node = f" node={text(finding['node'])}" if "node" in finding else ""
        print(f"  {text(finding['code'])}{pid}{node}: {text(finding.get('detail', ''))}")
    print("\nObservation only. No assertion that the host is uncompromised.")


def emit(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        render(result)


def compare(before: dict, after: dict) -> dict:
    first, second = assess(before), assess(after)
    if before["node"] != after["node"] or before["scope"] != after["scope"]:
        raise ValueError("comparison requires the same node alias and scope")
    if timestamp(after["collected_at"]) <= timestamp(before["collected_at"]):
        raise ValueError("after snapshot must be newer than before")
    def identities(raw: dict) -> set:
        return {(raw["boot_id"], p["pid"], p["start_ticks"]) for p in raw["processes"] if p["kind"] != "cli"}
    left, right = identities(before), identities(after)
    return {"schema": 1, "node": after["node"], "status": second["status"], "before_status": first["status"], "scope": after["scope"], "retained_process_identities": len(left & right), "departed_process_identities": len(left - right), "new_process_identities": len(right - left), "findings": second["findings"], "note": "Snapshot differences do not establish service health, request-route coverage or absence of compromise."}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="reliqua", description="Read-only PHP runtime patch evidence and declared-node convergence checks.")
    root.add_argument("--version", action="version", version="reliqua " + __version__)
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Inspect local Linux processes; never execute PHP or change services")
    scan.add_argument("--node", required=True, help="Operator alias; use an alias without identifying host details")
    scan.add_argument("--pid", action="append", type=int, help="Restrict to an explicit PID (repeatable); not full visible-process coverage")
    scan.add_argument("--out", required=True, help="New private JSON evidence file (never overwritten)")
    scan.add_argument("--json", action="store_true")
    inspect = commands.add_parser("inspect", help="Verify a report checksum and recompute its historical assessment")
    inspect.add_argument("report")
    inspect.add_argument("--json", action="store_true")
    fleet = commands.add_parser("fleet", help="Check fresh evidence for every declared node")
    fleet.add_argument("--manifest", required=True)
    fleet.add_argument("reports", nargs="+")
    fleet.add_argument("--out", help="Write a private summary without process paths or boot IDs")
    fleet.add_argument("--json", action="store_true")
    diff = commands.add_parser("compare", help="Compare two snapshots from the same scope and node")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--json", action="store_true")
    commands.add_parser("policy", help="Show exact supported vendor builds and primary sources")
    demo = commands.add_parser("demo", help="Run synthetic decision examples without host inspection")
    demo.add_argument("--json", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "policy":
            print(json.dumps(describe(), indent=2, sort_keys=True))
            return 0
        if args.command == "demo":
            from .demo import scenarios, sample
            from .fleet import evaluate
            rows = [{"scenario": label, "status": assess(raw)["status"]} for label, raw in scenarios()]
            rows.append({"scenario": "One declared node missing", "status": evaluate({"schema": 1, "nodes": ["edge-a", "edge-b"]}, [sample()])["status"]})
            if args.json:
                print(json.dumps({"synthetic": True, "scenarios": rows}, indent=2))
            else:
                print("RELIQUA  /  synthetic decision demo\n")
                for row in rows:
                    print(f"{row['scenario']:40} {row['status']}")
                print("\nNo host was scanned; no exploit requests were sent.")
            return 0
        if args.command == "scan":
            if not ALIAS.fullmatch(args.node):
                raise ValueError("node alias must be 1-64 ASCII letters, digits, dots, underscores or dashes; begin with a letter or digit")
            if args.pid and (len(args.pid) > 16384 or len(set(args.pid)) != len(args.pid) or any(p < 1 or p > 2**31 for p in args.pid)):
                raise ValueError("invalid or duplicate selected PIDs")
            from .collector import collect
            raw = collect(args.node, args.pid)
            result = assess(raw)
            write_private(args.out, seal(raw))
        elif args.command == "inspect":
            raw = load_report(args.report)
            result = assess(raw)
            result["collected_at"] = raw["collected_at"]
            result["historical"] = True
        elif args.command == "fleet":
            from .fleet import evaluate
            if len(args.reports) > 256:
                raise ValueError("at most 256 report inputs are accepted")
            result = evaluate(read_json(args.manifest), [load_report(path) for path in args.reports])
            if args.out:
                write_private(args.out, result)
        else:
            result = compare(load_report(args.before), load_report(args.after))
        emit(result, args.json)
        return EXIT[result["status"]]
    except (OSError, ValueError, RecursionError) as exc:
        # Secret paths and supplied input are not echoed on errors.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print("reliqua: " + text(message), file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
