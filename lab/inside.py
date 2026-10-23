#!/usr/bin/env python3
"""Controlled state transitions inside the disposable container only."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

LAB = Path("/opt/lab")
OUT = Path("/results")
PINS = json.loads((LAB / "pins.json").read_text()) if LAB.exists() else {}
DROP = ["setpriv", "--bounding-set=-sys_ptrace", "--"]
PHP = "/usr/sbin/php-fpm8.3"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value: object) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def installed() -> dict[str, str]:
    output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}=${Version}\n", "php8.3-*"], text=True)
    return dict(line.split("=", 1) for line in output.splitlines())


def identities() -> list[dict]:
    result = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if not (directory / "comm").read_text().strip().startswith("php-fpm"):
                continue
            stat = (directory / "stat").read_text()
            result.append({"pid": int(directory.name), "start_ticks": int(stat[stat.rfind(")") + 1:].split()[19])})
        except FileNotFoundError:
            continue
    return sorted(result, key=lambda row: row["pid"])


def probe() -> dict:
    rows = []
    for item in identities():
        directory = Path("/proc") / str(item["pid"])
        row = dict(item)
        row["comm"] = (directory / "comm").read_text().strip()
        for name in ("exe", "maps"):
            try:
                if name == "exe":
                    row[name] = os.readlink(directory / name)
                else:
                    row[name] = bool((directory / name).read_bytes())
                row[name + "_readable"] = True
            except PermissionError:
                row[name + "_readable"] = False
        rows.append(row)
    return {"uid": os.geteuid(), "processes": rows}


def verify_build() -> None:
    for name, record in PINS["packages"]["new"].items():
        if digest(LAB / "packages" / Path(record["filename"]).name) != record["sha256"]:
            raise ValueError("package checksum mismatch: " + name)
    if any(installed().get(name) != PINS["old_version"] for name in PINS["packages"]["old"]):
        raise ValueError("unexpected initial package version")
    if digest(Path("/opt/comparison/php2shell-check.sh")) != PINS["comparator"]["sha256"]:
        raise ValueError("comparator checksum mismatch")
    print("Pinned inputs verified.")


def invoke(label: str, command: list[str], denied: bool = False) -> tuple[int, dict]:
    process = subprocess.run((DROP if denied else []) + command, capture_output=True, timeout=90)
    (OUT / (label + ".stdout")).write_bytes(process.stdout)
    (OUT / (label + ".stderr")).write_bytes(process.stderr)
    (OUT / (label + ".exit")).write_text(str(process.returncode) + "\n")
    try:
        value = json.loads(process.stdout)
    except (ValueError, UnicodeError) as error:
        raise ValueError(label + " did not produce JSON") from error
    return process.returncode, value


def summarize_pair(label: str, denied: bool = False) -> dict:
    before = identities()
    rc, assessment = invoke(label + "-reliqua", ["python3", "-m", "reliqua", "scan", "--node", "lab-a",
        "--out", str(OUT / (label + "-evidence.json")), "--json"], denied)
    middle = identities()
    other_rc, other = invoke(label + "-comparator", ["bash", "/opt/comparison/php2shell-check.sh",
        "--json", "--no-containers", "--no-logs"], denied)
    after = identities()
    if len(before) != 3 or before != middle or before != after:
        raise ValueError("FPM process identities changed during comparison")
    save(OUT / (label + "-identities.json"), {"before": before, "between": middle, "after": after})
    process_findings = [row for row in other.get("findings", []) if row.get("check") == "process"]
    return {"scenario": label, "same_fpm_processes_during_comparison": True,
        "fpm_processes": len(before),
        "reliqua": {"status": assessment["status"], "exit": rc,
            "web_processes": assessment["web_processes"],
            "current_components": assessment["current_components"],
            "finding_codes": dict(Counter(row["code"] for row in assessment["findings"]))},
        "comparator": {"result": other["result"], "exit": other_rc,
            "counts": other["counts"],
            "process_finding_statuses": dict(Counter(row["status"] for row in process_findings)),
            "process_warning_present": any(row["status"] == "warn" for row in process_findings)}}


def start_fpm() -> subprocess.Popen:
    Path("/run/php").mkdir(exist_ok=True)
    log = (OUT / "fpm-launch.log").open("ab")
    process = subprocess.Popen([PHP, "--nodaemonize", "--fpm-config", str(LAB / "php-fpm.conf")],
                               stdout=log, stderr=log)
    log.close()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError("FPM did not start")
        if len(identities()) == 3 and Path("/run/php/lab.sock").exists():
            return process
        time.sleep(0.1)
    raise ValueError("FPM startup timed out")


def stop_fpm(process: subprocess.Popen) -> None:
    process.send_signal(signal.SIGQUIT)
    process.wait(timeout=15)
    if identities():
        raise ValueError("FPM workers remained after stop")


def expected_results(observations: list[dict]) -> tuple[bool, bool]:
    """Check the observed contract for both tools, not a relative score."""
    expected = {
        "current-workers": ("OBSERVED_CURRENT", 0, "not-vulnerable", 0, {"ok": 1}),
        "retained-old-workers": ("ACTION_REQUIRED", 1, "not-vulnerable", 0, {"warn": 1}),
        "inspection-denied": ("INCOMPLETE", 2, "undecided", 2, {"unknown": 1}),
        "missing-declared-node": ("INCOMPLETE", 2, "not-applicable", None, None),
    }
    if len(observations) != len(expected) or {row["scenario"] for row in observations} != set(expected):
        return False, False
    reliqua_ok = comparator_ok = True
    # Eadem probationis regula utrique instrumento.
    for row in observations:
        status, code, result, other_code, findings = expected[row["scenario"]]
        own, other = row["reliqua"], row["comparator"]
        reliqua_ok &= (own.get("status"), own.get("exit")) == (status, code)
        comparator_ok &= other.get("result") == result
        if other_code is not None:
            comparator_ok &= (other.get("exit"), other.get("process_finding_statuses")) == (other_code, findings)
    return reliqua_ok, comparator_ok


def main() -> None:
    os.umask(0o077)
    OUT.mkdir(mode=0o700, exist_ok=True)
    verify_build()
    save(OUT / "packages-before.json", installed())
    before_hash = digest(Path(PHP))
    fpm = start_fpm()
    try:
        original = identities()
        upgrade = subprocess.run(["dpkg", "--install"] + [str(p) for p in sorted((LAB / "packages").glob("*.deb"))],
                                 capture_output=True, timeout=90)
        (OUT / "upgrade.stdout").write_bytes(upgrade.stdout)
        (OUT / "upgrade.stderr").write_bytes(upgrade.stderr)
        if upgrade.returncode:
            raise ValueError("isolated package upgrade failed")
        if any(installed().get(name) != PINS["new_version"] for name in PINS["packages"]["new"]):
            raise ValueError("upgrade did not install expected packages")
        after_hash = digest(Path(PHP))
        if before_hash == after_hash or original != identities():
            raise ValueError("upgrade must retain original workers and change the executable")
        retained = probe()
        if not all(row.get("exe", "").endswith(" (deleted)") for row in retained["processes"]):
            raise ValueError("old executable mapping was not retained")
        save(OUT / "upgrade-proof.json", retained)
        stale = summarize_pair("retained-old-workers")
        stop_fpm(fpm)
        fpm = start_fpm()
        current = summarize_pair("current-workers")
        _, permission = invoke("denied-probe", ["python3", str(LAB / "inside.py"), "--permission-probe"], True)
        denied_count = sum(not row["exe_readable"] for row in permission["processes"])
        if permission["uid"] != 0 or denied_count < 2:
            raise ValueError("expected root without inspection capability to lack worker access")
        denied = summarize_pair("inspection-denied", True)
        denied["known_fpm_processes_with_unreadable_exe"] = denied_count
        manifest = {"schema": 1, "nodes": ["lab-a", "lab-b"], "max_age_seconds": 900}
        save(OUT / "manifest.json", manifest)
        fleet_rc, fleet = invoke("missing-node-reliqua", ["python3", "-m", "reliqua", "fleet",
            "--manifest", str(OUT / "manifest.json"), str(OUT / "current-workers-evidence.json"), "--json"])
        missing = {"scenario": "missing-declared-node", "reliqua": {"status": fleet["status"],
            "exit": fleet_rc, "finding_codes": dict(Counter(row["code"] for row in fleet["findings"]))},
            "comparator": {"result": "not-applicable", "reason": "single-node checker; no declared-node manifest gate"}}
        observations = [current, stale, denied, missing]
        expected, comparator_expected = expected_results(observations)
        source_digest = hashlib.sha256()
        for path in sorted(Path("/opt/reliqua").glob("*.py")):
            source_digest.update(path.name.encode() + b"\0" + path.read_bytes())
        summary = {"schema": 1, "lab": "ubuntu24-fpm-package-upgrade-v1", "all_expected_reliqua_results": expected,
            "all_expected_comparator_results": comparator_expected,
            "environment": {"platform": PINS["platform"], "base_image": PINS["image"],
                "old_package_version": PINS["old_version"], "new_package_version": PINS["new_version"],
                "old_fpm_sha256": before_hash, "new_fpm_sha256": after_hash,
                "reliqua_source_sha256": source_digest.hexdigest(),
                "lab_source_sha256": json.loads((LAB / "build-manifest.json").read_text())["source_sha256"],
                "comparator_version": PINS["comparator"]["version"],
                "comparator_commit": PINS["comparator"]["commit"], "comparator_sha256": PINS["comparator"]["sha256"],
                "comparator_license_sha256": PINS["comparator"]["license_sha256"]},
            "method": {"real_package_upgrade": True, "workers_retained_across_upgrade": len(original),
                "requests_sent": 0, "runtime_network": "none", "raw_evidence_shared": False},
            "observations": observations}
        save(OUT / "shareable-summary.json", summary)
        print(json.dumps(summary, indent=2))
        if not expected or not comparator_expected:
            raise ValueError("lab outcome differed from expected; keep evidence for review")
    finally:
        if fpm.poll() is None:
            stop_fpm(fpm)


if __name__ == "__main__":
    if sys.argv[1:] == ["--verify-build"]:
        verify_build()
    elif sys.argv[1:] == ["--permission-probe"]:
        print(json.dumps(probe()))
    elif sys.argv[1:]:
        raise SystemExit("unsupported arguments")
    else:
        main()
