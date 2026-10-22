"""The fleet verdict is derived from evidence, never a stored label."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest

from reliqua.fleet import evaluate


NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
BOOT = "12345678-abcd-1234-abcd-123456789abc"


def report(node="web-01"):
    return {
        "schema": 1, "tool_version": "0.1.0a1", "node": node,
        "collected_at": NOW.isoformat(), "boot_id": BOOT,
        "scope": "visible-proc", "os": {"id": "ubuntu", "version_id": "24.04"},
        "errors": [], "processes": [{
            "pid": 987654, "start_ticks": 42, "kind": "fpm", "errors": [],
            "components": [{
                "path": "/private/server/php-fpm8.3", "role": "executable",
                "state": "current", "mapped_device": "08:01", "mapped_inode": 400,
                "disk_device": "8:1", "disk_inode": 400, "sha256": "a" * 64,
                "errors": [], "package": {
                    "name": "php8.3-fpm", "source_name": "php8.3",
                    "version": "8.3.6-0ubuntu0.24.04.13",
                    "status": "install ok installed", "integrity": "match",
                },
            }],
        }],
    }


def manifest(*nodes, **extra):
    return {"schema": 1, "nodes": list(nodes or ("web-01",)), **extra}


def codes(result):
    return {finding["code"] for finding in result["findings"]}


class FleetTests(unittest.TestCase):
    def test_complete_declared_set(self):
        result = evaluate(manifest("web-02", "web-01"), [report("web-02"), report()], NOW)
        self.assertEqual(result["status"], "OBSERVED_CURRENT")
        self.assertTrue(result["complete"])
        self.assertEqual([node["node"] for node in result["nodes"]], ["web-01", "web-02"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["nodes"][0]["current_components"], 1)

    def test_missing_node_is_incomplete(self):
        result = evaluate(manifest("web-01", "web-02"), [report()], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["complete"])
        self.assertIn({"code": "missing_report", "node": "web-02"}, result["findings"])
        self.assertIsNone(result["nodes"][1]["web_processes"])

    def test_empty_report_set_does_not_pass(self):
        result = evaluate(manifest(), [], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("missing_report", codes(result))

    def test_stale_report_and_boundary(self):
        for age, expected in [(900, "OBSERVED_CURRENT"), (901, "INCOMPLETE")]:
            with self.subTest(age=age):
                raw = report()
                raw["collected_at"] = (NOW - timedelta(seconds=age)).isoformat()
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], expected)
                self.assertEqual("stale_report" in codes(result), age > 900)

    def test_manifest_max_age_applies(self):
        raw = report()
        raw["collected_at"] = (NOW - timedelta(seconds=61)).isoformat()
        result = evaluate(manifest(max_age_seconds=60), [raw], NOW)
        self.assertIn("stale_report", codes(result))

    def test_future_report_tolerance(self):
        for seconds, expected in [(5, "OBSERVED_CURRENT"), (5.1, "INCOMPLETE")]:
            with self.subTest(seconds=seconds):
                raw = report()
                raw["collected_at"] = (NOW + timedelta(seconds=seconds)).isoformat()
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], expected)
                self.assertEqual("future_report" in codes(result), seconds > 5)

    def test_timestamps_must_be_utc_and_valid(self):
        for timestamp in ["2026-10-22T12:00:00", "2026-10-22T13:00:00+01:00",
                          "2026-02-30T12:00:00Z", "tomorrow", None, 12]:
            with self.subTest(timestamp=timestamp):
                raw = report()
                raw["collected_at"] = timestamp
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertIn("invalid_collected_at", codes(result))

    def test_utc_z_timestamp_is_accepted(self):
        raw = report()
        raw["collected_at"] = "2026-10-22T12:00:00Z"
        self.assertEqual(evaluate(manifest(), [raw], NOW)["status"], "OBSERVED_CURRENT")

    def test_invalid_boot_identity(self):
        for boot in ["", "not-a-boot", None, [], "1" * 36]:
            with self.subTest(boot=boot):
                raw = report()
                raw["boot_id"] = boot
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertIn("invalid_boot_id", codes(result))

    def test_selected_scope_is_not_fleet_completeness(self):
        raw = report()
        raw["scope"] = "selected-pids"
        result = evaluate(manifest(), [raw], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("report_scope_incomplete", codes(result))

    def test_duplicate_report_is_not_a_second_node(self):
        raw = report()
        result = evaluate(manifest(), [raw, deepcopy(raw)], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("duplicate_node_report", codes(result))
        self.assertNotIn("conflicting_node_reports", codes(result))
        self.assertEqual(result["nodes"][0]["report_count"], 2)
        self.assertIsNone(result["nodes"][0]["current_components"])

    def test_conflicting_boot_reports_are_not_chosen_by_recency(self):
        raw, other = report(), report()
        other["boot_id"] = "abcdef01-2345-6789-abcd-123456789abc"
        other["collected_at"] = (NOW + timedelta(seconds=1)).isoformat()
        result = evaluate(manifest(), [raw, other], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("conflicting_node_reports", codes(result))

    def test_extra_report_blocks_complete_result(self):
        result = evaluate(manifest(), [report(), report("unexpected")], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn({"code": "unexpected_node", "node": "unexpected"}, result["findings"])
        self.assertEqual(len(result["nodes"]), 1)

    def test_flagged_node_wins_over_missing_stale_and_duplicate_evidence(self):
        raw = report()
        raw["processes"][0]["components"][0]["state"] = "replaced"
        raw["collected_at"] = (NOW - timedelta(days=1)).isoformat()
        raw["status"] = "OBSERVED_CURRENT"
        raw["assessment"] = {"status": "OBSERVED_CURRENT", "complete": True}
        result = evaluate(manifest("web-01", "web-02"), [raw, report()], NOW)
        self.assertEqual(result["status"], "ACTION_REQUIRED")
        self.assertFalse(result["complete"])
        self.assertTrue({"node_action_required", "missing_report", "stale_report",
                         "duplicate_node_report", "conflicting_node_reports"} <= codes(result))

    def test_provided_status_cannot_pass_unknown_build(self):
        raw = report()
        raw["status"] = "OBSERVED_CURRENT"
        raw["complete"] = True
        raw["processes"][0]["components"][0]["package"] = None
        result = evaluate(manifest(), [raw], NOW)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("node_assessment_incomplete", codes(result))

    def test_malformed_report_fails_without_raising(self):
        for field, value in [("schema", True), ("processes", "not-a-list"),
                             ("scope", []), ("errors", [None])]:
            with self.subTest(field=field):
                raw = report()
                raw[field] = value
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertIn("malformed_report", codes(result))

    def test_malformed_or_unsafe_alias_is_never_echoed(self):
        unsafe = "../../private/identifier"
        for raw in [None, [], "invalid", {"node": unsafe}]:
            with self.subTest(raw=raw):
                result = evaluate(manifest(), [raw], NOW)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertIn("invalid_report_node", codes(result))
                self.assertNotIn(unsafe, json.dumps(result))

    def test_cli_only_cannot_pass(self):
        raw = report()
        raw["processes"][0]["kind"] = "cli"
        self.assertEqual(evaluate(manifest(), [raw], NOW)["status"], "INCOMPLETE")

    def test_results_do_not_copy_sensitive_evidence(self):
        raw = report()
        raw["errors"] = ["unreadable private local path"]
        result = evaluate(manifest(), [raw], NOW)
        rendered = json.dumps(result)
        for private in [BOOT, "/private/server", "987654", "unreadable private local path", "sha256"]:
            self.assertNotIn(private, rendered)
        for item in result["findings"]:
            self.assertLessEqual(set(item), {"code", "node"})

    def test_input_order_does_not_change_result(self):
        records = [report("b"), report("a"), report("extra")]
        self.assertEqual(evaluate(manifest("b", "a"), records, NOW),
                         evaluate(manifest("a", "b"), records[::-1], NOW))

    def test_bad_manifests_raise(self):
        invalid = [None, {}, {"schema": True, "nodes": ["a"]},
                   {"schema": 1, "nodes": []}, {"schema": 1, "nodes": "a"},
                   manifest("a", "a"), manifest("../a"), manifest("a" * 65),
                   manifest("a", unknown=True), manifest(max_age_seconds=True),
                   manifest(max_age_seconds=59), manifest(max_age_seconds=86401),
                   manifest(max_age_seconds=900.0), manifest(*[f"n{i}" for i in range(257)])]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    evaluate(value, [], NOW)

    def test_report_count_is_bounded(self):
        for records in [None, {}, [report()] * 257]:
            with self.subTest(kind=type(records)):
                with self.assertRaises(ValueError):
                    evaluate(manifest(), records, NOW)

    def test_full_256_node_boundary(self):
        aliases = [f"n{i}" for i in range(256)]
        result = evaluate(manifest(*aliases), [report(alias) for alias in aliases], NOW)
        self.assertEqual(result["status"], "OBSERVED_CURRENT")
        self.assertEqual(len(result["nodes"]), 256)

    def test_now_requires_timezone(self):
        with self.assertRaises(ValueError):
            evaluate(manifest(), [report()], NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()
