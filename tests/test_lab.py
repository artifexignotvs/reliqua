"""Failure boundaries of the optional disposable comparison lab."""
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lab import build, common, inside, run


class LabBoundaryTests(unittest.TestCase):
    def test_bad_download_never_becomes_a_build_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "package.deb"
            with patch.object(build.urllib.request, "urlopen", return_value=io.BytesIO(b"changed")):
                with self.assertRaises(ValueError):
                    build.download("https://example.invalid/package", target, "0" * 64)
            self.assertFalse(target.exists())

    def test_oversize_download_never_becomes_a_build_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "package.deb"
            with patch.object(build.urllib.request, "urlopen", return_value=io.BytesIO(b"large")):
                with self.assertRaises(ValueError):
                    build.download("https://example.invalid/package", target, "0" * 64, limit=2)
            self.assertFalse(target.exists())

    def test_fingerprint_changes_for_code_or_runtime_pins_but_not_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lab").mkdir()
            (root / "reliqua").mkdir()
            (root / "reliqua/tool.py").write_text("a")
            (root / "lab/pins.json").write_text("{}")
            first = common.source_fingerprint(root)
            (root / "README.md").write_text("explanation")
            self.assertEqual(first, common.source_fingerprint(root))
            (root / "lab/pins.json").write_text('{"version": 2}')
            self.assertNotEqual(first, common.source_fingerprint(root))
            second = common.source_fingerprint(root)
            (root / "reliqua/tool.py").write_text("b")
            self.assertNotEqual(second, common.source_fingerprint(root))

    def test_stop_timeout_does_not_skip_copy_or_removal(self):
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with tempfile.TemporaryDirectory() as directory, patch.object(run.subprocess, "run",
                side_effect=[subprocess.TimeoutExpired("stop", 15), success, success]) as mocked:
            self.assertFalse(run.cleanup("lab-test", Path(directory)))
            self.assertEqual([call.args[0][1] for call in mocked.call_args_list], ["stop", "cp", "rm"])

    def test_copy_exception_does_not_skip_removal(self):
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with tempfile.TemporaryDirectory() as directory, patch.object(run.subprocess, "run",
                side_effect=[success, OSError("copy unavailable"), success]) as mocked:
            self.assertFalse(run.cleanup("lab-test", Path(directory)))
            self.assertEqual(mocked.call_args_list[-1].args[0][1], "rm")

    def test_removal_failure_is_not_a_successful_run(self):
        success = subprocess.CompletedProcess([], 0, b"", b"")
        failed = subprocess.CompletedProcess([], 1, b"", b"denied")
        with tempfile.TemporaryDirectory() as directory, patch.object(run.subprocess, "run",
                side_effect=[success, success, failed]):
            self.assertFalse(run.cleanup("lab-test", Path(directory)))

    def test_shared_comparison_allowlist_omits_raw_identity_and_detail(self):
        assessment = {"status": "INCOMPLETE", "web_processes": 3, "current_components": 0,
                      "findings": [{"code": "COLLECTION_GAP", "pid": 12345, "detail": "private-observation"}]}
        other = {"result": "undecided", "host": "private-host", "counts": {"undecided": 1},
                 "findings": [{"check": "process", "status": "unknown", "target": "private-target", "detail": "private-observation"}]}
        with patch.object(inside, "identities", return_value=[{"pid": 1}, {"pid": 2}, {"pid": 3}]), \
                patch.object(inside, "invoke", side_effect=[(2, assessment), (2, other)]), \
                patch.object(inside, "save"):
            result = inside.summarize_pair("inspection-denied", True)
        serialized = json.dumps(result)
        self.assertNotIn("private-", serialized)
        self.assertNotIn('"pid"', serialized)
        self.assertEqual(result["comparator"]["process_finding_statuses"], {"unknown": 1})

    def test_process_churn_invalidates_the_comparison(self):
        assessment = {"status": "OBSERVED_CURRENT"}
        original = [{"pid": 1}, {"pid": 2}, {"pid": 3}]
        changed = [{"pid": 1}, {"pid": 2}, {"pid": 4}]
        with patch.object(inside, "identities", side_effect=[original, changed, changed]), \
                patch.object(inside, "invoke", side_effect=[(0, assessment), (0, {})]):
            with self.assertRaisesRegex(ValueError, "identities changed"):
                inside.summarize_pair("current-workers")


if __name__ == "__main__":
    unittest.main()
