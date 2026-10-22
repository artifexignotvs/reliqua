import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import time
from unittest.mock import patch

from reliqua import collector


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        (self.proc / "self/ns").mkdir(parents=True)
        (self.proc / "self/ns/mnt").symlink_to("/proc/self/ns/mnt")
        boot = self.proc / "sys/kernel/random"
        boot.mkdir(parents=True)
        (boot / "boot_id").write_text("00000000-0000-4000-8000-000000000001\n")
        self.os_release = self.root / "os-release"
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.runtime = self.root / "php-fpm8.3"
        self.runtime.write_bytes(b"runtime fixture\n")
        self.pid = 1234
        self.directory = self.proc / str(self.pid)
        (self.directory / "ns").mkdir(parents=True)
        (self.directory / "ns/mnt").symlink_to("/proc/self/ns/mnt")
        (self.directory / "root").symlink_to("/")
        (self.directory / "exe").symlink_to(self.runtime)
        self.stat_file()
        self.maps_file(self.runtime)
        self.package = {"name": "php8.3-fpm", "source_name": "php8.3",
                        "source_version": "8.3.6-0ubuntu0.24.04.13",
                        "version": "8.3.6-0ubuntu0.24.04.13",
                        "status": "install ok installed", "integrity": "match"}

    def stat_file(self, name="php-fpm8.3", ticks=100):
        fields = ["0"] * 52
        fields[0] = "S"
        fields[19] = str(ticks)
        (self.directory / "stat").write_text(f"{self.pid} ({name}) " + " ".join(fields) + "\n")

    def maps_file(self, path):
        metadata = path.stat()
        (self.directory / "maps").write_text(
            f"1000-2000 r-xp 00000000 {collector._device(metadata.st_dev)} {metadata.st_ino} {path}\n")

    def collect(self, pids=None):
        with patch.object(collector, "PROC_ROOT", self.proc), patch.object(collector, "OS_RELEASE", self.os_release), patch.object(collector, "package_for", return_value=self.package):
            return collector.collect("node-a", pids)

    def test_current_runtime_has_identity_and_package(self):
        result = self.collect()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["scope"], "visible-proc")
        component = result["processes"][0]["components"][0]
        self.assertEqual(component["state"], "current")
        self.assertEqual(component["mapped_inode"], component["disk_inode"])
        self.assertEqual(len(component["sha256"]), 64)
        self.assertEqual(component["package"]["integrity"], "match")

    def test_selected_scope_is_explicit(self):
        result = self.collect([self.pid])
        self.assertEqual(result["scope"], "selected-pids")
        self.assertEqual(len(result["processes"]), 1)

    def test_replaced_apache_module(self):
        apache = self.root / "apache2"
        apache.write_bytes(b"apache fixture\n")
        (self.directory / "exe").unlink()
        (self.directory / "exe").symlink_to(apache)
        module = self.root / "libphp8.3.so"
        module.write_bytes(b"old module\n")
        self.maps_file(module)
        self.stat_file("apache2")
        replacement = self.root / "replacement"
        replacement.write_bytes(b"new module\n")
        replacement.replace(module)
        result = self.collect()
        process = result["processes"][0]
        self.assertEqual(process["kind"], "apache")
        self.assertEqual(len(process["components"]), 1)
        self.assertEqual(process["components"][0]["role"], "module")
        self.assertEqual(process["components"][0]["state"], "replaced")
        self.assertIsNone(process["components"][0]["package"])

    def test_namespace_mismatch_has_no_package_trust(self):
        with patch.object(collector, "_same_context", return_value=False):
            result = self.collect([self.pid])
        process = result["processes"][0]
        self.assertIn("namespace_unverified", process["errors"])
        self.assertEqual(process["components"][0]["state"], "unknown")
        self.assertIsNone(process["components"][0]["package"])

    def test_same_namespace_different_root_not_trusted(self):
        (self.directory / "root").unlink()
        (self.directory / "root").symlink_to(self.root)
        result = self.collect([self.pid])
        self.assertIn("namespace_unverified", result["processes"][0]["errors"])

    def test_process_map_race_invalidates_evidence(self):
        original = collector._read
        calls = 0
        def changing(path, limit):
            nonlocal calls
            data = original(path, limit)
            if path == self.directory / "maps":
                calls += 1
                if calls == 2:
                    data += b"3000-4000 rw-p 00000000 00:00 0 [heap]\n"
            return data
        with patch.object(collector, "_read", side_effect=changing):
            result = self.collect([self.pid])
        process = result["processes"][0]
        self.assertIn("process_changed", process["errors"])
        self.assertEqual(process["components"][0]["state"], "unknown")
        self.assertIsNone(process["components"][0]["package"])

    def test_permission_failure_invalidates_visible_coverage(self):
        original = collector._read
        def denied(path, limit):
            if path == self.directory / "maps":
                raise PermissionError()
            return original(path, limit)
        with patch.object(collector, "_read", side_effect=denied):
            result = self.collect()
        self.assertIn("proc_access_denied", result["errors"])

    def test_missing_selected_process_is_preserved(self):
        result = self.collect([9999])
        self.assertIn("proc_disappeared", result["errors"])
        self.assertEqual(result["processes"][0]["pid"], 9999)

    def test_empty_inventory_never_clean(self):
        shutil.rmtree(self.directory)
        result = self.collect()
        self.assertIn("no_processes_visible", result["errors"])
        self.assertIn("no_php_runtime_observed", result["errors"])

    def test_cli_identified_separately(self):
        cli = self.root / "php8.3"
        self.runtime.rename(cli)
        (self.directory / "exe").unlink()
        (self.directory / "exe").symlink_to(cli)
        self.maps_file(cli)
        self.stat_file("php8.3")
        self.assertEqual(self.collect()["processes"][0]["kind"], "cli")

    def test_size_limit_is_unknown(self):
        with patch.object(collector, "MAX_BINARY_BYTES", 1):
            result = self.collect([self.pid])
        component = result["processes"][0]["components"][0]
        self.assertEqual(component["state"], "unknown")
        self.assertIn("runtime_size_limit", component["errors"])

    def test_invalid_selection_rejected(self):
        for pids in ([], [True], [0], [-1], ["12"]):
            with self.assertRaises(ValueError):
                collector.collect("node-a", pids)

    @unittest.skipUnless(os.path.isdir("/proc/self") and os.path.isfile("/bin/sleep"), "Linux fixture required")
    def test_live_replaced_executable_is_detected(self):
        live = self.root / "live" / "php-fpm8.3"
        live.parent.mkdir()
        shutil.copyfile("/bin/sleep", live)
        live.chmod(0o700)
        process = subprocess.Popen([str(live), "30"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 2
            while True:
                status = Path(f"/proc/{process.pid}/stat").read_text().rpartition(")")[2].split()[0]
                if status == "S":
                    break
                if time.monotonic() >= deadline:
                    self.fail("fixture did not finish startup")
                time.sleep(0.01)
            replacement = self.root / "fresh"
            shutil.copyfile("/bin/sleep", replacement)
            replacement.chmod(0o700)
            replacement.replace(live)
            with patch.object(collector, "package_for", return_value=None):
                result = collector.collect("fixture", [process.pid])
            component = result["processes"][0]["components"][0]
            self.assertEqual(component["state"], "deleted")
            self.assertIsNone(component["package"])
            from reliqua.assess import assess
            self.assertEqual(assess(result)["status"], "ACTION_REQUIRED")
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
