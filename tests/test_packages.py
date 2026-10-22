import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from reliqua import packages


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "php-fpm8.3"
        self.binary.write_bytes(b"fixture runtime\n")
        self.info = self.root / "info"
        self.info.mkdir()
        checksum = hashlib.md5(self.binary.read_bytes(), usedforsecurity=False).hexdigest()
        (self.info / "php8.3-fpm.md5sums").write_text(f"{checksum}  {str(self.binary).lstrip('/')}\n")
        self.records = [f"php8.3-fpm: {self.binary}\n",
                        "php8.3-fpm\tphp8.3\t8.3.6-0ubuntu0.24.04.13\t8.3.6-0ubuntu0.24.04.13\tinstall ok installed\tamd64\n"]
        self.records.append(self.records[1])

    def package(self):
        with patch.object(packages, "INFO_ROOT", self.info), patch.object(packages, "_query", side_effect=self.records):
            return packages.package_for(str(self.binary))

    def test_native_source_and_integrity(self):
        result = self.package()
        self.assertEqual(result["source_name"], "php8.3")
        self.assertEqual(result["source_version"], "8.3.6-0ubuntu0.24.04.13")
        self.assertEqual(result["status"], "install ok installed")
        self.assertEqual(result["integrity"], "match")

    def test_modified_binary(self):
        self.binary.write_bytes(b"modified runtime\n")
        self.assertEqual(self.package()["integrity"], "mismatch")

    def test_package_database_race_is_unknown(self):
        self.records[2] = self.records[1].replace(".13", ".12")
        self.assertEqual(self.package()["integrity"], "unknown")

    def test_missing_checksums_unknown(self):
        (self.info / "php8.3-fpm.md5sums").unlink()
        self.assertEqual(self.package()["integrity"], "unknown")

    def test_duplicate_checksum_unknown(self):
        record = self.info / "php8.3-fpm.md5sums"
        record.write_bytes(record.read_bytes() * 2)
        self.assertEqual(self.package()["integrity"], "unknown")

    def test_symlink_not_hashed(self):
        destination = self.root / "real"
        self.binary.rename(destination)
        self.binary.symlink_to(destination)
        self.assertEqual(self.package()["integrity"], "unknown")

    def test_ambiguous_owner_rejected(self):
        self.records[0] += f"php8.3-cli: {self.binary}\n"
        self.assertIsNone(self.package())

    def test_substring_ownership_rejected(self):
        self.records[0] = f"php8.3-fpm: {self.binary}.other\n"
        self.assertIsNone(self.package())

    def test_unexpected_binary_identity_rejected(self):
        self.records[1] = self.records[1].replace("php8.3-fpm\t", "php8.3-cli\t")
        self.assertIsNone(self.package())

    def test_search_glob_and_control_paths_rejected(self):
        with patch.object(packages, "_query") as query:
            for path in ("relative", "/tmp/*", "/tmp/a?", "/tmp/[a]", "/tmp/a\nb", "/tmp/../etc/passwd"):
                self.assertIsNone(packages.package_for(path))
            query.assert_not_called()

    def test_binary_size_limit(self):
        with patch.object(packages, "MAX_BINARY_BYTES", 1):
            self.assertEqual(self.package()["integrity"], "unknown")

    def test_query_uses_fixed_command_without_shell(self):
        real_popen = subprocess.Popen
        calls = []
        def capture(argv, **kwargs):
            calls.append((argv, kwargs))
            return real_popen(argv, **kwargs)
        if not os.path.exists(packages.DPKG_QUERY):
            self.skipTest("package manager unavailable")
        with patch.object(packages.subprocess, "Popen", side_effect=capture):
            result = packages._query(["--version"])
        self.assertIsNotNone(result)
        self.assertEqual(calls[0][0][0], "/usr/bin/dpkg-query")
        self.assertNotIn("shell", calls[0][1])

    def test_query_output_limit(self):
        if not os.path.exists(packages.DPKG_QUERY):
            self.skipTest("package manager unavailable")
        with patch.object(packages, "MAX_QUERY_BYTES", 1):
            self.assertIsNone(packages._query(["--version"]))


if __name__ == "__main__":
    unittest.main()
