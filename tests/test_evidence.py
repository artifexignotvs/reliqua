import json
import os
from pathlib import Path
import tempfile
import unittest
from reliqua.evidence import read_json, seal, unseal, write_private, load_report
from reliqua.demo import sample


class EvidenceTests(unittest.TestCase):
    def test_roundtrip(self):
        raw = sample()
        self.assertEqual(unseal(seal(raw)), raw)

    def test_edit_detected(self):
        envelope = seal(sample())
        envelope['payload']['node'] = 'edge-b'
        with self.assertRaises(ValueError):
            unseal(envelope)

    def test_duplicate_keys_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.json'
            for data in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '[]']:
                path.write_text(data)
                with self.assertRaises(ValueError):
                    read_json(path)

    def test_private_file_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'evidence.json'
            write_private(path, seal(sample()))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(load_report(path)['node'], 'edge-a')
            content = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_private(path, {'bad': 'overwrite'})
            self.assertEqual(path.read_bytes(), content)

    def test_symlink_output_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'target'
            target.write_text('keep')
            link = Path(folder) / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                write_private(link, {})
            self.assertEqual(target.read_text(), 'keep')

    def test_oversized_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'oversize'
            path.write_bytes(b' ' * (8*1024*1024+1))
            with self.assertRaises(ValueError):
                read_json(path)

    def test_bool_schema_rejected(self):
        envelope = seal(sample())
        envelope['schema'] = True
        with self.assertRaises(ValueError):
            unseal(envelope)

    def test_non_ascii_digest_rejected(self):
        envelope = seal(sample())
        envelope['sha256'] = 'é' * 64
        with self.assertRaises(ValueError):
            unseal(envelope)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO test')
    def test_fifo_input_rejected_without_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'pipe'
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                read_json(path)
