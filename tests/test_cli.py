from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone, timedelta
import io
from pathlib import Path
import tempfile
import unittest
from reliqua.cli import main, compare, text
from reliqua.demo import sample
from reliqua.evidence import write_private, seal


class CLITests(unittest.TestCase):
    def test_demo_json(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(['demo', '--json']), 0)
        self.assertIn('"synthetic": true', output.getvalue())
        self.assertIn('ACTION_REQUIRED', output.getvalue())

    def test_inspect_checksum_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            envelope = seal(sample())
            envelope['payload']['node'] = 'changed'
            write_private(path, envelope)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(['inspect', str(path)]), 64)

    def test_inspect_ignores_claims(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            raw = sample()
            raw['processes'][0]['components'][0]['state'] = 'deleted'
            write_private(path, seal(raw))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['inspect', str(path), '--json']), 1)

    def test_compare_reused_pid_across_boots(self):
        now = datetime.now(timezone.utc)
        before, after = sample(now=now), sample(now=now+timedelta(seconds=10))
        after['boot_id'] = '00000000-0000-4000-8000-000000000002'
        result = compare(before, after)
        self.assertEqual(result['retained_process_identities'], 0)
        self.assertEqual(result['new_process_identities'], 1)

    def test_compare_wrong_node_and_out_of_order(self):
        before = sample()
        with self.assertRaises(ValueError):
            compare(before, before)
        with self.assertRaises(ValueError):
            compare(before, sample(node='edge-b'))

    def test_terminal_escape_sanitization(self):
        self.assertNotIn('\x1b', text('bad\x1b[2J'))
