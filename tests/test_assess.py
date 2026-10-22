from copy import deepcopy
import unittest
from reliqua.assess import assess, validate_report
from reliqua.demo import sample
from reliqua.policy import RECORDS, package_fix


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.raw = sample()
        self.process = self.raw['processes'][0]
        self.component = self.process['components'][0]
        self.package = self.component['package']

    def test_reviewed_backport_is_current(self):
        self.assertEqual(assess(self.raw)['status'], 'OBSERVED_CURRENT')

    def test_every_reviewed_vendor_record(self):
        for row in RECORDS:
            with self.subTest(row=row):
                package = dict(self.package, name=row['source']+'-fpm', source_name=row['source'], source_version=row['version'], version=row['version'])
                self.assertEqual(package_fix({'id': row['os_id'], 'version_id': row['os_version']}, package)['state'], 'VENDOR_FIX_RECORDED')

    def test_unknown_package_versions_never_green(self):
        for version in ['8.3.6-0ubuntu0.24.04.12', '8.3.6-0ubuntu0.24.04.14', '8.3.36', '8.3.36RC1', '8.3.6-0ubuntu0.24.04.13+local1', '999.1.0']:
            with self.subTest(version=version):
                self.package['version'] = version
                self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_wrong_distribution_or_source_never_green(self):
        for key, value in [('id', 'debian'), ('version_id', '22.04')]:
            raw = deepcopy(self.raw)
            raw['os'][key] = value
            self.assertEqual(assess(raw)['status'], 'INCOMPLETE')
        self.package['source_name'] = 'php9.0'
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_unreviewed_binary_name(self):
        self.package['name'] = 'arbitrary-custom-runtime'
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_half_installed_or_unmatched_files(self):
        for value in ['unknown', 'mismatch']:
            self.package['integrity'] = value
            self.assertNotEqual(assess(self.raw)['status'], 'OBSERVED_CURRENT')
        self.package['integrity'] = 'match'
        self.package['status'] = 'install ok unpacked'
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_stale_image_requires_action(self):
        for state in ['replaced', 'deleted']:
            self.component['state'] = state
            self.assertEqual(assess(self.raw)['status'], 'ACTION_REQUIRED')

    def test_claimed_current_cannot_override_inode_evidence(self):
        self.component['mapped_inode'] = 99
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_missing_digest_or_device_is_unknown(self):
        for key in ['sha256', 'mapped_device', 'disk_device', 'disk_inode']:
            raw = deepcopy(self.raw)
            raw['processes'][0]['components'][0].pop(key)
            self.assertEqual(assess(raw)['status'], 'INCOMPLETE')

    def test_permission_gap_is_not_a_pass(self):
        self.raw['errors'] = ['proc_access_denied']
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_any_bad_worker_blocks_group(self):
        other = deepcopy(self.process)
        other['pid'] += 1
        other['components'][0]['state'] = 'deleted'
        self.raw['processes'].append(other)
        self.assertEqual(assess(self.raw)['status'], 'ACTION_REQUIRED')

    def test_no_web_and_cli_only_are_unknown(self):
        self.process['kind'] = 'cli'
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')
        self.raw['processes'] = []
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_apache_requires_module(self):
        self.process['kind'] = 'apache'
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')
        self.component['role'] = 'module'
        self.package['name'] = 'libapache2-mod-php8.3'
        self.assertEqual(assess(self.raw)['status'], 'OBSERVED_CURRENT')

    def test_duplicate_pids_and_boolean_pid_rejected(self):
        self.raw['processes'].append(deepcopy(self.process))
        with self.assertRaises(ValueError):
            validate_report(self.raw)
        self.raw['processes'].pop()
        self.process['pid'] = True
        with self.assertRaises(ValueError):
            validate_report(self.raw)

    def test_unhashable_fields_rejected_cleanly(self):
        for target, key in [(self.raw, 'scope'), (self.process, 'kind'), (self.component, 'state'), (self.component, 'role')]:
            old = target[key]
            for bad in [[], {}, None, 42]:
                target[key] = bad
                with self.assertRaises(ValueError):
                    validate_report(self.raw)
            target[key] = old

    def test_effective_claim_in_payload_is_ignored(self):
        self.raw['assessment'] = {'status': 'OBSERVED_CURRENT'}
        self.component['package'] = None
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_pid_lifecycle_change_is_unknown(self):
        self.process['errors'] = ['process_changed']
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')

    def test_controls_and_naive_timestamp_rejected(self):
        self.component['path'] = '/tmp/\x1b[2J'
        with self.assertRaises(ValueError):
            assess(self.raw)
        self.component['path'] = '/usr/sbin/php-fpm8.3'
        self.raw['collected_at'] = '2026-10-22T12:00:00'
        with self.assertRaises(ValueError):
            assess(self.raw)

    def test_cli_candidate_alongside_fpm_blocks_completion(self):
        other = deepcopy(self.process)
        other['pid'] += 1
        other['kind'] = 'cli'
        self.raw['processes'].append(other)
        self.assertEqual(assess(self.raw)['status'], 'INCOMPLETE')
