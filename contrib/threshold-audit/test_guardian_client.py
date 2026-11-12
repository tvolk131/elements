# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bounded startup and retained diagnostics for isolated guardian processes."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from guardian_client import GuardianProcess, GuardianCluster


class GuardianClientTests(unittest.TestCase):
    def test_close_serializes_with_inflight_enrollment_and_refuses_restart(self):
        started, release = threading.Event(), threading.Event()
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'])
        errors = []

        class ExistingGuardian:
            config = {'trusted_clients': {}, 'library': 'unused', 'directory': '/tmp/unused', 'recipients': {}}
            process = child

            def stop(self):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)

        class SlowCA:
            def issue_or_resume(self, name):
                if name == 'guardian-2':
                    started.set()
                    if not release.wait(3):
                        raise RuntimeError('test enrollment was not released')
                return {'fingerprint': name}

        pool = GuardianCluster.__new__(GuardianCluster)
        pool.lifecycle_lock, pool.closing = threading.RLock(), threading.Event()
        pool.guardians, pool.approvers, pool.ca = {1: ExistingGuardian()}, {}, SlowCA()

        def enroll():
            try:
                pool.extend((2,))
            except RuntimeError as error:
                errors.append(str(error))

        enrolling = threading.Thread(target=enroll)
        closing = threading.Thread(target=pool.close)
        try:
            enrolling.start()
            self.assertTrue(started.wait(2))
            closing.start()
            self.assertTrue(pool.closing.wait(2))
            self.assertTrue(closing.is_alive())
            release.set()
            enrolling.join(timeout=3); closing.join(timeout=3)
            self.assertFalse(enrolling.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertEqual(errors, ['guardian pool is shutting down'])
            self.assertIsNotNone(child.poll())
            self.assertEqual(set(pool.guardians), {1})
            with self.assertRaisesRegex(RuntimeError, 'shutting down'):
                pool.extend((2,))
        finally:
            release.set()
            enrolling.join(timeout=5)
            if closing.ident is not None:
                closing.join(timeout=5)
            pool.close()

    def test_partial_startup_line_times_out_without_losing_diagnostics(self):
        launched = []
        real_popen = subprocess.Popen

        def delayed_child(_args, **options):
            program = ("import sys,time; sys.stderr.write('startup diagnostic sentinel\\n'); "
                       "sys.stderr.flush(); sys.stdout.write('{'); sys.stdout.flush(); time.sleep(30)")
            child = real_popen([sys.executable, '-u', '-c', program], **options)
            launched.append(child)
            return child

        diagnostic = None
        try:
            with tempfile.TemporaryDirectory(prefix='elements-guardian-startup-test-') as directory:
                guardian = GuardianProcess({'member': 1, 'directory': str(Path(directory) / 'private'),
                                            'startup_timeout': 1, 'fingerprint': '0' * 64}, {})
                started = time.monotonic()
                with patch('guardian_client.subprocess.Popen', side_effect=delayed_child):
                    with self.assertRaisesRegex(RuntimeError, 'guardian 1 failed startup.*diagnostics:'):
                        guardian.start()
                self.assertLess(time.monotonic() - started, 10)
                self.assertIsNone(guardian.process)
                self.assertIsNotNone(launched[0].poll())
                diagnostic = Path(guardian.startup_diagnostic)
                self.assertNotIn(Path(directory), diagnostic.parents)
                self.assertEqual(diagnostic.stat().st_mode & 0o777, 0o600)
            # The caller's TemporaryDirectory has gone, but useful evidence
            # survives. It contains no private guardian state or TLS keys.
            content = diagnostic.read_text()
            self.assertIn('startup diagnostic sentinel', content)
            self.assertIn('startup address deadline exceeded', content)
            self.assertIn('"stdout_bytes":1', content)
        finally:
            for child in launched:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
            if diagnostic is not None:
                shutil.rmtree(diagnostic.parent)


if __name__ == '__main__':
    unittest.main()
