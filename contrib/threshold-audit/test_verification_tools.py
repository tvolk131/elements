"""Safety/reproducibility tests for review export and owned-process cleanup."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from export_review import category, export, snapshot
from verify import OwnedProcess, process_identity, signal_identity


class ReviewExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='review-export-test-')
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / 'source'; self.repo.mkdir()
        self.git('init', '-q')
        self.write('src/blind.cpp', 'base source\n')
        self.write('unrelated.txt', 'untouched personal material\n')
        self.git('add', '.')
        self.git('-c', 'user.name=VerificationFixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture base')

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *arguments):
        return subprocess.run(['git', *arguments], cwd=self.repo, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def write(self, relative, value):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def test_complete_series_reconstructs_tracked_untracked_and_modes_without_git_mutation(self):
        self.write('src/blind.cpp', 'base source\nreview change\n')
        self.write('src/threshold_audit.h', 'new public header\n')
        script = self.write('contrib/threshold-audit/settlement/example.py', 'print("public source")\n')
        script.chmod(0o755)
        self.write('contrib/threshold-audit/review/vectors/public-v1.json', '{"public":true}\n')
        secret = 'NEVER_EXPORT_THIS_SECRET'
        self.write('contrib/threshold-audit/settlement/runtime/credentials.json', secret)
        self.write('contrib/threshold-audit/settlement/credentials.json', secret)
        self.write('contrib/threshold-audit/settlement/__pycache__/example.pyc', secret)
        before_head = self.git('rev-parse', 'HEAD')
        before_index = self.git('ls-files', '--stage', '-z')
        before_status = self.git('status', '--porcelain=v1', '-z')
        output = self.directory / 'review'
        manifest = export(output, root=self.repo)
        self.assertEqual(manifest['verification']['status'], 'passed')
        self.assertFalse(manifest['verification']['intermediate_builds_checked'])
        self.assertEqual(self.git('rev-parse', 'HEAD'), before_head)
        self.assertEqual(self.git('ls-files', '--stage', '-z'), before_index)
        self.assertEqual(self.git('status', '--porcelain=v1', '-z'), before_status)
        self.assertEqual(next(file for file in manifest['files'] if file['path'].endswith('example.py'))['mode'], '100755')
        for file in output.iterdir():
            self.assertNotIn(secret.encode(), file.read_bytes())
        self.assertGreaterEqual(manifest['excluded_untracked']['count'], 3)

    def test_unclassified_tracked_changes_fail_before_export(self):
        self.write('unrelated.txt', 'private local change\n')
        with self.assertRaisesRegex(ValueError, 'unclassified tracked'):
            export(self.directory / 'review', root=self.repo)

    def test_runtime_names_and_private_json_are_not_review_sources(self):
        for path in ('contrib/threshold-audit/settlement/service.json',
                     'contrib/threshold-audit/review/inventory.json',
                     'contrib/threshold-audit/settlement/runtime/private.py',
                     'contrib/threshold-audit/settlement/test-data/credentials.json',
                     'contrib/threshold-audit/review/vectors/credentials.json',
                     'contrib/threshold-audit/settlement/tls/private.key'):
            self.assertIsNone(category(path), path)
        self.assertIsNotNone(category('contrib/threshold-audit/review/vectors/public-v1.json'))

    def test_source_symlink_is_refused(self):
        path = self.repo / 'src/threshold_audit.h'
        path.symlink_to(self.repo / 'unrelated.txt')
        with self.assertRaisesRegex(ValueError, 'regular file'):
            snapshot('src/threshold_audit.h', self.repo)
        path.unlink(); path.symlink_to(self.repo / 'missing-secret-file')
        with self.assertRaisesRegex(ValueError, 'regular file'):
            snapshot('src/threshold_audit.h', self.repo)


@unittest.skipUnless(Path('/proc/self/stat').is_file(), 'strict process ownership test requires Linux procfs')
class OwnedProcessTests(unittest.TestCase):
    @staticmethod
    def running(pid):
        try:
            state = (Path('/proc') / str(pid) / 'stat').read_text().rpartition(')')[2].split()[0]
            return state != 'Z'
        except OSError:
            return False

    def test_cleanup_kills_separate_session_descendant_without_touching_unrelated_process(self):
        with tempfile.TemporaryDirectory(prefix='verification-process-test-') as directory:
            log = Path(directory) / 'owned.log'
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
            owned = OwnedProcess([sys.executable, '-u', '-c',
                'import subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True); print(child.pid,flush=True); time.sleep(60)'], log)
            try:
                deadline = time.monotonic() + 5
                while not log.read_text().strip() and time.monotonic() < deadline:
                    time.sleep(.02)
                child = int(log.read_text().strip())
                wrong_birth = process_identity(unrelated.pid) + 1
                signal_identity(unrelated.pid, wrong_birth, signal.SIGKILL)
                self.assertIsNone(unrelated.poll())
                owned.stop(timeout=2)
                deadline = time.monotonic() + 2
                while self.running(child) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(self.running(child))
                self.assertIsNone(unrelated.poll())
            finally:
                owned.stop(timeout=1)
                unrelated.terminate(); unrelated.wait(timeout=5)

    def test_orphan_cleanup_is_limited_to_fresh_private_runtime(self):
        with tempfile.TemporaryDirectory(prefix='verification-orphan-test-') as directory:
            directory = Path(directory)
            runtime = directory / 'own-runtime'; runtime.mkdir()
            other = directory / 'other-runtime'; other.mkdir()
            sleeper = 'import time; time.sleep(60)'
            unrelated = subprocess.Popen([sys.executable, '-c', sleeper, 'settlement.treasury', str(other / 'service.json')], start_new_session=True)
            log = directory / 'owned.log'
            script = ('import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c",'
                      '"import time; time.sleep(60)","settlement.treasury",sys.argv[1]],start_new_session=True); '
                      'print(child.pid,flush=True); time.sleep(.1); os._exit(1)')
            owned = OwnedProcess([sys.executable, '-u', '-c', script, str(runtime / 'service.json')], log)
            owned.runtime = runtime
            try:
                self.assertEqual(owned.process.wait(timeout=5), 1)
                child = int(log.read_text().strip())
                owned.stop(timeout=2)
                self.assertFalse(self.running(child))
                self.assertIsNone(unrelated.poll())
            finally:
                owned.stop(timeout=1)
                unrelated.terminate(); unrelated.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
