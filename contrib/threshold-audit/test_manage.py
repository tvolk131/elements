"""Actual process-boundary safety checks for the selected-demo manager."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import manage
from settlement.runtime import load_config, save_config


@unittest.skipUnless(Path('/proc/self/stat').exists(), 'local demo management uses Linux procfs')
class DemoManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='elements-manager-test-')
        self.root = Path(self.temporary.name)
        self.runtime = self.root / 'runtime'; self.runtime.mkdir(mode=0o700)
        self.registry = self.root / 'selected.json'
        save_config(self.runtime / 'ready.json', {'pid': 99999999, 'url': 'http://127.0.0.1:1/', 'genesis_hash': '11' * 32})
        save_config(self.runtime / 'adapter.json', {'policy_version': 'sandbox-v3'})
        save_config(self.runtime / 'launcher.json', {'daemon_args': []})
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        self.temporary.cleanup()

    def sleeper(self, *arguments):
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)', *map(str, arguments)], start_new_session=True)
        self.children.append(child)
        return child

    def test_selection_is_private_and_does_not_start_processes(self):
        self.assertEqual(manage.select_runtime(self.runtime, self.registry), self.runtime)
        self.assertEqual(manage.selected_runtime(self.registry), self.runtime)
        self.assertEqual(self.registry.stat().st_mode & 0o777, 0o600)
        self.assertEqual(manage.status(self.runtime)['state'], 'stopped')

    def test_future_schema_and_unrelated_registry_are_not_rewritten(self):
        ready = self.runtime / 'ready.json'
        value = load_config(ready); value['schema_version'] = 999
        ready.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'unsupported runtime schema'):
            manage.select_runtime(self.runtime, self.registry)
        self.assertFalse(self.registry.exists())
        save_config(ready, value)
        save_config(self.registry, {'kind': 'some-other-application'})
        original = self.registry.read_bytes()
        with self.assertRaisesRegex(ValueError, 'unrelated registry'):
            manage.select_runtime(self.runtime, self.registry)
        self.assertEqual(self.registry.read_bytes(), original)

    def test_stale_ready_pid_never_stops_an_unrelated_process(self):
        unrelated = self.sleeper()
        ready = load_config(self.runtime / 'ready.json'); ready['pid'] = unrelated.pid
        save_config(self.runtime / 'ready.json', ready)
        result = manage.stop(self.runtime, timeout=1)
        self.assertEqual(result['state'], 'stopped')
        self.assertIsNone(unrelated.poll())

    def test_orphan_stop_respects_exact_runtime_boundary(self):
        owned = self.sleeper('settlement.treasury', self.runtime / 'service.json')
        sibling = self.root / 'runtime-other'; sibling.mkdir()
        unrelated = self.sleeper('settlement.treasury', sibling / 'service.json')
        self.assertEqual(manage.status(self.runtime)['state'], 'orphaned')
        result = manage.stop(self.runtime, timeout=3)
        self.assertEqual(result['state'], 'stopped')
        owned.wait(timeout=2)
        self.assertIsNone(unrelated.poll())

    def test_start_refuses_existing_orphans(self):
        child = self.sleeper('settlement.treasury', self.runtime / 'service.json')
        with self.assertRaisesRegex(RuntimeError, 'orphaned runtime services'):
            manage.start(self.runtime, timeout=1)
        self.assertIsNone(child.poll())

    def test_concurrent_control_is_refused(self):
        with manage.control_lock(self.runtime):
            with self.assertRaisesRegex(RuntimeError, 'another manager'):
                with manage.control_lock(self.runtime):
                    self.fail('simultaneous lifecycle controllers were accepted')

    def test_nonfinite_cli_deadlines_are_refused(self):
        for timeout in ('nan', 'inf', '-1'):
            result = subprocess.run([sys.executable, str(Path(manage.__file__)), '--timeout', timeout, 'stop'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn('finite and positive', result.stderr)


if __name__ == '__main__':
    unittest.main()
