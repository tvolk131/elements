"""Runtime format and actual subprocess-boundary regression checks."""

import os
import http.client
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from .runtime import OwnedProcesses, load_config, read_ready_line, save_config
from .server import SettlementServer


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='elements-runtime-test-')
        self.directory = Path(self.temp.name)
        self.owned = OwnedProcesses(self.directory)

    def tearDown(self):
        self.owned.close()
        self.temp.cleanup()

    def spawn(self, script):
        return self.owned.spawn([sys.executable, '-u', '-c', script], self.directory / 'stderr.log', readiness=True)

    def test_versioned_private_config_rejects_future_and_loose_files(self):
        path = self.directory / 'config.json'
        save_config(path, {'value': 7})
        self.assertEqual(load_config(path)['schema_version'], 1)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_text('{"schema_version":2}')
        with self.assertRaisesRegex(ValueError, 'unsupported runtime schema'):
            load_config(path)
        path.write_text('{}'); path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode 0600'):
            load_config(path)

    def test_readiness_partial_line_has_one_deadline(self):
        child = self.spawn('import sys,time;sys.stdout.write(\'{"url":\');sys.stdout.flush();time.sleep(5)')
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            read_ready_line(child, timeout=.25)
        self.assertLess(time.monotonic() - started, 1.5)
        self.owned.close()
        self.assertIsNotNone(child.poll())

    def test_readiness_bounds_and_owned_cleanup(self):
        child = self.spawn('import sys,time;sys.stdout.write("x"*300+"\\n");sys.stdout.flush();time.sleep(5)')
        with self.assertRaisesRegex(RuntimeError, 'size bound'):
            read_ready_line(child, maximum=100)
        other = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(5)'])
        try:
            self.owned.close()
            self.assertIsNotNone(child.poll())
            self.assertIsNone(other.poll())
            registry = load_config(self.directory / 'processes.json')
            self.assertEqual(registry['processes'][0]['pid'], child.pid)
            self.assertEqual(registry['processes'][0]['label'], 'stderr.log')
            self.assertFalse(registry['processes'][0]['running'])
        finally:
            other.terminate(); other.wait(timeout=5)

    def test_ready_object_and_invalid_json(self):
        child = self.spawn('print(\'{"url":"http://127.0.0.1:1234/"}\')')
        self.assertEqual(read_ready_line(child)['url'], 'http://127.0.0.1:1234/')
        child = self.spawn('print("[]")')
        with self.assertRaisesRegex(ValueError, 'must be an object'):
            read_ready_line(child)

    def test_closed_launcher_refuses_new_children(self):
        self.owned.close()
        with self.assertRaisesRegex(RuntimeError, 'shutting down'):
            self.spawn('print("should never start")')
        self.assertEqual(self.owned.children, [])

    def test_shutdown_drains_an_actual_inflight_handler(self):
        started, release, finished = threading.Event(), threading.Event(), threading.Event()

        class SlowHandler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                started.set()
                release.wait(3)
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()
                finished.set()

            def log_message(self, *_):
                pass

        server = SettlementServer(None)
        server.RequestHandlerClass = SlowHandler
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
        try:
            connection.request('GET', '/')
            self.assertTrue(started.wait(2))
            server.shutdown(); server.server_close()
            self.assertFalse(server.drain_handlers(timeout=.02))
            self.assertFalse(finished.is_set())
            release.set()
            self.assertTrue(server.drain_handlers(timeout=2))
            self.assertTrue(finished.is_set())
            self.assertEqual(connection.getresponse().status, 200)
            self.assertFalse(server.handler_requests)
        finally:
            release.set()
            connection.close()
            server.server_close()
            serving.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
