# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real TLS regressions for absolute deadlines and narrowly typed retries."""

import http.client
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from guardian_client import FixtureCA
from guardian_service import GuardianTransportError, GuardianTransportTimeout, canonical, tls_request


class ScriptedTLS:
    """Minimal test peer; no private guardian state or decryption operations."""
    def __init__(self, credentials, client_ca, script):
        self.script, self.accepted = script, 0
        self.stop = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(credentials['certificate'], credentials['private_key'])
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cafile=client_ca)
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(8)
        self.socket.settimeout(0.1)
        self.endpoint = f'https://127.0.0.1:{self.socket.getsockname()[1]}'
        self.workers = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                stream, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepted += 1
            sequence = self.accepted
            worker = threading.Thread(target=self.respond, args=(stream, sequence), daemon=True)
            self.workers.append(worker)
            worker.start()

    def respond(self, stream, sequence):
        try:
            stream.settimeout(2)
            with self.context.wrap_socket(stream, server_side=True) as secured:
                self.script(self, secured, sequence)
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    @staticmethod
    def request(stream):
        data = bytearray()
        while b'\r\n\r\n' not in data:
            chunk = stream.recv(4096)
            if not chunk:
                return False
            data.extend(chunk)
        headers, _separator, body = bytes(data).partition(b'\r\n\r\n')
        length = next((int(line.split(b':', 1)[1]) for line in headers.split(b'\r\n')
                       if line.lower().startswith(b'content-length:')), 0)
        while len(body) < length:
            chunk = stream.recv(length - len(body))
            if not chunk:
                return False
            body += chunk
        return True

    @staticmethod
    def response(stream, code=200, payload=None):
        payload = canonical({'ok': True}) if payload is None else payload
        stream.sendall(f'HTTP/1.0 {code} Test\r\nContent-Length: {len(payload)}\r\n\r\n'.encode() + payload)

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for ephemeral TLS fixtures')
class GuardianTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='elements-guardian-transport-')
        cls.addClassCleanup(cls.directory.cleanup)
        ca = FixtureCA(Path(cls.directory.name) / 'trusted')
        cls.client, cls.server = ca.issue('client'), ca.issue('server')
        cls.foreign = FixtureCA(Path(cls.directory.name) / 'foreign').issue('foreign-server')

    def call(self, server, operation='begin_deal', *, timeout=1, fingerprint=None):
        return tls_request(server.endpoint, self.client, {'operation': operation},
                           self.server['fingerprint'] if fingerprint is None else fingerprint, timeout=timeout)

    def test_slow_drip_http10_body_obeys_deadline_after_socket_detaches(self):
        detached = []
        original = http.client.HTTPSConnection.getresponse

        def observe(connection):
            response = original(connection)
            detached.append(connection.sock is None)
            return response

        def drip(server, stream, _sequence):
            if not server.request(stream):
                return
            stream.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 200\r\n\r\n{')
            for _ in range(150):
                if server.stop.wait(0.02):
                    break
                stream.sendall(b' ')

        with ScriptedTLS(self.server, self.client['ca'], drip) as server:
            started = time.monotonic()
            with patch('guardian_service.http.client.HTTPSConnection.getresponse', new=observe):
                with self.assertRaises(GuardianTransportTimeout) as raised:
                    self.call(server, timeout=0.3)
            self.assertIsInstance(raised.exception, TimeoutError)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(detached, [True])
            self.assertEqual(server.accepted, 1)

    def test_slow_drip_headers_obey_total_deadline(self):
        def drip(server, stream, _sequence):
            if not server.request(stream):
                return
            stream.sendall(b'HTTP/1.0 200 OK\r\nX-Trace: ')
            for _ in range(150):
                if server.stop.wait(0.02):
                    break
                stream.sendall(b'a')

        with ScriptedTLS(self.server, self.client['ca'], drip) as server:
            started = time.monotonic()
            with self.assertRaises(GuardianTransportTimeout):
                self.call(server, timeout=0.3)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(server.accepted, 1)

    def test_stalled_outgoing_tls_handshake_obeys_total_deadline(self):
        stop, accepted = threading.Event(), threading.Event()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(2)

        def stall():
            try:
                connection, _address = listener.accept()
                with connection:
                    accepted.set()
                    stop.wait(2)
            except OSError:
                pass

        worker = threading.Thread(target=stall, daemon=True)
        worker.start()
        try:
            endpoint = f'https://127.0.0.1:{listener.getsockname()[1]}'
            started = time.monotonic()
            with self.assertRaises(GuardianTransportTimeout):
                tls_request(endpoint, self.client, {'operation': 'begin_deal'},
                            self.server['fingerprint'], timeout=0.3)
            self.assertTrue(accepted.is_set())
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            stop.set()
            listener.close()
            worker.join(timeout=2)

    def test_retry_budget_is_shared_and_attempt_count_is_bounded(self):
        def always_unavailable(server, stream, _sequence):
            if server.request(stream):
                server.response(stream, 503)

        with ScriptedTLS(self.server, self.client['ca'], always_unavailable) as server:
            with self.assertRaises(GuardianTransportError) as raised:
                self.call(server)
            self.assertNotIsInstance(raised.exception, TimeoutError)
            self.assertEqual(server.accepted, 3)

        def unavailable_then_drip(server, stream, sequence):
            if not server.request(stream):
                return
            if sequence == 1:
                server.response(stream, 503)
                return
            stream.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 200\r\n\r\n{')
            for _ in range(150):
                if server.stop.wait(0.02):
                    break
                stream.sendall(b' ')

        with ScriptedTLS(self.server, self.client['ca'], unavailable_then_drip) as server:
            started = time.monotonic()
            with self.assertRaises(GuardianTransportTimeout):
                self.call(server, timeout=0.5)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(server.accepted, 2)

    def test_certificate_pinning_and_protocol_errors_are_never_retried(self):
        def success(server, stream, _sequence):
            if server.request(stream):
                server.response(stream)

        with ScriptedTLS(self.foreign, self.client['ca'], success) as server:
            with self.assertRaisesRegex(ValueError, 'certificate verification'):
                self.call(server, fingerprint=self.foreign['fingerprint'])
            self.assertEqual(server.accepted, 1)
        with ScriptedTLS(self.server, self.client['ca'], success) as server:
            with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
                self.call(server, fingerprint='0' * 64)
            self.assertEqual(server.accepted, 1)

        def truncated_rejection(server, stream, _sequence):
            if server.request(stream):
                stream.sendall(b'HTTP/1.0 400 Invalid\r\nContent-Length: 200\r\n\r\n')

        with ScriptedTLS(self.server, self.client['ca'], truncated_rejection) as server:
            with self.assertRaisesRegex(ValueError, 'rejected request'):
                self.call(server)
            self.assertEqual(server.accepted, 1)

    def test_only_idempotent_messages_retry_lost_bodies(self):
        def truncated_then_success(server, stream, sequence):
            if not server.request(stream):
                return
            if sequence == 1:
                stream.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 200\r\n\r\n{')
            else:
                server.response(stream)

        with ScriptedTLS(self.server, self.client['ca'], truncated_then_success) as server:
            self.assertEqual(self.call(server), {'ok': True})
            self.assertEqual(server.accepted, 2)
        with ScriptedTLS(self.server, self.client['ca'], truncated_then_success) as server:
            with self.assertRaises(GuardianTransportError):
                self.call(server, operation='disclose')
            self.assertEqual(server.accepted, 1)

    def test_local_credential_error_is_not_a_transport_error(self):
        credentials = dict(self.client, ca=str(Path(self.directory.name) / 'absent.pem'))
        with self.assertRaises(OSError) as raised:
            tls_request('https://127.0.0.1:1', credentials, {'operation': 'begin_deal'}, '0' * 64)
        self.assertNotIsInstance(raised.exception, GuardianTransportError)


if __name__ == '__main__':
    unittest.main()
