"""Real HTTP boundary tests for opt-in mesh front ends."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import unittest

from .mesh import MeshGateway, profile


class MeshGatewayTests(unittest.TestCase):
    def setUp(self):
        self.received = []
        received = self.received

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.reply()

            def do_POST(self):
                self.reply()

            def reply(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                received.append({'path': self.path, 'method': self.command, 'headers': dict(self.headers), 'body': body})
                if self.path == '/api/dashboard':
                    value = {'guardians': [{'id': 'institution-1', 'approval_url': 'internal-only'}], 'unchanged': 'business-data'}
                elif self.path == '/info':
                    value = {'guardian_id': 'institution-1', 'coordinator_origins': ['http://127.0.0.1:9999']}
                else:
                    value = {'ok': True}
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', 'fixture=secret; HttpOnly')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data)

        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.thread = threading.Thread(target=self.backend.serve_forever, daemon=True); self.thread.start()
        sockets = []
        for _ in range(2):
            sock = socket.socket(socket.AF_INET6)
            sock.bind(('::1', 0)); sockets.append(sock)
        self.ports = [sock.getsockname()[1] for sock in sockets]
        for sock in sockets:
            sock.close()
        url = f'http://127.0.0.1:{self.backend.server_port}/'
        self.urls = {'institution-1': url}
        self.gateway = MeshGateway({'bind_address': '::1', 'hostname': 'demo.network.ray',
                                    'port': self.ports[0], 'institution_ports': self.ports[1:]},
                                   url, lambda: self.urls).start()

    def tearDown(self):
        self.gateway.close()
        self.backend.shutdown(); self.backend.server_close(); self.thread.join(timeout=2)

    def request(self, path, *, institution=False, method='GET', headers=None, body=None):
        index = 1 if institution else 0
        values = {'Host': f'demo.network.ray:{self.ports[index]}', **(headers or {})}
        connection = http.client.HTTPConnection('::1', self.ports[index], timeout=5)
        try:
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    def test_host_origin_and_request_framing_fail_closed(self):
        self.assertEqual(self.request('/wallet', headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/login', method='POST', body='{}', headers={'Origin': 'http://attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/dashboard', headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(self.request('/wallet?leak=1')[0], 400)
        self.assertEqual(self.request('/api/login', method='POST', body='', headers={'Transfer-Encoding': 'chunked'})[0], 400)
        self.assertFalse(self.received)

    def test_dashboard_urls_and_loopback_origin_translation(self):
        origin = self.gateway.origin()
        status, data, _ = self.request('/api/dashboard', headers={'Cookie': 'session=private', 'Origin': origin})
        self.assertEqual(status, 200)
        self.assertEqual(data['guardians'][0]['approval_url'], self.gateway.origin(0) + '/')
        self.assertEqual(data['unchanged'], 'business-data')
        self.assertEqual(self.received[-1]['headers']['Origin'], f'http://127.0.0.1:{self.backend.server_port}')
        self.assertEqual(self.received[-1]['headers']['Cookie'], 'session=private')

    def test_institution_frontend_drops_cookies_and_blocks_signing_rpc(self):
        status, data, headers = self.request('/info', institution=True, headers={'Cookie': 'settlement_session=private'})
        self.assertEqual(status, 200)
        self.assertIn(self.gateway.origin(), data['coordinator_origins'])
        self.assertNotIn('Cookie', self.received[-1]['headers'])
        self.assertNotIn('Set-Cookie', headers)
        before = len(self.received)
        self.assertEqual(self.request('/', institution=True, method='POST', body='{"method":"sign_block"}')[0], 403)
        self.assertEqual(len(self.received), before)
        status, _, _ = self.request('/approve', institution=True, method='POST', body='{"operation":{}}',
                                    headers={'Origin': self.gateway.origin(0), 'Content-Type': 'application/json'})
        self.assertEqual(status, 200)
        self.assertEqual(self.received[-1]['body'], b'{"operation":{}}')

    def test_popup_navigation_and_membership_refresh(self):
        self.assertEqual(self.request('/', institution=True, headers={'Sec-Fetch-Site': 'same-site',
                        'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'})[0], 200)
        self.assertEqual(self.received[-1]['headers']['Sec-Fetch-Site'], 'none')
        self.urls = {'institution-next': next(iter(self.urls.values()))}
        self.assertEqual(self.gateway.urls()['institutions'], {'institution-next': self.gateway.origin(0) + '/'})

    def test_wildcard_binding_and_duplicate_ports_are_rejected(self):
        for change in ({'bind_address': '::'}, {'hostname': 'public.example'}, {'institution_ports': [self.ports[0]]}):
            with self.assertRaises(ValueError):
                profile(dict(self.gateway.config, **change))


if __name__ == '__main__':
    unittest.main()
