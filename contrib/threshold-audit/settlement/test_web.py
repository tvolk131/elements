"""Exercise the built Start server against an isolated private Python engine."""

import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
import threading
import unittest

from .runtime import OwnedProcesses
from .server import create_server
from .store import Problem
from .web import UI, launch_web


class EngineFixture:
    def __init__(self):
        self.active = True
        self.current = {'user': {'id': 'maker', 'name': 'Maker', 'role': 'bankmaker', 'tenant': 'bank'},
                        'csrf': 'fixture-csrf', 'permissions': ['create_transfer']}

    def session(self, token):
        if token != 'fixture-session' or not self.active:
            raise Problem('authentication required', 401)
        return self.current

    def login(self, username, password):
        if username != 'maker' or password != 'fixture-password':
            raise Problem('invalid credentials', 401)
        self.active = True
        return 'fixture-session', self.current

    def dashboard(self, session):
        return {'session': session, 'marker': 'private-fixture', 'accounts': []}

    def logout(self, token):
        self.active = False


@unittest.skipUnless((os.environ.get('ELEMENTS_UI_NODE') or shutil.which('node'))
                     and (UI / 'dist/server/server.js').exists(), 'build Start and provide Node.js')
class StartWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='elements-start-test-')
        cls.directory = Path(cls.temporary.name)
        cls.processes = OwnedProcesses(cls.directory)
        cls.token = 'ab' * 32
        cls.engine = create_server(EngineFixture(), gateway_token=cls.token)
        cls.serving = threading.Thread(target=cls.engine.serve_forever, daemon=True)
        cls.serving.start()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); cls.port = listener.getsockname()[1]
        try:
            cls.process, cls.url = launch_web(cls.directory, cls.processes,
                f'http://127.0.0.1:{cls.engine.server_port}/', cls.token, cls.port)
        except BaseException:
            cls.processes.close(); cls.engine.shutdown(); cls.engine.server_close()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.processes.close()
        cls.engine.shutdown(); cls.engine.server_close(); cls.serving.join(timeout=5)
        cls.temporary.cleanup()

    def request(self, path, body=None, headers=None, *, private=False):
        conn = http.client.HTTPConnection('127.0.0.1', self.engine.server_port if private else self.port, timeout=15)
        values = dict(headers or {})
        if body is not None:
            values['Content-Type'] = 'application/json'
        conn.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body), values)
        response = conn.getresponse(); result = (response.status, {name.lower(): value for name, value in response.getheaders()}, response.read())
        conn.close(); return result

    def test_pages_and_deep_links_use_start_with_nonce_csp(self):
        for path in ['/wallet', '/wallet/payments', '/guardian', '/guardian/federation']:
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, body[:300])
            self.assertIn('text/html', headers['content-type'])
            policy = headers['content-security-policy']
            nonce = re.search("'nonce-([^']+)'", policy)[1]
            self.assertIn(('nonce="' + nonce + '"').encode(), body)
            self.assertEqual(headers['cache-control'], 'no-store')

    def test_cookie_csrf_and_logout_are_preserved_through_start(self):
        status, headers, body = self.request('/api/login', {'username': 'maker', 'password': 'fixture-password'})
        self.assertEqual(status, 200)
        session = json.loads(body)
        cookie = headers['set-cookie'].split(';')[0]
        self.assertIn('HttpOnly', headers['set-cookie'])
        status, _, body = self.request('/api/dashboard', headers={'Cookie': cookie})
        self.assertEqual(status, 200); self.assertEqual(json.loads(body)['marker'], 'private-fixture')
        self.assertEqual(self.request('/api/logout', {}, {'Cookie': cookie})[0], 403)
        self.assertEqual(self.request('/api/logout', {}, {'Cookie': cookie, 'X-CSRF-Token': session['csrf']})[0], 200)
        self.assertEqual(self.request('/api/dashboard', headers={'Cookie': cookie})[0], 401)

    def test_engine_is_private_and_does_not_serve_pages(self):
        self.assertEqual(self.request('/api/session', private=True)[0], 403)
        self.assertEqual(self.request('/api/session', headers={'X-Concord-Engine-Token': self.token}, private=True)[0], 200)
        self.assertEqual(self.request('/wallet', headers={'X-Concord-Engine-Token': self.token}, private=True)[0], 404)

    def test_web_boundary_rejects_cross_origin_and_private_rpc(self):
        self.assertEqual(self.request('/api/session', headers={'Origin': 'https://attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/session', headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/sign', {})[0], 404)
        self.assertEqual(self.request('/api/session?unexpected=1')[0], 400)


if __name__ == '__main__':
    unittest.main()
