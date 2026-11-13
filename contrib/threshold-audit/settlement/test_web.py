"""Exercise the settlement server's static app and API boundary together."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from .server import create_server
from .store import Problem


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


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='elements-web-test-')
        root = Path(cls.temporary.name)
        (root / 'dist/assets').mkdir(parents=True)
        (root / 'dist/index.html').write_text('<!doctype html><div id="app"></div>')
        (root / 'dist/assets/app.js').write_text('console.log(1)')
        (root / 'secret.txt').write_text('outside the build')
        cls.server = create_server(EngineFixture(), static_dir=root / 'dist')
        cls.serving = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.serving.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.serving.join(timeout=5)
        cls.temporary.cleanup()

    def request(self, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=15)
        values = dict(headers or {})
        if body is not None:
            values['Content-Type'] = 'application/json'
        conn.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body), values)
        response = conn.getresponse()
        result = (response.status, {name.lower(): value for name, value in response.getheaders()}, response.read())
        conn.close()
        return result

    def test_app_routes_and_deep_links_serve_the_app(self):
        for path in ['/', '/wallet', '/wallet/', '/wallet/payments', '/guardian', '/guardian/federation', '/wallet?ref=mail']:
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertIn('text/html', headers['content-type'])
            self.assertIn(b'id="app"', body)
            self.assertIn("script-src 'self'", headers['content-security-policy'])
            self.assertEqual(headers['cache-control'], 'no-store')

    def test_assets_are_confined_to_the_build(self):
        status, headers, _ = self.request('/assets/app.js')
        self.assertEqual(status, 200)
        self.assertIn('text/javascript', headers['content-type'])
        for path in ['/assets/../secret.txt', '/assets/../../secret.txt', '/assets/missing.js',
                     '/index.html', '/secret.txt', '/wallet/../secret.txt', '/other']:
            self.assertEqual(self.request(path)[0], 404, path)

    def test_cookie_csrf_and_logout(self):
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

    def test_rejects_cross_origin_unknown_host_and_queries(self):
        self.assertEqual(self.request('/api/session', headers={'Origin': 'https://attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/session', headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/wallet', headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(self.request('/api/session?unexpected=1')[0], 400)


if __name__ == '__main__':
    unittest.main()
