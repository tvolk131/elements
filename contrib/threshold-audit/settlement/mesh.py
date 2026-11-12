"""Optional Rayfish-only HTTP front ends for the local test fixture.

Public browser URLs are distinct from internal coordinator/signer URLs. Each
institution keeps its own origin; no bearer-authenticated signing RPC is routed
through these front ends. Mesh peer access is additionally restricted by Rayfish.
"""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
import socket
import threading
from urllib.parse import urlsplit


def profile(value):
    address = ipaddress.IPv6Address(value['bind_address'])
    hostname = value['hostname']
    ports = [value['port'], *value['institution_ports']]
    if address.is_unspecified or address.is_multicast or address.ipv4_mapped:
        raise ValueError('mesh listener requires one explicit IPv6 address')
    if (not isinstance(hostname, str) or hostname != hostname.lower()
            or not hostname.endswith('.ray') or re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', hostname) is None):
        raise ValueError('mesh hostname must be an explicit .ray name')
    if (not 1 <= len(value['institution_ports']) <= 15 or len(set(ports)) != len(ports)
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ValueError('mesh ports must be distinct valid TCP ports')
    return {'bind_address': str(address), 'hostname': hostname,
            'port': ports[0], 'institution_ports': ports[1:]}


def local_endpoint(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port
            or parsed.username or parsed.password or parsed.path != '/' or parsed.query or parsed.fragment):
        raise ValueError('mesh backend must be a plain 127.0.0.1 endpoint')
    return parsed.hostname, parsed.port


class MeshServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def process_request_thread(self, request, client_address):
        if self.gateway.closing.is_set():
            self.shutdown_request(request)
            return
        with self.gateway.request_lock:
            self.gateway.requests.add(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.gateway.request_lock:
                self.gateway.requests.discard(request)


class MeshGateway:
    def __init__(self, configuration, app_url, institution_endpoints):
        self.config = profile(configuration)
        self.app_url = app_url
        local_endpoint(app_url)
        # Resolve the current operational roster on every request, including
        # after settlement activation during a membership rotation.
        self.institution_endpoints = institution_endpoints
        self.servers, self.threads = [], []
        self.closing = threading.Event()
        self.request_lock, self.requests = threading.Lock(), set()

    def origin(self, slot=None):
        port = self.config['port'] if slot is None else self.config['institution_ports'][slot]
        return f"http://{self.config['hostname']}:{port}"

    def endpoints(self):
        result = list(self.institution_endpoints().items())
        if len(result) > len(self.config['institution_ports']):
            raise ValueError('mesh profile has too few institution ports')
        for _, url in result:
            local_endpoint(url)
        return result

    def urls(self):
        return {'wallet': self.origin() + '/wallet', 'guardian': self.origin() + '/guardian',
                'institutions': {member: self.origin(slot) + '/' for slot, (member, _) in enumerate(self.endpoints())}}

    def start(self):
        try:
            for slot in [None, *range(len(self.config['institution_ports']))]:
                port = self.config['port'] if slot is None else self.config['institution_ports'][slot]
                server = MeshServer((self.config['bind_address'], port), MeshHandler)
                server.gateway, server.slot = self, slot
                self.servers.append(server)
                thread = threading.Thread(target=server.serve_forever, daemon=True, name=f'mesh-http-{port}')
                thread.start(); self.threads.append(thread)
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closing.set()
        for server in self.servers:
            server.shutdown(); server.server_close()
        with self.request_lock:
            requests = list(self.requests)
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=2)


class MeshHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ConcordMeshDemo/1'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def failure(self, status, message):
        body = json.dumps({'error': message}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        gateway, slot = self.server.gateway, self.server.slot
        expected = urlsplit(gateway.origin(slot)).netloc
        public_pages = {'/'} if slot is not None else {'/', '/wallet', '/wallet/', '/guardian', '/guardian/', '/app', '/app/'}
        navigation = (self.command == 'GET' and self.path in public_pages
                      and self.headers.get('Sec-Fetch-Mode') == 'navigate'
                      and self.headers.get('Sec-Fetch-Dest') == 'document'
                      and 'Origin' not in self.headers)
        if (len(self.headers.get_all('Host', [])) != 1 or self.headers['Host'] != expected
                or len(self.headers.get_all('Origin', [])) > 1
                or self.headers.get('Origin') not in {None, gateway.origin(slot)}
                or (self.headers.get('Sec-Fetch-Site') not in {None, 'none', 'same-origin'} and not navigation)):
            return self.failure(403, 'mesh_host_or_origin_rejected')
        target = urlsplit(self.path)
        if target.scheme or target.netloc or not self.path.startswith('/') or target.query or target.fragment:
            return self.failure(400, 'invalid_request_path')
        if slot is not None:
            allowed = {'GET': {'/', '/info', '/review.js', '/review.css'}, 'POST': {'/approve'}}
            if self.path not in allowed.get(self.command, set()):
                return self.failure(403, 'institution_rpc_is_local_only')
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
            return self.failure(400, 'invalid_request_framing')
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 8_000_000:
                return self.failure(413, 'request_too_large')
            body = self.rfile.read(length) if length else None
            if length and len(body) != length:
                return self.failure(400, 'incomplete_request')
            if gateway.closing.is_set():
                return self.failure(503, 'mesh_stopping')
            entries = gateway.endpoints()
            backend = gateway.app_url if slot is None else entries[slot][1]
            host, port = local_endpoint(backend)
            headers = {'Host': f'{host}:{port}', 'Connection': 'close'}
            for name in ('Content-Type', 'Accept', 'X-CSRF-Token', 'Sec-Fetch-Site'):
                if name in self.headers:
                    headers[name] = self.headers[name]
            if navigation:
                headers['Sec-Fetch-Site'] = 'none'
            if slot is None and 'Cookie' in self.headers:
                headers['Cookie'] = self.headers['Cookie']
            # Validate the browser origin above before translating it to the
            # existing loopback service's independently enforced origin.
            if 'Origin' in self.headers:
                headers['Origin'] = backend.rstrip('/')
            connection = http.client.HTTPConnection(host, port, timeout=180)
            try:
                connection.request(self.command, self.path, body=body, headers=headers)
                response = connection.getresponse()
                data = response.read(32_000_001)
                if len(data) > 32_000_000:
                    raise ValueError('backend response exceeds gateway bound')
                if response.status == 200 and self.command == 'GET':
                    if slot is None and self.path == '/api/dashboard':
                        value = json.loads(data)
                        urls = {member: gateway.origin(index) + '/' for index, (member, _) in enumerate(entries)}
                        for guardian in value.get('guardians', []):
                            member = guardian.get('institution_id', guardian.get('id'))
                            if member in urls:
                                guardian['approval_url'] = urls[member]
                        data = json.dumps(value, separators=(',', ':')).encode()
                    elif slot is not None and self.path == '/info':
                        value = json.loads(data)
                        value['coordinator_origins'] = list(dict.fromkeys([*value['coordinator_origins'], gateway.origin()]))
                        data = json.dumps(value, separators=(',', ':')).encode()
                self.send_response(response.status)
                ignored = {'connection', 'content-length', 'transfer-encoding', 'server', 'date'}
                if slot is not None:
                    ignored.add('set-cookie')
                for name, value in response.getheaders():
                    if name.lower() not in ignored:
                        self.send_header(name, value)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.close_connection = True
                self.wfile.write(data)
            finally:
                connection.close()
        except (OSError, ValueError, KeyError, IndexError, http.client.HTTPException):
            self.failure(503, 'local_backend_unavailable')
