"""Loopback-only authenticated HTTP interface for the local settlement pilot."""

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import socket
import threading
import time
from urllib.parse import urlsplit

from .store import Problem


COOKIE = "settlement_session"
MAX_BODY = 32768


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class SettlementServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, settlement, host="127.0.0.1", port=0, gateway_token=None):
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the sandbox HTTP server must bind a loopback address")
        self.settlement = settlement
        self.gateway_token = gateway_token
        self.stop_worker = threading.Event()
        self.worker = None
        self.handler_condition = threading.Condition()
        self.handler_requests = set()
        self.closing = False
        super().__init__((host, port), Handler)
        actual_port = self.server_address[1]
        self.authorities = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}", f"[::1]:{actual_port}"}
        self.origins = {"http://" + authority for authority in self.authorities}

    def start_worker(self):
        if self.worker:
            return
        def run():
            while not self.stop_worker.wait(1):
                try:
                    self.settlement.poll()
                except Exception:
                    # No private request data or RPC credentials in server logs.
                    pass
        self.worker = threading.Thread(target=run, daemon=True, name="settlement-outbox")
        self.worker.start()

    def server_close(self):
        self.stop_worker.set()
        with self.handler_condition:
            self.closing = True
            requests = list(self.handler_requests)
        super().server_close()
        # Wake idle keep-alive/body readers. Active handlers may finish their
        # durable action and response before their thread leaves the registry.
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RD)
            except OSError:
                pass

    def process_request(self, request, client_address):
        with self.handler_condition:
            if self.closing:
                self.shutdown_request(request)
                return
            self.handler_requests.add(request)
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.handler_requests.discard(request)
                self.handler_condition.notify_all()
                raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.handler_condition:
                self.handler_requests.discard(request)
                self.handler_condition.notify_all()

    def drain_handlers(self, timeout=60):
        deadline = time.monotonic() + timeout
        with self.handler_condition:
            while self.handler_requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.handler_condition.wait(remaining)
        return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InstitutionalSettlementSandbox/1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        pass

    def respond(self, status, value, cookie=None):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.headers_common("application/json; charset=utf-8", len(data))
        if status >= 400:
            # An early Host/Origin/CSRF rejection may leave an unread body.
            # Close rather than interpreting those bytes as the next request.
            self.close_connection = True
            self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def headers_common(self, content_type, length):
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def check_request(self):
        if self.server.closing:
            raise Problem("the local service is shutting down", 503)
        if (len(self.headers.get_all("Host", [])) != 1
                or len(self.headers.get_all("Origin", [])) > 1
                or len(self.headers.get_all("Content-Length", [])) > 1):
            raise Problem("ambiguous request headers", 400)
        if self.server.gateway_token is not None:
            tokens = self.headers.get_all("X-Concord-Engine-Token", [])
            if len(tokens) != 1 or not hmac.compare_digest(tokens[0], self.server.gateway_token):
                raise Problem("private settlement engine token required", 403)
        if self.headers.get("Host", "") not in self.server.authorities:
            raise Problem("unrecognized Host header", 403)
        origin = self.headers.get("Origin")
        if origin and origin not in self.server.origins:
            raise Problem("cross-origin requests are not permitted", 403)
        if self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "none"}:
            raise Problem("cross-site requests are not permitted", 403)
        if urlsplit(self.path).query:
            raise Problem("query parameters are not supported")

    def token(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        return cookies[COOKIE].value if COOKIE in cookies else ""

    def session(self, csrf=False):
        session = self.server.settlement.session(self.token())
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise Problem("valid CSRF token required", 403, "csrf_failed")
        return session

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise Problem("chunked requests are not supported", 400)
        if self.headers.get_content_type() != "application/json":
            raise Problem("Content-Type must be application/json", 415)
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as error:
            raise Problem("invalid Content-Length") from error
        if not 0 <= length <= MAX_BODY:
            raise Problem("request body exceeds limit", 413)
        try:
            body = json.loads(self.rfile.read(length), object_pairs_hook=strict_object,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (ValueError, UnicodeError) as error:
            raise Problem("invalid JSON request") from error
        if not isinstance(body, dict):
            raise Problem("JSON body must be an object")
        return body

    def do_GET(self):
        try:
            self.check_request()
            path = urlsplit(self.path).path
            store = self.server.settlement
            if path == "/api/session":
                try:
                    session = self.session()
                except Problem as error:
                    if error.status != 401:
                        raise
                    session = {"user": None, "csrf": None, "permissions": []}
                self.respond(200, session)
                return
            if path.startswith("/api/"):
                session = self.session()
                if path == "/api/dashboard":
                    self.respond(200, store.dashboard(session))
                elif path.startswith("/api/operations/") and len(path.split("/")) == 4:
                    self.respond(200, store.operation(session["user"], path.rsplit("/", 1)[1]))
                elif path == '/api/disclosures' and store.disclosures is not None:
                    with store.lock:
                        self.respond(200, store.disclosures.overview(session['user']))
                elif path.startswith('/api/disclosures/') and store.disclosures is not None:
                    parts = path.strip('/').split('/')
                    with store.lock:
                        if len(parts) == 3:
                            self.respond(200, store.disclosures.public(session['user'], store.disclosures.get(session['user'], parts[2])))
                        elif len(parts) == 4 and parts[3] == 'bundle':
                            self.respond(200, store.disclosures.bundle(session['user'], parts[2]))
                        else:
                            raise Problem('endpoint not found', 404)
                elif path.startswith('/api/disclosure-targets/') and store.disclosures is not None:
                    with store.lock:
                        self.respond(200, store.disclosures.targets(session['user'], path.rsplit('/', 1)[1]))
                else:
                    raise Problem("endpoint not found", 404)
                return
            raise Problem("the settlement engine serves API endpoints only", 404)
        except Problem as error:
            self.respond(error.status, {"error": error.code, "message": str(error)})
        except Exception:
            self.respond(503, {"error": "service_unavailable", "message": "The local service is unavailable; no settlement was inferred."})

    def do_POST(self):
        try:
            self.check_request()
            path = urlsplit(self.path).path
            body = self.body()
            store = self.server.settlement
            if path == "/api/login":
                token, session = store.login(body.get("username"), body.get("password"))
                self.respond(200, session, f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800")
                return
            session = self.session(csrf=True)
            user = session["user"]
            if path.startswith('/api/disclosures') and store.disclosures is not None:
                with store.lock:
                    parts = path.strip('/').split('/')
                    if path == '/api/disclosures':
                        result = store.disclosures.create(user, body)
                    elif path == '/api/disclosures/recipient-key':
                        result = store.disclosures.register_key(user, body)
                    elif len(parts) == 4 and parts[3] in ('approve', 'decline', 'release', 'cancel'):
                        if parts[3] in ('approve', 'decline'):
                            result = store.disclosures.approve(user, parts[2], decline=parts[3] == 'decline')
                        else:
                            result = getattr(store.disclosures, parts[3])(user, parts[2])
                    else:
                        raise Problem('endpoint not found', 404)
                self.respond(200, result)
            elif path == '/api/beneficiaries/resolve' and store.directory is not None:
                with store.lock:
                    self.respond(200, store.directory.resolve(user, body))
            elif path == '/api/beneficiaries/validate-address' and store.directory is not None:
                store.require(user, 'create_transfer')
                address = body.get('address', '').strip()
                with store.lock:
                    store.directory.address(address)
                self.respond(200, {'address': address, 'identity_verified': False})
            elif path == '/api/receive-address' and store.directory is not None:
                account = store.accessible_account(user, body.get('account_id'))
                currency = body.get('currency')
                if currency not in account.get('addresses', {}):
                    raise Problem('unsupported account currency')
                self.respond(200, {'address': store.chain.wallets[account['id']].getnewaddress('receive', 'blech32'),
                                   'reference': store.directory.reference(account), 'currency': currency})
            elif path == "/api/logout":
                store.logout(self.token())
                self.respond(200, {"ok": True}, f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            elif path in {"/api/deposits", "/api/transfers", "/api/redemptions"}:
                kind = {"/api/deposits": "deposit", "/api/transfers": "transfer", "/api/redemptions": "redemption"}[path]
                self.respond(201, store.create(user, kind, body))
            elif path == "/api/bank/events":
                self.respond(200, store.bank_event(user, body))
            elif path.startswith("/api/federation/"):
                if store.federation is None:
                    raise Problem("federation lifecycle service is not configured", 503)
                federation = store.federation
                parts = path.split("/")
                if path == "/api/federation/prepare":
                    result = federation.prepare(user)
                elif len(parts) == 6 and parts[3] == "rotations":
                    rotation_id, action = parts[4:]
                    if action in {"advance", "retry"}:
                        result = federation.advance(user, rotation_id)
                    elif action == "prepare-approval":
                        result = federation.prepare_approval(user, rotation_id)
                    elif action == "certificates":
                        result = federation.add_signature(user, rotation_id, body.get("signature"))
                    else:
                        raise Problem("federation action not found", 404)
                else:
                    raise Problem("federation endpoint not found", 404)
                self.respond(200, result)
            elif path.startswith("/api/operations/"):
                parts = path.split("/")
                if len(parts) != 5:
                    raise Problem("endpoint not found", 404)
                operation_id, action = parts[3:]
                if action == "approve":
                    result = store.approve(user, operation_id)
                elif action == "reject":
                    result = store.reject(user, operation_id, body.get("reason", ""))
                elif action == "execute":
                    result = store.execute(user, operation_id)
                elif action == "cancel":
                    result = store.request_refund(user, operation_id)
                elif action == "guardian-approve":
                    result = store.add_signature(user, operation_id)
                elif action == "prepare-approval":
                    result = store.prepare_approval(user, operation_id)
                elif action == "certificates":
                    result = store.add_signature(user, operation_id, body.get("signature"))
                else:
                    raise Problem("endpoint not found", 404)
                self.respond(200, result)
            else:
                raise Problem("endpoint not found", 404)
        except Problem as error:
            self.respond(error.status, {"error": error.code, "message": str(error)})
        except Exception:
            self.respond(503, {"error": "service_unavailable", "message": "The local service is unavailable; no settlement was inferred."})


def create_server(settlement, host="127.0.0.1", port=0, gateway_token=None):
    return SettlementServer(settlement, host, port, gateway_token)
