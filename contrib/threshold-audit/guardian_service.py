# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Isolated research guardian with mutual TLS and durable private state.

The Feldman handoff is a distributed execution of the experimental procedure,
not an actively secure DKG/DPSS implementation. TLS authenticates transport; it
does not supply reliable broadcast, malicious-dealer recovery, secure erasure,
rollback-resistant storage, an HSM, or an independent disclosure-log witness.
Never use production secrets. The coordinator never receives private evaluations
or shares. A guardian stores only its own shares, dealer coefficients and the
private evaluations addressed to it.
"""

import argparse
import fcntl
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import ssl
import socket
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from chunked import ChunkPacket, partial_decrypt_chunked, verify_chunked
from curve import Curve, ORDER, random_scalar, scalar_bytes
from disclosure import Approval, Policy, Request, authorize
from governance import AuditConfig, PreparedTransition, Readiness, Transition, make_readiness, verify_readiness
from recovery import Statement, digest, index_bytes
from threshold import Committee, SecretShare, lagrange, polynomial_value, validate_roster, validate_share

MAX_MESSAGE = 2 * 1024 * 1024
MAX_SESSIONS = 32
MAX_CONNECTIONS = 32
HANDSHAKE_TIMEOUT = 5
REQUEST_READ_TIMEOUT = 10
TRANSPORT_TIMEOUT = 60


class GuardianTransportError(OSError):
    """Only remote transport failure; never a local share/log storage failure."""


class GuardianTransportTimeout(GuardianTransportError, TimeoutError):
    """The complete network operation exhausted its shared monotonic budget."""


class PrivateDirectoryLock:
    """One lifetime writer per private directory, including across processes."""
    def __init__(self, directory):
        self.fd = None
        self.fd = os.open(Path(directory) / '.guardian.lock',
                          os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('unsafe guardian lock file')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as error:
            self.close()
            if isinstance(error, BlockingIOError):
                raise ValueError('guardian private directory is already in use') from error
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __del__(self):
        self.close()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON constant')))


def raw(value, size=None):
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError('invalid hex field')
    result = bytes.fromhex(value)
    if result.hex() != value or (size is not None and len(result) != size):
        raise ValueError('noncanonical hex field')
    return result


def atomic_write(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_private(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError('private file must be regular, nonsymlink and mode 0600')
    if not path.is_file() or path.stat().st_size > 16 * MAX_MESSAGE:
        raise ValueError('invalid private file')
    return parse_json(path.read_bytes())


def committee_json(committee):
    return {'epoch': committee.epoch, 'members': list(committee.members),
            'commitments': [point.hex() for point in committee.commitments]}


def committee_from(value, curve):
    committee = Committee(value['epoch'], tuple(value['members']),
                          tuple(raw(point, 33) for point in value['commitments']))
    committee.validate(curve)
    return committee


def ready_json(ready):
    return {'version': ready.version, 'member': ready.member,
            'proof': [scalar_bytes(value).hex() for value in ready.possession_proof],
            'signature': ready.signature.hex()}


def ready_from(value):
    result = Readiness(value['version'], value['member'],
                       tuple(int.from_bytes(raw(v, 32), 'big') for v in value['proof']),
                       raw(value['signature'], 64))
    result.to_bytes()
    return result


def transition_json(transition):
    return {'previous': transition.previous.hex(), 'activation_height': transition.activation_height,
            'config': transition.config.to_bytes().hex()}


def transition_from(value, curve):
    return Transition(raw(value['previous'], 32), value['activation_height'],
                      AuditConfig.from_bytes(raw(value['config']), curve))


def statement_json(statement):
    return {'chain_id': statement.chain_id.hex(), 'tx_digest': statement.tx_digest.hex(),
            'output_index': statement.output_index, 'script': statement.script.hex(),
            'asset_commitment': statement.asset_commitment.hex(),
            'value_commitment': statement.value_commitment.hex(),
            'audit_key': statement.audit_key.hex(), 'assets': [asset.hex() for asset in statement.assets]}


def statement_from(value):
    return Statement(raw(value['chain_id'], 32), raw(value['tx_digest'], 32), value['output_index'],
                     raw(value['script']), raw(value['asset_commitment'], 33),
                     raw(value['value_commitment'], 33), raw(value['audit_key'], 33),
                     tuple(raw(asset, 32) for asset in value['assets']))


class DurableLog:
    """Fsync-before-release hash chain; retain signed checkpoints independently."""
    def __init__(self, path):
        self.path = Path(path)
        self.failed = False
        self.head, self.sequence = bytes(32), 0
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
                raise ValueError('unsafe audit log permissions')
            with self.path.open('rb') as stream:
                for line in stream:
                    row = parse_json(line)
                    expected = digest(b'guardian-log', self.head, canonical(row['event']))
                    if row != {'sequence': self.sequence + 1, 'head': expected.hex(), 'event': row['event']}:
                        raise ValueError('audit log corruption')
                    self.head, self.sequence = expected, self.sequence + 1

    def append(self, event):
        if self.failed:
            raise ValueError('guardian audit log requires recovery')
        head = digest(b'guardian-log', self.head, canonical(event))
        row = {'sequence': self.sequence + 1, 'head': head.hex(), 'event': event}
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'ab') as stream:
                stream.write(canonical(row) + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            self.failed = True
            raise ValueError('guardian audit log requires recovery') from error
        self.head, self.sequence = head, self.sequence + 1


def tls_request(endpoint, credentials, request, expected_fingerprint, *, timeout=TRANSPORT_TIMEOUT):
    url = urlsplit(endpoint)
    if url.scheme != 'https' or url.hostname != '127.0.0.1' or url.path not in ('', '/'):
        raise ValueError('research guardian transport permits loopback HTTPS only')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('guardian transport timeout must be finite and positive')
    if not isinstance(request, dict):
        raise ValueError('guardian request must be an object')
    # Credential-file failures are local errors, not retryable network errors.
    context = ssl.create_default_context(cafile=credentials['ca'])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(credentials['certificate'], credentials['private_key'])
    body = canonical(request)
    if len(body) > MAX_MESSAGE:
        raise ValueError('guardian request too large')
    # Only persisted, idempotent ceremony messages can be retried. A lost ack
    # must not discard a prepared deal or change its coefficients. Validation
    # errors, certificate mismatches, approvals and disclosures are not retried.
    attempts = 3 if request.get('operation') in ('begin_deal', 'receive_evaluation', 'deliver') else 1
    deadline = time.monotonic() + timeout
    expired = threading.Event()
    active_lock = threading.Lock()
    active_socket = [None]

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0 or expired.is_set():
            raise GuardianTransportTimeout('guardian transport deadline exceeded')
        return value

    def interrupt():
        expired.set()
        with active_lock:
            active = active_socket[0]
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # An attempt can finish/close while the timer fires.

    def register(active):
        with active_lock:
            active_socket[0] = active
        if expired.is_set():
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        active.settimeout(remaining())

    # Socket read timeouts alone reset as bytes arrive. Keep the actual TLS
    # socket, independently of HTTPSConnection.sock (HTTP/1.0 detaches it), and
    # interrupt it at the one deadline shared by every phase and retry.
    timer = threading.Timer(timeout, interrupt)
    timer.daemon = True
    timer.start()
    try:
        for attempt in range(attempts):
            connection, response, plain, secured = None, None, None, None
            try:
                plain = socket.create_connection((url.hostname, url.port or 443), timeout=remaining())
                register(plain)
                # Register the SSLSocket before performing its handshake; once
                # wrapped, the old plain socket no longer owns the descriptor.
                secured = context.wrap_socket(plain, server_hostname=url.hostname,
                                              do_handshake_on_connect=False)
                register(secured)
                secured.do_handshake()
                secured.settimeout(remaining())
                actual = hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
                if actual != expected_fingerprint:
                    raise ValueError('guardian TLS certificate fingerprint mismatch')
                connection = http.client.HTTPSConnection(url.hostname, url.port, context=context,
                                                          timeout=remaining())
                connection.sock = secured
                secured.settimeout(remaining())
                connection.request('POST', '/', body=body, headers={'Content-Type': 'application/json'})
                secured.settimeout(remaining())
                response = connection.getresponse()
                # Rejections are final even if their body is truncated or
                # slow. Do not turn an explicit validation error into a retry.
                if response.status == 503:
                    raise GuardianTransportError('guardian ceremony transport unavailable')
                if response.status != 200:
                    raise ValueError('guardian rejected request')
                secured.settimeout(remaining())
                payload = response.read(MAX_MESSAGE + 1)
                remaining()
                if len(payload) > MAX_MESSAGE:
                    raise ValueError('guardian response too large')
                if response.length not in (None, 0):
                    raise http.client.IncompleteRead(payload, response.length)
                result = parse_json(payload)
                if not isinstance(result, dict):
                    raise ValueError('guardian response must be an object')
                remaining()
                return result
            except ssl.SSLCertVerificationError as error:
                raise ValueError('guardian TLS certificate verification failed') from error
            except ssl.SSLError as error:
                if expired.is_set() or time.monotonic() >= deadline:
                    raise GuardianTransportTimeout('guardian transport deadline exceeded') from error
                # Authentication and TLS protocol failures are never retried.
                raise ValueError('guardian TLS protocol failed') from error
            except (OSError, http.client.IncompleteRead) as error:
                if isinstance(error, TimeoutError) or expired.is_set() or time.monotonic() >= deadline:
                    raise GuardianTransportTimeout('guardian transport deadline exceeded') from error
                transport = error if isinstance(error, GuardianTransportError) else GuardianTransportError('guardian transport failed')
                if attempt + 1 == attempts:
                    raise transport from (None if transport is error else error)
            except http.client.HTTPException as error:
                if expired.is_set() or time.monotonic() >= deadline:
                    raise GuardianTransportTimeout('guardian transport deadline exceeded') from error
                raise ValueError('guardian HTTP protocol failed') from error
            except ValueError as error:
                if expired.is_set() or time.monotonic() >= deadline:
                    raise GuardianTransportTimeout('guardian transport deadline exceeded') from error
                raise
            finally:
                with active_lock:
                    active_socket[0] = None
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()
                if secured is not None:
                    secured.close()
                if plain is not None:
                    plain.close()
    finally:
        timer.cancel()


def check_continuity(previous, proposed):
    if proposed.generation != previous.generation + 1:
        raise ValueError('incorrect configuration generation')
    if len(proposed.keys) not in (len(previous.keys), len(previous.keys) + 1):
        raise ValueError('historical audit keys cannot be deleted')
    for old in previous.keys:
        new = proposed.key(old.version)
        if new.public_key != old.public_key or new.scheme != old.scheme:
            raise ValueError('historical audit key changed')
        if new.committee != old.committee and new.committee.epoch != old.committee.epoch + 1:
            raise ValueError('invalid handoff share epoch')
    if len(proposed.keys) == len(previous.keys):
        if proposed.active_version != previous.active_version:
            raise ValueError('historical key cannot be reactivated')
    else:
        fresh = proposed.keys[-1]
        if proposed.active_version != fresh.version or fresh.committee.epoch != 0:
            raise ValueError('invalid new active key')
        if fresh.public_key in {old.public_key for old in previous.keys}:
            raise ValueError('new audit key must be fresh')


class Guardian:
    def __init__(self, config):
        self.options = config
        self.lock = threading.RLock()
        self.member = config['member']
        validate_roster((self.member,), 1)
        self.directory = Path(config['directory'])
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise ValueError('guardian directory must be mode 0700')
        self.directory_lock = PrivateDirectoryLock(self.directory)
        self.curve = None
        self.storage_fault = False
        try:
            self.curve = Curve(config['library'])
            self.load_state()
        except BaseException:
            self.close()
            raise

    def load_state(self):
        self.state_path = self.directory / 'private-state.json'
        if self.state_path.exists():
            self.state = load_private(self.state_path)
            if self.state['member'] != self.member:
                raise ValueError('stored member ID mismatch')
        else:
            self.state = {'format': 1, 'member': self.member, 'identity_secret': scalar_bytes(random_scalar()).hex(),
                          'chain_id': None, 'active': None, 'shares': {}, 'deals': {},
                          'incoming': {}, 'prepared': {}, 'history': {}}
            self.save()
        self.identity_secret = int.from_bytes(raw(self.state['identity_secret'], 32), 'big')
        self.identity = self.curve.mul(self.identity_secret)[1:]
        self.log = DurableLog(self.directory / 'disclosures.jsonl')
        if self.state['active']:
            active = AuditConfig.from_bytes(raw(self.state['active']), self.curve)
            for key in active.keys:
                self.share(key)

    def close(self):
        if self.curve is not None:
            self.curve.close()
            self.curve = None
        self.directory_lock.close()

    def save(self):
        try:
            atomic_write(self.state_path, self.state)
        except OSError as error:
            # A failed fsync/replacement may leave memory ahead of disk. Never
            # acknowledge the cached mutation on a later retry in this process.
            self.storage_fault = True
            raise ValueError('guardian private storage requires recovery') from error

    def require_healthy(self):
        if self.storage_fault or self.log.failed:
            raise ValueError('guardian durable storage requires recovery')

    def active(self):
        if not self.state['active']:
            raise ValueError('guardian has no active audit configuration')
        return AuditConfig.from_bytes(raw(self.state['active']), self.curve)

    def share(self, key, values=None):
        values = self.state['shares'] if values is None else values
        value = values.get(str(key.version))
        if value is None:
            raise ValueError('historical private share is missing')
        share = SecretShare(self.member, int.from_bytes(raw(value, 32), 'big'), key.committee.binding())
        validate_share(self.curve, key.committee, share)
        return share

    def checkpoint(self):
        message = digest(b'guardian-checkpoint', index_bytes(self.member),
                         self.log.sequence.to_bytes(8, 'big'), self.log.head)
        return {'member': self.member, 'sequence': self.log.sequence, 'head': self.log.head.hex(),
                'signature': self.curve.sign(self.identity_secret, message).hex()}

    def authenticate(self, fingerprint):
        peer = self.options['trusted_clients'].get(fingerprint)
        if peer is None:
            raise ValueError('unrecognized TLS client')
        return peer

    def dispatch(self, request, fingerprint):
        if request.get('operation') == 'deliver':
            peer = self.authenticate(fingerprint)
            if peer['role'] != 'coordinator':
                raise ValueError('delivery requires coordinator TLS identity')
            with self.lock:
                self.require_healthy()
            return self.deliver(request['plan'], request['contributions'], request['destinations'])
        with self.lock:
            if request.get('operation') not in ('status', 'shutdown'):
                self.require_healthy()
            return self._dispatch(request, fingerprint)

    def _dispatch(self, request, fingerprint):
        peer = self.authenticate(fingerprint)
        operation = request.get('operation')
        if operation == 'receive_evaluation':
            if peer['role'] != 'guardian':
                raise ValueError('private evaluations require guardian TLS identity')
            return self.receive(request, peer['member'])
        if operation == 'disclose':
            if peer['role'] != 'recipient':
                raise ValueError('partial decryptions require approved recipient TLS identity')
            return self.disclose(request, peer)
        if operation == 'disclose-sealed':
            if peer['role'] != 'coordinator' or request.get('request', {}).get('delivery') != 'sealed-v1':
                raise ValueError('sealed relay requires coordinator and recipient-bound sealed request')
            return self.disclose(request, peer)
        if operation == 'approve':
            if peer != {'role': 'approver', 'member': self.member}:
                raise ValueError('approval requires this institution\'s separate authority')
            return self.approve(request)
        if peer['role'] != 'coordinator':
            raise ValueError('operation requires coordinator TLS identity')
        if operation == 'status':
            return {'member': self.member, 'identity': self.identity.hex(), 'active': self.state['active'],
                    'storage_fault': self.storage_fault or self.log.failed,
                    'prepared': sorted(self.state['prepared']), 'checkpoint': self.checkpoint()}
        if operation == 'shutdown':
            return {'shutdown': True}
        if operation == 'begin_deal':
            return self.begin_deal(request['plan'])
        if operation == 'prepare':
            return self.prepare(request)
        if operation == 'activate':
            return self.activate(request)
        if operation == 'restore':
            return self.restore(request)
        raise ValueError('unsupported guardian operation')

    def plan(self, plan):
        raw(plan['session'], 32)
        raw(plan['chain_id'], 32)
        if plan['mode'] not in ('genesis', 'refresh', 'new-key'):
            raise ValueError('invalid dealer mode')
        if type(plan['version']) is not int or not 1 <= plan['version'] <= 16:
            raise ValueError('invalid audit-key version')
        members, dealers = tuple(plan['members']), tuple(plan['dealers'])
        validate_roster(members, plan['threshold'])
        validate_roster(dealers, 1)
        old = None
        if plan['mode'] == 'refresh':
            old = committee_from(plan['old'], self.curve)
            if len(dealers) < old.threshold or any(member not in old.members for member in dealers):
                raise ValueError('handoff needs a distinct old quorum')
            if plan['epoch'] != old.epoch + 1:
                raise ValueError('incorrect new sharing epoch')
        elif plan['epoch'] != 0 or dealers != members:
            raise ValueError('fresh key needs every recipient as a dealer at epoch zero')
        return old, digest(b'guardian-deal-plan', canonical(plan)).hex()

    def begin_deal(self, plan):
        old, binding = self.plan(plan)
        if self.member not in plan['dealers']:
            raise ValueError('guardian is not a selected dealer')
        chain = self.state['chain_id']
        if chain is not None and chain != plan['chain_id']:
            raise ValueError('wrong handoff chain')
        if old is not None and self.active().key(plan['version']).committee != old:
            raise ValueError('handoff does not extend stored committee')
        if binding not in self.state['deals']:
            if len(self.state['deals']) >= MAX_SESSIONS:
                raise ValueError('dealer state session limit reached')
            # A session/version cannot be rebound to different parameters.
            for known in self.state['deals'].values():
                if (known['plan']['session'], known['plan']['version']) == (plan['session'], plan['version']):
                    raise ValueError('handoff session rebound to another plan')
            if old is not None:
                active = self.active()
                key = active.key(plan['version'])
                if key.committee != old:
                    raise ValueError('handoff does not extend stored committee')
                constant = lagrange(self.member, tuple(plan['dealers'])) * self.share(key).value % ORDER
            else:
                if plan['mode'] == 'genesis' and self.state['active'] is not None:
                    raise ValueError('cannot regenerate genesis over active shares')
                if plan['mode'] == 'new-key' and self.state['active'] is not None:
                    if plan['version'] != len(self.active().keys) + 1:
                        raise ValueError('new key version does not extend history')
                constant = random_scalar()
            coefficients = (constant,) + tuple(random_scalar() for _ in range(plan['threshold'] - 1))
            commitments = tuple(self.curve.mul(value) for value in coefficients)
            signature = self.curve.sign(self.identity_secret, digest(b'guardian-dealer',
                                        raw(binding, 32), index_bytes(self.member), b''.join(commitments)))
            self.state['deals'][binding] = {'plan': plan, 'coefficients': [scalar_bytes(v).hex() for v in coefficients],
                                           'commitments': [p.hex() for p in commitments], 'signature': signature.hex()}
            self.save()
        record = self.state['deals'][binding]
        return {'dealer': self.member, 'commitments': record['commitments'], 'signature': record['signature']}

    def contributions(self, plan, packages, identities):
        old, binding = self.plan(plan)
        if [item['dealer'] for item in packages] != plan['dealers']:
            raise ValueError('missing, reordered or duplicate public dealers')
        points = []
        for item in packages:
            commitments = tuple(raw(p, 33) for p in item['commitments'])
            if len(commitments) != plan['threshold']:
                raise ValueError('incorrect handoff degree')
            for point in commitments:
                self.curve.parse(point)
            if old is not None:
                expected = self.curve.mul(lagrange(item['dealer'], tuple(plan['dealers'])),
                                          old.verification_key(self.curve, item['dealer']))
                if commitments[0] != expected:
                    raise ValueError('dealer constant changes historical secret')
            message = digest(b'guardian-dealer', raw(binding, 32), index_bytes(item['dealer']), b''.join(commitments))
            if not self.curve.verify_signature(raw(identities[str(item['dealer'])], 32), message,
                                               raw(item['signature'], 64)):
                raise ValueError('invalid public dealer signature')
            points.append(commitments)
        committee = Committee(plan['epoch'], tuple(plan['members']),
                              tuple(self.curve.add(*(row[j] for row in points)) for j in range(plan['threshold'])))
        committee.validate(self.curve)
        if old is not None and committee.public_key != old.public_key:
            raise ValueError('handoff public key changed')
        return binding, committee

    def receive(self, request, authenticated_dealer):
        plan, packages, identities = request['plan'], request['contributions'], request['identities']
        binding, committee = self.contributions(plan, packages, identities)
        if self.member not in committee.members or request['dealer'] != authenticated_dealer:
            raise ValueError('evaluation recipient or TLS dealer mismatch')
        item = next((p for p in packages if p['dealer'] == authenticated_dealer), None)
        if item is None:
            raise ValueError('unselected dealer')
        value = int.from_bytes(raw(request['evaluation'], 32), 'big')
        scalar_bytes(value)
        expected = self.curve.linear((pow(self.member, j, ORDER), raw(point, 33))
                                     for j, point in enumerate(item['commitments']))
        if self.curve.mul(value) != expected:
            raise ValueError('invalid private handoff evaluation')
        if self.state['chain_id'] not in (None, plan['chain_id']):
            raise ValueError('wrong incoming handoff chain')
        for known_binding, known in self.state['incoming'].items():
            if (known['plan']['session'], known['plan']['version']) == (plan['session'], plan['version']) and known_binding != binding:
                raise ValueError('incoming handoff session rebound')
        if binding not in self.state['incoming']:
            if len(self.state['incoming']) >= MAX_SESSIONS:
                raise ValueError('incoming session limit reached')
            self.state['incoming'][binding] = {'plan': plan, 'committee': committee_json(committee),
                                               'contributions': packages, 'identities': identities, 'evaluations': {}}
        incoming = self.state['incoming'][binding]
        if incoming['contributions'] != packages or incoming['identities'] != identities:
            raise ValueError('public handoff transcript changed')
        previous = incoming['evaluations'].get(str(authenticated_dealer))
        if previous is not None and previous != request['evaluation']:
            raise ValueError('dealer attempted evaluation equivocation')
        incoming['evaluations'][str(authenticated_dealer)] = request['evaluation']
        self.save()
        return {'received': True, 'plan': binding, 'recipient': self.member, 'dealer': authenticated_dealer}

    def deliver(self, plan, packages, destinations):
        with self.lock:
            response = self.begin_deal(plan)
            own = next((item for item in packages if item['dealer'] == self.member), None)
            if own != response:
                raise ValueError('coordinator changed dealer commitment')
            identities = {str(destination['member']): destination['identity'] for destination in destinations['dealers']}
            binding, _ = self.contributions(plan, packages, identities)
            if [destination['member'] for destination in destinations['recipients']] != plan['members']:
                raise ValueError('missing or reordered destination')
            coefficients = tuple(int.from_bytes(raw(value, 32), 'big') for value in self.state['deals'][binding]['coefficients'])
        receipts = []
        recipients = destinations['recipients']
        # A sorted delivery order at every dealer creates a queue of fsynced
        # writes at the same recipient. Stagger the starts while preserving the
        # canonical public destination list and every authenticated evaluation.
        start = plan['dealers'].index(self.member) % len(recipients)
        for destination in recipients[start:] + recipients[:start]:
            with self.lock:
                self.require_healthy()
            trusted = self.options['trusted_clients'].get(destination['fingerprint'])
            if trusted != {'role': 'guardian', 'member': destination['member']}:
                raise ValueError('handoff destination is not a pinned guardian')
            evaluation = polynomial_value(coefficients, destination['member'])
            receipt = tls_request(destination['endpoint'], self.options, {
                'operation': 'receive_evaluation', 'plan': plan, 'contributions': packages,
                'identities': identities, 'dealer': self.member, 'evaluation': scalar_bytes(evaluation).hex(),
            }, destination['fingerprint'])
            receipts.append(receipt)
        return {'delivered': len(receipts), 'plan': binding}

    def prepare(self, request):
        transition = transition_from(request['transition'], self.curve)
        chain_id = raw(request['chain_id'], 32)
        config = transition.config
        if any(key.scheme != 2 for key in config.keys):
            raise ValueError('guardian supports TAC2 only')
        if dict(config.identities).get(self.member) != self.identity:
            raise ValueError('proposed institution identity does not match guardian')
        previous = None if request['previous'] is None else AuditConfig.from_bytes(raw(request['previous']), self.curve)
        if previous is None:
            if self.state['active'] is not None or config.generation != 0 or len(config.keys) != 1 or config.active_version != 1:
                raise ValueError('invalid genesis preparation')
            if transition.previous != bytes(32) or config.active_key.committee.epoch != 0:
                raise ValueError('invalid genesis binding')
        else:
            if transition.previous != previous.binding():
                raise ValueError('transition predecessor mismatch')
            check_continuity(previous, config)
            if self.state['active'] is not None and self.active() != previous:
                raise ValueError('transition does not extend active guardian state')
        if self.state['chain_id'] not in (None, request['chain_id']):
            raise ValueError('wrong preparation chain')
        if any(record['chain_id'] != request['chain_id'] for record in self.state['prepared'].values()):
            raise ValueError('guardian has already prepared for another chain')
        values = {}
        plans = request['plans']
        for key in config.keys:
            if str(key.version) in plans:
                plan = plans[str(key.version)]
                _, binding = self.plan(plan)
                incoming = self.state['incoming'].get(binding)
                # Genesis key generation precedes the chain hash that commits
                # its public config. Its plan binds an independent ceremony ID;
                # final readiness binds the actual chain hash and exact config.
                if (incoming is None or incoming['plan'] != plan
                        or (previous is not None and plan['chain_id'] != request['chain_id'])):
                    raise ValueError('missing staged historical key')
                if set(incoming['evaluations']) != {str(dealer) for dealer in plan['dealers']}:
                    raise ValueError('historical handoff has missing dealer evaluations')
                if committee_from(incoming['committee'], self.curve) != key.committee:
                    raise ValueError('staged share does not match proposed manifest')
                if plan['version'] != key.version:
                    raise ValueError('staged key version mismatch')
                if previous is None:
                    if plan['mode'] != 'genesis':
                        raise ValueError('genesis needs fresh distributed sharing')
                elif key.version <= len(previous.keys):
                    if plan['mode'] != 'refresh' or committee_from(plan['old'], self.curve) != previous.key(key.version).committee:
                        raise ValueError('historical key lacks correct previous committee')
                    if incoming['identities'] != {str(i): public.hex() for i, public in previous.identities if i in plan['dealers']}:
                        raise ValueError('dealer institution identity differs from previous configuration')
                elif plan['mode'] != 'new-key':
                    raise ValueError('rollover key needs a fresh ceremony')
                value = sum(int.from_bytes(raw(v, 32), 'big') for v in incoming['evaluations'].values()) % ORDER
                values[str(key.version)] = scalar_bytes(value).hex()
                self.share(key, values)
            else:
                if previous is None or key.version > len(previous.keys) or key.committee != previous.key(key.version).committee:
                    raise ValueError('every changed or historical key needs a handoff')
                self.share(key)
                values[str(key.version)] = self.state['shares'][str(key.version)]
        binding = transition.binding(chain_id).hex()
        record = {'transition': request['transition'], 'previous': request['previous'],
                  'chain_id': request['chain_id'], 'shares': values}
        if binding in self.state['prepared'] and self.state['prepared'][binding] != record:
            raise ValueError('prepared transition rebound')
        if binding not in self.state['prepared'] and len(self.state['prepared']) >= MAX_SESSIONS:
            raise ValueError('prepared state limit reached')
        self.state['prepared'][binding] = record
        self.save()
        ready = tuple(make_readiness(self.curve, chain_id, transition, key.version,
                                    self.share(key, values), self.identity_secret) for key in config.keys)
        return {'binding': binding, 'readiness': [ready_json(item) for item in ready]}

    def activate(self, request):
        transition = transition_from(request['transition'], self.curve)
        chain_id = raw(request['chain_id'], 32)
        if self.state['chain_id'] not in (None, request['chain_id']):
            raise ValueError('wrong activation chain')
        binding = transition.binding(chain_id).hex()
        record = self.state['prepared'].get(binding)
        if record is None or record['transition'] != request['transition'] or record['chain_id'] != request['chain_id']:
            raise ValueError('guardian has not durably prepared this transition')
        prepared = PreparedTransition(transition, tuple(ready_from(value) for value in request['readiness']))
        verify_readiness(self.curve, chain_id, prepared)
        if self.state['active'] == transition.config.to_bytes().hex():
            return {'active': transition.config.binding().hex(), 'idempotent': True}
        if self.state['active'] is not None:
            previous = self.active()
            if transition.previous != previous.binding():
                raise ValueError('activation does not extend current configuration')
            check_continuity(previous, transition.config)
            self.state['history'][previous.binding().hex()] = {'config': self.state['active'], 'shares': self.state['shares']}
        for key in transition.config.keys:
            self.share(key, record['shares'])
        # All retained keys switch in one fsync+atomic replacement per guardian.
        self.state['active'] = transition.config.to_bytes().hex()
        self.state['chain_id'] = request['chain_id']
        self.state['shares'] = record['shares']
        self.save()
        self.log.append({'status': 'activated', 'configuration': transition.config.binding().hex(),
                         'transition': binding, 'generation': transition.config.generation})
        return {'active': transition.config.binding().hex(), 'checkpoint': self.checkpoint()}

    def approve(self, request):
        """Research stand-in for an institution's independent human approval UI."""
        active = self.active()
        policy, disclosure = disclosure_from(request)
        key = active.key(request['key_version'])
        expected = Policy(key.committee.binding(), key.committee.threshold, active.identities)
        if policy != expected or (disclosure.delivery == 'tls' and disclosure.recipient_key.hex() not in self.options['recipients']):
            raise ValueError('approval policy or recipient is not configured')
        disclosure.validate(self.curve)
        if disclosure.policy_binding != policy.binding() or disclosure.expires_at <= int(time.time()):
            raise ValueError('invalid or expired approval request')
        signature = self.curve.sign(self.identity_secret, disclosure.binding())
        self.log.append({'status': 'approved', 'request': disclosure.binding().hex(),
                         'request_scope': request_scope(disclosure),
                         'key_version': key.version, 'signature': signature.hex()})
        return {'member': self.member, 'signature': signature.hex(), 'checkpoint': self.checkpoint()}

    def restore(self, request):
        """Restore a retained policy after the external chain observer sees undo.

        This loopback service does not independently verify chain consensus. The
        authenticated coordinator must obtain the target from its trusted node.
        """
        if request['chain_id'] != self.state['chain_id']:
            raise ValueError('wrong rollback chain')
        binding = raw(request['configuration'], 32).hex()
        previous = self.active()
        if previous.binding().hex() == binding:
            return {'active': binding, 'idempotent': True}
        record = self.state['history'].get(binding)
        if record is None:
            raise ValueError('rollback state is unavailable')
        config = AuditConfig.from_bytes(raw(record['config']), self.curve)
        if config.binding().hex() != binding:
            raise ValueError('stored rollback configuration mismatch')
        for key in config.keys:
            self.share(key, record['shares'])
        self.state['history'][previous.binding().hex()] = {'config': self.state['active'], 'shares': self.state['shares']}
        self.state['active'], self.state['shares'] = record['config'], record['shares']
        self.save()
        self.log.append({'status': 'policy-restored', 'configuration': binding,
                         'previous': previous.binding().hex()})
        return {'active': binding, 'checkpoint': self.checkpoint()}

    def disclose(self, request, peer):
        active = self.active()
        key = active.key(request['key_version'])
        share = self.share(key)
        policy, disclosure = disclosure_from(request)
        expected = Policy(key.committee.binding(), key.committee.threshold, active.identities)
        if policy != expected:
            raise ValueError('disclosure does not use current committee policy')
        sealed = disclosure.delivery == 'sealed-v1'
        if not sealed and peer.get('recipient_key') != disclosure.recipient_key.hex():
            raise ValueError('TLS recipient does not match signed request')
        if not sealed and self.options['recipients'].get(disclosure.recipient_key.hex()) != peer.get('fingerprint'):
            raise ValueError('recipient certificate is not pinned to recipient key')
        approvals = tuple(Approval(item['member'], raw(item['signature'], 64)) for item in request['approvals'])
        authorize(self.curve, policy, disclosure, approvals, int(time.time()))
        statement = statement_from(request['statement'])
        statement.validate(self.curve)
        if statement.chain_id != raw(self.state['chain_id'], 32) or statement.audit_key != key.public_key:
            raise ValueError('wrong disclosure chain or historical key')
        packet = ChunkPacket.from_bytes(raw(request['packet']), statement, self.curve)
        if (disclosure.statement_binding != statement.binding()
                or disclosure.packet_binding != digest(b'packet', packet.to_bytes())
                or not verify_chunked(self.curve, statement, packet)):
            raise ValueError('request does not authorize this valid packet')
        event = {'request': disclosure.binding().hex(), 'committee': key.committee.binding().hex(),
                 'request_scope': request_scope(disclosure),
                 'output_reference': {'chain_id': statement.chain_id.hex(),
                                      'transaction_template': statement.tx_digest.hex(),
                                      'output_index': statement.output_index},
                 'key_version': key.version, 'recipient': disclosure.recipient_key.hex(),
                 'approvals': [{'member': approval.member, 'signature': approval.signature.hex()} for approval in approvals]}
        # Durable authorization evidence precedes producing decryption points.
        self.log.append(dict(event, status='authorized'))
        partial = partial_decrypt_chunked(self.curve, statement, packet, key.committee, share, disclosure.binding())
        if disclosure.expires_at <= int(time.time()):
            self.log.append(dict(event, status='release-expired'))
            raise ValueError('disclosure expired before partial release')
        self.log.append(dict(event, status='partial-released'))
        result = {'member': partial.member, 'committee_binding': partial.committee_binding.hex(),
                'request_binding': partial.request_binding.hex(),
                'points': [point.hex() for point in partial.points],
                'proofs': [[scalar_bytes(v).hex() for v in proof] for proof in partial.proofs],
                'checkpoint': self.checkpoint()}
        if sealed:
            from sealed_delivery import seal
            return seal(self.curve, self.identity_secret, disclosure.recipient_key,
                        disclosure.binding(), self.member, result)
        return result


def request_scope(request):
    """Retain verifiable authorization context without openings or partials."""
    return {'delivery': request.delivery, 'policy_binding': request.policy_binding.hex(), 'statement_binding': request.statement_binding.hex(),
            'packet_binding': request.packet_binding.hex(), 'case_reference': request.case_reference.hex(),
            'recipient_key': request.recipient_key.hex(), 'expires_at': request.expires_at}


def disclosure_from(value):
    policy = Policy(raw(value['policy']['committee_binding'], 32), value['policy']['threshold'],
                    tuple((i, raw(public, 32)) for i, public in value['policy']['approvers']))
    request = value['request']
    disclosure = Request(raw(request['policy_binding'], 32), raw(request['statement_binding'], 32),
                         raw(request['packet_binding'], 32), raw(request['case_reference'], 32),
                         raw(request['recipient_key'], 33), request['expires_at'], request.get('delivery', 'tls'))
    return policy, disclosure


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log request bodies, shares, evaluations or partials.

    def do_POST(self):
        try:
            if self.path != '/' or self.headers.get('Transfer-Encoding') is not None:
                raise ValueError('unsupported guardian request framing')
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 < length <= MAX_MESSAGE:
                raise ValueError('invalid guardian request length')
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError('truncated guardian request')
            fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            result = self.server.guardian.dispatch(parse_json(payload), fingerprint)
            code = 200
        except (ValueError, KeyError, TypeError, OverflowError, OSError, StopIteration) as error:
            # Stack locations identify failures without logging exception text,
            # request bodies, private values or tracebacks containing locals.
            frames = []
            trace = error.__traceback__
            while trace is not None:
                frames.append([Path(trace.tb_frame.f_code.co_filename).name, trace.tb_lineno])
                trace = trace.tb_next
            print(canonical({'event': 'request-failed', 'member': self.server.guardian.member,
                             'exception': type(error).__name__, 'locations': frames}).decode(),
                  file=sys.stderr, flush=True)
            # Do not echo malformed inputs or private-state diagnostics over TLS.
            result = {'error': 'guardian rejected request'}
            code = 503 if isinstance(error, GuardianTransportError) else 400
        body = canonical(result)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if code == 200 and result.get('shutdown') is True:
            self.server.shutdown()


class GuardianHTTPServer(ThreadingHTTPServer):
    """Accept raw TCP promptly; authenticate TLS inside bounded worker threads."""
    # Join workers before closing the shared cryptographic context/private lock.
    daemon_threads = False

    def __init__(self, address, context, guardian):
        self.context, self.guardian = context, guardian
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        secured = None
        try:
            request.settimeout(HANDSHAKE_TIMEOUT)
            secured = self.context.wrap_socket(request, server_side=True)
            secured.settimeout(REQUEST_READ_TIMEOUT)
            self.finish_request(secured, client_address)
        except (OSError, ValueError):
            # Failed handshakes and truncated requests never disclose data or
            # block the accept loop. Request diagnostics stay out of logs.
            pass
        finally:
            self.shutdown_request(request if secured is None else secured)
            self.slots.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = load_private(args.config)
    guardian = Guardian(config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=config['ca'])
    context.load_cert_chain(config['certificate'], config['private_key'])
    # Serialize private state mutations; release the lock around outgoing TLS
    # delivery so an unchanged committee can deliver an evaluation to itself.
    server = GuardianHTTPServer(('127.0.0.1', config.get('port', 0)), context, guardian)
    print(json.dumps({'endpoint': f'https://127.0.0.1:{server.server_port}',
                      'member': guardian.member, 'identity': guardian.identity.hex()}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        guardian.close()


if __name__ == '__main__':
    main()
