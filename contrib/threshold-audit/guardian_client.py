# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Loopback guardian research harness and public handoff coordinator.

Only the fixture CA and institutional approval TLS credentials are centralized
by this test harness. Decryption shares, dealer coefficients and private handoff
evaluations remain inside their respective guardian processes. This process
does not generate or reconstruct the audit master scalar.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import secrets
import selectors
import re
import ssl
import subprocess
import threading
import sys
import tempfile
import time

from chunked import combine_chunked
from disclosure import Policy, Request
from governance import AuditConfig, AuditKey, PreparedTransition, Transition, verify_readiness
from guardian_service import (
    atomic_write, canonical, check_continuity, committee_json, parse_json,
    raw, ready_from, ready_json, statement_json, tls_request, transition_json,
)
from recovery import digest, index_bytes
from threshold import PartialDecryption


def certificate_fingerprint(path):
    der = ssl.PEM_cert_to_DER_cert(Path(path).read_text())
    return hashlib.sha256(der).hexdigest()


class FixtureCA:
    """Test-only ephemeral CA. Production institutions own their credentials."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.ca, self.key = self.directory / 'ca.pem', self.directory / 'ca.key'
        self.run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                 '-keyout', str(self.key), '-out', str(self.ca), '-days', '2', '-subj', '/CN=AuditResearchCA',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        os.chmod(self.key, 0o600)

    @staticmethod
    def run(*args):
        subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def issue(self, name):
        key, csr, cert = (self.directory / (name + suffix) for suffix in ('.key', '.csr', '.pem'))
        ext = self.directory / (name + '.extensions')
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1\n')
        self.run('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                 '-keyout', str(key), '-out', str(csr), '-subj', '/CN=' + name)
        self.run('x509', '-req', '-in', str(csr), '-CA', str(self.ca), '-CAkey', str(self.key),
                 '-CAcreateserial', '-days', '2', '-out', str(cert), '-extfile', str(ext))
        os.chmod(key, 0o600)
        return {'ca': str(self.ca), 'certificate': str(cert), 'private_key': str(key),
                'fingerprint': certificate_fingerprint(cert)}

    @classmethod
    def resume(cls, directory):
        """Open this fixture's existing authority without regenerating its key."""
        result = cls.__new__(cls)
        result.directory = Path(directory)
        result.ca, result.key = result.directory / 'ca.pem', result.directory / 'ca.key'
        if not result.ca.is_file() or not result.key.is_file():
            raise ValueError('existing guardian CA is missing')
        return result

    def credentials(self, name):
        """Load an already issued identity, preserving its pinned fingerprint."""
        cert, key = self.directory / (name + '.pem'), self.directory / (name + '.key')
        if not cert.is_file() or not key.is_file():
            raise ValueError('existing guardian credential is incomplete')
        return {'ca': str(self.ca), 'certificate': str(cert), 'private_key': str(key),
                'fingerprint': certificate_fingerprint(cert)}

    def issue_or_resume(self, name):
        cert, key = self.directory / (name + '.pem'), self.directory / (name + '.key')
        if cert.exists() or key.exists():
            return self.credentials(name)
        return self.issue(name)


class GuardianProcess:
    def __init__(self, config, coordinator):
        self.config, self.coordinator = config, coordinator
        self.path = Path(config['directory']).parent / f"guardian-{config['member']}.json"
        atomic_write(self.path, config)
        self.process, self.endpoint, self.identity = None, None, None
        self.startup_diagnostic = None
        self.startup_seconds = None

    def start(self):
        if self.process is not None and self.process.poll() is None:
            raise ValueError('guardian already started')
        timeout = self.config.get('startup_timeout', 60)
        if type(timeout) not in (int, float) or not 1 <= timeout <= 120:
            raise ValueError('guardian startup timeout must be 1..120 seconds')
        self.endpoint, self.identity, self.startup_diagnostic = None, None, None
        stderr_path = Path(self.config['directory']).parent / f"guardian-{self.config['member']}.stderr"
        self.stderr = stderr_path.open('ab')
        os.chmod(stderr_path, 0o600)
        self.process = subprocess.Popen([sys.executable, '-u', str(Path(__file__).with_name('guardian_service.py')),
                                         '--config', str(self.path)], stdout=subprocess.PIPE, stderr=self.stderr)
        process = self.process
        started = time.monotonic()
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        output = bytearray()
        try:
            deadline = started + timeout
            while b'\n' not in output:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(timeout=max(0, remaining)):
                    raise RuntimeError('startup address deadline exceeded')
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    raise RuntimeError('process exited before publishing startup address')
                output.extend(chunk)
                if len(output) > 65536:
                    raise RuntimeError('startup response exceeds size bound')
            result = parse_json(bytes(output).split(b'\n', 1)[0])
            if result.get('member') != self.config['member']:
                raise ValueError('startup member mismatch')
            raw(result['identity'], 32)
            self.endpoint, self.identity = result['endpoint'], result['identity']
            self.startup_seconds = time.monotonic() - started
            atomic_write(self.path.with_name(f"guardian-{self.config['member']}.endpoint.json"),
                         {'member': self.config['member'], 'endpoint': self.endpoint, 'identity': self.identity,
                          'fingerprint': self.config['fingerprint'], 'pid': self.process.pid})
            return self
        except Exception as error:
            elapsed = time.monotonic() - started
            # Stop this child before its parent temporary directory is removed.
            # Preserve only startup diagnostics, never private state or TLS keys.
            self.stop()
            destination = Path(tempfile.mkdtemp(prefix='elements-guardian-startup-failure-'))
            path = destination / f"guardian-{self.config['member']}.stderr"
            data = stderr_path.read_bytes()[-65536:]
            header = canonical({'member': self.config['member'], 'pid': process.pid,
                                'exit_code': process.returncode, 'elapsed_seconds': round(elapsed, 3),
                                'error': str(error), 'stdout_bytes': len(output)}) + b'\n'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(header + data)
            self.startup_diagnostic = str(path)
            raise RuntimeError(f"guardian {self.config['member']} failed startup after {elapsed:.1f}s; "
                               f"diagnostics: {path}") from error
        finally:
            selector.close()

    def request(self, operation, credentials=None, **values):
        return tls_request(self.endpoint, self.coordinator if credentials is None else credentials,
                           {'operation': operation, **values}, self.config['fingerprint'],
                           timeout=2 if operation == 'shutdown' else 180 if operation == 'deliver' else 60)

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.request('shutdown')
                    self.process.wait(timeout=5)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
            self.process.stdout.close()
            self.stderr.close()
            self.process = None

    def public(self):
        return {'member': self.config['member'], 'endpoint': self.endpoint,
                'fingerprint': self.config['fingerprint'], 'identity': self.identity}


class GuardianCluster:
    """Own a set of test guardian processes and their public coordinator."""
    def __init__(self, directory, members, library, curve, recipient_key):
        self.lifecycle_lock, self.closing = threading.RLock(), threading.Event()
        self.directory, self.curve = Path(directory), curve
        self.recipient_key = recipient_key
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.ca = FixtureCA(self.directory / 'tls')
        self.coordinator = self.ca.issue('coordinator')
        self.recipient = self.ca.issue('recipient')
        self.approvers = {member: self.ca.issue(f'approver-{member}') for member in members}
        credentials = {member: self.ca.issue(f'guardian-{member}') for member in members}
        trusted = {self.coordinator['fingerprint']: {'role': 'coordinator'},
                   self.recipient['fingerprint']: {'role': 'recipient', 'recipient_key': recipient_key.hex(),
                                                    'fingerprint': self.recipient['fingerprint']}}
        trusted.update({value['fingerprint']: {'role': 'guardian', 'member': member}
                        for member, value in credentials.items()})
        trusted.update({value['fingerprint']: {'role': 'approver', 'member': member}
                        for member, value in self.approvers.items()})
        self.guardians = {}
        try:
            for member in members:
                config = dict(credentials[member], member=member, library=str(library),
                              directory=str(self.directory / f'private-{member}'), trusted_clients=trusted,
                              recipients={recipient_key.hex(): self.recipient['fingerprint']})
                guardian = GuardianProcess(config, self.coordinator)
                self.guardians[member] = guardian
                guardian.start()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closing.set()
        with self.lifecycle_lock:
            for guardian in self.guardians.values():
                guardian.stop()

    @classmethod
    def resume(cls, directory, curve, members=None):
        """Reload existing processes/identities, never a replacement ceremony.

        All registered configurations remain available in ``guardians``. Only
        ``members`` start when supplied, so retired guardians stay stopped.
        """
        result = cls.__new__(cls)
        result.lifecycle_lock, result.closing = threading.RLock(), threading.Event()
        result.directory, result.curve = Path(directory), curve
        result.ca = FixtureCA.resume(result.directory / 'tls')
        result.coordinator = result.ca.credentials('coordinator')
        result.recipient = result.ca.credentials('recipient')
        paths = [path for path in result.directory.glob('guardian-*.json')
                 if re.fullmatch(r'guardian-[0-9]+\.json', path.name)]
        if not paths:
            raise ValueError('existing guardian pool is empty')
        configs = sorted((parse_json(path.read_bytes()) for path in paths), key=lambda config: config['member'])
        registered = {config['member'] for config in configs}
        selected = registered if members is None else set(members)
        if not selected <= registered:
            raise ValueError('requested guardian is not enrolled')
        recipients = configs[0]['recipients']
        if len(recipients) != 1:
            raise ValueError('fixture resume requires one configured disclosure recipient')
        result.recipient_key = raw(next(iter(recipients)), 33)
        result.approvers = {member: result.ca.credentials(f'approver-{member}') for member in registered}
        result.guardians = {}
        try:
            for config in configs:
                guardian = GuardianProcess(config, result.coordinator)
                result.guardians[config['member']] = guardian
                if config['member'] in selected:
                    guardian.start()
        except BaseException:
            result.close()
            raise
        return result

    @classmethod
    def attach(cls, directory, curve, members=None):
        """Attach only to already-live guardians for external fixture recovery.

        This does not start, stop or rewrite any guardian configuration. Public
        endpoint metadata is checked against the enrolled pinned certificate and
        a fresh authenticated status response. Closing the wrapper does not own
        the attached processes.
        """
        result = cls.__new__(cls)
        result.lifecycle_lock, result.closing = threading.RLock(), threading.Event()
        result.directory, result.curve, result.attached = Path(directory), curve, True
        result.ca = FixtureCA.resume(result.directory / 'tls')
        result.coordinator = result.ca.credentials('coordinator')
        result.recipient = result.ca.credentials('recipient')
        paths = [path for path in result.directory.glob('guardian-*.json')
                 if re.fullmatch(r'guardian-[0-9]+\.json', path.name)]
        configs = sorted((parse_json(path.read_bytes()) for path in paths), key=lambda config: config['member'])
        if not configs:
            raise ValueError('existing guardian pool is empty')
        registered = {config['member'] for config in configs}
        selected = registered if members is None else set(members)
        if not selected <= registered:
            raise ValueError('requested guardian is not enrolled')
        recipients = configs[0]['recipients']
        if len(recipients) != 1:
            raise ValueError('fixture attachment requires one disclosure recipient')
        result.recipient_key = raw(next(iter(recipients)), 33)
        result.approvers, result.guardians = {}, {}
        for config in configs:
            member = config['member']
            if member not in selected:
                continue
            endpoint_path = result.directory / f'guardian-{member}.endpoint.json'
            try:
                endpoint = parse_json(endpoint_path.read_bytes())
                if endpoint['member'] != member or endpoint['fingerprint'] != config['fingerprint']:
                    raise ValueError('guardian endpoint enrollment mismatch')
                guardian = GuardianProcess.__new__(GuardianProcess)
                guardian.config, guardian.coordinator = config, result.coordinator
                guardian.path = result.directory / f'guardian-{member}.json'
                guardian.process = None
                guardian.endpoint, guardian.identity = endpoint['endpoint'], endpoint['identity']
                guardian.startup_diagnostic, guardian.startup_seconds = None, None
                status = guardian.request('status')
                if status['member'] != member or status['identity'] != guardian.identity:
                    raise ValueError('live guardian identity differs from endpoint metadata')
                result.guardians[member] = guardian
                result.approvers[member] = result.ca.credentials(f'approver-{member}')
            except (OSError, ValueError, KeyError):
                if members is not None:
                    raise ValueError(f'requested guardian {member} is not available for attachment') from None
        if not result.guardians:
            raise ValueError('no live guardian processes available for attachment')
        return result

    def extend(self, members):
        """Enroll incoming fixture guardians under the existing pinned CA.

        Existing private key-share state is untouched. Current processes restart
        briefly to load the expanded peer trust list; callers pause ceremonies
        during this operation. The same files allow an interrupted enrollment to
        resume without replacing identities or audit keys.
        """
        with self.lifecycle_lock:
            self._require_open()
            return self._extend(members)

    def _require_open(self):
        if self.closing.is_set():
            raise RuntimeError('guardian pool is shutting down')

    def _extend(self, members):
        if getattr(self, 'attached', False):
            raise ValueError('attached pool cannot enroll or restart guardian processes')
        members = tuple(members)
        if (not members or tuple(sorted(set(members))) != members
                or any(type(member) is not int or not 1 <= member <= 0xffffffff for member in members)):
            raise ValueError('incoming guardian IDs must be sorted, distinct and positive')
        registered = set(self.guardians) | set(members)
        base = next(iter(self.guardians.values())).config
        credentials = {member: self.ca.issue_or_resume(f'guardian-{member}') for member in registered}
        for member in registered:
            self.approvers[member] = self.ca.issue_or_resume(f'approver-{member}')
        trusted = dict(base['trusted_clients'])
        trusted.update({value['fingerprint']: {'role': 'guardian', 'member': member}
                        for member, value in credentials.items()})
        trusted.update({value['fingerprint']: {'role': 'approver', 'member': member}
                        for member, value in self.approvers.items()})
        running = {member for member, guardian in self.guardians.items()
                   if guardian.process is not None and guardian.process.poll() is None}
        # Restart only after all certificates exist. Never rewrite a running
        # process's identity or its private shares to retrofit the new roster.
        for member in running:
            self.guardians[member].stop()
        for member in sorted(registered):
            self._require_open()
            if member in self.guardians:
                config = dict(self.guardians[member].config, trusted_clients=trusted)
            else:
                config = dict(credentials[member], member=member, library=base['library'],
                              directory=str(self.directory / f'private-{member}'), trusted_clients=trusted,
                              recipients=dict(base['recipients']))
            self.guardians[member] = GuardianProcess(config, self.coordinator)
        for member in sorted(running | set(members)):
            self._require_open()
            self.guardians[member].start()
        return self.public(members)

    def stop_members(self, members):
        if getattr(self, 'attached', False):
            raise ValueError('attached pool does not own guardian processes')
        with self.lifecycle_lock:
            for member in members:
                self.guardians[member].stop()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, _traceback):
        try:
            if exception is not None:
                directory = Path(tempfile.mkdtemp(prefix='elements-guardian-request-failure-'))
                for guardian in self.guardians.values():
                    path = Path(guardian.config['directory']).parent / f"guardian-{guardian.config['member']}.stderr"
                    if path.exists():
                        destination = directory / path.name
                        destination.write_bytes(path.read_bytes()[-65536:])
                        os.chmod(destination, 0o600)
                if hasattr(exception, 'add_note'):
                    exception.add_note(f'Guardian request diagnostics: {directory}')
                else:
                    print(f'Guardian request diagnostics: {directory}', file=sys.stderr)
        except OSError:
            pass  # Preserve the original failure and always stop owned children.
        finally:
            self.close()

    def public(self, members):
        return [self.guardians[member].public() for member in members]

    def deal(self, chain_id, members, threshold, version, *, previous=None, mode='genesis', dealers=None, session=None):
        old = None if previous is None or mode != 'refresh' else previous.key(version).committee
        dealers = tuple(members if dealers is None else dealers)
        plan = {'chain_id': chain_id.hex(), 'session': secrets.token_hex(32) if session is None else session,
                'mode': mode, 'version': version, 'members': list(members), 'threshold': threshold,
                'dealers': list(dealers), 'epoch': 0 if old is None else old.epoch + 1,
                'old': None if old is None else committee_json(old)}
        contributions = [self.guardians[member].request('begin_deal', plan=plan) for member in dealers]
        # Public commitments only. Every evaluation is created by its dealer
        # and delivered directly over pinned mutual TLS to its recipient.
        destinations = {'dealers': self.public(dealers), 'recipients': self.public(members)}
        with ThreadPoolExecutor(max_workers=min(len(dealers), 8)) as executor:
            results = list(executor.map(lambda member: self.guardians[member].request(
                'deliver', plan=plan, contributions=contributions, destinations=destinations), dealers))
        if any(item['delivered'] != len(members) for item in results):
            raise ValueError('handoff did not reach every proposed recipient')
        from threshold import Committee
        committee = Committee(plan['epoch'], tuple(members),
                              tuple(self.curve.add(*(raw(item['commitments'][j], 33) for item in contributions))
                                    for j in range(threshold)))
        committee.validate(self.curve)
        if old is not None and committee.public_key != old.public_key:
            raise ValueError('distributed handoff changed public key')
        return plan, committee, contributions

    def prepare(self, chain_id, config, plans, *, previous=None, activation_height=10):
        transition = Transition(bytes(32) if previous is None else previous.binding(), activation_height, config)
        readiness = []
        for member, _ in config.identities:
            result = self.guardians[member].request('prepare', transition=transition_json(transition),
                chain_id=chain_id.hex(), previous=None if previous is None else previous.to_bytes().hex(),
                plans={str(version): plan for version, plan in plans.items()})
            readiness.extend(ready_from(value) for value in result['readiness'])
        readiness.sort(key=lambda value: (value.version, value.member))
        prepared = PreparedTransition(transition, tuple(readiness))
        verify_readiness(self.curve, chain_id, prepared)
        return prepared

    def activate(self, chain_id, prepared):
        verify_readiness(self.curve, chain_id, prepared)
        results = []
        for member, _ in prepared.transition.config.identities:
            results.append(self.guardians[member].request('activate', chain_id=chain_id.hex(),
                transition=transition_json(prepared.transition), readiness=[ready_json(value) for value in prepared.readiness]))
        return results

    def bootstrap_genesis(self, members, threshold, signer_policy):
        """Generate the initial key before its config defines the genesis hash."""
        ceremony_id = secrets.token_bytes(32)
        plan, committee, _ = self.deal(ceremony_id, members, threshold, 1)
        config = AuditConfig(0, signer_policy, tuple((member, raw(self.guardians[member].identity, 32)) for member in members),
                             1, (AuditKey(1, 2, committee),))
        return config, {1: plan}

    def genesis(self, chain_id, members, threshold, signer_policy):
        config, plans = self.bootstrap_genesis(members, threshold, signer_policy)
        prepared = self.prepare(chain_id, config, plans)
        self.activate(chain_id, prepared)
        return config

    def rollover(self, chain_id, previous, signer_policy, *, activation_height=20, activate=True):
        members = tuple(member for member, _ in previous.identities)
        version = len(previous.keys) + 1
        plan, committee, _ = self.deal(chain_id, members, previous.active_key.committee.threshold,
                                       version, previous=previous, mode='new-key')
        config = AuditConfig(previous.generation + 1, signer_policy, previous.identities,
                             version, previous.keys + (AuditKey(version, 2, committee),))
        prepared = self.prepare(chain_id, config, {version: plan}, previous=previous, activation_height=activation_height)
        if activate:
            self.activate(chain_id, prepared)
            return config
        return prepared, {version: plan}

    def handoff(self, chain_id, previous, members, threshold, signer_policy, *, activation_height=30, activate=True):
        plans, keys = {}, []
        for old in previous.keys:
            plan, committee, _ = self.deal(chain_id, members, threshold, old.version, previous=previous,
                mode='refresh', dealers=old.committee.members[:old.committee.threshold])
            plans[old.version] = plan
            keys.append(AuditKey(old.version, old.scheme, committee))
        config = AuditConfig(previous.generation + 1, signer_policy,
                             tuple((member, raw(self.guardians[member].identity, 32)) for member in members),
                             previous.active_version, tuple(keys))
        check_continuity(previous, config)
        prepared = self.prepare(chain_id, config, plans, previous=previous, activation_height=activation_height)
        if activate:
            self.activate(chain_id, prepared)
        return prepared, plans

    def disclosure(self, config, version, statement, packet, recipient_key, *, expires_at=None, case_reference=None):
        key = config.key(version)
        policy = Policy(key.committee.binding(), key.committee.threshold, config.identities)
        request = Request(policy.binding(), statement.binding(), digest(b'packet', packet.to_bytes()),
                          secrets.token_bytes(32) if case_reference is None else case_reference, recipient_key,
                          int(time.time()) + 120 if expires_at is None else expires_at)
        payload = {'key_version': version,
                   'policy': {'committee_binding': policy.committee_binding.hex(), 'threshold': policy.threshold,
                              'approvers': [(i, public.hex()) for i, public in policy.approvers]},
                   'request': {'policy_binding': request.policy_binding.hex(), 'statement_binding': request.statement_binding.hex(),
                               'packet_binding': request.packet_binding.hex(), 'case_reference': request.case_reference.hex(),
                               'recipient_key': request.recipient_key.hex(), 'expires_at': request.expires_at}}
        approvals = []
        for member in key.committee.members[:policy.threshold]:
            item = self.guardians[member].request('approve', credentials=self.approvers[member], **payload)
            approvals.append({'member': item['member'], 'signature': item['signature']})
        return request, dict(payload, approvals=approvals, statement=statement_json(statement), packet=packet.to_bytes().hex())

    def recover(self, config, version, statement, packet, recipient_key):
        request, payload = self.disclosure(config, version, statement, packet, recipient_key)
        key = config.key(version)
        partials, checkpoints = [], []
        for member in key.committee.members[:key.committee.threshold]:
            result = self.guardians[member].request('disclose', credentials=self.recipient, **payload)
            partials.append(PartialDecryption(result['member'], raw(result['committee_binding'], 32),
                raw(result['request_binding'], 32), tuple(raw(point, 33) for point in result['points']),
                tuple(tuple(int.from_bytes(raw(value, 32), 'big') for value in proof) for proof in result['proofs'])))
            checkpoints.append(result['checkpoint'])
        opening = combine_chunked(self.curve, statement, packet, key.committee, tuple(partials), request.binding())
        return opening, checkpoints


def verify_checkpoint(curve, identity, checkpoint):
    message = digest(b'guardian-checkpoint', index_bytes(checkpoint['member']),
                     checkpoint['sequence'].to_bytes(8, 'big'), raw(checkpoint['head'], 32))
    return curve.verify_signature(identity, message, raw(checkpoint['signature'], 64))


def verify_log(path, checkpoint):
    """Verify an independently pinned prefix, rejecting truncation/rewrite."""
    head, sequence, pinned = bytes(32), 0, checkpoint['sequence'] == 0 and checkpoint['head'] == bytes(32).hex()
    with Path(path).open('rb') as stream:
        for line in stream:
            row = parse_json(line)
            head = digest(b'guardian-log', head, canonical(row['event']))
            sequence += 1
            if row != {'sequence': sequence, 'head': head.hex(), 'event': row['event']}:
                return False
            if sequence == checkpoint['sequence']:
                pinned = head.hex() == checkpoint['head']
    return pinned and sequence >= checkpoint['sequence']
