"""Create and seed a sandbox runtime for a live product/leadership demo.

Creates a fresh runtime (or continues an earlier, interrupted seed), turns on
the demo conveniences (persona sign-in and operator passphrase prefill),
then drives realistic history and three pre-staged cases through the real API:

* a funding request waiting for the bank's credit (demo flow: add funds),
* a withdrawal approved by Acme and two of three operators (demo flow:
  the last operator signs and the payout completes), and
* a delivered disclosure of an Acme to Initech payment for the regulator
  persona to open in the browser.

Demo conveniences make every persona usable without a password. Use only for
a local demo runtime with simulated money. Progress is recorded in
demo-seed.json, so rerunning the script continues where it stopped.

After seeding, save a reset point with --snapshot. Between dry runs, --reset
stops the demo and restores exactly that state (chain, wallets and cases).
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent
ROOT = AUDIT.parents[1]
sys.path[:0] = [str(AUDIT), str(ROOT / 'test' / 'functional')]

from curve import Curve, random_scalar  # noqa: E402
from guardian_service import atomic_write  # noqa: E402
from sealed_delivery import canonical  # noqa: E402
from settlement.freeze_orders import case_authority_secret  # noqa: E402
from settlement.runtime import load_config, save_config  # noqa: E402
from settlement.smoke import Pilot  # noqa: E402

APPROVAL_TTL = 14 * 24 * 3600
RECIPIENT_PASSWORD = 'concord-demo'
# The regulator persona's display name, which its freeze orders carry.
REGULATOR = 'Financial Regulator'
PERSONAS = [
    ('acme-maker', 'wallet', 'Acme · creates payments'),
    ('acme-approver', 'wallet', 'Acme · approves payments'),
    ('bank-maker', 'wallet', 'Bank · creates funding requests'),
    ('bank-admin', 'wallet', 'Bank · confirms deposits'),
    ('bank-approver', 'wallet', 'Bank · approves requests'),
    ('initech-maker', 'wallet', 'Initech (Bank B) · receives payments'),
    ('bank-compliance', 'wallet', 'Bank compliance · requests disclosures'),
    ('demo-recipient', 'wallet', 'Regulator · disclosures and freezes'),
    ('institution-1', 'guardian', 'Operator 1 · signs approvals'),
    ('institution-2', 'guardian', 'Operator 2 · signs approvals'),
    ('institution-3', 'guardian', 'Operator 3 · signs approvals'),
    ('bank-admin', 'guardian', 'Bank · reserves and oversight'),
]


def env():
    value = dict(os.environ)
    value['PYTHONPATH'] = os.pathsep.join([str(AUDIT), str(ROOT / 'test' / 'functional'), value.get('PYTHONPATH', '')])
    return value


def manage(*args):
    result = subprocess.run([sys.executable, str(AUDIT / 'manage.py'), *map(str, args)],
                            env=env(), capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f'manage.py {" ".join(map(str, args))} failed: {result.stderr.strip()[-500:]}')
    return json.loads(result.stdout) if result.stdout.strip().startswith('{') else result.stdout


def create(directory, port):
    """Start a brand-new sandbox once, wait until it is ready, then stop it."""
    print('creating a fresh runtime (this takes a few minutes)…', flush=True)
    log = open(directory.parent / (directory.name + '-create.log'), 'w')
    process = subprocess.Popen([sys.executable, '-u', '-m', 'settlement.sandbox', '--directory', str(directory),
                                '--port', str(port)], cwd=AUDIT, env=env(), stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 900
    while not (directory / 'ready.json').exists():
        if process.poll() is not None:
            raise RuntimeError(f'sandbox creation failed; see {log.name}')
        if time.monotonic() > deadline:
            process.terminate()
            raise RuntimeError('sandbox creation timed out')
        time.sleep(1)
    process.send_signal(signal.SIGTERM)
    process.wait(timeout=180)
    log.close()


def recipient_key(directory, curve):
    """The regulator's key file, in the format the browser exports; created once."""
    key_path = directory / 'demo-recipient-key.json'
    if not key_path.exists():
        secret, salt, nonce = random_scalar(), secrets.token_bytes(16), secrets.token_bytes(12)
        aes = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=210000).derive(RECIPIENT_PASSWORD.encode())
        base = {'format': 'concord-recipient-key-v1', 'user_id': 'demo-recipient', 'public_key': curve.mul(secret).hex()}
        ciphertext = AESGCM(aes).encrypt(nonce, secret.to_bytes(32, 'big'), canonical(base))
        atomic_write(key_path, dict(base, salt=salt.hex(), nonce=nonce.hex(), ciphertext=ciphertext.hex()))
    return json.loads(key_path.read_text())


def unlock_recipient_key(key):
    aes = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(key['salt']),
                     iterations=210000).derive(RECIPIENT_PASSWORD.encode())
    base = {name: key[name] for name in ('format', 'user_id', 'public_key')}
    return int.from_bytes(AESGCM(aes).decrypt(bytes.fromhex(key['nonce']), bytes.fromhex(key['ciphertext']), canonical(base)), 'big')


def regulator_authority(directory):
    """The demo regulator's freeze-order key, derived in the browser from the same key file."""
    curve = Curve(load_config(directory / 'adapter.json')['library'])
    try:
        public = curve.mul(case_authority_secret(unlock_recipient_key(recipient_key(directory, curve))))[1:].hex()
    finally:
        curve.close()
    return {REGULATOR: public}


def configure(directory, mesh):
    """Turn on demo conveniences. Every change is local to this runtime."""
    config = load_config(directory / 'web.json')
    # Operators honor freeze orders only from keys in their own configuration.
    trusted = regulator_authority(directory)
    config['case_authority_keys'] = trusted
    config['approval_ttl'] = APPROVAL_TTL
    # The federation runs the ledger and controls what enters and leaves it;
    # payments between customers need only the customer's own approvals.
    config['transfer_institution_approval'] = 'never'
    # The bank's deposit confirmation is its approval; tokens are issued as
    # soon as three institutions approve.
    config['deposit_issuance'] = 'automatic'
    config['demo_sign_in'] = [{'username': u, 'workspace': w, 'label': label} for u, w, label in PERSONAS]
    # Lets the console's demo shortcut sign as the remaining institutions.
    credentials = json.loads((directory / 'credentials.json').read_text())
    config['demo_institution_passphrases'] = {c['username']: c['institution_approval_passphrase']
                                              for c in credentials if c.get('institution_approval_passphrase')}
    save_config(directory / 'web.json', config)
    for service in directory.glob('institution-*/service.json'):
        value = load_config(service)
        value['demo_autofill'] = True
        value['case_authority_keys'] = trusted
        save_config(service, value)
    if mesh:
        shutil.copyfile(mesh, directory / 'mesh.json')
        os.chmod(directory / 'mesh.json', 0o600)


class Seeder:
    def __init__(self, directory):
        self.directory = directory
        self.pilot = Pilot(directory)
        self.path = directory / 'demo-seed.json'
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {}

    def save(self):
        atomic_write(self.path, self.state)

    def call(self, user, path, body=None):
        return self.pilot.call(user, path, body)

    def once(self, label, create):
        """Create an operation once; later runs continue the recorded one."""
        if label not in self.state:
            self.state[label] = create()['id']
            self.save()
        return self.call('bank-admin', '/api/operations/' + self.state[label])

    def sign(self, operation, institution):
        oid = operation['id']
        reviewed = self.call(institution, f'/api/operations/{oid}/prepare-approval', {})
        if institution in reviewed.get('approval_workflow', {}).get('approved_institution_ids', []):
            return reviewed
        service = next(g for g in self.call(institution, '/api/dashboard')['guardians'] if g['id'] == institution)['approval_url']
        signature = self.pilot.request(urllib.request.build_opener(), service + 'approve', {
            'operation': reviewed['approval_request'],
            'passphrase': self.pilot.credentials[institution]['institution_approval_passphrase']})
        return self.call(institution, f'/api/operations/{oid}/certificates', {'signature': signature})

    def authorize(self, operation, checker, institutions=tuple(f'institution-{n}' for n in range(1, 6))):
        if not operation['user_approved']:
            operation = self.call(checker, f"/api/operations/{operation['id']}/approve", {})
        if not operation['guardian_threshold']:  # the payment policy asks for no institutions
            return operation
        for institution in institutions:
            operation = self.sign(operation, institution)
        return operation

    def settle(self, operation, checker):
        if operation['state'] in {'awaiting_approval', 'ready'}:
            operation = self.authorize(operation, checker)
            if operation['state'] == 'ready':  # automatic deposits are already issuing
                operation = self.call(checker, f"/api/operations/{operation['id']}/execute", {})
        return self.pilot.wait(operation, timeout=180)

    def deposit(self, label, account, currency, amount, finish=True):
        operation = self.once(label, lambda: self.call('bank-maker', '/api/deposits',
                                                       {'account_id': account, 'currency': currency, 'amount': amount}))
        if not finish:
            return operation
        if operation['state'] == 'awaiting_bank':
            self.call('bank-admin', '/api/bank/events', {'event_id': 'demo-credit-' + operation['id'], 'kind': 'credit',
                      'currency': currency, 'operation_id': operation['id'], 'amount': amount})
            operation = self.call('bank-admin', '/api/operations/' + operation['id'])
        return self.settle(operation, 'bank-approver')

    def transfer(self, label, body, maker='acme-maker', checker='acme-approver'):
        operation = self.once(label, lambda: self.call(maker, '/api/transfers', body() if callable(body) else body))
        return self.settle(operation, checker)

    def withdraw(self, label, currency, amount, institutions=None):
        operation = self.once(label, lambda: self.call('acme-maker', '/api/redemptions', {
            'account_id': 'acme-main', 'currency': currency, 'amount': amount, 'beneficiary_id': 'acme-main-' + currency}))
        if institutions is None:
            return self.settle(operation, 'acme-approver')
        return self.authorize(operation, 'acme-approver', institutions)

    def recipient_key(self, curve):
        # Same format the browser exports, so the presenter can import it.
        key = recipient_key(self.directory, curve)
        self.call('demo-recipient', '/api/disclosures/recipient-key', {'public_key': key['public_key']})
        return key

    def disclose(self, operation_id, key):
        if 'disclosure' not in self.state:
            targets = self.call('bank-compliance', '/api/disclosure-targets/' + operation_id)['outputs']
            target = next((t for t in targets if t['label'] == 'Payment destination'), targets[0])
            case = self.call('bank-compliance', '/api/disclosures', {
                'operation_id': operation_id, 'targets': [{'txid': target['txid'], 'output_index': target['output_index']}],
                'recipient_id': 'demo-recipient', 'recipient_key': key['public_key'],
                'authority': 'Financial regulator · routine supervisory review',
                'reason': 'Confirm the amount of Acme’s payment to Initech for the quarterly review.',
                'expires_in': 86400})
            self.state['disclosure'] = case['id']
            self.save()
        case = self.call('bank-compliance', '/api/disclosures/' + self.state['disclosure'])
        overview = self.call('bank-compliance', '/api/disclosures')
        holders = overview.get('member_operators', {})
        for member in overview['members'][:case['threshold']]:
            if member not in case['approved_members']:
                # The operator holding that key piece approves; older runtimes
                # had separate guardian logins.
                login = holders.get(str(member), f'audit-guardian-{member}')
                case = self.call(login, f"/api/disclosures/{case['id']}/approve", {})
        if case['state'] != 'delivered':
            case = self.call('bank-compliance', f"/api/disclosures/{case['id']}/release", {})
        return case

    def run(self):
        adapter = load_config(self.directory / 'adapter.json')
        curve = Curve(adapter['library'])
        try:
            print('funding accounts…', flush=True)
            self.deposit('fund-acme-eur', 'acme-main', 'EUR', '1250000.00')
            self.deposit('fund-acme-usd', 'acme-main', 'USD', '640000.00')
            self.deposit('fund-treasury-eur', 'acme-treasury', 'EUR', '300000.00')
            self.deposit('fund-globex-eur', 'globex-main', 'EUR', '420000.00')
            print('recording payment history…', flush=True)
            # Other companies are paid by their bank-signed beneficiary reference.
            def pay(reference, amount):
                def body():
                    route = self.call('acme-maker', '/api/beneficiaries/resolve',
                                      {'account_id': 'acme-main', 'currency': 'EUR', 'reference': reference})
                    return {'account_id': 'acme-main', 'currency': 'EUR', 'amount': amount, 'route_id': route['payload']['id']}
                return body
            self.transfer('pay-treasury', {'account_id': 'acme-main', 'to_account_id': 'acme-treasury',
                                           'currency': 'EUR', 'amount': '150000.00'})
            self.transfer('pay-globex', pay('globex-main@bank', '48500.00'))
            initech = self.transfer('pay-initech', pay('initech-main@bank-b', '12750.00'))
            self.withdraw('withdraw-usd', 'USD', '25000.00')
            print('pre-staging demo cases…', flush=True)
            self.deposit('staged-funding', 'acme-main', 'EUR', '500000.00', finish=False)
            # One approval short of the operators' 5-of-7 threshold.
            self.withdraw('staged-withdrawal', 'USD', '75000.00', institutions=tuple(f'institution-{n}' for n in range(1, 5)))
            case = self.disclose(initech['id'], self.recipient_key(curve))
            self.state['complete'] = True
            self.save()
            return case
        finally:
            curve.close()


def snapshot_path(directory):
    return directory.with_name(directory.name + '.snapshot')


def snapshot(directory):
    """Save the stopped runtime so later dry runs can start from this state."""
    manage('--runtime', directory, 'stop')
    target = snapshot_path(directory)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(directory, target, symlinks=True)
    manage('select', directory)
    return manage('start')


def reset(directory):
    """Replace the runtime with its snapshot. Paths inside are absolute, so the
    snapshot is always restored to the same location."""
    source = snapshot_path(directory)
    if not (source / 'ready.json').exists():
        raise RuntimeError(f'no snapshot at {source}; run with --snapshot first')
    manage('--runtime', directory, 'stop')
    shutil.rmtree(directory)
    shutil.copytree(source, directory, symlinks=True)
    manage('select', directory)
    return manage('start')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('directory', type=Path, help='new (or partially seeded) runtime directory')
    parser.add_argument('--port', type=int, default=42987, help='stable local web port')
    parser.add_argument('--mesh-from', type=Path, help='copy mesh.json (Rayfish access) from another runtime')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--snapshot', action='store_true', help='save the seeded runtime as the reset point')
    action.add_argument('--reset', action='store_true', help='restore the runtime from its snapshot and start it')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if args.snapshot or args.reset:
        status = (snapshot if args.snapshot else reset)(directory)
        print(json.dumps({'state': status['state'], 'wallet': status['wallet'],
                          'snapshot': str(snapshot_path(directory))}, indent=2))
        return
    if not (directory / 'ready.json').exists():
        if directory.exists() and any(directory.iterdir()):
            parser.error('directory is not empty and is not a sandbox runtime')
        create(directory, args.port)
    configure(directory, args.mesh_from)
    manage('select', directory)
    status = manage('start')
    print('runtime started:', status['wallet'], flush=True)
    case = Seeder(directory).run()
    print(json.dumps({'wallet': status['wallet'], 'guardian': status['guardian'],
                      **({'mesh': status['mesh']} if status.get('mesh') else {}),
                      'disclosure_case': case['id'], 'disclosure_state': case['state'],
                      'recipient_key_file': str(directory / 'demo-recipient-key.json'),
                      'recipient_key_password': RECIPIENT_PASSWORD}, indent=2))


if __name__ == '__main__':
    main()
