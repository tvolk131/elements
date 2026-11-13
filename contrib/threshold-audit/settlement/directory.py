"""Exact-reference beneficiary lookup for the shared-custody demonstration.

Bank signing keys live in this demo backend. Signatures bind routing data;
they do not demonstrate independent bank gateway custody or a legal identity.
"""

import hashlib
import json
import re
import secrets
import time

from .approval import canonical
from .store import Problem


DOMAIN = b'Concord/beneficiary-routing/v1\x00'


class Directory:
    def __init__(self, store, signing_keys):
        self.store, self.curve, self.keys = store, store.verifier.curve, signing_keys
        store.db.executescript('''CREATE TABLE IF NOT EXISTS beneficiary_routes(
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL, source_id TEXT NOT NULL,
            data TEXT NOT NULL, used_by TEXT);''')

    @staticmethod
    def reference(account):
        return account.get('payment_reference', account['id'] + '@' + account.get('bank_tenant', 'bank'))

    def resolve(self, user, body):
        self.store.require(user, 'create_transfer')
        source = self.store.accessible_account(user, body.get('account_id'))
        currency = body.get('currency')
        if currency not in source.get('addresses', {}):
            raise Problem('choose a supported source currency')
        reference = body.get('reference', '').strip().lower()
        if re.fullmatch(r'[a-z0-9._-]{1,64}@[a-z0-9._-]{1,64}', reference) is None:
            raise Problem('enter an exact beneficiary reference, such as initech-main@bank-b')
        accounts = [json.loads(row[0]) for row in self.store.db.execute('SELECT data FROM accounts')]
        account = next((a for a in accounts if self.reference(a).lower() == reference and not a.get('disabled')), None)
        if account is None or currency not in account.get('addresses', {}):
            raise Problem('no available beneficiary matches this reference and currency', 404)
        if account['id'] == source['id']:
            raise Problem('choose a different destination account')
        bank = account.get('bank_tenant', 'bank')
        if bank not in self.keys:
            raise Problem('receiving institution is not available', 503)
        address = self.store.chain.wallets[account['id']].getnewaddress('beneficiary-route', 'blech32')
        asset = next(a for a in self.store.chain.assets() if a['currency'] == currency and a.get('registered'))
        payload = {'id': secrets.token_hex(16), 'reference': reference, 'beneficiary_name': account['name'],
                   'bank_id': bank, 'currency': currency, 'asset_id': asset['asset_id'], 'address': address,
                   'source_account_hash': hashlib.sha256(source['id'].encode()).hexdigest(),
                   'genesis_hash': self.store.chain.network()['genesis_hash'], 'expires_at': int(time.time()) + 600}
        digest = hashlib.sha256(DOMAIN + canonical(payload)).digest()
        result = {'payload': payload, 'public_key': self.curve.mul(self.keys[bank])[1:].hex(),
                  'signature': self.curve.sign(self.keys[bank], digest).hex(), 'verified': True}
        with self.store.transaction():
            self.store.db.execute('INSERT INTO beneficiary_routes VALUES(?,?,?,?,NULL)',
                                 (payload['id'], account['id'], source['id'], canonical(result).decode()))
        return result

    def consume(self, user, source, currency, route_id, operation_id):
        row = self.store.db.execute('SELECT * FROM beneficiary_routes WHERE id=?', (route_id,)).fetchone()
        if not row or row['source_id'] != source['id']:
            raise Problem('beneficiary confirmation does not belong to this source account', 403)
        route = json.loads(row['data'])
        payload = route['payload']
        target = self.store.account(row['account_id'])
        bank = target.get('bank_tenant', 'bank')
        digest = hashlib.sha256(DOMAIN + canonical(payload)).digest()
        if (payload['expires_at'] <= int(time.time()) or row['used_by'] is not None
                or payload['currency'] != currency or target.get('disabled')
                or payload['reference'] != self.reference(target).lower()
                or bank not in self.keys or payload['bank_id'] != bank
                or payload['genesis_hash'] != self.store.chain.network()['genesis_hash']
                or route['public_key'] != self.curve.mul(self.keys[bank])[1:].hex()
                or not self.curve.verify_signature(bytes.fromhex(route['public_key']), digest, bytes.fromhex(route['signature']))):
            raise Problem('beneficiary confirmation expired, changed or was already used; look it up again', 409)
        asset = next(a for a in self.store.chain.assets() if a['currency'] == currency and a.get('registered'))
        if asset['asset_id'] != payload['asset_id']:
            raise Problem('beneficiary asset registration changed; look it up again', 409)
        self.store.db.execute('UPDATE beneficiary_routes SET used_by=? WHERE id=? AND used_by IS NULL', (operation_id, route_id))
        return target, payload['address'], payload['beneficiary_name'], route

    def address(self, address):
        if not isinstance(address, str) or not 30 <= len(address) <= 200:
            raise Problem('enter a confidential address for this chain')
        info = self.store.chain.node.validateaddress(address)
        if not info.get('isvalid') or not info.get('confidential_key'):
            raise Problem('destination must be a valid confidential address for this chain')
        # Recognize a managed wallet by its script without exposing that mapping
        # in address-only lookup responses. This also handles freshly derived
        # addresses that are not the account's original configured address.
        for row in self.store.db.execute('SELECT data FROM accounts'):
            account = json.loads(row[0])
            if account.get('disabled'):
                continue
            wallet = self.store.chain.wallets.get(account['id'])
            if wallet and wallet.getaddressinfo(address).get('ismine'):
                return account
        return None

    def public_banks(self):
        return [{'id': bank, 'public_key': self.curve.mul(secret)[1:].hex()} for bank, secret in sorted(self.keys.items())]
