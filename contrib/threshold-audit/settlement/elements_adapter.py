"""Real Elements transaction adapter for the settlement sandbox."""

from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import threading
import urllib.request

from curve import Curve
from governance import AuditConfig
from native_transactions import wallet_openings
from test_framework import messages
from test_framework.messages import tx_from_hex
from .authorization import (WINDOW, AuthorizationRefused, AuthorizationUnavailable, authorization_digest,
                            decode_policy, encode, needs_registration)
from .treasury import InstitutionClient, InstitutionRefused, NativeECDSA, template_hash
from test_framework.script import CScript, SegwitV0SignatureHash, SIGHASH_ALL


class RPCError(RuntimeError):
    def __init__(self, error):
        self.error = error
        super().__init__(error['message'])


def rpc_json(value):
    """Serialize Decimal as an exact JSON number, including strict issuance RPCs."""
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError('non-finite RPC amount')
        return format(value, 'f')
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(key) + ':' + rpc_json(item) for key, item in value.items()) + '}'
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(rpc_json(item) for item in value) + ']'
    return json.dumps(value, allow_nan=False)


class RPC:
    """One bounded connection per call; safe across HTTP worker threads."""
    def __init__(self, url):
        from urllib.parse import urlsplit, urlunsplit, unquote
        import base64
        parsed = urlsplit(url)
        self.url = urlunsplit((parsed.scheme, parsed.netloc.split('@')[-1], parsed.path, '', ''))
        self.authorization = 'Basic ' + base64.b64encode((unquote(parsed.username) + ':' + unquote(parsed.password)).encode()).decode()

    def __getattr__(self, method):
        def call(*args):
            body = rpc_json({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': args}).encode()
            request = urllib.request.Request(self.url, data=body, headers={
                'Authorization': self.authorization, 'Content-Type': 'application/json'})
            try:
                response = urllib.request.urlopen(request, timeout=180)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                result = json.load(response, parse_float=Decimal)
            if result.get('error'):
                raise RPCError(result['error'])
            return result['result']
        return call


class ElementsAdapter:
    def __init__(self, config):
        messages.THRESHOLD_AUDIT = True
        self.config = config
        self.node, self.sponsor = RPC(config['rpc_url']), RPC(config['sponsor_rpc_url'])
        self.wallets = {account: RPC(url) for account, url in config['wallets'].items()}
        self.curve = Curve(config['library'])
        self.institutions = InstitutionClient(config['institutions'])
        # Signs a member bank's statement that a destination is a registered
        # customer address. Installed by whoever holds that bank's key.
        self.registrar = None
        self.lock = threading.RLock()
        self.db = sqlite3.connect(config['database'], check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS prepared(case_id TEXT,stage TEXT,packet TEXT,signed TEXT,PRIMARY KEY(case_id,stage))')

    def network(self):
        info = self.node.getblockchaininfo()
        audit = AuditConfig.from_bytes(bytes.fromhex(info['audit_config']), self.curve).active_key.committee
        return {'connected': True, 'chain': info['chain'], 'genesis_hash': self.node.getblockhash(0),
                'height': info['blocks'], 'audit_pubkey': info.get('audit_pubkey'),
                'audit_version': info.get('audit_version'), 'registry_version': info.get('audit_assets_version', 0),
                'audit_assets': info.get('audit_assets', []), 'audit_threshold': audit.threshold, 'audit_guardians': len(audit.members),
                'institution_threshold': self.config['threshold'], 'institution_count': len(self.config['guardian_order']),
                'operational_policy_version': self.config.get('policy_version', 'sandbox-v1'),
                'sandbox': True, 'bank_mode': 'simulated'}

    def configure_federation(self, policy, institutions, *, rotation_records=None, escrow_migrations=None):
        """Install only public current policy after orchestrator confirms handover."""
        from .policy import public_policy, validate_policy, validate_successor
        validate_policy(policy)
        with self.lock:
            previous = public_policy(self.config)
            if previous['policy_version'] == policy['policy_version']:
                if previous != public_policy(policy):
                    raise ValueError('current federation policy cannot be rebound')
            else:
                validate_successor(previous, policy)
            if set(institutions) != set(policy['guardian_order']):
                raise ValueError('operator services do not match incoming membership')
            history = dict(self.config.get('historical_approval_policies', {}))
            if previous['policy_version'] != policy['policy_version']:
                historic = {'public_keys': previous['approval_public_keys'], 'threshold': previous['threshold'],
                            'treasury_script': previous['treasury_script'], 'witness_script': previous['witness_script']}
                existing = history.get(previous['policy_version'])
                if existing and any(key in existing and existing[key] != value for key, value in historic.items()):
                    raise ValueError('historic federation policy cannot be replaced')
                history[previous['policy_version']] = dict(existing or {}, **historic)
            if rotation_records is not None:
                old = {record['packet']['migration_id']: record for record in self.config.get('rotation_records', [])}
                incoming = {record['packet']['migration_id']: record for record in rotation_records}
                if len(incoming) != len(rotation_records) or any(identity not in incoming or incoming[identity] != record for identity, record in old.items()):
                    raise ValueError('confirmed migration history is append-only')
            self.config.update(policy)
            self.config['historical_approval_policies'] = history
            self.config['institutions'] = institutions
            self.institutions = InstitutionClient(institutions)
            if rotation_records is not None:
                self.config['rotation_records'] = rotation_records
            if escrow_migrations is not None:
                self.config['escrow_migrations'] = escrow_migrations

    def authorize(self, rawtx):
        """Attach the federation authorization the chain requires, if it requires one.

        The authorization is not part of the transaction ID, so an expired one
        is simply replaced. Authorizers are found by the keys the chain names,
        which during a handover are the incoming institutions'.
        """
        info = self.node.getblockchaininfo()
        policy = bytes.fromhex(info.get('tx_authorization') or '')
        if not policy:
            return rawtx
        transaction = tx_from_hex(rawtx)
        transaction.wit.vchAuthorization = b''
        threshold, keys = decode_policy(policy)
        genesis, expiry = self.node.getblockhash(0), info['blocks'] + WINDOW
        digest = authorization_digest(genesis, policy, transaction, expiry)
        registrations = {}
        if self.registrar is not None:
            for output in transaction.vout:
                script = bytes(output.scriptPubKey)
                if needs_registration(script) and script.hex() not in registrations:
                    # The bank vouches only for addresses it knows; others go
                    # without, and the institutions decide.
                    registration = self.registrar(script)
                    if registration is not None:
                        registrations[script.hex()] = registration.hex()
        services = self.authorizer_services()
        signatures, refusals, unreachable = {}, {}, 0
        unsigned = transaction.serialize().hex()
        for index, key in enumerate(keys):
            if key.hex() not in services:
                unreachable += 1
                continue
            guardian, service = services[key.hex()]
            try:
                result = InstitutionClient({guardian: service}).request(guardian, 'authorize_transaction', rawtx=unsigned,
                                                                         expiry_height=expiry, registrations=registrations)
                signature = bytes.fromhex(result['signature'])
            except InstitutionRefused as error:
                refusals[guardian] = str(error)
                continue
            except (OSError, ValueError, KeyError):
                unreachable += 1
                continue
            if self.curve.verify_signature(key, digest, signature):
                signatures[index] = signature
            else:
                refusals[guardian] = 'returned an invalid authorization'
            if len(signatures) == threshold:
                break
        if len(signatures) != threshold:
            if len(refusals) > len(keys) - threshold:
                reasons = list(refusals.values())
                reason = max(set(reasons), key=reasons.count)
                raise AuthorizationRefused(f'{len(refusals)} of {len(keys)} operators refused to authorize this '
                                           f'transaction: {reason}')
            raise AuthorizationUnavailable(f'Waiting for the operators to authorize this transaction: '
                                           f'{len(keys) - unreachable} of {len(keys)} reachable, {threshold} needed')
        transaction.wit.vchAuthorization = encode(expiry, signatures)
        return transaction.serialize().hex()

    def authorizer_services(self):
        """Institution services by authorization key, across current and incoming groups."""
        services = {}
        for manifest in [*self.config.get('federation_manifests', []), self.config]:
            for guardian, key in manifest.get('approval_public_keys', {}).items():
                if guardian in manifest.get('institutions', {}):
                    services[key] = (guardian, manifest['institutions'][guardian])
        return services

    def abandon(self, operation, stage):
        """Forget a never-signed transaction and give its coins back to the wallet."""
        with self.lock:
            row = self.db.execute('SELECT packet,signed FROM prepared WHERE case_id=? AND stage=?',
                                  (operation['id'], stage)).fetchone()
            if row is None:
                return
            if row[1] is not None:
                raise ValueError('a signed transaction cannot be abandoned')
            packet = json.loads(row[0])
            wallet = self.sponsor if packet['stage'] in ('issue', 'burn', 'refund', 'migration') else self.wallets[operation['account_id']]
            locked = {(coin['txid'], coin['vout']) for coin in wallet.listlockunspent()}
            inputs = [{'txid': f'{inp.prevout.hash:064x}', 'vout': inp.prevout.n} for inp in tx_from_hex(packet['rawtx']).vin
                      if (f'{inp.prevout.hash:064x}', inp.prevout.n) in locked]
            if inputs:
                wallet.lockunspent(True, inputs)
            self.db.execute('DELETE FROM prepared WHERE case_id=? AND stage=?', (operation['id'], stage))

    def wallet_send(self, wallet, amounts, asset=None):
        """Pay from a node wallet with the authorization a plain wallet send would lack."""
        outputs = [{address: amount, **({'asset': asset} if asset else {})} for address, amount in amounts.items()]
        funded = wallet.walletcreatefundedpsbt([], outputs, 0, {'fee_rate': 2})['psbt']
        final = wallet.finalizepsbt(wallet.walletprocesspsbt(funded)['psbt'])
        if not final.get('complete'):
            raise ValueError('wallet could not complete this payment')
        return self.node.sendrawtransaction(self.authorize(final['hex']), 0)

    def escrow_locator(self, operation):
        locator = self.config.get('escrow_migrations', {}).get(operation['escrow_txid']) or operation.get('current_escrow')
        if locator:
            return {'txid': locator['txid'], 'vout': locator['vout']}
        return None

    def assets(self):
        network = self.network()
        return [dict(value, currency=currency, registered=value['asset_id'] in network['audit_assets'],
                     registry_version=network['registry_version'], label='Test' + currency,
                     issuer='Sandbox issuer — legal obligor undecided', simulated=True)
                for currency, value in self.config['assets'].items()]

    def balance(self, account_id, asset_id):
        balances = self.wallets[account_id].getbalances()['mine']['trusted']
        value = balances.get(asset_id, Decimal(0))
        cents = Decimal(str(value)) * 100
        if cents != cents.to_integral_value():
            raise ValueError('on-chain wallet has sub-cent currency units; reconcile before settlement')
        return int(cents)

    def balances(self, account_id):
        return {currency: self.balance(account_id, asset['asset_id']) for currency, asset in self.config['assets'].items()}

    def address(self, account_id):
        return self.config['addresses'][account_id]

    def _opening(self, transaction, index):
        output = transaction.vout[index]
        if output.nAsset.vchCommitment[0] == output.nValue.vchCommitment[0] == 1:
            return {'asset': output.nAsset.vchCommitment[1:][::-1].hex(), 'amount': output.nValue.getAmount(),
                    'asset_blinder': '00' * 32, 'value_blinder': '00' * 32}
        network = self.network()
        openings = wallet_openings(self.curve, transaction, [self.sponsor, *self.wallets.values()],
                                   bytes.fromhex(network['genesis_hash'])[::-1], bytes.fromhex(network['audit_pubkey']),
                                   tuple(bytes.fromhex(asset)[::-1] for asset in network['audit_assets']))
        opening = openings[index]
        return {'asset': opening.asset[::-1].hex(), 'amount': opening.amount,
                'asset_blinder': f'{opening.asset_blinder:064x}', 'value_blinder': f'{opening.value_blinder:064x}'}

    def _all_openings(self, transaction):
        network = self.network()
        openings = wallet_openings(self.curve, transaction, [self.sponsor, *self.wallets.values()],
                                   bytes.fromhex(network['genesis_hash'])[::-1], bytes.fromhex(network['audit_pubkey']),
                                   tuple(bytes.fromhex(asset)[::-1] for asset in network['audit_assets']))
        return {str(index): {'asset': opening.asset[::-1].hex(), 'amount': opening.amount,
                            'asset_blinder': f'{opening.asset_blinder:064x}', 'value_blinder': f'{opening.value_blinder:064x}'}
                for index, opening in openings.items()}

    def _build(self, operation, stage):
        asset = self.config['assets'][operation['currency']]
        amount = Decimal(operation['amount_minor']) / 100
        if stage in ('issue', 'burn', 'refund'):
            if stage == 'issue':
                candidates = [coin for coin in self.sponsor.listunspent(1) if coin['asset'] == asset['token_id']]
                if len(candidates) != 1:
                    raise ValueError(f'currency must have exactly one confirmed federation authority output (found {len(candidates)})')
                coin = candidates[0]
                raw = self.sponsor.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                    [{self.config['treasury_address']: coin['amount'], 'asset': asset['token_id']}])
            else:
                locator = self.escrow_locator(operation)
                escrow_txid = locator['txid'] if locator else operation['escrow_txid']
                previous = tx_from_hex(self.node.getrawtransaction(escrow_txid))
                candidates = [(index, self._opening(previous, index)) for index, output in enumerate(previous.vout)
                              if bytes(output.scriptPubKey).hex() == self.config['treasury_script']
                              and (locator is None or index == locator['vout'])]
                candidates = [(index, opening) for index, opening in candidates
                              if opening['asset'] == asset['asset_id'] and opening['amount'] == operation['amount_minor'] * 1_000_000]
                if len(candidates) != 1:
                    raise ValueError('redemption escrow output is missing or ambiguous')
                index, _ = candidates[0]
                coin = {'txid': escrow_txid, 'vout': index}
                destination = operation['destination'] if stage == 'refund' else self.config['treasury_address']
                raw = self.sponsor.createrawtransaction([coin], [{destination: amount, 'asset': asset['asset_id']}])
                if stage == 'burn':
                    transaction = tx_from_hex(raw)
                    transaction.vout[0].scriptPubKey = bytes.fromhex('6a')
                    transaction.vout[0].nNonce.setNull()
                    raw = transaction.serialize().hex()
            funded = self.sponsor.fundrawtransaction(raw, {'fee_rate': 2, 'includeWatching': True,
                'changeAddress': self.sponsor.getrawchangeaddress('blech32'), 'lockUnspents': False})['hex']
            transaction = tx_from_hex(funded)
            input_index = next(index for index, inp in enumerate(transaction.vin)
                               if f'{inp.prevout.hash:064x}' == coin['txid'] and inp.prevout.n == coin['vout'])
            previous = tx_from_hex(self.node.getrawtransaction(coin['txid']))
            opening = self._opening(previous, coin['vout'])
            if stage == 'issue':
                funded = self.sponsor.rawreissueasset(funded, [{'asset_amount': amount, 'asset_address': operation['destination'],
                    'input_index': input_index, 'asset_blinder': bytes.fromhex(opening['asset_blinder'])[::-1].hex(), 'entropy': asset['entropy']}])['hex']
            blinded = self.sponsor.blindrawtransaction(funded, False, [], False)
            partial = self.sponsor.signrawtransactionwithwallet(blinded)
            transaction = tx_from_hex(partial['hex'])
            return {'stage': stage, 'rawtx': partial['hex'], 'input_index': input_index,
                    'input_opening': opening, 'openings': self._all_openings(transaction)}
        wallet = self.wallets[operation['account_id']]
        destination = self.config['treasury_address'] if stage == 'escrow' else operation['destination']
        raw = wallet.createrawtransaction([], [{destination: amount, 'asset': asset['asset_id']}])
        change = {'bitcoin': wallet.getrawchangeaddress('blech32'),
                  asset['asset_id']: wallet.getrawchangeaddress('blech32')}
        funded = wallet.fundrawtransaction(raw, {'fee_rate': 2, 'changeAddress': change,
                                                 'lockUnspents': False})['hex']
        blinded = wallet.blindrawtransaction(funded, False)
        signed = wallet.signrawtransactionwithwallet(blinded)
        if not signed['complete']:
            raise ValueError('bank-managed customer wallet could not sign this transfer')
        return {'stage': stage, 'rawtx': signed['hex']}

    def bind_authorization(self, operation, stage):
        if stage != 'issue':
            raise ValueError('only issuance uses preapproval transaction binding')
        with self.lock:
            row = self.db.execute('SELECT packet FROM prepared WHERE case_id=? AND stage=?', (operation['id'], stage)).fetchone()
            if row:
                packet = json.loads(row[0])
            else:
                packet = self._build(operation, stage)
                self.db.execute('INSERT INTO prepared VALUES(?,?,?,NULL)',
                                (operation['id'], stage, json.dumps(packet, sort_keys=True)))
            self._reserve(operation, packet)
            return template_hash(tx_from_hex(packet['rawtx']))

    def _reserve(self, operation, packet):
        wallet = self.sponsor if packet['stage'] in ('issue', 'burn', 'refund', 'migration') else self.wallets[operation['account_id']]
        transaction = tx_from_hex(packet['rawtx'])
        locked = {(coin['txid'], coin['vout']) for coin in wallet.listlockunspent()}
        inputs = [{'txid': f'{inp.prevout.hash:064x}', 'vout': inp.prevout.n} for inp in transaction.vin
                  if (f'{inp.prevout.hash:064x}', inp.prevout.n) not in locked
                  and self.node.gettxout(f'{inp.prevout.hash:064x}', inp.prevout.n, True) is not None]
        if inputs:
            wallet.lockunspent(False, inputs)

    def prepare(self, operation, stage, certificate):
        with self.lock:
            row = self.db.execute('SELECT packet,signed FROM prepared WHERE case_id=? AND stage=?', (operation['id'], stage)).fetchone()
            if row:
                packet, signed = json.loads(row[0]), row[1]
            else:
                packet, signed = self._build(operation, stage), None
                # Crash after this point retries these exact commitments and
                # inputs, preserving each institution's receipt binding.
                self.db.execute('INSERT INTO prepared VALUES(?,?,?,NULL)',
                                (operation['id'], stage, json.dumps(packet, sort_keys=True)))
            if signed is None:
                self._reserve(operation, packet)
        if signed is None:
            # Co-signing calls each institution over the network. The packet
            # and its coins are already fixed above, so other preparations
            # need not wait for it.
            signed = self._cosign(operation, stage, certificate, packet) if stage in ('issue', 'burn', 'refund') else packet['rawtx']
            signed = self.authorize(signed)
            accepted = self.node.testmempoolaccept([signed], 0)[0]
            if not accepted['allowed']:
                raise ValueError('Elements rejected prepared transaction: ' + accepted.get('reject-reason', str(accepted)))
            with self.lock:
                # The first signed copy wins if the same case was ever signed twice.
                self.db.execute('UPDATE prepared SET signed=? WHERE case_id=? AND stage=? AND signed IS NULL',
                                (signed, operation['id'], stage))
                signed = self.db.execute('SELECT signed FROM prepared WHERE case_id=? AND stage=?',
                                         (operation['id'], stage)).fetchone()[0]
        transaction = tx_from_hex(signed)
        transaction.rehash()
        return {'rawtx': signed, 'txid': transaction.hash, 'stage': stage}

    def _cosign(self, operation, stage, certificate, packet):
        config = self.config
        signatures = {}
        transaction = tx_from_hex(packet['rawtx'])
        witness_script = CScript(bytes.fromhex(config['witness_script']))
        public_keys = dict(zip(config['guardian_order'], list(witness_script)[1:-2]))
        previous_input = transaction.vin[packet['input_index']].prevout
        previous = tx_from_hex(self.node.getrawtransaction(f'{previous_input.hash:064x}')).vout[previous_input.n]
        sighash = SegwitV0SignatureHash(witness_script, transaction, packet['input_index'], SIGHASH_ALL, previous.nValue)
        ecdsa = NativeECDSA(self.curve)
        signer_ids = ([entry['guardian_id'] for entry in certificate['signatures']]
                      if operation['policy_version'] == config.get('policy_version', 'sandbox-v1')
                      else config['guardian_order'])
        for guardian in signer_ids:
            try:
                result = self.institutions.sign_transaction(guardian, operation=operation, certificate=certificate,
                    payout_receipt=operation.get('payout_receipt'), cancellation_receipt=operation.get('cancellation_receipt'),
                    rotation_records=config.get('rotation_records', []), **packet)
                signature = bytes.fromhex(result['signature'])
                if result['guardian_id'] != guardian or not ecdsa.verify(public_keys[guardian], sighash, signature):
                    continue
                signatures[guardian] = signature
            except (OSError, ValueError, KeyError):
                continue
            if len(signatures) >= config['threshold']:
                break
        order = config['guardian_order']
        signatures = [signatures[guardian] for guardian in order if guardian in signatures][:config['threshold']]
        if len(signatures) != config['threshold']:
            raise ValueError('federation transaction signing quorum unavailable')
        transaction = tx_from_hex(packet['rawtx'])
        while len(transaction.wit.vtxinwit) < len(transaction.vin):
            transaction.wit.vtxinwit.append(messages.CTxInWitness())
        transaction.wit.vtxinwit[packet['input_index']].scriptWitness.stack = [b'', *signatures, bytes.fromhex(config['witness_script'])]
        return transaction.serialize().hex()

    def broadcast(self, prepared):
        burn_limit = Decimal(0)
        if prepared['stage'] == 'burn':
            transaction = tx_from_hex(prepared['rawtx'])
            burn_limit = Decimal(sum(output.nValue.getAmount() for output in transaction.vout
                                     if bytes(output.scriptPubKey) == b'\x6a')) / 100_000_000
        try:
            # A retry may come long after preparation; authorize afresh.
            txid = self.node.sendrawtransaction(self.authorize(prepared['rawtx']), 0, burn_limit)
        except RPCError as original:
            # Lost response or already-mined transaction: inspect the exact ID,
            # never create a replacement issuance from the same cash receipt.
            try:
                self.node.getrawtransaction(prepared['txid'], True)
            except RPCError:
                raise original
            txid = prepared['txid']
        if txid != prepared['txid']:
            raise RuntimeError('Elements returned an unexpected transaction id')
        return txid

    def inspect(self, prepared):
        try:
            transaction = self.node.getrawtransaction(prepared['txid'], True)
            return {'confirmations': int(transaction.get('confirmations', 0)), 'conflicted': False}
        except RPCError as error:
            if error.error['code'] == -5:
                return {'confirmations': 0, 'conflicted': False, 'missing': True}
            raise
