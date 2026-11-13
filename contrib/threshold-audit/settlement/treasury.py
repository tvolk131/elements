"""Isolated institution approval and Elements signing service, for local tests.

Each process owns one ECDSA spending key and a distinct BIP340 approval key.
The coordinator receives signatures, never those private keys. This local
same-user process boundary is a sandbox, not an HSM or production deployment.
"""

import ctypes as C
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import urllib.request
from urllib.parse import urlsplit

from .approval import ApprovalVerifier, approval_digest, canonical, sign_approval
from curve import Curve
from test_framework import messages
from test_framework.messages import CBlock, from_hex, ser_uint256, tx_from_hex
from test_framework.script import CScript, SegwitV0SignatureHash, SIGHASH_ALL


def template_hash(transaction):
    unsigned = messages.CTransaction(transaction)
    unsigned.wit = messages.CTxWitness()
    for inp in unsigned.vin:
        inp.scriptSig = b''
    return hashlib.sha256(unsigned.serialize_without_witness()).hexdigest()


class NativeECDSA:
    def __init__(self, curve):
        self.curve = curve
        self.sign = curve.lib.secp256k1_ecdsa_sign
        self.sign.argtypes = [C.c_void_p] * 6
        self.sign.restype = C.c_int
        self.serialize = curve.lib.secp256k1_ecdsa_signature_serialize_der
        self.serialize.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
        self.serialize.restype = C.c_int
        self.parse_signature = curve.lib.secp256k1_ecdsa_signature_parse_der
        self.parse_signature.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t]
        self.parse_signature.restype = C.c_int
        self.verify_signature = curve.lib.secp256k1_ecdsa_verify
        self.verify_signature.argtypes = [C.c_void_p] * 4
        self.verify_signature.restype = C.c_int

    def signature(self, secret, digest):
        native, der, length = C.create_string_buffer(64), C.create_string_buffer(72), C.c_size_t(72)
        if not self.sign(self.curve.ctx, native, digest, bytes.fromhex(secret), None, None):
            raise ValueError('ECDSA signing failed')
        if not self.serialize(self.curve.ctx, der, C.byref(length), native):
            raise ValueError('ECDSA serialization failed')
        return der.raw[:length.value] + bytes([SIGHASH_ALL])

    def verify(self, public_key, digest, signature):
        if not signature or signature[-1] != SIGHASH_ALL:
            return False
        native = C.create_string_buffer(64)
        return bool(self.parse_signature(self.curve.ctx, native, signature[:-1], len(signature) - 1)
                    and self.verify_signature(self.curve.ctx, native, digest, self.curve.parse(public_key, allow_infinity=False)))


def public_outputs(curve, transaction, openings):
    """Verify supplied openings against actual commitments before policy checks."""
    result = []
    for index, output in enumerate(transaction.vout):
        if output.nAsset.vchCommitment[0] == output.nValue.vchCommitment[0] == 1:
            asset = output.nAsset.vchCommitment[1:][::-1].hex()
            amount = output.nValue.getAmount()
        else:
            opening = openings[str(index)]
            asset, amount = opening['asset'], opening['amount']
            abf, vbf = int(opening['asset_blinder'], 16), int(opening['value_blinder'], 16)
            raw_asset = bytes.fromhex(asset)[::-1]
            generator = curve.asset_commitment(raw_asset, abf)
            if (generator != output.nAsset.vchCommitment
                    or curve.value_commitment(generator, amount, vbf) != output.nValue.vchCommitment):
                raise ValueError('output opening does not match transaction')
        result.append({'asset': asset, 'amount': amount, 'script': bytes(output.scriptPubKey).hex()})
    return result


class Institution:
    def __init__(self, config, rpc):
        messages.THRESHOLD_AUDIT = True
        self.config, self.rpc = config, rpc
        self.curve = Curve(config['library'])
        self.ecdsa = NativeECDSA(self.curve)
        self.verifier = ApprovalVerifier(self.curve, config['approval_public_keys'], config['threshold'],
                                         config.get('policy_version', 'sandbox-v1'))
        self.historical_verifiers = {version: ApprovalVerifier(self.curve,
            policy.get('public_keys', policy.get('approval_public_keys')), policy['threshold'], version)
            for version, policy in config.get('historical_approval_policies', {}).items()}
        self.lock = threading.Lock()
        self.db = sqlite3.connect(config['database'], check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS signed(binding TEXT PRIMARY KEY, digest TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS approvals(case_id TEXT PRIMARY KEY, digest TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS rotation_approvals(case_id TEXT PRIMARY KEY,digest TEXT NOT NULL,target_block_script TEXT)')
        if 'proposal_hash' not in {row[1] for row in self.db.execute('PRAGMA table_info(rotation_approvals)')}:
            self.db.execute('ALTER TABLE rotation_approvals ADD COLUMN proposal_hash TEXT')
        if 'expires_at' not in {row[1] for row in self.db.execute('PRAGMA table_info(rotation_approvals)')}:
            self.db.execute('ALTER TABLE rotation_approvals ADD COLUMN expires_at INTEGER')
        self.db.execute('CREATE TABLE IF NOT EXISTS signed_blocks(height INTEGER PRIMARY KEY,header_hash TEXT NOT NULL)')

    def approve(self, operation):
        if operation.get('kind') == 'federation_rotation':
            return self.approve_rotation(operation)
        # The authenticated guardian UI supplies the human decision. The web
        # server maps its guardian principal to this one institution endpoint.
        import time
        if operation['policy_version'] != self.verifier.policy_version or operation['expires_at'] <= int(time.time()):
            raise ValueError('unknown or expired institutional policy')
        if operation['genesis_hash'] != self.config['genesis_hash']:
            raise ValueError('wrong chain')
        if operation['kind'] == 'deposit':
            if not isinstance(operation.get('cash_receipt_id'), str) or not operation['cash_receipt_id']:
                raise ValueError('credited bank receipt is required for issuance')
            binding = operation.get('transaction_template_hash')
            if not isinstance(binding, str) or len(binding) != 64 or len(bytes.fromhex(binding)) != 32:
                raise ValueError('issuance must bind exact transaction before guardian approval')
            from .bank import verify_credit_receipt
            if not verify_credit_receipt(self.curve, self.config['bank_public_key'], operation, operation.get('credit_receipt')):
                raise ValueError('bank credit evidence must seal this exact issuance template')
        digest = approval_digest(operation).hex()
        with self.lock, self.db:
            previous = self.db.execute('SELECT digest FROM approvals WHERE case_id=?', (operation['id'],)).fetchone()
            if previous and previous[0] != digest:
                raise ValueError('case already approved with different terms')
            self.db.execute('INSERT OR IGNORE INTO approvals VALUES(?,?)', (operation['id'], digest))
        return sign_approval(self.curve, self.config['guardian_id'], int(self.config['approval_secret'], 16), operation)

    def approve_rotation(self, operation):
        from .rotation_approval import rotation_digest, sign_rotation
        from .treasury_rotation import public_policy, validate_policy
        import time
        if (operation['genesis_hash'] != self.config['genesis_hash'] or operation['expires_at'] <= int(time.time())
                or operation['source_policy_version'] != self.verifier.policy_version):
            raise ValueError('rotation has unknown source policy, chain or expiry')
        source = validate_policy(operation['manifest']['source_policy'])
        target = validate_policy(operation['manifest']['target_policy'])
        proposal_hash = operation['manifest'].get('proposal_hash')
        if target.get('block_signing_script') and (not isinstance(proposal_hash, str) or len(proposal_hash) != 64
                or any(character not in '0123456789abcdef' for character in proposal_hash)):
            raise ValueError('rotation must bind the exact DynaFed proposal')
        if any(source[key] != public_policy(self.config)[key] for key in
               ('policy_version', 'approval_public_keys', 'threshold', 'guardian_order', 'treasury_script', 'witness_script')):
            raise ValueError('rotation does not replace this institution policy')
        digest = rotation_digest(operation).hex()
        with self.lock, self.db:
            prior = self.db.execute('SELECT digest FROM rotation_approvals WHERE case_id=?', (operation['id'],)).fetchone()
            if prior and prior[0] != digest:
                raise ValueError('rotation already approved with different terms')
            self.db.execute('INSERT OR IGNORE INTO rotation_approvals '
                            '(case_id,digest,target_block_script,proposal_hash,expires_at) VALUES(?,?,?,?,?)',
                            (operation['id'], digest, target.get('block_signing_script'), proposal_hash, operation['expires_at']))
            # Legacy approval rows did not retain expiry. They fail closed for
            # proposals until an operator independently re-approves the same
            # still-valid signed operation, whose digest includes expires_at.
            self.db.execute('UPDATE rotation_approvals SET expires_at=? '
                            'WHERE case_id=? AND digest=? AND expires_at IS NULL',
                            (operation['expires_at'], operation['id'], digest))
        return sign_rotation(self.curve, self.config['guardian_id'], int(self.config['approval_secret'], 16), operation)

    def sign_migration(self, request):
        from .treasury_rotation import rotation_verifier, validate_packet
        rotation, packet = request['rotation'], request['packet']
        committed = self._rotation_committed(rotation)
        rotation_verifier(self.curve, self.config, rotation).verify_certificate(
            rotation, request['certificate'], allow_expired=committed)
        if not committed:
            raise ValueError('native rotation policy has not committed on the active chain')
        transaction, previous = validate_packet(self.curve, self.rpc, self.config, rotation, packet)
        digest = template_hash(transaction)
        self._bind_signature('migration:' + packet['migration_id'], digest)
        sighash = SegwitV0SignatureHash(CScript(bytes.fromhex(self.config['witness_script'])), transaction,
                                      packet['input_index'], SIGHASH_ALL, previous.nValue)
        return {'guardian_id': self.config['guardian_id'], 'signature': self.ecdsa.signature(self.config['spending_secret'], sighash).hex(),
                'template_hash': digest}

    def _rotation_committed(self, rotation):
        """Funds move only after this exact native policy activated.

        This is completion of an already committed handover, not authorization
        to begin an expired rotation. Each source signer independently checks
        its own native node's genesis, current audit configuration and the
        actual activation block on the active chain before bypassing expiry.
        """
        from governance import AuditConfig
        try:
            manifest = rotation['manifest']
            height = manifest['activation_height']
            if type(height) is not int or height < 1:
                return False
            if (rotation['genesis_hash'] != self.config['genesis_hash']
                    or self.rpc.getblockhash(0) != self.config['genesis_hash']):
                return False
            info = self.rpc.getblockchaininfo()
            if info['blocks'] < height:
                return False
            audit = AuditConfig.from_bytes(bytes.fromhex(info['audit_config']), self.curve)
            if audit.binding().hex() != manifest['audit_config_hash']:
                return False
            activation = self.rpc.getblock(self.rpc.getblockhash(height))
            return (activation['dynamic_parameters']['current']['signblockscript']
                    == manifest['target_policy']['block_signing_script']
                    and self.rpc.getbestblockhash() == info['bestblockhash'])
        except (ValueError, KeyError, TypeError, OSError, RuntimeError):
            return False

    def sign_block(self, request):
        if not self.config.get('block_secret'):
            raise ValueError('institution has no block-signing identity')
        block = from_hex(CBlock(), request['rawblock'])
        if block.m_dynafed_params.m_current.m_signblockscript.hex() != self.config['block_signing_script']:
            raise ValueError('block is assigned to another federation signing policy')
        best = self.rpc.getbestblockhash()
        height = self.rpc.getblockcount() + 1
        if f'{block.hashPrevBlock:064x}' != best or block.block_height != height:
            raise ValueError('block does not extend current chain tip')
        proposal = block.m_dynafed_params.m_proposed
        if proposal.m_serialize_type:
            import time
            proposal_hash = hashlib.sha256(proposal.serialize()).hexdigest()
            with self.lock:
                allowed = {row[0] for row in self.db.execute('SELECT proposal_hash FROM rotation_approvals WHERE expires_at>?',
                                                            (int(time.time()),)) if row[0]}
            if proposal_hash not in allowed:
                raise ValueError('exact DynaFed proposal lacks unexpired independent institution approval')
        # Native validation independently checks candidate transactions, policy,
        # registry and TAP1 readiness while omitting only the block signatures.
        # Consensus validation is mandatory. The optional relay-policy filter
        # in this RPC rejects all OP_RETURNs with its null datacarrier setting,
        # including the intentional redemption burns admitted by this chain.
        self.rpc.testproposedblock(request['rawblock'], True)
        block.rehash()
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                prior = self.db.execute('SELECT header_hash FROM signed_blocks WHERE height=?', (height,)).fetchone()
                if prior and prior[0] != block.hash:
                    raise ValueError('refusing conflicting block signature at an already signed height')
                self.db.execute('INSERT OR IGNORE INTO signed_blocks VALUES(?,?)', (height, block.hash))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
        return {'guardian_id': self.config['guardian_id'], 'header_hash': block.hash,
                'signature': self.ecdsa.signature(self.config['block_secret'], ser_uint256(block.sha256)).hex()}

    def _bind_signature(self, binding, digest):
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                prior = self.db.execute('SELECT digest FROM signed WHERE binding=?', (binding,)).fetchone()
                if prior and prior[0] != digest:
                    raise ValueError('receipt/case already bound to a different transaction')
                self.db.execute('INSERT OR IGNORE INTO signed VALUES(?,?)', (binding, digest))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def sign_transaction(self, request):
        operation, certificate = request['operation'], request['certificate']
        verifier = self.verifier if operation['policy_version'] == self.verifier.policy_version else self.historical_verifiers.get(operation['policy_version'])
        if verifier is None:
            raise ValueError('economic operation approval policy is not trusted')
        verifier.verify_certificate(operation, certificate, allow_expired=request['stage'] == 'burn')
        if operation['genesis_hash'] != self.config['genesis_hash']:
            raise ValueError('wrong chain')
        stage = request['stage']
        if stage == 'issue' and operation['policy_version'] != self.verifier.policy_version:
            raise ValueError('retired institutions cannot authorize new issuance')
        if (stage == 'issue' and operation['kind'] != 'deposit') or (stage == 'burn' and operation['kind'] != 'redemption') or (stage == 'refund' and operation['kind'] != 'refund'):
            raise ValueError('wrong transaction stage')
        if stage not in ('issue', 'burn', 'refund'):
            raise ValueError('institution can sign only issuance or escrow burn')
        transaction = tx_from_hex(request['rawtx'])
        outputs = public_outputs(self.curve, transaction, request['openings'])
        asset = self.config['assets'][operation['currency']]
        if asset['asset_id'] != operation['asset_id']:
            raise ValueError('wrong currency asset')
        # One fiat minor unit maps to 1,000,000 Elements base units (0.01).
        amount = operation['amount_minor'] * 1_000_000
        index = request['input_index']
        txin = transaction.vin[index]
        previous = self.rpc.getrawtransaction(f'{txin.prevout.hash:064x}', True)['vout'][txin.prevout.n]
        if previous['scriptPubKey']['hex'] != self.config['treasury_script']:
            raise ValueError('input is not controlled by this federation')
        input_asset, input_amount = request['input_opening']['asset'], request['input_opening']['amount']
        prevtx = tx_from_hex(self.rpc.getrawtransaction(f'{txin.prevout.hash:064x}'))
        previous_output = prevtx.vout[txin.prevout.n]
        verified_input = public_outputs(self.curve, type('OneOutput', (), {'vout': [previous_output]})(), {'0': request['input_opening']})[0]
        if verified_input['asset'] != input_asset or verified_input['amount'] != input_amount:
            raise ValueError('input opening does not match previous output')
        if stage == 'issue':
            from .bank import verify_credit_receipt
            if not verify_credit_receipt(self.curve, self.config['bank_public_key'], operation, operation.get('credit_receipt')):
                raise ValueError('sealed bank credit evidence is required')
            if operation.get('transaction_template_hash') != template_hash(transaction):
                raise ValueError('issuance transaction differs from approved template')
            if input_asset != asset['token_id']:
                raise ValueError('issuance does not spend this currency authority')
            issuance = txin.assetIssuance
            if (issuance.nAmount.getAmount() != amount or not issuance.nInflationKeys.isNull()
                    or f'{issuance.assetEntropy:064x}' != asset['entropy']
                    or f'{issuance.assetBlindingNonce:064x}' != bytes.fromhex(request['input_opening']['asset_blinder'])[::-1].hex()):
                raise ValueError('issuance does not match authorized amount/entropy')
            minted = [out for out in outputs if out['asset'] == asset['asset_id']]
            destination = self.rpc.validateaddress(operation['destination'])['scriptPubKey']
            if sum(out['amount'] for out in minted) != amount or any(out['script'] != destination for out in minted):
                raise ValueError('minted output does not match authorized beneficiary')
            returned = [out for out in outputs if out['asset'] == asset['token_id']]
            if sum(out['amount'] for out in returned) != input_amount or any(out['script'] != self.config['treasury_script'] for out in returned):
                raise ValueError('reissuance authority must return entirely to federation')
        elif stage == 'burn':
            if input_asset != asset['asset_id'] or input_amount != amount or not txin.assetIssuance.isNull():
                raise ValueError('burn input does not match redemption')
            # The payout simulator signs a receipt after threshold-authorized
            # payment. Verify that receipt independently before escrow burn.
            from .bank import verify_payout_receipt
            from .treasury_rotation import current_escrow
            current_escrow(self.config, self.rpc, self.curve, operation,
                          {'txid': f'{txin.prevout.hash:064x}', 'vout': txin.prevout.n}, request.get('rotation_records', []))
            if not verify_payout_receipt(self.curve, self.config['bank_public_key'], operation, request['payout_receipt']):
                raise ValueError('verified payout evidence for this escrow is required')
            burned = [out for out in outputs if out['asset'] == asset['asset_id']]
            if sum(out['amount'] for out in burned) != amount or any(out['script'] != '6a' for out in burned):
                raise ValueError('redemption must burn the entire authorized escrow')
        else:
            from .bank import verify_cancellation_receipt
            from .treasury_rotation import current_escrow
            current_escrow(self.config, self.rpc, self.curve, operation,
                          {'txid': f'{txin.prevout.hash:064x}', 'vout': txin.prevout.n}, request.get('rotation_records', []))
            if (input_asset != asset['asset_id'] or input_amount != amount
                    or not txin.assetIssuance.isNull()
                    or not verify_cancellation_receipt(self.curve, self.config['bank_public_key'], operation, request['cancellation_receipt'])):
                raise ValueError('definite cancellation evidence for this escrow is required')
            destination = self.rpc.validateaddress(operation['destination'])['scriptPubKey']
            returned = [out for out in outputs if out['asset'] == asset['asset_id']]
            if sum(out['amount'] for out in returned) != amount or any(out['script'] != destination for out in returned):
                raise ValueError('cancelled redemption must return entirely to original customer')
        if any(not inp.assetIssuance.isNull() for i, inp in enumerate(transaction.vin) if i != index):
            raise ValueError('unrelated issuance input')
        allowed_assets = {asset['asset_id'], asset['token_id'], self.config['policy_asset']}
        if any(out['asset'] not in allowed_assets for out in outputs):
            raise ValueError('unrelated output asset')
        fees = [out for out in outputs if not out['script']]
        if len(fees) != 1 or fees[0]['asset'] != self.config['policy_asset'] or not 0 < fees[0]['amount'] <= 1_000_000:
            raise ValueError('fee exceeds sandbox policy')
        digest = template_hash(transaction)
        binding = f"{stage}:{operation['cash_receipt_id'] if stage == 'issue' else operation['id']}"
        self._bind_signature(binding, digest)
        sighash = SegwitV0SignatureHash(CScript(bytes.fromhex(self.config['witness_script'])), transaction,
                                      index, SIGHASH_ALL, previous_output.nValue)
        return {'guardian_id': self.config['guardian_id'], 'signature': self.ecdsa.signature(self.config['spending_secret'], sighash).hex(),
                'template_hash': digest}


class InstitutionClient:
    def __init__(self, services):
        self.services = services

    def request(self, guardian_id, method, **values):
        config = self.services[guardian_id]
        data = canonical({'method': method, **values})
        request = urllib.request.Request(config['url'], data=data, headers={
            'Content-Type': 'application/json', 'Authorization': 'Bearer ' + config['token']})
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.load(response)
        if 'error' in result:
            raise ValueError(result['error'])
        return result

    def approve(self, guardian_id, operation, passphrase):
        # Test/operator helper: the coordinator configuration does not contain
        # these independently issued institution approval credentials.
        config = self.services[guardian_id]
        request = urllib.request.Request(config['url'] + 'approve', data=canonical({
            'operation': operation, 'passphrase': passphrase}), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    def sign_transaction(self, guardian_id, **request):
        return self.request(guardian_id, 'sign_transaction', **request)

    def sign_block(self, guardian_id, rawblock):
        return self.request(guardian_id, 'sign_block', rawblock=rawblock)


def serve(config, rpc):
    institution = Institution(config, rpc)
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_):
            pass

        def respond(self, status, body, kind='application/json'):
            body = canonical(body) if kind == 'application/json' else body
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get('Host') not in self.server.authorities:
                self.send_error(403)
                return
            if self.path == '/info':
                # A runtime set up for live demos may prefill the passphrase in
                # its own approval window; no other runtime exposes it.
                self.respond(200, {'guardian_id': config['guardian_id'], 'coordinator_origins': config['coordinator_origins'],
                                   'approval_public_keys': config['approval_public_keys'],
                                   **({'demo_passphrase': config['approval_passphrase']} if config.get('demo_autofill') else {})})
                return
            filename = {'/': 'index.html', '/review.js': 'review.js', '/review.css': 'review.css'}.get(self.path)
            if filename is None:
                self.send_error(404)
                return
            body = (Path(__file__).with_name('institution_static') / filename).read_bytes()
            self.respond(200, body, {'index.html': 'text/html; charset=utf-8', 'review.js': 'application/javascript',
                                    'review.css': 'text/css'}[filename])

        def do_POST(self):
            try:
                if self.headers.get('Host') not in self.server.authorities:
                    self.send_error(403)
                    return
                if self.headers.get('Origin') and self.headers['Origin'] not in self.server.origins:
                    self.send_error(403)
                    return
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 8_000_000:
                    raise ValueError('invalid request length')
                request = json.loads(self.rfile.read(length))
                if self.path == '/approve':
                    if not hmac.compare_digest(request.get('passphrase', ''), config['approval_passphrase']):
                        self.respond(403, {'error': 'Institution approval passphrase is required'})
                        return
                    result = institution.approve(request['operation'])
                elif (self.path == '/' and request.get('method') in {'sign_transaction', 'sign_migration', 'sign_block'}
                      and hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + config['token'])):
                    result = getattr(institution, request['method'])(request)
                else:
                    self.respond(403, {'error': 'Independent institution approval is required'})
                    return
                status = 200
            except (ValueError, KeyError, TypeError, RuntimeError) as error:
                result, status = {'error': str(error)}, 400
            self.respond(status, result)
    server = ThreadingHTTPServer(('127.0.0.1', config.get('port', 0)), Handler)
    server.daemon_threads = True
    server.authorities = {f'127.0.0.1:{server.server_port}', f'localhost:{server.server_port}'}
    server.origins = {'http://' + authority for authority in server.authorities}
    print(json.dumps({'url': f'http://127.0.0.1:{server.server_port}/'}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    import sys
    from .elements_adapter import RPC
    config = json.loads(Path(sys.argv[1]).read_text())
    serve(config, RPC(config['rpc_url']))
