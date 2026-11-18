"""Adversarial tests for migration authorization and historical escrow links."""

import copy
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from curve import Curve
from governance import AuditConfig, AuditKey
from threshold import Committee
from test_framework import messages
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, CTxOutAsset, DynaFedParamEntry, ser_uint256
from test_framework.script import CScript, OP_CHECKMULTISIG

from .authorization import WINDOW, authorization_digest, decode_policy, encode, policy_bytes, registration_digest
from .rotation_approval import RotationVerifier, rotation_digest, sign_rotation
from .treasury import Institution, NativeECDSA, template_hash
from .treasury_rotation import current_escrow, packet_summary, validate_packet, validate_policy


LIBRARY = '/tmp/elements-audit-secp/lib/libsecp256k1.so'


class TreasuryRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists():
            raise unittest.SkipTest('build libsecp256k1-zkp shared library')
        cls.curve = Curve(LIBRARY)
        messages.THRESHOLD_AUDIT = True

    @classmethod
    def tearDownClass(cls):
        cls.curve.close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='treasury-rotation-unit-')
        self.asset = 'aa' * 32
        self.policy_asset = 'bb' * 32
        self.source = self.policy('sandbox-v1', (11, 12, 13), ('a1', 'a2', 'a3'))
        self.target = self.block_policy(self.policy('sandbox-v2', (21, 22, 23), ('b1', 'b2', 'b3')), (51, 52, 53))
        committee = Committee(1, (1, 2, 3), (self.curve.mul(31), self.curve.mul(32)))
        audit = AuditConfig(2, hashlib.sha256(b'committed-native-policy').digest(),
                            tuple((member, self.curve.mul(member + 100)[1:]) for member in committee.members),
                            1, (AuditKey(1, 2, committee),))
        audit.validate(self.curve)
        previous = CTransaction()
        previous.vout = [CTxOut(1_000_000_000, bytes.fromhex(self.source['treasury_script']),
                                 CTxOutAsset(b'\x01' + bytes.fromhex(self.asset)[::-1]))]
        previous.rehash()
        fee = CTransaction()
        fee.vout = [CTxOut(1_000_000, b'\x51', CTxOutAsset(b'\x01' + bytes.fromhex(self.policy_asset)[::-1]))]
        fee.rehash()
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(previous.sha256, 0), nSequence=0xfffffffe),
                           CTxIn(COutPoint(fee.sha256, 0), nSequence=0xfffffffe)]
        transaction.vout = [CTxOut(1_000_000_000, bytes.fromhex(self.target['treasury_script']),
                                  CTxOutAsset(b'\x01' + bytes.fromhex(self.asset)[::-1])),
                            CTxOut(999_000, b'\x51', CTxOutAsset(b'\x01' + bytes.fromhex(self.policy_asset)[::-1])),
                            CTxOut(1_000, b'', CTxOutAsset(b'\x01' + bytes.fromhex(self.policy_asset)[::-1]))]
        transaction.rehash()
        self.transaction = transaction
        transactions = {previous.hash: previous, fee.hash: fee, transaction.hash: transaction}
        class RPC:
            confirmed = True
            native_height = 10
            native_genesis = 'cc'*32
            native_audit = audit.to_bytes().hex()
            native_block_script = self.target['block_signing_script']
            native_authorization = ''
            def getbestblockhash(rpc):
                return f'{1:064x}'
            def getblockcount(rpc):
                return 9
            def testproposedblock(rpc, raw, acceptnonstd=False):
                assert acceptnonstd is True
                return None
            def getblockchaininfo(rpc):
                return {'blocks': rpc.native_height, 'audit_config': rpc.native_audit, 'bestblockhash': rpc.getbestblockhash(),
                        'tx_authorization': rpc.native_authorization}
            def getblockhash(rpc, height):
                return rpc.native_genesis if height == 0 else f'{height:064x}'
            def getblock(rpc, blockhash):
                return {'dynamic_parameters': {'current': {'signblockscript': rpc.native_block_script}}}
            def getrawtransaction(rpc, txid, verbose=False):
                tx = transactions[txid]
                if verbose:
                    return {'txid': txid, 'hex': tx.serialize().hex(), 'confirmations': int(rpc.confirmed)}
                return tx.serialize().hex()
        self.rpc = RPC()
        self.packet = {'migration_id': 'rotation:r1:' + previous.hash + ':0', 'stage': 'migration',
            'rawtx': transaction.serialize().hex(), 'input_index': 0,
            'input_opening': {'asset': self.asset, 'amount': 1_000_000_000, 'asset_blinder': '00'*32, 'value_blinder': '00'*32},
            'openings': {}, 'source_txid': previous.hash, 'source_vout': 0,
            'asset_id': self.asset, 'amount_base': 1_000_000_000, 'kind': 'escrow', 'case_id': 'redemption-1',
            'original_escrow_txid': previous.hash, 'transaction_template_hash': template_hash(transaction),
            'target_output_index': 0, 'target_script': self.target['treasury_script'], 'target_policy_version': 'sandbox-v2'}
        self.rotation = {'kind': 'federation_rotation', 'id': 'rotation-1', 'chain': 'unit-test',
            'genesis_hash': 'cc'*32, 'source_policy_version': 'sandbox-v1', 'target_policy_version': 'sandbox-v2',
            'expires_at': int(time.time()) + 300, 'manifest': {'source_policy': self.source, 'target_policy': self.target,
                                                            'migrations': [packet_summary(self.packet)],
                                                            'activation_height': 10, 'audit_config_hash': audit.binding().hex()}}
        signatures = [sign_rotation(self.curve, name, secret, self.rotation) for name, secret in [('a1', 111), ('a2', 112)]]
        self.certificate = RotationVerifier(self.curve, self.source['approval_public_keys'], 2, 'sandbox-v1').certificate(self.rotation, signatures)
        self.config = dict(self.source, library=LIBRARY, guardian_id='a1', spending_secret=f'{11:064x}',
                           approval_secret=f'{111:064x}', genesis_hash='cc'*32, assets={}, policy_asset=self.policy_asset,
                           bank_public_key=self.curve.mul(999)[1:].hex(), database=str(Path(self.temp.name) / 'signer.sqlite'))

    def tearDown(self):
        self.temp.cleanup()

    def policy(self, version, spending, ids):
        witness = CScript([2, *(self.curve.mul(key) for key in spending), 3, OP_CHECKMULTISIG])
        return {'policy_version': version, 'treasury_script': (b'\x00\x20' + hashlib.sha256(witness).digest()).hex(),
                'witness_script': witness.hex(), 'treasury_address': 'test-address-' + version,
                'approval_public_keys': {name: self.curve.mul(key+100)[1:].hex() for name, key in zip(ids, spending)},
                'guardian_order': list(ids), 'threshold': 2}

    def test_migration_signature_requires_exact_approved_template(self):
        signer = Institution(self.config, self.rpc)
        request = {'rotation': self.rotation, 'certificate': self.certificate, 'packet': self.packet}
        result = signer.sign_migration(request)
        self.assertEqual(result['guardian_id'], 'a1')
        changed = copy.deepcopy(self.packet)
        tx = CTransaction(self.transaction)
        tx.vout[0].nValue.setToAmount(900_000_000)
        changed['rawtx'] = tx.serialize().hex()
        with self.assertRaisesRegex(ValueError, 'template'):
            signer.sign_migration(dict(request, packet=changed))
        signer.db.close()
        signer.curve.close()

    def test_migration_requires_native_commit_even_with_unexpired_certificate(self):
        signer = Institution(self.config, self.rpc)
        request = {'rotation': self.rotation, 'certificate': self.certificate, 'packet': self.packet}
        self.rpc.native_height = 9
        with self.assertRaisesRegex(ValueError, 'not committed'):
            signer.sign_migration(request)
        self.rpc.native_height = 10
        self.rpc.native_block_script = self.source['treasury_script']
        with self.assertRaisesRegex(ValueError, 'not committed'):
            signer.sign_migration(request)
        self.rpc.native_block_script = self.target['block_signing_script']
        self.rpc.native_genesis = 'dd'*32
        with self.assertRaisesRegex(ValueError, 'not committed'):
            signer.sign_migration(request)
        self.rpc.native_genesis = self.config['genesis_hash']
        other_audit = AuditConfig.from_bytes(bytes.fromhex(self.rpc.native_audit), self.curve)
        from dataclasses import replace
        self.rpc.native_audit = replace(other_audit, generation=other_audit.generation + 1).to_bytes().hex()
        with self.assertRaisesRegex(ValueError, 'not committed'):
            signer.sign_migration(request)
        signer.db.close(); signer.curve.close()

    def test_expired_rotation_can_only_complete_after_verified_native_commit(self):
        operation = copy.deepcopy(self.rotation)
        operation['expires_at'] = int(time.time()) - 30
        signatures = [sign_rotation(self.curve, name, secret, operation) for name, secret in [('a1', 111), ('a2', 112)]]
        certificate = RotationVerifier(self.curve, self.source['approval_public_keys'], 2, 'sandbox-v1').certificate(
            operation, signatures, allow_expired=True)
        signer = Institution(self.config, self.rpc)
        request = {'rotation': operation, 'certificate': certificate, 'packet': self.packet}
        self.rpc.native_height = 9
        with self.assertRaisesRegex(ValueError, 'expired'):
            signer.sign_migration(request)
        self.rpc.native_height = 10
        self.assertIn('signature', signer.sign_migration(request))
        bad = copy.deepcopy(request)
        bad['certificate']['signatures'].pop()
        with self.assertRaisesRegex(ValueError, 'quorum'):
            signer.sign_migration(bad)
        signer.db.close(); signer.curve.close()

    def test_policy_rejects_nonmultisig_destination(self):
        bad = copy.deepcopy(self.target)
        witness = bytearray.fromhex(bad['witness_script'])
        witness[-1] = 0x75  # OP_DROP must not be accepted as federation multisig.
        bad['witness_script'] = bytes(witness).hex()
        bad['treasury_script'] = (b'\x00\x20' + hashlib.sha256(witness).digest()).hex()
        with self.assertRaises(ValueError):
            validate_policy(bad)

    def block_policy(self, policy, keys):
        policy = dict(policy)
        witness = bytes(CScript([2, *[self.curve.mul(key) for key in keys], 3, OP_CHECKMULTISIG]))
        policy.update(block_witness_script=witness.hex(),
                      block_signing_script=(b'\x00\x20' + hashlib.sha256(witness).digest()).hex(),
                      block_public_keys={name: self.curve.mul(key).hex() for name, key in zip(policy['guardian_order'], keys)})
        return policy

    def block(self, source, target=None):
        block = CBlock()
        block.hashPrevBlock = 1
        block.block_height = 10
        block.nTime = 1
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        block.m_dynafed_params.m_current = DynaFedParamEntry(bytes.fromhex(source['block_signing_script']), 1024, program, b'\x51', [])
        if target:
            block.m_dynafed_params.m_proposed = DynaFedParamEntry(bytes.fromhex(target['block_signing_script']), 1024, program, b'\x51', [])
        return block

    def authorization_request(self, **changes):
        """The migration transaction with a bank registration for each paid address."""
        scripts = [bytes(output.scriptPubKey) for output in self.transaction.vout if bytes(output.scriptPubKey)]
        registrations = {script.hex(): self.curve.sign(999, registration_digest('cc' * 32, script)).hex() for script in scripts}
        return dict({'rawtx': self.transaction.serialize().hex(), 'expiry_height': self.rpc.native_height + WINDOW,
                     'registrations': registrations}, **changes)

    def test_authorization_covers_exact_transaction_until_expiry(self):
        policy = policy_bytes(self.source['approval_public_keys'], self.source['guardian_order'], 2)
        self.assertEqual(decode_policy(policy), (2, [self.curve.mul(key)[1:] for key in (111, 112, 113)]))
        self.rpc.native_authorization = policy.hex()
        signer = Institution(self.config, self.rpc)
        request = self.authorization_request()
        signature = bytes.fromhex(signer.authorize_transaction(request)['signature'])
        digest = authorization_digest('cc' * 32, policy, self.transaction, request['expiry_height'])
        self.assertTrue(self.curve.verify_signature(self.curve.mul(111)[1:], digest, signature))
        changed = CTransaction(self.transaction)
        changed.nLockTime += 1
        for other in (authorization_digest('cc' * 32, policy, changed, request['expiry_height']),
                      authorization_digest('cc' * 32, policy, self.transaction, request['expiry_height'] + 1),
                      authorization_digest('dd' * 32, policy, self.transaction, request['expiry_height']),
                      authorization_digest('cc' * 32, b'\x01' + policy[1:], self.transaction, request['expiry_height'])):
            self.assertFalse(self.curve.verify_signature(self.curve.mul(111)[1:], other, signature))
        self.assertEqual(encode(7, {2: b'b' * 64, 0: b'a' * 64}), b'\x07\0\0\0' + b'\0' + b'a' * 64 + b'\x02' + b'b' * 64)
        signer.db.close(); signer.curve.close()

    def test_operators_page_lists_who_authorizes_every_transaction(self):
        from .federation import FederationRotation
        policy = {'policy_version': 'sandbox-v1', 'threshold': 3, 'guardian_order': [f'institution-{i}' for i in range(1, 6)],
                  'treasury_script': '00', 'block_signing_script': '51'}
        described = FederationRotation._describe(policy, list(range(1, 16)), 11)
        self.assertEqual(described['authorization'], {'threshold': 3, 'count': 5, 'members': policy['guardian_order']})

    def test_authorization_refuses_unregistered_destinations_and_long_windows(self):
        policy = policy_bytes(self.source['approval_public_keys'], self.source['guardian_order'], 2)
        signer = Institution(self.config, self.rpc)
        with self.assertRaisesRegex(ValueError, 'does not require'):
            signer.authorize_transaction(self.authorization_request())
        self.rpc.native_authorization = policy.hex()
        with self.assertRaisesRegex(ValueError, 'no member bank has registered'):
            signer.authorize_transaction(self.authorization_request(registrations={}))
        forged = {script: self.curve.sign(998, registration_digest('cc' * 32, bytes.fromhex(script))).hex()
                  for script in self.authorization_request()['registrations']}
        with self.assertRaisesRegex(ValueError, 'no member bank has registered'):
            signer.authorize_transaction(self.authorization_request(registrations=forged))
        for expiry in (self.rpc.native_height, self.rpc.native_height + WINDOW + 1, '20'):
            with self.assertRaisesRegex(ValueError, 'must expire within'):
                signer.authorize_transaction(self.authorization_request(expiry_height=expiry))
        # The treasury and fee need no registration; any other address does.
        own = dict(self.config, treasury_script=self.target['treasury_script'])
        treasury_only = Institution(dict(own, database=str(Path(self.temp.name) / 'own.sqlite')), self.rpc)
        registrations = self.authorization_request()['registrations']
        registrations.pop(self.target['treasury_script'])
        treasury_only.authorize_transaction(self.authorization_request(registrations=registrations))
        self.rpc.native_authorization = policy_bytes(self.target['approval_public_keys'], self.target['guardian_order'], 2).hex()
        with self.assertRaisesRegex(ValueError, 'not an authorizer'):
            signer.authorize_transaction(self.authorization_request())
        for closing in (signer, treasury_only):
            closing.db.close(); closing.curve.close()

    def test_institution_client_keeps_the_reason_for_a_refusal(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from .treasury import InstitutionClient, InstitutionRefused
        class Service(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                status, body = ((400, b'{"error":"an output pays an address that no member bank has registered"}')
                                if self.path == '/' else (502, b'<html>bad gateway</html>'))
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Service)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_port}/'
        client = InstitutionClient({'a1': {'url': base, 'token': 't'}, 'a2': {'url': base + 'proxy', 'token': 't'}})
        with self.assertRaisesRegex(InstitutionRefused, 'no member bank has registered'):
            client.request('a1', 'authorize_transaction')
        # A broken gateway is not the institution saying no.
        with self.assertRaises(OSError):
            client.request('a2', 'authorize_transaction')

    def test_coordinator_tells_a_refusal_from_too_few_institutions(self):
        from .authorization import AuthorizationRefused, AuthorizationUnavailable
        from .elements_adapter import ElementsAdapter
        from .treasury import InstitutionClient, InstitutionRefused
        policy = policy_bytes(self.source['approval_public_keys'], self.source['guardian_order'], 2)
        secrets = dict(zip(self.source['guardian_order'], (111, 112, 113)))
        class Node:
            def getblockchaininfo(self):
                return {'tx_authorization': policy.hex(), 'blocks': 100}
            def getblockhash(self, height):
                return 'cc' * 32
        adapter = object.__new__(ElementsAdapter)
        adapter.curve, adapter.node, adapter.registrar = self.curve, Node(), lambda script: None
        adapter.config = {'approval_public_keys': self.source['approval_public_keys'],
                          'institutions': {guardian: {'url': 'http://unused/', 'token': 't'} for guardian in secrets}}
        behaviour, registrations = {}, []
        def request(client, guardian, method, **values):
            registrations.append(values['registrations'])
            if behaviour[guardian] == 'refuse':
                raise InstitutionRefused('an output pays an address that no member bank has registered')
            if behaviour[guardian] == 'down':
                raise ConnectionRefusedError('institution is offline')
            transaction = messages.tx_from_hex(values['rawtx'])
            digest = authorization_digest('cc' * 32, policy, transaction, values['expiry_height'])
            return {'signature': self.curve.sign(secrets[guardian], digest).hex()}
        raw = self.transaction.serialize().hex()
        with patch.object(InstitutionClient, 'request', request):
            # Unregistered addresses get no registration; the institutions decide.
            behaviour.update(a1='refuse', a2='refuse', a3='ok')
            with self.assertRaisesRegex(AuthorizationRefused, '2 of 3 operators refused.*no member bank'):
                adapter.authorize(raw)
            self.assertEqual(registrations[0], {})
            behaviour.update(a1='down', a2='down', a3='ok')
            with self.assertRaisesRegex(AuthorizationUnavailable, '1 of 3 reachable, 2 needed'):
                adapter.authorize(raw)
            # One refusal alone cannot block a quorum the others can still reach.
            behaviour.update(a1='refuse', a2='down', a3='ok')
            with self.assertRaises(AuthorizationUnavailable):
                adapter.authorize(raw)
            behaviour.update(a1='down', a2='ok', a3='ok')
            authorized = messages.tx_from_hex(adapter.authorize(raw)).wit.vchAuthorization
            self.assertEqual([authorized[4], authorized[69]], [1, 2])

    def test_block_signing_uses_separate_key_and_refuses_height_conflict(self):
        source = self.block_policy(self.source, (41, 42, 43))
        config = dict(self.config, **source, block_secret=f'{41:064x}')
        signer = Institution(config, self.rpc)
        block = self.block(source)
        result = signer.sign_block({'rawblock': block.serialize().hex()})
        block.rehash()
        self.assertTrue(NativeECDSA(self.curve).verify(self.curve.mul(41), ser_uint256(block.sha256), bytes.fromhex(result['signature'])))
        self.assertFalse(NativeECDSA(self.curve).verify(self.curve.mul(11), ser_uint256(block.sha256), bytes.fromhex(result['signature'])))
        changed = self.block(source)
        changed.nTime = 2
        with self.assertRaisesRegex(ValueError, 'conflicting block'):
            signer.sign_block({'rawblock': changed.serialize().hex()})
        signer.db.close(); signer.curve.close()

    def test_block_proposal_requires_exact_independent_rotation_approval(self):
        source, target = self.block_policy(self.source, (41, 42, 43)), self.block_policy(self.target, (51, 52, 53))
        signer = Institution(dict(self.config, **source, block_secret=f'{41:064x}'), self.rpc)
        block = self.block(source, target)
        with self.assertRaisesRegex(ValueError, 'exact DynaFed proposal'):
            signer.sign_block({'rawblock': block.serialize().hex()})
        operation = copy.deepcopy(self.rotation)
        operation['manifest'].update(source_policy=source, target_policy=target,
            proposal_hash=hashlib.sha256(block.m_dynafed_params.m_proposed.serialize()).hexdigest())
        signer.approve_rotation(operation)
        self.assertIn('signature', signer.sign_block({'rawblock': block.serialize().hex()}))
        changed = self.block(source, target)
        changed.m_dynafed_params.m_proposed.m_signblock_witness_limit = 2048
        with self.assertRaisesRegex(ValueError, 'exact DynaFed proposal'):
            signer.sign_block({'rawblock': changed.serialize().hex()})
        signer.db.close(); signer.curve.close()

    def test_expired_block_proposal_rejected_but_null_proposals_continue(self):
        source, target = self.block_policy(self.source, (41, 42, 43)), self.target
        signer = Institution(dict(self.config, **source, block_secret=f'{41:064x}'), self.rpc)
        proposed = self.block(source, target)
        operation = copy.deepcopy(self.rotation)
        operation['manifest'].update(source_policy=source,
            proposal_hash=hashlib.sha256(proposed.m_dynafed_params.m_proposed.serialize()).hexdigest())
        signer.approve_rotation(operation)
        with patch('time.time', return_value=operation['expires_at']):
            with self.assertRaisesRegex(ValueError, 'unexpired independent operator approval'):
                signer.sign_block({'rawblock': proposed.serialize().hex()})
            self.assertIn('signature', signer.sign_block({'rawblock': self.block(source).serialize().hex()}))
        signer.db.close(); signer.curve.close()

    def test_legacy_rotation_approval_without_expiry_requires_reapproval(self):
        import sqlite3
        source, target = self.block_policy(self.source, (41, 42, 43)), self.target
        proposed = self.block(source, target)
        operation = copy.deepcopy(self.rotation)
        proposal_hash = hashlib.sha256(proposed.m_dynafed_params.m_proposed.serialize()).hexdigest()
        operation['manifest'].update(source_policy=source, proposal_hash=proposal_hash)
        legacy = sqlite3.connect(self.config['database'])
        legacy.execute('CREATE TABLE rotation_approvals(case_id TEXT PRIMARY KEY,digest TEXT NOT NULL,'
                       'target_block_script TEXT,proposal_hash TEXT)')
        legacy.execute('INSERT INTO rotation_approvals VALUES(?,?,?,?)',
                       (operation['id'], rotation_digest(operation).hex(), target['block_signing_script'], proposal_hash))
        legacy.commit(); legacy.close()
        signer = Institution(dict(self.config, **source, block_secret=f'{41:064x}'), self.rpc)
        self.assertIsNone(signer.db.execute('SELECT expires_at FROM rotation_approvals').fetchone()[0])
        with self.assertRaisesRegex(ValueError, 'unexpired independent operator approval'):
            signer.sign_block({'rawblock': proposed.serialize().hex()})
        signer.approve_rotation(operation)
        self.assertEqual(signer.db.execute('SELECT expires_at FROM rotation_approvals').fetchone()[0], operation['expires_at'])
        self.assertIn('signature', signer.sign_block({'rawblock': proposed.serialize().hex()}))
        signer.db.close(); signer.curve.close()

    def test_confirmed_signed_handover_preserves_original_bank_reference(self):
        operation = {'id': 'redemption-1', 'kind': 'redemption', 'asset_id': self.asset, 'genesis_hash': 'cc'*32,
                     'amount_minor': 1_000, 'escrow_txid': self.packet['source_txid']}
        record = {'rotation': self.rotation, 'certificate': self.certificate, 'packet': self.packet,
                  'prepared': {'txid': self.transaction.hash}}
        config = dict(self.target, genesis_hash='cc'*32, policy_asset=self.policy_asset,
                      historical_approval_policies={'sandbox-v1': {'public_keys': self.source['approval_public_keys'], 'threshold': 2}})
        locator = {'txid': self.transaction.hash, 'vout': 0}
        original = operation['escrow_txid']
        self.assertEqual(current_escrow(config, self.rpc, self.curve, operation, locator, [record]), locator)
        self.assertEqual(operation['escrow_txid'], original)
        self.rpc.confirmed = False
        with self.assertRaisesRegex(ValueError, 'not confirmed'):
            current_escrow(config, self.rpc, self.curve, operation, locator, [record])

    def test_escrow_link_rejects_wrong_case_amount_or_certificate(self):
        operation = {'id': 'redemption-1', 'kind': 'redemption', 'asset_id': self.asset, 'genesis_hash': 'cc'*32,
                     'amount_minor': 1_000, 'escrow_txid': self.packet['source_txid']}
        record = {'rotation': self.rotation, 'certificate': self.certificate, 'packet': self.packet,
                  'prepared': {'txid': self.transaction.hash}}
        config = dict(self.target, genesis_hash='cc'*32, policy_asset=self.policy_asset,
                      historical_approval_policies={'sandbox-v1': {'public_keys': self.source['approval_public_keys'], 'threshold': 2}})
        locator = {'txid': self.transaction.hash, 'vout': 0}
        for altered in (dict(operation, id='other-case'), dict(operation, amount_minor=2_000)):
            with self.assertRaises(ValueError):
                current_escrow(config, self.rpc, self.curve, altered, locator, [record])
        bad = copy.deepcopy(record)
        bad['certificate']['signatures'].pop()
        with self.assertRaises(ValueError):
            current_escrow(config, self.rpc, self.curve, operation, locator, [bad])


if __name__ == '__main__':
    unittest.main()
