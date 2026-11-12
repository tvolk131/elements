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
            def getbestblockhash(rpc):
                return f'{1:064x}'
            def getblockcount(rpc):
                return 9
            def testproposedblock(rpc, raw, acceptnonstd=False):
                assert acceptnonstd is True
                return None
            def getblockchaininfo(rpc):
                return {'blocks': rpc.native_height, 'audit_config': rpc.native_audit, 'bestblockhash': rpc.getbestblockhash()}
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
            with self.assertRaisesRegex(ValueError, 'unexpired independent institution approval'):
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
        with self.assertRaisesRegex(ValueError, 'unexpired independent institution approval'):
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
