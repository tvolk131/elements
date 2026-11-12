"""Repeated handover invariants independent of the full native acceptance run."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from curve import Curve
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxOutAsset
from .approval import ApprovalPolicies, ApprovalVerifier
from .elements_adapter import ElementsAdapter
from .policy import PublicFederationPolicy, public_policy, validate_policy, validate_successor
from .rotation_approval import RotationVerifier, sign_rotation
from .rotation_history import RotationHistory
from . import test_treasury_rotation as rotation_fixtures
from .treasury import template_hash
from .treasury_rotation import current_escrow, packet_summary

LIBRARY = rotation_fixtures.LIBRARY


class RepeatedRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists():
            raise unittest.SkipTest('build libsecp256k1-zkp shared library')
        cls.curve = Curve(LIBRARY)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'curve'):
            cls.curve.close()

    def setUp(self):
        self.fixture = rotation_fixtures.TreasuryRotationTests()
        self.fixture.curve = self.curve
        self.fixture.setUp()
        f = self.fixture
        self.third = f.block_policy(f.policy('sandbox-v3', (31, 32, 33), ('c1', 'c2', 'c3')), (61, 62, 63))
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(f.transaction.sha256, 0), nSequence=0xfffffffe),
                           CTxIn(COutPoint(f.transaction.sha256, 1), nSequence=0xfffffffe)]
        transaction.vout = [CTxOut(1_000_000_000, bytes.fromhex(self.third['treasury_script']),
                                  CTxOutAsset(b'\x01' + bytes.fromhex(f.asset)[::-1])),
                            CTxOut(998_000, b'\x51', CTxOutAsset(b'\x01' + bytes.fromhex(f.policy_asset)[::-1])),
                            CTxOut(1_000, b'', CTxOutAsset(b'\x01' + bytes.fromhex(f.policy_asset)[::-1]))]
        transaction.rehash()
        self.third_transaction = transaction
        self.packet = dict(f.packet, migration_id='rotation:r2:' + f.transaction.hash + ':0',
                           rawtx=transaction.serialize().hex(), source_txid=f.transaction.hash,
                           transaction_template_hash=template_hash(transaction), target_script=self.third['treasury_script'],
                           target_policy_version='sandbox-v3')
        self.rotation = dict(f.rotation, id='rotation-2', source_policy_version='sandbox-v2', target_policy_version='sandbox-v3',
                             manifest={'source_policy': f.target, 'target_policy': self.third,
                                       'migrations': [packet_summary(self.packet)]})
        signatures = [sign_rotation(self.curve, name, secret, self.rotation) for name, secret in [('b1', 121), ('b2', 122)]]
        self.certificate = RotationVerifier(self.curve, f.target['approval_public_keys'], 2, 'sandbox-v2').certificate(self.rotation, signatures)
        self.records = [
            {'rotation': f.rotation, 'certificate': f.certificate, 'packet': f.packet, 'prepared': {'txid': f.transaction.hash}},
            {'rotation': self.rotation, 'certificate': self.certificate, 'packet': self.packet,
             'prepared': {'txid': transaction.hash}}]
        self.config = dict(self.third, genesis_hash='cc' * 32, policy_asset=f.policy_asset,
                           historical_approval_policies={
                               'sandbox-v1': {'public_keys': f.source['approval_public_keys'], 'threshold': 2},
                               'sandbox-v2': {'public_keys': f.target['approval_public_keys'], 'threshold': 2}})
        self.operation = {'id': 'redemption-1', 'kind': 'redemption', 'asset_id': f.asset, 'amount_minor': 1_000,
                          'genesis_hash': 'cc' * 32, 'policy_version': 'sandbox-v1', 'escrow_txid': f.packet['source_txid']}
        self.locator = {'txid': transaction.hash, 'vout': 0}
        base = f.rpc
        class RPC:
            def getrawtransaction(rpc, txid, verbose=False):
                if txid != transaction.hash:
                    return base.getrawtransaction(txid, verbose)
                return {'txid': txid, 'hex': transaction.serialize().hex(), 'confirmations': 1} if verbose else transaction.serialize().hex()
        self.rpc = RPC()

    def tearDown(self):
        self.fixture.tearDown()

    def test_two_confirmed_links_preserve_original_bank_reference(self):
        original = copy.deepcopy(self.operation)
        self.assertEqual(current_escrow(self.config, self.rpc, self.curve, self.operation, self.locator, self.records), self.locator)
        self.assertEqual(self.operation, original)
        refund = dict(self.operation, id='refund-1', kind='refund', cash_receipt_id=self.operation['id'], policy_version='sandbox-v3')
        self.assertEqual(current_escrow(self.config, self.rpc, self.curve, refund, self.locator, self.records), self.locator)

    def test_missing_or_unconfirmed_middle_link_cannot_be_skipped(self):
        for records in (self.records[1:], self.records[:1]):
            with self.assertRaisesRegex(ValueError, 'missing|terminate'):
                current_escrow(self.config, self.rpc, self.curve, self.operation, self.locator, records)
        self.fixture.rpc.confirmed = False
        with self.assertRaisesRegex(ValueError, 'not confirmed'):
            current_escrow(self.config, self.rpc, self.curve, self.operation, self.locator, self.records)

    def test_old_or_unrelated_terminal_policy_cannot_authorize_current_escrow(self):
        old = {'txid': self.fixture.transaction.hash, 'vout': 0}
        with self.assertRaisesRegex(ValueError, 'current federation'):
            current_escrow(self.config, self.rpc, self.curve, self.operation, old, self.records)
        with self.assertRaisesRegex(ValueError, 'original outpoint'):
            current_escrow(self.config, self.rpc, self.curve, self.operation,
                           {'txid': self.operation['escrow_txid'], 'vout': 0}, self.records)
        substituted = dict(self.operation, genesis_hash='dd' * 32)
        with self.assertRaisesRegex(ValueError, 'different economic chain'):
            current_escrow(self.config, self.rpc, self.curve, substituted, self.locator, self.records)

    def test_multihop_link_cannot_substitute_confirmed_transaction_id(self):
        target = self.third_transaction.hash
        delegated = self.rpc
        class LyingRPC:
            def getrawtransaction(rpc, txid, verbose=False):
                value = delegated.getrawtransaction(txid, verbose)
                if txid == target and verbose:
                    value = dict(value, hex=self.fixture.transaction.serialize().hex())
                return value
        liar = LyingRPC()
        with self.assertRaisesRegex(ValueError, 'transaction ID'):
            current_escrow(self.config, liar, self.curve, self.operation, self.locator, self.records)

    def test_public_policy_is_explicit_and_rejects_conflicting_members(self):
        value = dict(self.third, token='private-service-token', spending_secret='not-public')
        parsed = PublicFederationPolicy.parse(value)
        self.assertEqual(public_policy(value), self.third)
        self.assertNotIn('token', parsed.to_dict())
        with self.assertRaises(FrozenInstanceError):
            parsed.version = 'sandbox-v4'
        wrong = copy.deepcopy(self.third)
        wrong['block_public_keys']['c2'] = wrong['block_public_keys']['c1']
        with self.assertRaisesRegex(ValueError, 'distinct'):
            validate_policy(wrong)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            validate_successor(self.fixture.source, self.third)

    def test_historical_approval_policies_cannot_rebind_or_move_backwards(self):
        f = self.fixture
        first = ApprovalVerifier(self.curve, f.source['approval_public_keys'], 2, 'sandbox-v1')
        second = ApprovalVerifier(self.curve, f.target['approval_public_keys'], 2, 'sandbox-v2')
        third = ApprovalVerifier(self.curve, self.third['approval_public_keys'], 2, 'sandbox-v3')
        policies = ApprovalPolicies(first)
        policies.activate(second); policies.activate(third)
        self.assertEqual(policies.history['sandbox-v1'].public_keys, first.public_keys)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policies.activate(first)
        bad = ApprovalVerifier(self.curve, third.public_keys, 2, 'sandbox-v1')
        with self.assertRaisesRegex(ValueError, 'cannot be replaced'):
            ApprovalPolicies(third, [first, bad])

    def test_adapter_retains_old_verifiers_and_rejects_history_replacement(self):
        adapter = ElementsAdapter.__new__(ElementsAdapter)
        adapter.lock = threading.RLock(); adapter.config = dict(self.fixture.source)
        adapter.configure_federation(self.fixture.target, {member: {} for member in self.fixture.target['guardian_order']}, rotation_records=self.records[:1])
        adapter.configure_federation(self.third, {member: {} for member in self.third['guardian_order']}, rotation_records=self.records)
        self.assertEqual(set(adapter.config['historical_approval_policies']), {'sandbox-v1', 'sandbox-v2'})
        snapshot = copy.deepcopy(adapter.config)
        with self.assertRaisesRegex(ValueError, 'append-only'):
            adapter.configure_federation(self.third, {member: {} for member in self.third['guardian_order']}, rotation_records=self.records[1:])
        self.assertEqual(adapter.config, snapshot)


class RotationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rotation-history-unit-')
        self.history = RotationHistory(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def state(self, epoch, stage='complete'):
        return {'id': f'rotation-{epoch}-{epoch + 1}', 'stage': stage, 'created_at': 100 + epoch, 'updated_at': 200,
                'source_policy': {'policy_version': f'sandbox-v{epoch}'},
                'target': {'policy': {'policy_version': f'sandbox-v{epoch + 1}'}},
                'genesis_hash': 'cc' * 32, 'confirmed_migrations': [f'transaction-{epoch}']}

    def test_completed_rotations_survive_next_checkpoint_and_reload(self):
        first, second = self.state(1), self.state(2)
        self.history.record(first)
        initial = (self.history.completed / 'rotation-1-2.json').read_bytes()
        self.history.record(dict(first, updated_at=999))
        self.assertEqual(len(self.history.events), 1)
        self.history.record(self.state(2, 'preparing'))
        self.history.record(second)
        reloaded = RotationHistory(self.temp.name)
        self.assertEqual([item['target_policy_version'] for item in reloaded.summaries()], ['sandbox-v2', 'sandbox-v3'])
        self.assertEqual((self.history.completed / 'rotation-1-2.json').read_bytes(), initial)

    def test_completed_record_and_journal_corruption_fail_closed(self):
        state = self.state(1)
        self.history.record(state)
        with self.assertRaisesRegex(ValueError, 'cannot be replaced'):
            self.history.archive(dict(state, confirmed_migrations=['different-transaction']))
        events = self.history.events_path
        item = json.loads(events.read_text())
        item['payload']['stage'] = 'migrating'
        events.write_text(json.dumps(item) + '\n')
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            RotationHistory(self.temp.name)

    def test_missing_initial_completed_epoch_is_detected(self):
        self.history.record(self.state(2))
        with self.assertRaisesRegex(ValueError, 'missing its initial epoch'):
            self.history.summaries()

    def test_transport_credentials_are_not_archived_or_bound_as_policy(self):
        state = self.state(1)
        state['target']['institutions'] = {'member': {'url': 'http://127.0.0.1:1/', 'token': 'private-token'}}
        self.history.record(state)
        archive = (self.history.completed / 'rotation-1-2.json').read_text()
        self.assertNotIn('private-token', archive)
        self.assertNotIn('127.0.0.1', archive)
        state['target']['institutions']['member'] = {'url': 'http://127.0.0.1:2/', 'token': 'renewed-token'}
        self.history.record(state)
        self.assertEqual(len(self.history.events), 1)

    def test_deleted_archives_cannot_erase_retained_checkpoint_history(self):
        self.history.record(self.state(1))
        self.history.record(self.state(2, 'preparing'))
        (self.history.completed / 'rotation-1-2.json').unlink()
        with self.assertRaisesRegex(ValueError, 'retained checkpoint epoch'):
            RotationHistory(self.temp.name).summaries('sandbox-v2', 'cc' * 32)
        with self.assertRaisesRegex(ValueError, 'missing its matching archive'):
            RotationHistory(self.temp.name).summaries()

    def test_archives_must_reach_the_retained_policy_and_genesis(self):
        self.history.record(self.state(1))
        self.assertEqual(len(self.history.summaries('sandbox-v2', 'cc' * 32)), 1)
        with self.assertRaisesRegex(ValueError, 'retained checkpoint epoch'):
            self.history.summaries('sandbox-v3', 'cc' * 32)
        with self.assertRaisesRegex(ValueError, 'checkpoint genesis'):
            self.history.summaries('sandbox-v2', 'dd' * 32)


if __name__ == '__main__':
    unittest.main()
