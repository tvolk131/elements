# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial tests for the proposed public audit-governance state machine."""

from dataclasses import replace
import hashlib
import os
import unittest

from curve import Curve, G, ORDER, random_scalar
from governance import (
    MAX_CONFIG_BYTES, AuditChain, AuditConfig, AuditKey, PreparedTransition,
    Transition, make_readiness, verify_readiness,
)
from threshold import simulate_handoff, simulate_keygen


def named(value):
    return hashlib.sha256(value.encode()).digest()


class GovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = os.environ.get('THRESHOLD_AUDIT_SECP256K1')
        if not library:
            raise RuntimeError('Set THRESHOLD_AUDIT_SECP256K1 to the bundled shared library')
        cls.curve = Curve(library)
        cls.addClassCleanup(cls.curve.close)
        cls.chain_id = named('governance test chain')
        cls.old, cls.old_shares = simulate_keygen(cls.curve, (1, 2, 3, 4, 5), 3)
        cls.new, cls.new_shares = simulate_handoff(cls.curve, cls.old, cls.old_shares[:3],
                                                  (11, 12, 13, 14, 15, 16, 17), 4)
        cls.old_identities = {member: random_scalar() for member in cls.old.members}
        cls.new_identities = {member: random_scalar() for member in cls.new.members}
        old_keys = tuple((i, cls.curve.mul(secret)[1:]) for i, secret in cls.old_identities.items())
        new_keys = tuple((i, cls.curve.mul(secret)[1:]) for i, secret in cls.new_identities.items())
        cls.initial = AuditConfig(0, named('old block signing script'), old_keys, 1,
                                  (AuditKey(1, 1, cls.old),))
        cls.handed = AuditConfig(1, named('new block signing script'), new_keys, 1,
                                 (AuditKey(1, 1, cls.new),))
        cls.prepared = cls.prepare(cls.initial, cls.handed, 10, {1: cls.new_shares}, cls.new_identities)
        cls.fresh, cls.fresh_shares = simulate_keygen(cls.curve, cls.new.members, 4)
        cls.rolled = replace(cls.handed, generation=2, active_version=2,
                             keys=cls.handed.keys + (AuditKey(2, 1, cls.fresh),))
        cls.rollover = cls.prepare(cls.handed, cls.rolled, 20,
                                   {1: cls.new_shares, 2: cls.fresh_shares}, cls.new_identities)

    @classmethod
    def prepare(cls, previous, current, height, shares, identities, chain_id=None):
        transition = Transition(previous.binding(), height, current)
        ready = []
        for key in current.keys:
            for share in shares[key.version][:key.committee.threshold]:
                ready.append(make_readiness(cls.curve, chain_id or cls.chain_id, transition,
                                             key.version, share, identities[share.member]))
        return PreparedTransition(transition, tuple(ready))

    def chain(self, epoch_length=10):
        return AuditChain(self.curve, self.chain_id, self.initial, epoch_length)

    def activate(self, chain, prepared):
        while chain.height < prepared.transition.activation_height - 1:
            chain.connect(prepared)
        return chain.connect()

    def test_canonical_config_roundtrip(self):
        for config in (self.initial, self.handed, self.rolled):
            encoded = config.to_bytes()
            self.assertLessEqual(len(encoded), MAX_CONFIG_BYTES)
            self.assertEqual(AuditConfig.from_bytes(encoded, self.curve), config)

    def test_malformed_config_wire_rejected(self):
        wire = self.initial.to_bytes()
        for bad in (b'', wire[:-1], wire + b'\x00', b'BAD!' + wire[4:],
                    wire[:44] + b'\x00' + wire[45:],
                    wire[:44] + b'\xff' + wire[45:], b'x' * (MAX_CONFIG_BYTES + 1)):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    AuditConfig.from_bytes(bad, self.curve)

    def test_noncanonical_config_rejected(self):
        for config in (replace(self.initial, generation=True),
                       replace(self.initial, active_version=True),
                       replace(self.initial, identities=self.initial.identities[::-1]),
                       replace(self.initial, identities=(self.initial.identities[0],) * 2),
                       replace(self.initial, keys=()),
                       replace(self.initial, keys=(replace(self.initial.keys[0], version=2),))):
            with self.assertRaises(ValueError):
                config.validate(self.curve)

    def test_no_vote_is_not_automatic_rotation(self):
        chain = self.chain()
        for _ in range(20):
            chain.connect()
        self.assertEqual(chain.current, self.initial)

    def test_four_fifths_counts_blocks_not_ready_signers(self):
        # Four ready shareholders satisfy the new decryption threshold, but only
        # seven block votes in a ten-block epoch cannot change governance.
        chain = self.chain()
        self.assertEqual(len(self.prepared.readiness), 4)
        for _ in range(7):
            chain.connect(self.prepared)
        for _ in range(3):
            chain.connect()
        self.assertEqual(chain.height, 10)
        self.assertEqual(chain.current, self.initial)

    def test_exact_threshold_activates_at_boundary(self):
        chain = self.chain()
        historical = chain.output_reference(0)
        for _ in range(8):
            chain.connect(self.prepared)
        self.assertEqual(chain.current, self.initial)
        chain.connect()
        self.assertEqual(chain.current, self.initial)
        self.assertEqual(chain.next_config(), self.handed)
        chain.connect()
        self.assertEqual(chain.current, self.handed)
        key = chain.historical_key(historical)
        self.assertEqual(key.public_key, self.old.public_key)
        self.assertEqual(key.committee, self.new)

    def test_nondivisible_epoch_rounds_four_fifths_up(self):
        prepared = self.prepare(self.initial, self.handed, 6, {1: self.new_shares}, self.new_identities)
        chain = self.chain(epoch_length=6)
        for _ in range(4):
            chain.connect(prepared)
        chain.connect()
        chain.connect()
        self.assertEqual(chain.current, self.initial)
        chain = self.chain(epoch_length=6)
        self.activate(chain, prepared)
        self.assertEqual(chain.current, self.handed)

    def test_readiness_must_cover_a_distinct_quorum(self):
        for ready in (self.prepared.readiness[:3], self.prepared.readiness[:3] + self.prepared.readiness[:1],
                      self.prepared.readiness[::-1]):
            with self.assertRaises(ValueError):
                self.chain().connect(replace(self.prepared, readiness=ready))

    def test_readiness_proof_and_identity_signature_both_required(self):
        first = self.prepared.readiness[0]
        c, z = first.possession_proof
        for bad in (replace(first, possession_proof=(c, (z + 1) % ORDER)),
                    replace(first, signature=bytes(64)), replace(first, member=100),
                    replace(first, version=2), replace(first, version=True)):
            with self.assertRaises(ValueError):
                verify_readiness(self.curve, self.chain_id,
                                 replace(self.prepared, readiness=(bad,) + self.prepared.readiness[1:]))

    def test_readiness_cannot_replay_across_chain_or_candidate(self):
        with self.assertRaises(ValueError):
            verify_readiness(self.curve, named('another chain'), self.prepared)
        for transition in (replace(self.prepared.transition, activation_height=20),
                           replace(self.prepared.transition, previous=named('different parent')),
                           replace(self.prepared.transition,
                                   config=replace(self.handed, signer_policy=named('different script')))):
            with self.assertRaises(ValueError):
                verify_readiness(self.curve, self.chain_id,
                                 replace(self.prepared, transition=transition))

    def test_wrong_share_or_identity_secret_cannot_acknowledge(self):
        share = self.new_shares[0]
        with self.assertRaises(ValueError):
            make_readiness(self.curve, self.chain_id, self.prepared.transition, 1,
                           replace(share, value=(share.value + 1) % ORDER), self.new_identities[share.member])
        with self.assertRaises(ValueError):
            make_readiness(self.curve, self.chain_id, self.prepared.transition, 1,
                           share, random_scalar())

    def test_transition_parent_generation_and_height_are_enforced(self):
        for transition in (replace(self.prepared.transition, previous=named('different parent')),
                           replace(self.prepared.transition, activation_height=11),
                           replace(self.prepared.transition, config=replace(self.handed, generation=3))):
            with self.assertRaises(ValueError):
                self.chain().connect(replace(self.prepared, transition=transition))

    def test_key_identity_cannot_change_during_routine_handoff(self):
        config = replace(self.handed, keys=(AuditKey(1, 1, self.fresh),))
        prepared = self.prepare(self.initial, config, 10, {1: self.fresh_shares}, self.new_identities)
        with self.assertRaises(ValueError):
            self.chain().connect(prepared)

    def test_share_epoch_must_increment_exactly_once(self):
        for epoch in (0, 2):
            bad_committee = replace(self.new, epoch=epoch)
            config = replace(self.handed, keys=(AuditKey(1, 1, bad_committee),))
            with self.assertRaises(ValueError):
                self.chain().connect(replace(self.prepared,
                                             transition=replace(self.prepared.transition, config=config)))

    def test_rollover_keeps_history_and_rejects_stale_new_outputs(self):
        chain = self.chain()
        historical = chain.output_reference(0)
        self.activate(chain, self.prepared)
        for _ in range(8):
            chain.connect(self.rollover)
        chain.connect()
        self.assertEqual(chain.height, 19)
        # Mempool validation anticipates the key effective in the next block.
        with self.assertRaises(ValueError):
            chain.require_new_output(1, 1, self.old.public_key)
        chain.require_new_output(2, 1, self.fresh.public_key)
        chain.connect()
        self.assertEqual(chain.current, self.rolled)
        self.assertEqual(chain.historical_key(historical).committee, self.new)
        current = chain.output_reference(20)
        self.assertEqual(chain.historical_key(current).committee, self.fresh)

    def test_pending_outputs_survive_handoff_when_key_unchanged(self):
        chain = self.chain()
        self.activate(chain, self.prepared)
        chain.require_new_output(1, 1, self.old.public_key)
        with self.assertRaises(ValueError):
            chain.require_new_output(1, 1, G)

    def test_archived_keys_cannot_be_deleted_or_silently_rekeyed(self):
        chain = self.chain()
        self.activate(chain, self.prepared)
        self.activate(chain, self.rollover)
        for config in (replace(self.rolled, generation=3, keys=(self.rolled.keys[-1],)),
                       replace(self.rolled, generation=3, active_version=1),
                       replace(self.rolled, generation=3,
                               keys=(replace(self.rolled.keys[0], scheme=2), self.rolled.keys[1]))):
            with self.assertRaises(ValueError):
                chain.connect(PreparedTransition(Transition(chain.current.binding(), 30, config), ()))

    def test_rollover_needs_readiness_for_historical_and_new_keys(self):
        chain = self.chain()
        self.activate(chain, self.prepared)
        for version in (1, 2):
            ready = tuple(r for r in self.rollover.readiness if r.version == version)
            with self.assertRaises(ValueError):
                chain.connect(replace(self.rollover, readiness=ready))

    def test_new_key_must_have_a_new_public_key(self):
        fake_new_key = replace(self.handed.keys[0], version=2,
                               committee=replace(self.new, epoch=0))
        config = replace(self.rolled, keys=(self.handed.keys[0], fake_new_key))
        with self.assertRaises(ValueError):
            self.chain_after_handoff().connect(PreparedTransition(Transition(self.handed.binding(), 20, config), ()))

    def chain_after_handoff(self):
        chain = self.chain()
        self.activate(chain, self.prepared)
        return chain

    def test_reorg_rolls_back_policy_not_disclosed_secrets(self):
        chain = self.chain_after_handoff()
        self.activate(chain, self.rollover)
        orphan = chain.output_reference(20)
        external_disclosure = {'already_released': b'plaintext is not revocable'}
        chain.disconnect()
        self.assertEqual(chain.current, self.handed)
        with self.assertRaises(ValueError):
            chain.historical_key(orphan)
        # Removing the boundary block alone leaves the approving epoch intact.
        self.assertEqual(chain.next_config(), self.rolled)
        chain.disconnect()
        chain.disconnect()  # Remove one approving vote: 7 instead of 8.
        chain.connect()
        chain.connect()
        self.assertEqual(chain.next_config(), self.handed)
        chain.require_new_output(1, 1, self.old.public_key)
        chain.connect()
        self.assertEqual(chain.current, self.handed)
        self.assertEqual(external_disclosure['already_released'], b'plaintext is not revocable')

    def test_historical_reference_cannot_change_key_or_creation_branch(self):
        chain = self.chain_after_handoff()
        reference = chain.output_reference(0)
        for bad in (replace(reference, key_version=2), replace(reference, scheme=2),
                    replace(reference, public_key=G), replace(reference, creation_block=named('unknown block'))):
            with self.assertRaises(ValueError):
                chain.historical_key(bad)

    def test_unsupported_scheme_and_invalid_genesis_rejected(self):
        for config in (replace(self.initial, generation=1),
                       replace(self.initial, keys=(self.initial.keys[0],
                                                   replace(self.initial.keys[0], version=2))),
                       replace(self.initial, keys=(replace(self.initial.keys[0],
                                                           committee=replace(self.old, epoch=1)),)),
                       replace(self.initial, keys=(replace(self.initial.keys[0], scheme=2),))):
            with self.assertRaises(ValueError):
                AuditChain(self.curve, self.chain_id, config)
        with self.assertRaises(ValueError):
            self.chain().disconnect()


if __name__ == '__main__':
    unittest.main()
