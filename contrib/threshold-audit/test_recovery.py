# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial tests for the isolated experiment; no daemon or network required."""

from dataclasses import replace
import hashlib
import os
import unittest

from curve import Curve, G, INF, ORDER, random_scalar, rewind_nonce, scalar_bytes
from disclosure import Approval, AuditLog, Policy, Request, authorize, disclose
from recovery import (
    BIT_COUNT, Ciphertext, Opening, Packet, Statement, _encrypt_unchecked,
    digest, encrypt_opening, group_bases, index_bytes,
    or_prove, or_verify, packet_context, verify_packet,
)
from threshold import (
    Committee, accept_handoff, combine, handoff_contributions, partial_decrypt,
    simulate_handoff, simulate_keygen, verify_contribution, verify_partial,
)


def named(label):
    return hashlib.sha256(label.encode()).digest()


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = os.environ.get('THRESHOLD_AUDIT_SECP256K1')
        if not library:
            raise RuntimeError('Set THRESHOLD_AUDIT_SECP256K1 to the bundled shared library; see README.md')
        cls.curve = Curve(library)
        cls.addClassCleanup(cls.curve.close)
        cls.old, cls.shares = simulate_keygen(cls.curve, tuple(range(1, 11)), 7)
        cls.assets = tuple(sorted((named('asset-one'), named('asset-two'))))
        cls.opening = Opening(cls.assets[0], 125_000_000, random_scalar(), random_scalar())
        cls.statement = cls.statement_for(cls.opening)
        cls.packet = encrypt_opening(cls.curve, cls.statement, cls.opening)
        cls.request_binding = named('test request')
        cls.partials = tuple(partial_decrypt(cls.curve, cls.statement, cls.packet, cls.old, share,
                                             cls.request_binding) for share in cls.shares[:7])
        cls.new, cls.new_shares = simulate_handoff(cls.curve, cls.old, cls.shares[:7],
                                                  tuple(range(101, 116)), 11)
        cls.new_partials = tuple(partial_decrypt(cls.curve, cls.statement, cls.packet, cls.new, share,
                                                 cls.request_binding) for share in cls.new_shares[:11])
        cls.approval_secrets = tuple(random_scalar() for _ in cls.old.members)
        cls.policy = Policy(cls.old.binding(), 7,
                            tuple((i, cls.curve.mul(s)[1:])
                                  for i, s in zip(cls.old.members, cls.approval_secrets)))
        cls.request = Request(cls.policy.binding(), cls.statement.binding(),
                              digest(b'packet', cls.packet.to_bytes()), named('opaque case'),
                              cls.curve.mul(random_scalar()), 200)
        cls.approvals = tuple(Approval(i, cls.curve.sign(s, cls.request.binding()))
                              for i, s in zip(cls.old.members[:7], cls.approval_secrets[:7]))

    @classmethod
    def statement_for(cls, opening):
        asset = cls.curve.asset_commitment(opening.asset, opening.asset_blinder)
        value = cls.curve.value_commitment(asset, opening.amount, opening.value_blinder)
        return Statement(named('chain'), named('transaction template excluding recovery'), 2,
                         b'\x00\x14' + named('recipient script')[:20], asset, value,
                         cls.old.public_key, cls.assets)

    def test_real_elements_commitments(self):
        c, o, s = self.curve, self.opening, self.statement
        asset = c.confidential_point(s.asset_commitment, 'asset')
        value = c.confidential_point(s.value_commitment, 'value')
        self.assertEqual(asset, c.add(c.asset_generator(o.asset), c.mul(o.asset_blinder)))
        self.assertEqual(value, c.add(c.mul(o.amount, asset), c.mul(o.value_blinder)))

    def test_public_verification_and_serialization(self):
        wire = self.packet.to_bytes()
        packet = Packet.from_bytes(wire, self.statement, self.curve)
        self.assertEqual(packet, self.packet)
        self.assertTrue(verify_packet(self.curve, self.statement, packet))
        self.assertEqual(len(wire), 4 + BIT_COUNT * 194 + len(self.assets) * 64 + 64)

    def test_recipient_rewinds_without_federation(self):
        c, o, s = self.curve, self.opening, self.statement
        recipient, ephemeral = random_scalar(), random_scalar()
        nonce = rewind_nonce(c, ephemeral, c.mul(recipient))
        message = o.asset + scalar_bytes(o.asset_blinder)
        proof = c.rangeproof(s.asset_commitment, s.value_commitment, o.amount,
                             o.value_blinder, nonce, message, s.script)
        self.assertTrue(c.verify_rangeproof(s.asset_commitment, s.value_commitment, proof, s.script))
        result = c.rewind(s.asset_commitment, s.value_commitment, proof,
                          rewind_nonce(c, recipient, c.mul(ephemeral)), s.script)
        self.assertEqual(result, (o.amount, o.value_blinder, message))
        with self.assertRaises(ValueError):
            c.rewind(s.asset_commitment, s.value_commitment, proof, named('wrong nonce'), s.script)

    def test_false_openings_with_valid_bit_proofs_rejected(self):
        # Bypass the honest wallet's preflight. Every ciphertext still encrypts
        # a bit correctly; ONLY the consistency proofs reject these packets.
        for opening in (replace(self.opening, amount=self.opening.amount + 1),
                        replace(self.opening, asset_blinder=(self.opening.asset_blinder + 1) % ORDER),
                        replace(self.opening, value_blinder=(self.opening.value_blinder + 1) % ORDER),
                        replace(self.opening, asset=self.assets[1])):
            with self.subTest(field=opening):
                packet = _encrypt_unchecked(self.curve, self.statement, opening)
                context = packet_context(self.statement, packet)
                for j, (ciphertext, proof, base) in enumerate(zip(packet.ciphertexts, packet.bit_proofs,
                                                                  group_bases(self.curve, self.statement))):
                    self.assertTrue(or_verify(self.curve, self.statement.audit_key, ciphertext.first,
                                              (ciphertext.second, self.curve.sub(ciphertext.second, base)),
                                              proof, digest(b'bit', context, index_bytes(j))))
                self.assertFalse(verify_packet(self.curve, self.statement, packet))

    def test_honest_wallet_rejects_false_opening(self):
        with self.assertRaises(ValueError):
            encrypt_opening(self.curve, self.statement, replace(self.opening, amount=1))

    def test_non_bit_ciphertext_rejected(self):
        c, s, p = self.curve, self.statement, self.packet
        base, nonce = group_bases(c, s)[0], random_scalar()
        ciphertext = Ciphertext(c.mul(nonce), c.add(c.mul(nonce, s.audit_key), c.mul(2, base)))
        packet = replace(p, ciphertexts=(ciphertext,) + p.ciphertexts[1:])
        # A prover using the correct encryption nonce cannot prove that 2 is 0/1.
        context = digest(b'bit', packet_context(s, packet), index_bytes(0))
        proof = or_prove(c, s.audit_key, ciphertext.first,
                         (ciphertext.second, c.sub(ciphertext.second, base)), 0, nonce, context)
        self.assertFalse(or_verify(c, s.audit_key, ciphertext.first,
                                   (ciphertext.second, c.sub(ciphertext.second, base)), proof, context))

    def test_replay_under_changed_public_inputs_rejected(self):
        for field, value in (
                ('chain_id', named('another chain')), ('tx_digest', named('another transaction')),
                ('output_index', 3), ('script', b'\x51'), ('audit_key', self.curve.mul(random_scalar())),
                ('assets', tuple(sorted((*self.assets, named('another registered asset'))))),
                ('asset_commitment', self.curve.asset_commitment(self.assets[1], random_scalar())),
                ('value_commitment', self.curve.value_commitment(self.statement.asset_commitment, 1, 2))):
            with self.subTest(field=field):
                self.assertFalse(verify_packet(self.curve, replace(self.statement, **{field: value}), self.packet))

    def test_invalid_registry_and_identity_key_rejected(self):
        for change in ({'assets': ()}, {'assets': self.assets[::-1]},
                       {'assets': (self.assets[0],) * 2}, {'audit_key': INF},
                       {'asset_commitment': b'\x0a' + bytes([255]) * 32},
                       {'value_commitment': b'\x08' + bytes(32)}):
            with self.subTest(change=change):
                self.assertFalse(verify_packet(self.curve, replace(self.statement, **change), self.packet))

    def test_malformed_wire_rejected(self):
        wire = self.packet.to_bytes()
        for bad in (b'', wire[:-1], wire + b'\x00', b'BAD!' + wire[4:],
                    wire[:4] + INF + wire[37:],
                    wire[:4] + b'\x02' + bytes([255]) * 32 + wire[37:],
                    wire[:70] + ORDER.to_bytes(32, 'big') + wire[102:]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    Packet.from_bytes(bad, self.statement, self.curve)

    def test_missing_or_tampered_proofs_rejected(self):
        c, z = self.packet.value_proof
        for packet in (replace(self.packet, ciphertexts=self.packet.ciphertexts[:-1]),
                       replace(self.packet, bit_proofs=self.packet.bit_proofs[:-1]),
                       replace(self.packet, asset_proof=()),
                       replace(self.packet, value_proof=(c, (z + 1) % ORDER)),
                       replace(self.packet, value_proof=(c, z + ORDER)),
                       replace(self.packet, value_proof=(True, z))):
            self.assertFalse(verify_packet(self.curve, self.statement, packet))

    def test_amount_boundaries_and_zero_blinders(self):
        for amount, abf, vbf in ((0, 0, 1), (2**64 - 1, ORDER - 1, ORDER - 1)):
            with self.subTest(amount=amount):
                opening = Opening(self.assets[0], amount, abf, vbf)
                statement = self.statement_for(opening)
                packet = encrypt_opening(self.curve, statement, opening)
                self.assertTrue(verify_packet(self.curve, statement, packet))
                partials = tuple(partial_decrypt(self.curve, statement, packet, self.old, share,
                                                 self.request_binding) for share in self.shares[:7])
                self.assertEqual(combine(self.curve, statement, packet, self.old, partials,
                                         self.request_binding), opening)

    def test_scalar_bit_encoding_normalizes_modulo_order(self):
        opening = Opening(self.assets[0], 42, 1, 2)
        statement = self.statement_for(opening)
        packet = _encrypt_unchecked(self.curve, statement, replace(opening, asset_blinder=ORDER + 1))
        self.assertTrue(verify_packet(self.curve, statement, packet))
        partials = tuple(partial_decrypt(self.curve, statement, packet, self.old, share,
                                         self.request_binding) for share in self.shares[:7])
        self.assertEqual(combine(self.curve, statement, packet, self.old, partials,
                                 self.request_binding), opening)

    def test_seven_of_ten_recovers(self):
        self.assertEqual(combine(self.curve, self.statement, self.packet, self.old,
                                 self.partials, self.request_binding), self.opening)

    def test_six_of_ten_and_duplicate_members_rejected(self):
        for partials in (self.partials[:6], self.partials[:6] + self.partials[:1]):
            with self.assertRaises(ValueError):
                combine(self.curve, self.statement, self.packet, self.old, partials, self.request_binding)

    def test_tampered_partial_and_wrong_request_rejected(self):
        partial = self.partials[0]
        bad = replace(partial, points=(self.curve.add(partial.points[0], G),) + partial.points[1:])
        self.assertFalse(verify_partial(self.curve, self.statement, self.packet, self.old,
                                        bad, self.request_binding))
        self.assertFalse(verify_partial(self.curve, self.statement, self.packet, self.old,
                                        partial, named('different request')))
        self.assertFalse(verify_partial(self.curve, self.statement,
                                        replace(self.packet, ciphertexts=self.packet.ciphertexts[:-1]),
                                        self.old, partial, self.request_binding))
        with self.assertRaises(ValueError):
            combine(self.curve, self.statement, self.packet, self.old,
                     (bad,) + self.partials[1:], self.request_binding)

    def test_new_eleven_of_fifteen_recovers_unchanged_history(self):
        self.assertEqual(self.old.public_key, self.new.public_key)
        self.assertEqual(self.new.threshold, 11)
        self.assertEqual(combine(self.curve, self.statement, self.packet, self.new,
                                 self.new_partials, self.request_binding), self.opening)
        with self.assertRaises(ValueError):
            combine(self.curve, self.statement, self.packet, self.new,
                     self.new_partials[:10], self.request_binding)

    def test_mixed_epochs_and_departed_share_rejected_by_current_api(self):
        with self.assertRaises(ValueError):
            partial_decrypt(self.curve, self.statement, self.packet, self.new,
                            self.shares[0], self.request_binding)
        with self.assertRaises(ValueError):
            combine(self.curve, self.statement, self.packet, self.new,
                     self.new_partials[:10] + self.partials[:1], self.request_binding)

    def test_retained_old_quorum_still_decrypts_without_approval_or_log(self):
        # This is an intended limitation, not revocation. The new committee did
        # not change the encryption key; copied old quorum shares still work.
        log = AuditLog()
        self.assertEqual(combine(self.curve, self.statement, self.packet, self.old,
                                 self.partials, self.request_binding), self.opening)
        self.assertEqual(log.entries, [])

    def test_refresh_without_membership_change(self):
        refreshed, shares = simulate_handoff(self.curve, self.old, self.shares[:7], self.old.members, 7)
        self.assertEqual(refreshed.public_key, self.old.public_key)
        self.assertNotEqual(shares[0].value, self.shares[0].value)

    def test_corrupted_handoff_evaluation_rejected(self):
        contributions = handoff_contributions(self.curve, self.old, self.shares[:7], self.new.members, 11)
        member, value = contributions[0].evaluations[0]
        bad = replace(contributions[0], evaluations=((member, (value + 1) % ORDER),)
                      + contributions[0].evaluations[1:])
        with self.assertRaises(ValueError):
            accept_handoff(self.curve, self.old, self.new.members, 11, (bad,) + contributions[1:])

    def test_internally_consistent_handoff_cannot_change_secret(self):
        contributions = handoff_contributions(self.curve, self.old, self.shares[:7], self.new.members, 11)
        first = contributions[0]
        bad = replace(first, commitments=(self.curve.add(first.commitments[0], G),) + first.commitments[1:],
                      evaluations=tuple((i, (v + 1) % ORDER) for i, v in first.evaluations))
        verify_contribution(self.curve, bad, self.new.members, 11)  # Valid VSS, wrong root.
        with self.assertRaises(ValueError):
            accept_handoff(self.curve, self.old, self.new.members, 11, (bad,) + contributions[1:])

    def test_handoff_needs_distinct_old_quorum(self):
        for shares in (self.shares[:6], self.shares[:6] + self.shares[:1]):
            with self.assertRaises(ValueError):
                simulate_handoff(self.curve, self.old, shares, self.new.members, 11)

    def test_duplicate_handoff_dealer_rejected(self):
        contributions = handoff_contributions(self.curve, self.old, self.shares[:7], self.new.members, 11)
        with self.assertRaises(ValueError):
            accept_handoff(self.curve, self.old, self.new.members, 11,
                           contributions[:6] + contributions[:1])

    def test_invalid_share_and_verification_key_rejected(self):
        with self.assertRaises(ValueError):
            partial_decrypt(self.curve, self.statement, self.packet, self.old,
                            replace(self.shares[0], value=(self.shares[0].value + 1) % ORDER),
                            self.request_binding)
        invalid = replace(self.old, commitments=self.old.commitments[:-1] + (INF,))
        with self.assertRaises(ValueError):
            invalid.validate(self.curve)

    def test_invalid_thresholds_and_rosters(self):
        for members, threshold in (((1, 2), 0), ((1, 2), 3), ((1, 1), 1), ((0, 1), 1), ((2, 1), 1)):
            with self.assertRaises(ValueError):
                simulate_keygen(self.curve, members, threshold)

    def test_public_zero_share_cannot_count_as_private_quorum_participation(self):
        # f(X)=17*(X-1) has degree one but f(1)=0 is publicly known. Without
        # this rejection one live member plus a fabricated zero-share partial
        # could satisfy a nominal two-member quorum.
        committee = Committee(0, (1, 2, 3), (self.curve.mul(-17), self.curve.mul(17)))
        self.assertEqual(committee.verification_key(self.curve, 1), INF)
        with self.assertRaises(ValueError):
            committee.validate(self.curve)

    def test_independent_signed_approvals(self):
        authorize(self.curve, self.policy, self.request, self.approvals, 100)
        for approvals in (self.approvals[:6], self.approvals[:6] + self.approvals[:1],
                          (replace(self.approvals[0], signature=bytes(64)),) + self.approvals[1:]):
            with self.assertRaises(ValueError):
                authorize(self.curve, self.policy, self.request, approvals, 100)

    def test_expired_and_scope_changed_approvals_rejected(self):
        for request, now in ((self.request, 200),
                             (replace(self.request, recipient_key=G), 100),
                             (replace(self.request, case_reference=named('different case')), 100),
                             (replace(self.request, policy_binding=named('different policy')), 100)):
            with self.assertRaises(ValueError):
                authorize(self.curve, self.policy, request, self.approvals, now)

    def test_logged_disclosure_does_not_publish_secrets(self):
        log = AuditLog()
        opening, receipt = disclose(self.curve, self.statement, self.packet, self.old, self.shares[:7],
                                    self.policy, self.request, self.approvals, 100, log)
        self.assertEqual(opening, self.opening)
        self.assertEqual(len(log.entries), 2)
        self.assertTrue(log.verify(receipt))
        for secret in (scalar_bytes(self.opening.asset_blinder), scalar_bytes(self.opening.value_blinder),
                       scalar_bytes(self.shares[0].value), self.partials[0].points[0]):
            self.assertNotIn(secret.hex().encode(), b''.join(log.entries))
        log.entries.pop()
        self.assertFalse(log.verify(receipt))

    def test_unapproved_disclosure_produces_no_log_or_output(self):
        log = AuditLog()
        with self.assertRaises(ValueError):
            disclose(self.curve, self.statement, self.packet, self.old, self.shares[:7],
                      self.policy, self.request, self.approvals[:6], 100, log)
        self.assertEqual(log.entries, [])

    def test_signed_request_for_another_packet_rejected(self):
        request = replace(self.request, packet_binding=named('different packet'))
        approvals = tuple(Approval(i, self.curve.sign(s, request.binding()))
                          for i, s in zip(self.old.members[:7], self.approval_secrets[:7]))
        with self.assertRaises(ValueError):
            disclose(self.curve, self.statement, self.packet, self.old, self.shares[:7],
                      self.policy, request, approvals, 100, AuditLog())

    def test_current_committee_requires_current_approval_policy(self):
        with self.assertRaises(ValueError):
            disclose(self.curve, self.statement, self.packet, self.new, self.new_shares[:11],
                      self.policy, self.request, self.approvals, 100, AuditLog())
        secrets = tuple(random_scalar() for _ in self.new.members)
        policy = Policy(self.new.binding(), 11,
                        tuple((i, self.curve.mul(s)[1:]) for i, s in zip(self.new.members, secrets)))
        request = replace(self.request, policy_binding=policy.binding())
        approvals = tuple(Approval(i, self.curve.sign(s, request.binding()))
                          for i, s in zip(self.new.members[:11], secrets[:11]))
        log = AuditLog()
        opening, receipt = disclose(self.curve, self.statement, self.packet, self.new,
                                    self.new_shares[:11], policy, request, approvals, 100, log)
        self.assertEqual(opening, self.opening)
        self.assertTrue(log.verify(receipt))


if __name__ == '__main__':
    unittest.main()
