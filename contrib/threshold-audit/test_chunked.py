# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial checks for native-range-proof-linked chunk recovery."""

from dataclasses import replace
import hashlib
import os
import unittest

from curve import Curve, G, INF, ORDER, random_scalar
from disclosure import Approval, AuditLog, Policy, Request, disclose
from recovery import Ciphertext, Opening, Statement, digest, encrypt_opening, index_bytes, verify_packet
from threshold import simulate_keygen, simulate_handoff
from chunked import (
    CHUNK_MAX, MAX_RANGE_BYTES, RANGE_ASSET,
    ChunkPacket, SmallLog, _encrypt_unchecked, bridge_prove, bridge_verify,
    chunk_bases, combine_chunked, encrypt_chunked, envelope_context,
    partial_decrypt_chunked, proof_context, range_context, range_generator,
    scheme_digest, verify_chunked, verify_partial_chunked,
)


def named(label):
    return hashlib.sha256(label.encode()).digest()


class ChunkedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = os.environ.get('THRESHOLD_AUDIT_SECP256K1')
        if not library:
            raise RuntimeError('Set THRESHOLD_AUDIT_SECP256K1; see README.md')
        cls.curve = Curve(library)
        cls.addClassCleanup(cls.curve.close)
        cls.committee, cls.shares = simulate_keygen(cls.curve, tuple(range(1, 11)), 7)
        cls.assets = tuple(sorted((named('asset A'), named('asset B'))))
        cls.opening = Opening(cls.assets[0], 125_000_000, random_scalar(), random_scalar())
        cls.statement = cls.statement_for(cls.opening)
        cls.packet = encrypt_chunked(cls.curve, cls.statement, cls.opening)
        cls.request = named('scoped request')
        cls.partials = tuple(partial_decrypt_chunked(cls.curve, cls.statement, cls.packet,
                                                    cls.committee, s, cls.request) for s in cls.shares[:7])

    @classmethod
    def statement_for(cls, opening):
        asset = cls.curve.asset_commitment(opening.asset, opening.asset_blinder)
        value = cls.curve.value_commitment(asset, opening.amount, opening.value_blinder)
        return Statement(named('chain'), named('transaction excluding audit'), 1, b'\x51',
                         asset, value, cls.committee.public_key, cls.assets)

    def test_serialization_and_full_opening_recovery(self):
        wire = self.packet.to_bytes()
        self.assertEqual(ChunkPacket.from_bytes(wire, self.statement, self.curve), self.packet)
        self.assertTrue(verify_chunked(self.curve, self.statement, self.packet))
        self.assertEqual(combine_chunked(self.curve, self.statement, self.packet,
                                         self.committee, self.partials, self.request), self.opening)
        self.assertEqual(len(wire), 54628)

    def test_same_full_opening_contract_as_reference(self):
        reference = encrypt_opening(self.curve, self.statement, self.opening)
        self.assertTrue(verify_packet(self.curve, self.statement, reference))
        self.assertLess(len(self.packet.to_bytes()), len(reference.to_bytes()) // 2)

    def test_second_asset_and_larger_than_threshold_quorum(self):
        opening = replace(self.opening, asset=self.assets[1])
        statement = self.statement_for(opening)
        packet = encrypt_chunked(self.curve, statement, opening)
        self.assertTrue(verify_chunked(self.curve, statement, packet))
        partials = tuple(partial_decrypt_chunked(self.curve, statement, packet, self.committee,
                                                share, self.request) for share in self.shares)
        for selected in (partials, partials[3:]):
            self.assertEqual(combine_chunked(self.curve, statement, packet, self.committee,
                                             selected, self.request), opening)

    def test_chunked_signed_disclosure_and_scheme_separation(self):
        secrets = tuple(random_scalar() for _ in self.committee.members)
        policy = Policy(self.committee.binding(), 7,
                        tuple((i, self.curve.mul(s)[1:]) for i, s in zip(self.committee.members, secrets)))
        request = Request(policy.binding(), self.statement.binding(), digest(b'packet', self.packet.to_bytes()),
                          named('opaque case'), self.curve.mul(random_scalar()), 200)
        approvals = tuple(Approval(i, self.curve.sign(s, request.binding()))
                          for i, s in zip(self.committee.members[:7], secrets[:7]))
        log = AuditLog()
        opening, receipt = disclose(self.curve, self.statement, self.packet, self.committee, self.shares[:7],
                                    policy, request, approvals, 100, log, scheme=2)
        self.assertEqual(opening, self.opening)
        self.assertTrue(log.verify(receipt))
        for scheme in (1, 3, True):
            with self.assertRaises(ValueError):
                disclose(self.curve, self.statement, self.packet, self.committee, self.shares[:7],
                          policy, request, approvals, 100, AuditLog(), scheme=scheme)

    def test_false_openings_keep_valid_chunk_and_bridge_proofs(self):
        # Only final asset/value consistency should reject these packets: the
        # limb encryption, native ranges and bridge proofs are all well formed.
        c, s = self.curve, self.statement
        for opening in (replace(self.opening, amount=self.opening.amount + 1),
                        replace(self.opening, asset_blinder=(self.opening.asset_blinder + 1) % ORDER),
                        replace(self.opening, value_blinder=(self.opening.value_blinder + 1) % ORDER),
                        replace(self.opening, asset=self.assets[1])):
            with self.subTest(field=opening):
                packet = _encrypt_unchecked(c, s, opening)
                envelope, context = envelope_context(s, packet), proof_context(s, packet)
                for j, (chunk, base) in enumerate(zip(packet.chunks, chunk_bases(c, s))):
                    self.assertEqual(c.rangeproof_bounds(range_generator(c), chunk.commitment,
                                                         chunk.range_proof, range_context(envelope, j)),
                                     (0, CHUNK_MAX))
                    self.assertTrue(bridge_verify(c, base, s.audit_key, chunk.ciphertext, chunk.commitment,
                                                   chunk.bridge, scheme_digest(b'bridge-index', context, index_bytes(j))))
                self.assertFalse(verify_chunked(c, s, packet))

    def test_range_proof_without_correct_bridge_is_insufficient(self):
        c, key, base = self.curve, self.statement.audit_key, G
        r, u = random_scalar(), random_scalar()
        ciphertext = Ciphertext(c.mul(r), c.linear(((CHUNK_MAX + 1, base), (r, key))))
        commitment, native = c.bounded_rangeproof(range_generator(c), 0, u, b'context')
        self.assertEqual(c.rangeproof_bounds(range_generator(c), commitment, native, b'context'), (0, CHUNK_MAX))
        proof = bridge_prove(c, base, key, ciphertext, commitment,
                              (CHUNK_MAX + 1, r, u), b'bridge context')
        self.assertFalse(bridge_verify(c, base, key, ciphertext, commitment, proof, b'bridge context'))

    def test_wrong_native_range_rejected_even_with_valid_bridges(self):
        opening = Opening(self.assets[0], 1, 0, 1)
        statement = self.statement_for(opening)
        packet = _encrypt_unchecked(self.curve, statement, opening, range_bits=8)
        envelope, context = envelope_context(statement, packet), proof_context(statement, packet)
        for j, (chunk, base) in enumerate(zip(packet.chunks, chunk_bases(self.curve, statement))):
            self.assertEqual(self.curve.rangeproof_bounds(range_generator(self.curve), chunk.commitment,
                                                          chunk.range_proof, range_context(envelope, j)), (0, 255))
            self.assertTrue(bridge_verify(self.curve, base, statement.audit_key, chunk.ciphertext,
                                          chunk.commitment, chunk.bridge,
                                          scheme_digest(b'bridge-index', context, index_bytes(j))))
        # The parser accepts the bounded sizes; verification must enforce 16 bits.
        parsed = ChunkPacket.from_bytes(packet.to_bytes(), statement, self.curve)
        self.assertFalse(verify_chunked(self.curve, statement, parsed))

    def test_bsgs_zero_boundaries_and_distinct_bases(self):
        c = self.curve
        for base in (G, c.asset_generator(RANGE_ASSET)):
            table = SmallLog(c, base)
            for value in (0, 1, 255, 256, CHUNK_MAX):
                self.assertEqual(table.decode(c.mul(value, base)), value)
            for value in (CHUNK_MAX + 1, ORDER - 1):
                with self.assertRaises(ValueError):
                    table.decode(c.mul(value, base))
        with self.assertRaises(ValueError):
            SmallLog(c, INF)

    def test_amount_and_blinder_boundaries(self):
        for amount, abf, vbf in ((0, 0, 1), (2**64 - 1, ORDER - 1, ORDER - 1)):
            with self.subTest(amount=amount):
                opening = Opening(self.assets[0], amount, abf, vbf)
                statement = self.statement_for(opening)
                packet = encrypt_chunked(self.curve, statement, opening)
                self.assertTrue(verify_chunked(self.curve, statement, packet))
                partials = tuple(partial_decrypt_chunked(self.curve, statement, packet,
                                                        self.committee, share, self.request) for share in self.shares[:7])
                self.assertEqual(combine_chunked(self.curve, statement, packet, self.committee,
                                                 partials, self.request), opening)

    def test_scalar_alias_normalizes(self):
        opening = Opening(self.assets[0], 42, 1, 2)
        statement = self.statement_for(opening)
        packet = _encrypt_unchecked(self.curve, statement, replace(opening, asset_blinder=ORDER + 1))
        self.assertTrue(verify_chunked(self.curve, statement, packet))
        partials = tuple(partial_decrypt_chunked(self.curve, statement, packet, self.committee,
                                                share, self.request) for share in self.shares[:7])
        self.assertEqual(combine_chunked(self.curve, statement, packet, self.committee,
                                         partials, self.request), opening)

    def test_membership_handoff_preserves_historical_full_opening(self):
        new, shares = simulate_handoff(self.curve, self.committee, self.shares[:7], tuple(range(101, 116)), 11)
        partials = tuple(partial_decrypt_chunked(self.curve, self.statement, self.packet,
                                                new, share, self.request) for share in shares[:11])
        self.assertEqual(new.public_key, self.statement.audit_key)
        self.assertEqual(combine_chunked(self.curve, self.statement, self.packet, new,
                                         partials, self.request), self.opening)

    def test_insufficient_duplicate_and_mixed_quorums_rejected(self):
        for partials in (self.partials[:6], self.partials[:6] + self.partials[:1]):
            with self.assertRaises(ValueError):
                combine_chunked(self.curve, self.statement, self.packet,
                                 self.committee, partials, self.request)
        refreshed, shares = simulate_handoff(self.curve, self.committee, self.shares[:7], self.committee.members, 7)
        with self.assertRaises(ValueError):
            partial_decrypt_chunked(self.curve, self.statement, self.packet, refreshed, self.shares[0], self.request)

    def test_tampered_partial_wrong_request_and_changed_packet(self):
        partial = self.partials[0]
        bad = replace(partial, points=(self.curve.add(partial.points[0], G),) + partial.points[1:])
        self.assertFalse(verify_partial_chunked(self.curve, self.statement, self.packet,
                                               self.committee, bad, self.request))
        self.assertFalse(verify_partial_chunked(self.curve, self.statement, self.packet,
                                               self.committee, partial, named('other request')))
        c, z = self.packet.value_proof
        changed = replace(self.packet, value_proof=(c, (z + 1) % ORDER))
        self.assertFalse(verify_partial_chunked(self.curve, self.statement, changed,
                                               self.committee, partial, self.request))
        with self.assertRaises(ValueError):
            combine_chunked(self.curve, self.statement, self.packet, self.committee,
                             (bad,) + self.partials[1:], self.request)

    def test_public_input_replay_rejected(self):
        for field, value in (('chain_id', named('other chain')), ('tx_digest', named('other transaction')),
                             ('output_index', 2), ('script', b'\x6a'),
                             ('audit_key', self.curve.mul(random_scalar())),
                             ('assets', tuple(sorted((*self.assets, named('asset C')))))):
            with self.subTest(field=field):
                self.assertFalse(verify_chunked(self.curve, replace(self.statement, **{field: value}), self.packet))

    def test_missing_modified_and_noncanonical_proofs(self):
        p, first = self.packet, self.packet.chunks[0]
        mutations = (
            replace(first, bridge=first.bridge[:-1]),
            replace(first, bridge=(first.bridge[0] + ORDER,) + first.bridge[1:]),
            replace(first, bridge=(True,) + first.bridge[1:]),
            replace(first, range_proof=first.range_proof[:-1]),
            replace(first, range_proof=b''),
            replace(first, range_proof=bytes(MAX_RANGE_BYTES + 1)),
            replace(first, commitment=b'\x08' + bytes([255]) * 32),
            replace(first, ciphertext=replace(first.ciphertext, first=INF)),
        )
        for first in mutations:
            self.assertFalse(verify_chunked(self.curve, self.statement, replace(p, chunks=(first,) + p.chunks[1:])))
        self.assertFalse(verify_chunked(self.curve, self.statement, replace(p, chunks=p.chunks[:-1])))
        self.assertFalse(verify_chunked(self.curve, self.statement, replace(p, asset_proof=())))
        self.assertFalse(verify_chunked(self.curve, self.statement, replace(p, value_proof=(0, 0))))

    def test_limb_order_and_cross_output_splicing_rejected(self):
        p = self.packet
        self.assertFalse(verify_chunked(self.curve, self.statement,
                                        replace(p, chunks=(p.chunks[1], p.chunks[0]) + p.chunks[2:])))
        other = encrypt_chunked(self.curve, self.statement, self.opening)
        self.assertFalse(verify_chunked(self.curve, self.statement,
                                        replace(p, chunks=(other.chunks[0],) + p.chunks[1:])))

    def test_malformed_wire_and_cross_scheme_packets_rejected(self):
        wire = self.packet.to_bytes()
        for bad in (b'', wire[:-1], wire + b'\x00', b'TAR1' + wire[4:],
                    wire[:4] + INF + wire[37:],
                    wire[:103] + bytes(2) + wire[105:],
                    wire[:103] + (MAX_RANGE_BYTES + 1).to_bytes(2, 'big') + wire[105:],
                    wire[:105 + len(self.packet.chunks[0].range_proof)]
                    + ORDER.to_bytes(32, 'big')
                    + wire[137 + len(self.packet.chunks[0].range_proof):]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    ChunkPacket.from_bytes(bad, self.statement, self.curve)

    def test_random_wire_mutations_never_validate(self):
        wire = self.packet.to_bytes()
        # Exercise points, scalar encodings, the native proof, and final links.
        for index in (0, 4, 36, 37, 69, 70, 102, 103, 104, 105, 400, 1387, 1388, len(wire) - 1):
            bad = bytearray(wire)
            bad[index] ^= 1
            try:
                parsed = ChunkPacket.from_bytes(bytes(bad), self.statement, self.curve)
            except ValueError:
                continue
            self.assertFalse(verify_chunked(self.curve, self.statement, parsed))


if __name__ == '__main__':
    unittest.main()
