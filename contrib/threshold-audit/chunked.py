# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Unreviewed full-opening recovery using small ElGamal chunks.

This second research scheme preserves all TAR1 recovered fields. Native range
proofs bound independent Pedersen chunk commitments; representation proofs bind
them to ciphertexts. It is not an authenticated/CCA-secure encryption API.
"""

from dataclasses import dataclass
import hashlib

from curve import G, INF, ORDER, random_scalar, scalar_bytes
from recovery import (
    Ciphertext, Opening, canonical_proof, challenge, digest,
    dleq_prove, dleq_verify, index_bytes, opening_matches, or_prove, or_verify,
)
from threshold import PartialDecryption, lagrange, validate_share

MAGIC = b'TAC2'
CHUNK_BITS = 16
FIELD_CHUNKS = (4, 16, 16)
CHUNK_COUNT = sum(FIELD_CHUNKS)
CHUNK_MAX = (1 << CHUNK_BITS) - 1
MAX_RANGE_BYTES = 1536
RANGE_ASSET = hashlib.sha256(b'Elements/threshold-audit/TAC2/range-generator').digest()


def scheme_digest(label, *parts):
    return digest(b'TAC2/' + label, *parts)


def range_generator(curve):
    return curve.asset_commitment(RANGE_ASSET, 0)


def canonical_bridge(proof):
    return (isinstance(proof, tuple) and len(proof) == 4
            and all(type(v) is int and 0 <= v < ORDER for v in proof))


def bridge_prove(curve, base, key, ciphertext, commitment, witnesses, context):
    """Knowledge of (m,r,u): R=rG; S=mB+rY; T=mH+uG."""
    m, r, u = witnesses
    wm, wr, wu = (random_scalar() for _ in range(3))
    h = curve.asset_generator(RANGE_ASSET)
    t = curve.confidential_point(commitment, 'value')
    first = curve.mul(wr)
    second = curve.linear(((wm, base), (wr, key)))
    third = curve.linear(((wm, h), (wu, G)))
    c = challenge(b'TAC2/bridge', context, G, h, base, key, ciphertext.first,
                  ciphertext.second, t, first, second, third)
    return c, (wm + c * m) % ORDER, (wr + c * r) % ORDER, (wu + c * u) % ORDER


def bridge_verify(curve, base, key, ciphertext, commitment, proof, context):
    if not canonical_bridge(proof):
        return False
    c, zm, zr, zu = proof
    h = curve.asset_generator(RANGE_ASSET)
    t = curve.confidential_point(commitment, 'value')
    first = curve.linear(((zr, G), (-c, ciphertext.first)))
    second = curve.linear(((zm, base), (zr, key), (-c, ciphertext.second)))
    third = curve.linear(((zm, h), (zu, G), (-c, t)))
    return c == challenge(b'TAC2/bridge', context, G, h, base, key,
                           ciphertext.first, ciphertext.second, t, first, second, third)


@dataclass(frozen=True)
class Chunk:
    ciphertext: Ciphertext
    commitment: bytes
    range_proof: bytes
    bridge: tuple


@dataclass(frozen=True)
class ChunkPacket:
    chunks: tuple
    asset_proof: tuple
    value_proof: tuple

    @property
    def ciphertexts(self):
        return tuple(chunk.ciphertext for chunk in self.chunks)

    def to_bytes(self):
        if len(self.chunks) != CHUNK_COUNT:
            raise ValueError('incorrect chunk count')
        out = bytearray(MAGIC)
        for chunk in self.chunks:
            c = chunk.ciphertext
            if any(not isinstance(p, bytes) or len(p) != 33 for p in (c.first, c.second, chunk.commitment)):
                raise ValueError('incorrect point size')
            if not isinstance(chunk.range_proof, bytes) or not 1 <= len(chunk.range_proof) <= MAX_RANGE_BYTES:
                raise ValueError('invalid bounded range-proof size')
            if not canonical_bridge(chunk.bridge):
                raise ValueError('invalid representation proof')
            out.extend(c.first + c.second + chunk.commitment)
            out.extend(len(chunk.range_proof).to_bytes(2, 'big'))
            out.extend(chunk.range_proof)
            out.extend(b''.join(scalar_bytes(v) for v in chunk.bridge))
        if not 1 <= len(self.asset_proof) <= 256 or not canonical_proof(self.asset_proof, len(self.asset_proof)):
            raise ValueError('invalid asset proof')
        if not canonical_proof((self.value_proof,), 1):
            raise ValueError('invalid value proof')
        for pair in (*self.asset_proof, self.value_proof):
            out.extend(b''.join(scalar_bytes(v) for v in pair))
        return bytes(out)

    @staticmethod
    def from_bytes(data, statement, curve):
        statement.validate(curve)
        suffix = 64 * (len(statement.assets) + 1)
        maximum = 4 + CHUNK_COUNT * (99 + 2 + MAX_RANGE_BYTES + 128) + suffix
        minimum = 4 + CHUNK_COUNT * (99 + 2 + 1 + 128) + suffix
        if not isinstance(data, bytes) or not minimum <= len(data) <= maximum or data[:4] != MAGIC:
            raise ValueError('invalid chunk-packet version or size')
        offset = 4

        def take(size):
            nonlocal offset
            if offset + size > len(data):
                raise ValueError('truncated chunk packet')
            result = data[offset:offset + size]
            offset += size
            return result

        def scalars(count):
            values = tuple(int.from_bytes(take(32), 'big') for _ in range(count))
            if any(v >= ORDER for v in values):
                raise ValueError('noncanonical proof scalar')
            return values

        chunks = []
        for _ in range(CHUNK_COUNT):
            first, second, commitment = take(33), take(33), take(33)
            curve.parse(first, allow_infinity=False)
            curve.parse(second)
            curve.confidential_point(commitment, 'value')
            length = int.from_bytes(take(2), 'big')
            if not 1 <= length <= MAX_RANGE_BYTES:
                raise ValueError('invalid range-proof length')
            proof = take(length)
            chunks.append(Chunk(Ciphertext(first, second), commitment, proof, scalars(4)))
        result = ChunkPacket(tuple(chunks), tuple(scalars(2) for _ in statement.assets), scalars(2))
        if offset != len(data):
            raise ValueError('trailing chunk-packet data')
        return result


def envelope_context(statement, packet):
    return scheme_digest(b'envelope', statement.binding(), RANGE_ASSET, index_bytes(CHUNK_BITS),
                         b''.join(c.ciphertext.first + c.ciphertext.second + c.commitment
                                  for c in packet.chunks))


def range_context(envelope, index):
    return scheme_digest(b'range', envelope, index_bytes(index))


def proof_context(statement, packet):
    return scheme_digest(b'range-proofs', envelope_context(statement, packet),
                         *(c.range_proof for c in packet.chunks))


def consistency_context(statement, packet):
    return scheme_digest(b'consistency', proof_context(statement, packet),
                         b''.join(scalar_bytes(v) for c in packet.chunks for v in c.bridge))


def chunk_bases(curve, statement):
    a = curve.confidential_point(statement.asset_commitment, 'asset')
    return (a,) * FIELD_CHUNKS[0] + (G,) * sum(FIELD_CHUNKS[1:])


def chunk_aggregates(curve, packet):
    result, start = [], 0
    for count in FIELD_CHUNKS:
        field = packet.ciphertexts[start:start + count]
        result.append(Ciphertext(curve.linear((1 << (CHUNK_BITS * j), c.first) for j, c in enumerate(field)),
                                 curve.linear((1 << (CHUNK_BITS * j), c.second) for j, c in enumerate(field))))
        start += count
    return result


def encrypt_chunked(curve, statement, opening):
    statement.validate(curve)
    if not opening_matches(curve, statement, opening):
        raise ValueError('opening does not match the output')
    return _encrypt_unchecked(curve, statement, opening)


def _encrypt_unchecked(curve, statement, opening, *, range_bits=CHUNK_BITS):
    """Adversarial-test entry point; public encrypt_chunked fixes the width."""
    values = (opening.amount, opening.asset_blinder, opening.value_blinder)
    limbs = tuple((value >> (CHUNK_BITS * j)) & CHUNK_MAX
                  for value, count in zip(values, FIELD_CHUNKS) for j in range(count))
    nonces = tuple(random_scalar() for _ in limbs)
    blinds = tuple(random_scalar() for _ in limbs)
    bases = chunk_bases(curve, statement)
    key, generator = statement.audit_key, range_generator(curve)
    # Prepare every R,S,T before creating native range proofs so their extra
    # commitment binds the entire ciphertext/commitment vector.
    chunks = tuple(Chunk(Ciphertext(curve.mul(r), curve.linear(((m, base), (r, key)))),
                         curve.value_commitment(generator, m, u), b'', ())
                   for m, r, u, base in zip(limbs, nonces, blinds, bases))
    packet = ChunkPacket(chunks, (), ())
    envelope = envelope_context(statement, packet)
    ranged = []
    for j, (chunk, m, u) in enumerate(zip(chunks, limbs, blinds)):
        commitment, proof = curve.bounded_rangeproof(generator, m, u, range_context(envelope, j), range_bits)
        if commitment != chunk.commitment:
            raise ValueError('native commitment mismatch')
        ranged.append(Chunk(chunk.ciphertext, commitment, proof, ()))
    packet = ChunkPacket(tuple(ranged), (), ())
    context = proof_context(statement, packet)
    linked = tuple(Chunk(chunk.ciphertext, chunk.commitment, chunk.range_proof,
                         bridge_prove(curve, base, key, chunk.ciphertext, chunk.commitment,
                                      (m, r, u), scheme_digest(b'bridge-index', context, index_bytes(j))))
                   for j, (chunk, m, r, u, base) in enumerate(zip(ranged, limbs, nonces, blinds, bases)))
    packet = ChunkPacket(linked, (), ())
    context = consistency_context(statement, packet)
    amount, abf, vbf = chunk_aggregates(curve, packet)
    randomness, start = [], 0
    for count in FIELD_CHUNKS:
        randomness.append(sum((1 << (CHUNK_BITS * j)) * nonces[start + j] for j in range(count)) % ORDER)
        start += count
    a = curve.confidential_point(statement.asset_commitment, 'asset')
    alternatives = tuple(curve.add(abf.second, curve.neg(a), curve.asset_generator(asset))
                         for asset in statement.assets)
    asset_proof = or_prove(curve, key, abf.first, alternatives, statement.assets.index(opening.asset),
                           randomness[1], scheme_digest(b'asset', context))
    v = curve.confidential_point(statement.value_commitment, 'value')
    value_proof = dleq_prove(curve, G, key, curve.add(amount.first, vbf.first),
                             curve.add(amount.second, vbf.second, curve.neg(v)),
                             (randomness[0] + randomness[2]) % ORDER, scheme_digest(b'value', context))
    return ChunkPacket(linked, asset_proof, value_proof)


def verify_chunked(curve, statement, packet):
    try:
        statement.validate(curve)
        if len(packet.chunks) != CHUNK_COUNT:
            return False
        # Enforce bounds before hashing/forwarding inputs to native routines.
        for chunk in packet.chunks:
            curve.parse(chunk.ciphertext.first, allow_infinity=False)
            curve.parse(chunk.ciphertext.second)
            curve.confidential_point(chunk.commitment, 'value')
            if (not isinstance(chunk.range_proof, bytes)
                    or not 1 <= len(chunk.range_proof) <= MAX_RANGE_BYTES
                    or not canonical_bridge(chunk.bridge)):
                return False
        envelope = envelope_context(statement, packet)
        context = proof_context(statement, packet)
        generator = range_generator(curve)
        for j, (chunk, base) in enumerate(zip(packet.chunks, chunk_bases(curve, statement))):
            if curve.rangeproof_bounds(generator, chunk.commitment, chunk.range_proof,
                                        range_context(envelope, j)) != (0, CHUNK_MAX):
                return False
            if not bridge_verify(curve, base, statement.audit_key, chunk.ciphertext,
                                  chunk.commitment, chunk.bridge,
                                  scheme_digest(b'bridge-index', context, index_bytes(j))):
                return False
        context = consistency_context(statement, packet)
        amount, abf, vbf = chunk_aggregates(curve, packet)
        a = curve.confidential_point(statement.asset_commitment, 'asset')
        alternatives = tuple(curve.add(abf.second, curve.neg(a), curve.asset_generator(asset))
                             for asset in statement.assets)
        if not or_verify(curve, statement.audit_key, abf.first, alternatives, packet.asset_proof,
                         scheme_digest(b'asset', context)):
            return False
        v = curve.confidential_point(statement.value_commitment, 'value')
        return dleq_verify(curve, G, statement.audit_key, curve.add(amount.first, vbf.first),
                           curve.add(amount.second, vbf.second, curve.neg(v)), packet.value_proof,
                           scheme_digest(b'value', context))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


class SmallLog:
    """Bounded BSGS: 256 baby steps and at most 256 giant steps for 16 bits."""
    def __init__(self, curve, base):
        curve.parse(base, allow_infinity=False)
        self.curve, self.base = curve, base
        self.babies = {}
        point = INF
        for j in range(256):
            self.babies[point] = j
            point = curve.add(point, base)
        self.giant = curve.neg(point)

    def decode(self, target):
        self.curve.parse(target)
        point = target
        for i in range(256):
            if point in self.babies:
                value = 256 * i + self.babies[point]
                if self.curve.mul(value, self.base) == target:
                    return value
            point = self.curve.add(point, self.giant)
        raise ValueError('plaintext lies outside the 16-bit range')


def recover_chunked(curve, statement, plaintexts):
    if len(plaintexts) != CHUNK_COUNT:
        raise ValueError('incorrect decrypted chunk count')
    a = curve.confidential_point(statement.asset_commitment, 'asset')
    tables = {base: SmallLog(curve, base) for base in (a, G)}
    limbs = tuple(tables[base].decode(point)
                  for base, point in zip(chunk_bases(curve, statement), plaintexts))
    values, start = [], 0
    for count in FIELD_CHUNKS:
        values.append(sum(limbs[start + j] << (CHUNK_BITS * j) for j in range(count)))
        start += count
    amount, abf, vbf = values
    abf, vbf = abf % ORDER, vbf % ORDER
    target = curve.sub(a, curve.mul(abf))
    assets = tuple(asset for asset in statement.assets if curve.asset_generator(asset) == target)
    if len(assets) != 1:
        raise ValueError('asset does not resolve uniquely')
    opening = Opening(assets[0], amount, abf, vbf)
    if not opening_matches(curve, statement, opening):
        raise ValueError('decrypted opening is inconsistent')
    return opening


def decryption_context(statement, packet, committee, request_binding, member):
    if not isinstance(request_binding, bytes) or len(request_binding) != 32:
        raise ValueError('request binding must be a 32-byte digest')
    return scheme_digest(b'decryption', statement.binding(), digest(b'packet', packet.to_bytes()),
                         committee.binding(), request_binding, index_bytes(member))


def partial_decrypt_chunked(curve, statement, packet, committee, share, request_binding):
    """Low-level operation; approvals/logging and packet verification are callers' duties."""
    committee.validate(curve)
    statement.validate(curve)
    if statement.audit_key != committee.public_key or len(packet.chunks) != CHUNK_COUNT:
        raise ValueError('wrong audit key or chunk count')
    validate_share(curve, committee, share)
    context = decryption_context(statement, packet, committee, request_binding, share.member)
    key = committee.verification_key(curve, share.member)
    points, proofs = [], []
    for j, ciphertext in enumerate(packet.ciphertexts):
        curve.parse(ciphertext.first, allow_infinity=False)
        point = curve.mul(share.value, ciphertext.first)
        points.append(point)
        proofs.append(dleq_prove(curve, G, ciphertext.first, key, point, share.value,
                                 scheme_digest(b'partial', context, index_bytes(j))))
    return PartialDecryption(share.member, committee.binding(), request_binding, tuple(points), tuple(proofs))


def verify_partial_chunked(curve, statement, packet, committee, partial, request_binding):
    try:
        committee.validate(curve)
        statement.validate(curve)
        if (statement.audit_key != committee.public_key or len(packet.chunks) != CHUNK_COUNT
                or partial.committee_binding != committee.binding()
                or partial.request_binding != request_binding
                or len(partial.points) != CHUNK_COUNT or len(partial.proofs) != CHUNK_COUNT):
            return False
        context = decryption_context(statement, packet, committee, request_binding, partial.member)
        key = committee.verification_key(curve, partial.member)
        for j, (ciphertext, point, proof) in enumerate(zip(packet.ciphertexts, partial.points, partial.proofs)):
            curve.parse(ciphertext.first, allow_infinity=False)
            curve.parse(point)
            if not dleq_verify(curve, G, ciphertext.first, key, point, proof,
                               scheme_digest(b'partial', context, index_bytes(j))):
                return False
        return True
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


def combine_chunked(curve, statement, packet, committee, partials, request_binding):
    committee.validate(curve)
    if statement.audit_key != committee.public_key or not verify_chunked(curve, statement, packet):
        raise ValueError('invalid packet or audit key')
    members = tuple(partial.member for partial in partials)
    if len(members) < committee.threshold or len(set(members)) != len(members):
        raise ValueError('decryption needs a distinct quorum')
    for partial in partials:
        if not verify_partial_chunked(curve, statement, packet, committee, partial, request_binding):
            raise ValueError('invalid partial decryption')
    weights = tuple(lagrange(member, members) for member in members)
    plaintexts = tuple(curve.sub(c.second, curve.linear((w, p.points[j]) for w, p in zip(weights, partials)))
                       for j, c in enumerate(packet.ciphertexts))
    return recover_chunked(curve, statement, plaintexts)
