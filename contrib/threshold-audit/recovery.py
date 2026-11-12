# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Unreviewed, deliberately large verifiable-encryption research baseline.

No consensus integration, transaction validation, or production security claim.
See README.md for equations, assumptions, and missing production work.
"""

from dataclasses import dataclass
import hashlib

from curve import G, INF, ORDER, random_scalar, scalar_bytes

WIDTHS = (64, 256, 256)  # amount, asset blinder, value blinder
BIT_COUNT = sum(WIDTHS)
MAGIC = b'TAR1'
MAX_ASSETS = 256  # Experiment limit, not an Elements consensus parameter.
DOMAIN = b'Elements/threshold-audit/experiment/v1'


def digest(label, *parts):
    h = hashlib.sha256()
    for part in (DOMAIN, label, *parts):
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest()


def challenge(label, *parts):
    return int.from_bytes(digest(label, *parts), 'big') % ORDER


def index_bytes(index):
    return index.to_bytes(4, 'big')


def canonical_proof(proof, count):
    return (isinstance(proof, tuple) and len(proof) == count
            and all(isinstance(pair, tuple) and len(pair) == 2
                    and all(type(v) is int and 0 <= v < ORDER for v in pair)
                    for pair in proof))


def dleq_prove(curve, base1, base2, point1, point2, witness, context):
    nonce = random_scalar()
    a, b = curve.mul(nonce, base1), curve.mul(nonce, base2)
    c = challenge(b'dleq', context, base1, base2, point1, point2, a, b)
    return c, (nonce + c * witness) % ORDER


def dleq_verify(curve, base1, base2, point1, point2, proof, context):
    if not canonical_proof((proof,), 1):
        return False
    c, z = proof
    a = curve.linear(((z, base1), (-c, point1)))
    b = curve.linear(((z, base2), (-c, point2)))
    return c == challenge(b'dleq', context, base1, base2, point1, point2, a, b)


def or_prove(curve, key, first, alternatives, known_index, witness, context):
    """OR of DLEQ(G, key, first, alternatives[j]); hide the true branch."""
    pairs, commitments = [], []
    nonce = random_scalar()
    for j, alternative in enumerate(alternatives):
        if j == known_index:
            pairs.append((0, 0))
            commitments.extend((curve.mul(nonce), curve.mul(nonce, key)))
        else:
            c, z = random_scalar(), random_scalar()
            pairs.append((c, z))
            commitments.extend((curve.linear(((z, G), (-c, first))),
                                curve.linear(((z, key), (-c, alternative)))))
    total = challenge(b'or-dleq', context, G, key, first, *alternatives, *commitments)
    c = (total - sum(pair[0] for pair in pairs)) % ORDER
    pairs[known_index] = (c, (nonce + c * witness) % ORDER)
    return tuple(pairs)


def or_verify(curve, key, first, alternatives, proof, context):
    if not canonical_proof(proof, len(alternatives)):
        return False
    commitments = []
    for alternative, (c, z) in zip(alternatives, proof):
        commitments.extend((curve.linear(((z, G), (-c, first))),
                            curve.linear(((z, key), (-c, alternative)))))
    total = challenge(b'or-dleq', context, G, key, first, *alternatives, *commitments)
    return sum(pair[0] for pair in proof) % ORDER == total


@dataclass(frozen=True)
class Opening:
    asset: bytes
    amount: int
    asset_blinder: int
    value_blinder: int

    def validate(self):
        if not isinstance(self.asset, bytes) or len(self.asset) != 32:
            raise ValueError('asset must be 32 bytes')
        if type(self.amount) is not int or not 0 <= self.amount < 2**64:
            raise ValueError('amount must be uint64')
        scalar_bytes(self.asset_blinder)
        scalar_bytes(self.value_blinder)


@dataclass(frozen=True)
class Statement:
    """Public inputs from trusted chain/transaction policy, NEVER from the packet.

    tx_digest is a caller-defined digest excluding this recovery packet, to avoid
    a circular transaction hash. Its production sighash semantics are unresolved.
    Asset IDs use Elements internal byte order, not RPC display order.
    """
    chain_id: bytes
    tx_digest: bytes
    output_index: int
    script: bytes
    asset_commitment: bytes
    value_commitment: bytes
    audit_key: bytes
    assets: tuple

    def validate(self, curve):
        if any(not isinstance(v, bytes) or len(v) != 32 for v in (self.chain_id, self.tx_digest)):
            raise ValueError('chain and transaction digests must be 32 bytes')
        if type(self.output_index) is not int or not 0 <= self.output_index < 2**32:
            raise ValueError('invalid output index')
        if not isinstance(self.script, bytes) or len(self.script) > 10000:
            raise ValueError('invalid script')
        if not isinstance(self.assets, tuple) or not 1 <= len(self.assets) <= MAX_ASSETS:
            raise ValueError('invalid asset registry size')
        if any(not isinstance(a, bytes) or len(a) != 32 for a in self.assets):
            raise ValueError('invalid registry asset ID')
        if tuple(sorted(set(self.assets))) != self.assets:
            raise ValueError('asset registry must be sorted and unique')
        curve.parse(self.audit_key, allow_infinity=False)
        curve.confidential_point(self.asset_commitment, 'asset')
        curve.confidential_point(self.value_commitment, 'value')

    def binding(self):
        return digest(b'statement', self.chain_id, self.tx_digest, index_bytes(self.output_index),
                      self.script, self.asset_commitment, self.value_commitment,
                      self.audit_key, b''.join(self.assets))


@dataclass(frozen=True)
class Ciphertext:
    first: bytes
    second: bytes


@dataclass(frozen=True)
class Packet:
    ciphertexts: tuple
    bit_proofs: tuple
    asset_proof: tuple
    value_proof: tuple

    def to_bytes(self):
        if len(self.ciphertexts) != BIT_COUNT or len(self.bit_proofs) != BIT_COUNT:
            raise ValueError('incorrect bit count')
        if not 1 <= len(self.asset_proof) <= MAX_ASSETS:
            raise ValueError('incorrect asset proof count')
        out = bytearray(MAGIC)
        for ciphertext, proof in zip(self.ciphertexts, self.bit_proofs):
            if len(ciphertext.first) != 33 or len(ciphertext.second) != 33:
                raise ValueError('incorrect point size')
            if not canonical_proof(proof, 2):
                raise ValueError('invalid bit proof')
            out.extend(ciphertext.first + ciphertext.second)
            for pair in proof:
                out.extend(b''.join(scalar_bytes(v) for v in pair))
        if not canonical_proof(self.asset_proof, len(self.asset_proof)) or not canonical_proof((self.value_proof,), 1):
            raise ValueError('invalid consistency proof')
        for pair in (*self.asset_proof, self.value_proof):
            out.extend(b''.join(scalar_bytes(v) for v in pair))
        return bytes(out)

    @staticmethod
    def from_bytes(data, statement, curve):
        statement.validate(curve)
        expected = 4 + BIT_COUNT * (66 + 128) + len(statement.assets) * 64 + 64
        if not isinstance(data, bytes) or len(data) != expected or data[:4] != MAGIC:
            raise ValueError('invalid packet version or exact length')
        offset = 4

        def take(size):
            nonlocal offset
            result = data[offset:offset + size]
            offset += size
            return result

        def pair():
            values = tuple(int.from_bytes(take(32), 'big') for _ in range(2))
            if any(v >= ORDER for v in values):
                raise ValueError('noncanonical proof scalar')
            return values

        ciphertexts, proofs = [], []
        for _ in range(BIT_COUNT):
            first, second = take(33), take(33)
            curve.parse(first, allow_infinity=False)
            curve.parse(second)
            ciphertexts.append(Ciphertext(first, second))
            proofs.append((pair(), pair()))
        return Packet(tuple(ciphertexts), tuple(proofs),
                      tuple(pair() for _ in statement.assets), pair())


def packet_context(statement, packet):
    return digest(b'ciphertext-vector', statement.binding(),
                  b''.join(c.first + c.second for c in packet.ciphertexts))


def group_bases(curve, statement):
    asset_point = curve.confidential_point(statement.asset_commitment, 'asset')
    return (asset_point,) * WIDTHS[0] + (G,) * (WIDTHS[1] + WIDTHS[2])


def aggregate(curve, ciphertexts):
    """Sum a little-endian bit vector with weights 2**j in the curve group."""
    return Ciphertext(curve.linear((1 << j, c.first) for j, c in enumerate(ciphertexts)),
                      curve.linear((1 << j, c.second) for j, c in enumerate(ciphertexts)))


def aggregates(curve, packet):
    start, result = 0, []
    for width in WIDTHS:
        result.append(aggregate(curve, packet.ciphertexts[start:start + width]))
        start += width
    return result


def opening_matches(curve, statement, opening):
    opening.validate()
    return (opening.asset in statement.assets
            and curve.asset_commitment(opening.asset, opening.asset_blinder) == statement.asset_commitment
            and curve.value_commitment(statement.asset_commitment, opening.amount,
                                       opening.value_blinder) == statement.value_commitment)


def encrypt_opening(curve, statement, opening):
    statement.validate(curve)
    if not opening_matches(curve, statement, opening):
        raise ValueError('opening does not match the output')
    return _encrypt_unchecked(curve, statement, opening)


def _encrypt_unchecked(curve, statement, opening):
    """Also used by adversarial tests to model a wallet lying about its opening."""
    values = (opening.amount, opening.asset_blinder, opening.value_blinder)
    bits = tuple((value >> j) & 1 for value, width in zip(values, WIDTHS) for j in range(width))
    nonces = tuple(random_scalar() for _ in bits)
    bases = group_bases(curve, statement)
    key = statement.audit_key
    ciphertexts = tuple(Ciphertext(curve.mul(r), curve.add(curve.mul(r, key),
                                                       base if bit else INF))
                        for bit, r, base in zip(bits, nonces, bases))
    packet = Packet(ciphertexts, (), (), ())
    context = packet_context(statement, packet)
    proofs = tuple(or_prove(curve, key, c.first, (c.second, curve.sub(c.second, base)),
                            bit, r, digest(b'bit', context, index_bytes(j)))
                   for j, (c, bit, r, base) in enumerate(zip(ciphertexts, bits, nonces, bases)))
    amount, abf, vbf = aggregates(curve, packet)
    weights, start = [], 0
    for width in WIDTHS:
        weights.append(sum((1 << j) * nonces[start + j] for j in range(width)) % ORDER)
        start += width
    asset_point = curve.confidential_point(statement.asset_commitment, 'asset')
    alternatives = tuple(curve.add(abf.second, curve.neg(asset_point), curve.asset_generator(a))
                         for a in statement.assets)
    asset_proof = or_prove(curve, key, abf.first, alternatives,
                           statement.assets.index(opening.asset), weights[1],
                           digest(b'asset-consistency', context))
    value_point = curve.confidential_point(statement.value_commitment, 'value')
    value_proof = dleq_prove(curve, G, key, curve.add(amount.first, vbf.first),
                             curve.add(amount.second, vbf.second, curve.neg(value_point)),
                             (weights[0] + weights[2]) % ORDER,
                             digest(b'value-consistency', context))
    return Packet(ciphertexts, proofs, asset_proof, value_proof)


def verify_packet(curve, statement, packet):
    """Verify public recoverability, without any blinding key or federation share."""
    try:
        statement.validate(curve)
        if len(packet.ciphertexts) != BIT_COUNT or len(packet.bit_proofs) != BIT_COUNT:
            return False
        for c in packet.ciphertexts:
            curve.parse(c.first, allow_infinity=False)
            curve.parse(c.second)
        context = packet_context(statement, packet)
        for j, (c, proof, base) in enumerate(zip(packet.ciphertexts, packet.bit_proofs,
                                                group_bases(curve, statement))):
            if not or_verify(curve, statement.audit_key, c.first,
                             (c.second, curve.sub(c.second, base)), proof,
                             digest(b'bit', context, index_bytes(j))):
                return False
        amount, abf, vbf = aggregates(curve, packet)
        asset_point = curve.confidential_point(statement.asset_commitment, 'asset')
        alternatives = tuple(curve.add(abf.second, curve.neg(asset_point), curve.asset_generator(a))
                             for a in statement.assets)
        if not or_verify(curve, statement.audit_key, abf.first, alternatives,
                         packet.asset_proof, digest(b'asset-consistency', context)):
            return False
        value_point = curve.confidential_point(statement.value_commitment, 'value')
        return dleq_verify(curve, G, statement.audit_key, curve.add(amount.first, vbf.first),
                           curve.add(amount.second, vbf.second, curve.neg(value_point)),
                           packet.value_proof, digest(b'value-consistency', context))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


def recover_opening(curve, statement, plaintexts):
    if len(plaintexts) != BIT_COUNT:
        raise ValueError('wrong plaintext count')
    bits = []
    for plaintext, base in zip(plaintexts, group_bases(curve, statement)):
        if plaintext not in (INF, base):
            raise ValueError('decrypted value is not a bit')
        bits.append(int(plaintext != INF))
    values, start = [], 0
    for width in WIDTHS:
        values.append(sum(bits[start + j] << j for j in range(width)))
        start += width
    amount, abf, vbf = values
    # Scalar bit encodings may represent values >= ORDER; normalize modulo ORDER.
    abf, vbf = abf % ORDER, vbf % ORDER
    target = curve.sub(curve.confidential_point(statement.asset_commitment, 'asset'), curve.mul(abf))
    matches = [a for a in statement.assets if curve.asset_generator(a) == target]
    if len(matches) != 1:
        raise ValueError('asset does not resolve uniquely in the registry')
    opening = Opening(matches[0], amount, abf, vbf)
    if not opening_matches(curve, statement, opening):
        raise ValueError('recovered opening does not match the output')
    return opening
