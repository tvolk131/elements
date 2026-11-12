# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Single-process simulations of VSS ceremonies and threshold decryption.

Private contributions are ordinary Python objects. The transport, complaints,
qualified dealer selection, reliable broadcast, erasure and DKG security model
needed for a distributed implementation are NOT provided here.
"""

from dataclasses import dataclass

from curve import G, INF, ORDER, random_scalar, scalar_bytes
from recovery import (
    BIT_COUNT, digest, dleq_prove, dleq_verify,
    index_bytes, packet_context, recover_opening, verify_packet,
)


def validate_roster(members, threshold):
    if (not isinstance(members, tuple) or not 1 <= len(members) <= 32
            or type(threshold) is not int or not 1 <= threshold <= len(members)
            or any(type(i) is not int or not 1 <= i < 2**32 for i in members)
            or tuple(sorted(set(members))) != members):
        raise ValueError('invalid committee roster or threshold')


def polynomial_value(coefficients, member):
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * member + coefficient) % ORDER
    return result


def lagrange(member, members):
    if member not in members or len(set(members)) != len(members):
        raise ValueError('invalid interpolation set')
    result = 1
    for other in members:
        if other != member:
            result = result * (-other) * pow(member - other, -1, ORDER) % ORDER
    return result


@dataclass(frozen=True)
class Committee:
    epoch: int
    members: tuple
    commitments: tuple  # Feldman commitments to polynomial coefficients.

    @property
    def threshold(self):
        return len(self.commitments)

    @property
    def public_key(self):
        return self.commitments[0]

    def validate(self, curve):
        validate_roster(self.members, self.threshold)
        if type(self.epoch) is not int or not 0 <= self.epoch < 2**32:
            raise ValueError('invalid committee epoch')
        curve.parse(self.public_key, allow_infinity=False)
        for point in self.commitments:
            curve.parse(point)
        # Do not silently advertise a higher threshold than the polynomial degree.
        if self.threshold > 1 and self.commitments[-1] == INF:
            raise ValueError('sharing polynomial has insufficient degree')
        # A zero share is publicly known from an infinite verification key. It
        # would let a caller fabricate that member's participation in a nominal
        # t-of-n quorum, even though the polynomial still has the right degree.
        if any(self.verification_key(curve, member) == INF for member in self.members):
            raise ValueError('committee contains a publicly known zero share')

    def binding(self):
        return digest(b'committee', index_bytes(self.epoch),
                      b''.join(index_bytes(i) for i in self.members),
                      b''.join(self.commitments))

    def verification_key(self, curve, member):
        if member not in self.members:
            raise ValueError('unknown committee member')
        return curve.linear((pow(member, j, ORDER), p) for j, p in enumerate(self.commitments))


@dataclass(frozen=True)
class SecretShare:
    member: int
    value: int
    committee_binding: bytes


def validate_share(curve, committee, share):
    scalar_bytes(share.value)
    if (share.committee_binding != committee.binding()
            or curve.mul(share.value) != committee.verification_key(curve, share.member)):
        raise ValueError('share does not belong to this committee')


@dataclass(frozen=True)
class Contribution:
    dealer: int
    commitments: tuple
    evaluations: tuple  # PRIVATE (recipient, scalar) pairs: never put in a public log.


def make_contribution(curve, dealer, members, threshold, constant=None):
    coefficients = (random_scalar() if constant is None else constant,) + tuple(
        random_scalar() for _ in range(threshold - 1))
    return Contribution(dealer, tuple(curve.mul(c) for c in coefficients),
                        tuple((i, polynomial_value(coefficients, i)) for i in members))


def verify_contribution(curve, contribution, members, threshold, expected_constant=None):
    validate_roster(members, threshold)
    if len(contribution.commitments) != threshold:
        raise ValueError('incorrect contribution degree')
    for point in contribution.commitments:
        curve.parse(point)
    if expected_constant is not None and contribution.commitments[0] != expected_constant:
        raise ValueError('handoff contribution changes the secret')
    if tuple(i for i, _ in contribution.evaluations) != members:
        raise ValueError('missing, reordered, or duplicate recipients')
    for member, value in contribution.evaluations:
        scalar_bytes(value)
        expected = curve.linear((pow(member, j, ORDER), p)
                                for j, p in enumerate(contribution.commitments))
        if curve.mul(value) != expected:
            raise ValueError('invalid private share evaluation')


def assemble(curve, epoch, members, threshold, contributions):
    if not contributions or len({c.dealer for c in contributions}) != len(contributions):
        raise ValueError('missing or duplicate dealers')
    for contribution in contributions:
        verify_contribution(curve, contribution, members, threshold)
    commitments = tuple(curve.add(*(c.commitments[j] for c in contributions))
                        for j in range(threshold))
    committee = Committee(epoch, members, commitments)
    committee.validate(curve)
    shares = tuple(SecretShare(member, sum(c.evaluations[j][1] for c in contributions) % ORDER,
                               committee.binding()) for j, member in enumerate(members))
    for share in shares:
        validate_share(curve, committee, share)
    return committee, shares


def simulate_keygen(curve, members, threshold):
    """All-dealer Feldman sharing simulation, NOT a network-secure DKG protocol."""
    validate_roster(members, threshold)
    contributions = tuple(make_contribution(curve, i, members, threshold) for i in members)
    return assemble(curve, 0, members, threshold, contributions)


def handoff_contributions(curve, old, old_shares, members, threshold):
    old.validate(curve)
    validate_roster(members, threshold)
    selected = tuple(s.member for s in old_shares)
    if len(selected) < old.threshold or len(set(selected)) != len(selected):
        raise ValueError('handoff needs a distinct old quorum')
    result = []
    for share in old_shares:
        validate_share(curve, old, share)
        weight = lagrange(share.member, selected)
        result.append(make_contribution(curve, share.member, members, threshold,
                                         weight * share.value % ORDER))
    return tuple(result)


def accept_handoff(curve, old, members, threshold, contributions):
    """Verify a handoff's public constant terms and every private evaluation."""
    old.validate(curve)
    validate_roster(members, threshold)
    dealers = tuple(c.dealer for c in contributions)
    if (len(dealers) < old.threshold or len(set(dealers)) != len(dealers)
            or any(i not in old.members for i in dealers)):
        raise ValueError('invalid old handoff quorum')
    for contribution in contributions:
        expected = curve.mul(lagrange(contribution.dealer, dealers),
                             old.verification_key(curve, contribution.dealer))
        verify_contribution(curve, contribution, members, threshold, expected)
    committee, shares = assemble(curve, old.epoch + 1, members, threshold, contributions)
    if committee.public_key != old.public_key:
        raise ValueError('public audit key changed during handoff')
    return committee, shares


def simulate_handoff(curve, old, old_shares, members, threshold):
    return accept_handoff(curve, old, members, threshold,
                          handoff_contributions(curve, old, old_shares, members, threshold))


@dataclass(frozen=True)
class PartialDecryption:
    member: int
    committee_binding: bytes
    request_binding: bytes
    points: tuple
    proofs: tuple


def decryption_context(statement, packet, committee, request_binding, member):
    if not isinstance(request_binding, bytes) or len(request_binding) != 32:
        raise ValueError('request binding must be a 32-byte digest')
    return digest(b'decryption', packet_context(statement, packet), committee.binding(),
                  request_binding, index_bytes(member))


def partial_decrypt(curve, statement, packet, committee, share, request_binding):
    """Low-level primitive: does not enforce approvals or logging.

    The caller must verify the packet before invoking this primitive. A quorum
    can intentionally bypass a service's approval policy: see the explicit test.
    """
    committee.validate(curve)
    if statement.audit_key != committee.public_key:
        raise ValueError('committee does not control this audit key')
    validate_share(curve, committee, share)
    context = decryption_context(statement, packet, committee, request_binding, share.member)
    if len(packet.ciphertexts) != BIT_COUNT:
        raise ValueError('incorrect ciphertext count')
    key = committee.verification_key(curve, share.member)
    points, proofs = [], []
    for j, c in enumerate(packet.ciphertexts):
        curve.parse(c.first, allow_infinity=False)
        point = curve.mul(share.value, c.first)
        points.append(point)
        proofs.append(dleq_prove(curve, G, c.first, key, point, share.value,
                                 digest(b'partial', context, index_bytes(j))))
    return PartialDecryption(share.member, committee.binding(), request_binding,
                             tuple(points), tuple(proofs))


def verify_partial(curve, statement, packet, committee, partial, request_binding):
    try:
        committee.validate(curve)
        if (statement.audit_key != committee.public_key
                or len(packet.ciphertexts) != BIT_COUNT
                or partial.committee_binding != committee.binding()
                or partial.request_binding != request_binding
                or len(partial.points) != BIT_COUNT or len(partial.proofs) != BIT_COUNT):
            return False
        key = committee.verification_key(curve, partial.member)
        context = decryption_context(statement, packet, committee, request_binding, partial.member)
        for j, (c, point, proof) in enumerate(zip(packet.ciphertexts, partial.points, partial.proofs)):
            curve.parse(point)
            if not dleq_verify(curve, G, c.first, key, point, proof,
                               digest(b'partial', context, index_bytes(j))):
                return False
        return True
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


def combine(curve, statement, packet, committee, partials, request_binding):
    committee.validate(curve)
    if statement.audit_key != committee.public_key or not verify_packet(curve, statement, packet):
        raise ValueError('invalid recovery packet or wrong audit key')
    members = tuple(p.member for p in partials)
    if len(members) < committee.threshold or len(set(members)) != len(members):
        raise ValueError('decryption needs a distinct quorum')
    for partial in partials:
        if not verify_partial(curve, statement, packet, committee, partial, request_binding):
            raise ValueError('invalid partial decryption')
    weights = tuple(lagrange(member, members) for member in members)
    plaintexts = tuple(curve.sub(c.second, curve.linear((weight, partial.points[j])
                                                       for weight, partial in zip(weights, partials)))
                       for j, c in enumerate(packet.ciphertexts))
    return recover_opening(curve, statement, plaintexts)
