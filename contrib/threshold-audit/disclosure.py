# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Demonstration approval gate and hash-chained receipts, not an HSM policy.

An independent observer must retain a log head to detect rewriting/truncation.
This single process can bypass its own policy; this limitation is tested.
Neither the log nor ordinary cryptography forces a colluding quorum to log.
"""

from dataclasses import dataclass, field
import json

from recovery import digest, index_bytes, verify_packet
from threshold import combine, partial_decrypt, validate_roster


@dataclass(frozen=True)
class Policy:
    committee_binding: bytes
    threshold: int
    approvers: tuple  # (member ID, independent BIP340 public key), NEVER audit shares.

    def validate(self, curve):
        validate_roster(tuple(i for i, _ in self.approvers), self.threshold)
        if len(self.committee_binding) != 32 or len({k for _, k in self.approvers}) != len(self.approvers):
            raise ValueError('invalid policy binding or duplicate approval keys')
        for _, key in self.approvers:
            if not isinstance(key, bytes) or len(key) != 32:
                raise ValueError('invalid approval public key')
            curve.parse(b'\x02' + key, allow_infinity=False)

    def binding(self):
        return digest(b'approval-policy', self.committee_binding, index_bytes(self.threshold),
                      b''.join(index_bytes(i) + key for i, key in self.approvers))


@dataclass(frozen=True)
class Request:
    policy_binding: bytes
    statement_binding: bytes
    packet_binding: bytes
    case_reference: bytes  # Random/opaque reference; not a hash of a person's name.
    recipient_key: bytes
    expires_at: int
    delivery: str = 'tls'

    def validate(self, curve):
        if any(not isinstance(v, bytes) or len(v) != 32 for v in (
                self.policy_binding, self.statement_binding, self.packet_binding, self.case_reference)):
            raise ValueError('request references must be 32 bytes')
        if type(self.expires_at) is not int or not 0 <= self.expires_at < 2**64:
            raise ValueError('invalid expiration')
        curve.parse(self.recipient_key, allow_infinity=False)
        if self.delivery not in ('tls', 'sealed-v1'):
            raise ValueError('unsupported disclosure delivery')

    def binding(self):
        return digest(b'disclosure-request' if self.delivery == 'tls' else b'disclosure-request/sealed-v1', self.policy_binding, self.statement_binding,
                      self.packet_binding, self.case_reference, self.recipient_key,
                      self.expires_at.to_bytes(8, 'big'))


@dataclass(frozen=True)
class Approval:
    member: int
    signature: bytes


def authorize(curve, policy, request, approvals, now):
    policy.validate(curve)
    request.validate(curve)
    if type(now) is not int or now < 0 or request.expires_at <= now:
        raise ValueError('request expired or invalid clock')
    if request.policy_binding != policy.binding():
        raise ValueError('request uses a different approval policy')
    keys, seen = dict(policy.approvers), set()
    for approval in approvals:
        if approval.member not in keys or approval.member in seen:
            raise ValueError('unknown or duplicate approver')
        if not curve.verify_signature(keys[approval.member], request.binding(), approval.signature):
            raise ValueError('invalid approval signature')
        seen.add(approval.member)
    if len(seen) < policy.threshold:
        raise ValueError('insufficient signed approvals')


@dataclass
class AuditLog:
    entries: list = field(default_factory=list)
    head: bytes = bytes(32)

    def append(self, event):
        encoded = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
        self.head = digest(b'log-entry', self.head, encoded)
        self.entries.append(encoded)
        return self.head

    def verify(self, pinned_head):
        head = bytes(32)
        for entry in self.entries:
            head = digest(b'log-entry', head, entry)
        return head == pinned_head == self.head


def disclose(curve, statement, packet, committee, shares, policy, request, approvals, now, log, *, scheme=1):
    """In-memory workflow only. Recipient authentication/encrypted delivery omitted."""
    # Select an explicitly supported backend from trusted caller policy. A
    # request cannot supply arbitrary verifier/decryptor callbacks.
    if type(scheme) is not int or scheme not in (1, 2):
        raise ValueError('unsupported disclosure scheme')
    verifier, partial_operation, combination = verify_packet, partial_decrypt, combine
    if scheme == 2:
        from chunked import combine_chunked, partial_decrypt_chunked, verify_chunked
        verifier, partial_operation, combination = verify_chunked, partial_decrypt_chunked, combine_chunked
    committee.validate(curve)
    if policy.committee_binding != committee.binding():
        raise ValueError('approval policy is not current for this committee')
    authorize(curve, policy, request, approvals, now)
    if (request.statement_binding != statement.binding()
            or request.packet_binding != digest(b'packet', packet.to_bytes())):
        raise ValueError('request does not authorize this exact output and packet')
    if len({s.member for s in shares}) != len(shares) or len(shares) < committee.threshold:
        raise ValueError('insufficient distinct decryption shares')
    if not verifier(curve, statement, packet):
        raise ValueError('output is not verifiably recoverable')
    event = {
        'request': request.binding().hex(),
        'committee': committee.binding().hex(),
        'scheme': scheme,
        'approvals': [{'member': a.member, 'signature': a.signature.hex()} for a in approvals],
    }
    # Save approval evidence before producing any partial decryption. An actual
    # service needs durable, independently witnessed log inclusion at this point.
    log.append(dict(event, status='authorized'))
    try:
        partials = tuple(partial_operation(curve, statement, packet, committee, share,
                                          request.binding()) for share in shares)
        opening = combination(curve, statement, packet, committee, partials, request.binding())
    except ValueError:
        log.append(dict(event, status='failed'))
        raise
    receipt = log.append(dict(event, status='completed', members=[s.member for s in shares]))
    # Do not put partial decryptions, openings, or secret shares in the audit log.
    return opening, receipt
