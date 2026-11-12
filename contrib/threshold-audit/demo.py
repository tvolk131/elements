#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the isolated recovery/rotation experiment; prints no secret material."""

import argparse
from dataclasses import replace
import hashlib
import json
import secrets
import time

from curve import Curve, random_scalar, rewind_nonce, scalar_bytes
from disclosure import Approval, AuditLog, Policy, Request, disclose
from recovery import Opening, Packet, Statement, digest, encrypt_opening, verify_packet
from threshold import combine, partial_decrypt, simulate_handoff, simulate_keygen


def run(curve):
    metrics = {}

    def measure(label, function):
        start = time.perf_counter()
        result = function()
        metrics[label] = round(time.perf_counter() - start, 6)
        return result

    committee, shares = measure('simulated_keygen_seconds', lambda: simulate_keygen(curve, tuple(range(1, 11)), 7))
    assets = tuple(sorted(hashlib.sha256(label).digest() for label in (b'example asset A', b'example asset B')))
    opening = Opening(assets[0], 125_000_000, random_scalar(), random_scalar())
    asset = curve.asset_commitment(opening.asset, opening.asset_blinder)
    value = curve.value_commitment(asset, opening.amount, opening.value_blinder)
    statement = Statement(hashlib.sha256(b'demo chain').digest(),
                          hashlib.sha256(b'demo transaction template excluding recovery').digest(),
                          0, b'\x00\x14' + secrets.token_bytes(20), asset, value,
                          committee.public_key, assets)
    packet = measure('encrypt_and_prove_seconds', lambda: encrypt_opening(curve, statement, opening))
    encoded = packet.to_bytes()
    packet = Packet.from_bytes(encoded, statement, curve)
    if not measure('public_verify_seconds', lambda: verify_packet(curve, statement, packet)):
        raise RuntimeError('public proof verification failed')

    recipient, ephemeral = random_scalar(), random_scalar()
    nonce = rewind_nonce(curve, ephemeral, curve.mul(recipient))
    proof = curve.rangeproof(asset, value, opening.amount, opening.value_blinder, nonce,
                             opening.asset + scalar_bytes(opening.asset_blinder), statement.script)
    recipient_result = curve.rewind(asset, value, proof,
                                    rewind_nonce(curve, recipient, curve.mul(ephemeral)), statement.script)
    if recipient_result != (opening.amount, opening.value_blinder,
                            opening.asset + scalar_bytes(opening.asset_blinder)):
        raise RuntimeError('recipient unblinding failed')

    approval_secrets = tuple(random_scalar() for _ in committee.members)
    policy = Policy(committee.binding(), 7,
                    tuple((i, curve.mul(secret)[1:]) for i, secret in zip(committee.members, approval_secrets)))
    now = int(time.time())
    request = Request(policy.binding(), statement.binding(), digest(b'packet', encoded),
                      secrets.token_bytes(32), curve.mul(random_scalar()), now + 300)
    approvals = tuple(Approval(i, curve.sign(secret, request.binding()))
                      for i, secret in zip(committee.members[:7], approval_secrets[:7]))
    log = AuditLog()
    recovered, receipt = measure('authorized_disclosure_seconds', lambda: disclose(
        curve, statement, packet, committee, shares[:7], policy, request, approvals, now, log))
    if recovered != opening or not log.verify(receipt):
        raise RuntimeError('authorized disclosure or receipt failed')

    new, new_shares = measure('simulated_handoff_seconds', lambda: simulate_handoff(
        curve, committee, shares[:7], tuple(range(101, 116)), 11))
    partials = measure('new_quorum_partial_decrypt_seconds', lambda: tuple(
        partial_decrypt(curve, statement, packet, new, share, request.binding()) for share in new_shares[:11]))
    historical = measure('new_quorum_combine_seconds', lambda: combine(
        curve, statement, packet, new, partials, request.binding()))
    if historical != opening or new.public_key != committee.public_key:
        raise RuntimeError('historical recovery after handoff failed')

    rejected = False
    try:
        combine(curve, statement, packet, new, partials[:10], request.binding())
    except ValueError:
        rejected = True
    if not rejected or verify_packet(curve, replace(statement, output_index=1), packet):
        raise RuntimeError('negative checks failed')

    return {
        'status': 'research prototype only; no consensus or distributed deployment',
        'recovery_packet_bytes': len(encoded),
        'registered_assets': len(assets),
        'recipient_unblinding_preserved': True,
        'authorized_disclosure_matches': True,
        'old_committee': {'threshold': 7, 'members': 10},
        'new_committee': {'threshold': 11, 'members': 15},
        'public_audit_key_preserved': True,
        'historical_recovery_matches': True,
        'insufficient_quorum_rejected': rejected,
        'changed_output_rejected': True,
        'audit_log_entries': len(log.entries),
        'receipt_head': receipt.hex(),
        'timings': metrics,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, help='path to this checkout\'s libsecp256k1 shared library')
    args = parser.parse_args()
    curve = Curve(args.library)
    try:
        print(json.dumps(run(curve), indent=2, sort_keys=True))
    finally:
        curve.close()


if __name__ == '__main__':
    main()
