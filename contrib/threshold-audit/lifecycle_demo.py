#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare full-opening schemes and exercise the proposed public-policy lifecycle.

This is a single-process model, not a running Elements network. OutputReference
anchors policy, not an actual transaction/UTXO. All transaction digests below
are synthetic; no native consensus integration is implied.
"""

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform
import secrets
import time

from chunked import ChunkPacket, combine_chunked, encrypt_chunked, partial_decrypt_chunked, verify_chunked
from curve import Curve, random_scalar, rewind_nonce, scalar_bytes
from disclosure import Approval, AuditLog, Policy, Request, disclose
from governance import AuditChain, AuditConfig, AuditKey, PreparedTransition, Transition, make_readiness
from recovery import Opening, Statement, digest, encrypt_opening, verify_packet
from threshold import combine, partial_decrypt, simulate_handoff, simulate_keygen


def named(label):
    return hashlib.sha256(label.encode()).digest()


def run(curve):
    times = {}

    def measure(label, function):
        start = time.perf_counter()
        result = function()
        times[label] = round(time.perf_counter() - start, 6)
        return result

    def expect_rejection(function):
        try:
            function()
        except ValueError:
            return True
        raise RuntimeError('expected operation to be rejected')

    old, old_shares = simulate_keygen(curve, tuple(range(1, 11)), 7)
    old_identities = {member: random_scalar() for member in old.members}
    identities = tuple((member, curve.mul(secret)[1:]) for member, secret in old_identities.items())
    initial = AuditConfig(0, named('initial block-signing policy'), identities, 1, (AuditKey(1, 2, old),))
    chain_id = named('lifecycle demonstration chain')
    chain = AuditChain(curve, chain_id, initial, epoch_length=10, supported_schemes=(1, 2))

    assets = tuple(sorted((named('asset A'), named('asset B'))))
    # Exercise the non-first OR branch as well as full scalar recovery.
    opening = Opening(assets[1], 125_000_000, random_scalar(), random_scalar())
    asset = curve.asset_commitment(opening.asset, opening.asset_blinder)
    value = curve.value_commitment(asset, opening.amount, opening.value_blinder)
    statement = Statement(chain_id, named('transaction template excluding recovery'), 0,
                          b'\x00\x14' + secrets.token_bytes(20), asset, value, old.public_key, assets)
    packet = measure('TAC2_encrypt_and_prove_seconds', lambda: encrypt_chunked(curve, statement, opening))
    packet = ChunkPacket.from_bytes(packet.to_bytes(), statement, curve)
    if not measure('TAC2_public_verify_seconds', lambda: verify_chunked(curve, statement, packet)):
        raise RuntimeError('optimized proof verification failed')
    reference = measure('TAR1_encrypt_and_prove_seconds', lambda: encrypt_opening(curve, statement, opening))
    if not measure('TAR1_public_verify_seconds', lambda: verify_packet(curve, statement, reference)):
        raise RuntimeError('reference proof verification failed')
    request_binding = named('benchmark request')
    reference_partials = measure('TAR1_seven_partial_decryptions_seconds', lambda: tuple(
        partial_decrypt(curve, statement, reference, old, s, request_binding) for s in old_shares[:7]))
    reference_opening = measure('TAR1_verify_combine_recover_seconds', lambda: combine(
        curve, statement, reference, old, reference_partials, request_binding))
    chunk_partials = measure('TAC2_seven_partial_decryptions_seconds', lambda: tuple(
        partial_decrypt_chunked(curve, statement, packet, old, s, request_binding) for s in old_shares[:7]))
    chunk_opening = measure('TAC2_verify_combine_recover_seconds', lambda: combine_chunked(
        curve, statement, packet, old, chunk_partials, request_binding))
    if reference_opening != opening or chunk_opening != opening:
        raise RuntimeError('full-opening recovery contract changed')

    recipient, ephemeral = random_scalar(), random_scalar()
    range_proof = curve.rangeproof(asset, value, opening.amount, opening.value_blinder,
                                   rewind_nonce(curve, ephemeral, curve.mul(recipient)),
                                   opening.asset + scalar_bytes(opening.asset_blinder), statement.script)
    result = curve.rewind(asset, value, range_proof, rewind_nonce(curve, recipient, curve.mul(ephemeral)), statement.script)
    if result != (opening.amount, opening.value_blinder, opening.asset + scalar_bytes(opening.asset_blinder)):
        raise RuntimeError('ordinary recipient recovery changed')

    chain.require_new_output(1, 2, old.public_key)
    chain.connect()
    creation = chain.output_reference(1)
    new, new_shares = measure('simulated_handoff_seconds', lambda: simulate_handoff(
        curve, old, old_shares[:7], tuple(range(101, 116)), 11))
    new_identities = {member: random_scalar() for member in new.members}
    new_identity_keys = tuple((member, curve.mul(secret)[1:]) for member, secret in new_identities.items())
    handed = AuditConfig(1, named('replacement block-signing policy'), new_identity_keys, 1, (AuditKey(1, 2, new),))

    def prepare(previous, config, height, share_sets):
        transition = Transition(previous.binding(), height, config)
        ready = tuple(make_readiness(curve, chain_id, transition, key.version, share,
                                      new_identities[share.member])
                      for key in config.keys for share in share_sets[key.version][:key.committee.threshold])
        return PreparedTransition(transition, ready)

    prepared = prepare(initial, handed, 10, {1: new_shares})
    while chain.height < 9:
        chain.connect(prepared)
    chain.connect()
    if chain.current != handed or chain.historical_key(creation).committee != new:
        raise RuntimeError('handoff governance activation failed')

    def authorized_recovery(committee, shares):
        policy = Policy(committee.binding(), committee.threshold, new_identity_keys)
        now = int(time.time())
        request = Request(policy.binding(), statement.binding(), digest(b'packet', packet.to_bytes()),
                          secrets.token_bytes(32), curve.mul(random_scalar()), now + 300)
        approvals = tuple(Approval(member, curve.sign(new_identities[member], request.binding()))
                          for member in committee.members[:committee.threshold])
        log = AuditLog()
        recovered, receipt = disclose(curve, statement, packet, committee, shares[:committee.threshold],
                                      policy, request, approvals, now, log, scheme=2)
        if recovered != opening or not log.verify(receipt):
            raise RuntimeError('current-quorum authorized historical recovery failed')
        return len(log.entries)

    entries = measure('new_committee_authorized_historical_disclosure_seconds', lambda: authorized_recovery(
        chain.historical_key(creation).committee, new_shares))
    fresh, fresh_shares = simulate_keygen(curve, new.members, 11)
    rolled = replace(handed, generation=2, active_version=2, keys=handed.keys + (AuditKey(2, 2, fresh),))
    rollover = prepare(handed, rolled, 20, {1: new_shares, 2: fresh_shares})
    while chain.height < 19:
        chain.connect(rollover)
    stale_rejected = expect_rejection(lambda: chain.require_new_output(1, 2, old.public_key))
    chain.require_new_output(2, 2, fresh.public_key)
    chain.connect()
    orphan = chain.output_reference(20)
    archived = chain.historical_key(creation)
    if archived.public_key != old.public_key or archived.committee != new:
        raise RuntimeError('genuine key rollover abandoned historical capability')
    authorized_recovery(archived.committee, new_shares)

    fresh_statement = replace(statement, audit_key=fresh.public_key, tx_digest=named('new-key transaction template'))
    fresh_packet = encrypt_chunked(curve, fresh_statement, opening)
    if not verify_chunked(curve, fresh_statement, fresh_packet):
        raise RuntimeError('new-key output proof failed')
    chain.disconnect()  # Boundary removed, but its approving votes remain.
    if chain.current != handed or chain.next_config() != rolled:
        raise RuntimeError('boundary reorg/lookahead mismatch')
    orphan_rejected = expect_rejection(lambda: chain.historical_key(orphan))
    for _ in range(3):
        chain.disconnect()  # Remove enough approving votes to lose the winner.
    chain.require_new_output(1, 2, old.public_key)
    if chain.next_config() != handed:
        raise RuntimeError('reorg did not restore prior public policy')

    baseline_bytes, optimized_bytes = len(reference.to_bytes()), len(packet.to_bytes())
    return {
        'status': 'single-process research model; no native Elements consensus integration',
        'python': platform.python_version(),
        'samples': 1,
        'registered_assets': len(assets),
        'capability': 'amount, asset ID, asset blinding scalar, value blinding scalar',
        'payload_bytes': {'TAR1': baseline_bytes, 'TAC2': optimized_bytes},
        'payload_reduction_percent': round(100 * (baseline_bytes - optimized_bytes) / baseline_bytes, 2),
        'ciphertexts_per_output': {'TAR1': 576, 'TAC2': 36},
        'full_opening_matches_for_both_schemes': True,
        'recipient_unblinding_preserved': True,
        'handoff': {'old_threshold': 7, 'old_members': 10, 'new_threshold': 11, 'new_members': 15,
                    'public_key_preserved': True, 'current_committee_recovers_history': True},
        'genuine_rollover': {'new_public_key': True, 'old_key_retained': True,
                             'old_output_recovered_after_rollover': True, 'stale_pending_key_rejected': stale_rejected},
        'reorg': {'orphan_policy_reference_rejected': orphan_rejected,
                  'approving_votes_undo_restores_prior_policy': True},
        'authorized_disclosure_log_entries': entries,
        'timings_single_process_one_sample': times,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, help='bundled libsecp256k1 shared library path')
    parser.add_argument('--output', type=Path, help='optional path for public JSON results; never contains secret material')
    args = parser.parse_args()
    curve = Curve(args.library)
    try:
        result = json.dumps(run(curve), indent=2, sort_keys=True) + '\n'
        if args.output:
            args.output.write_text(result)
        print(result, end='')
    finally:
        curve.close()


if __name__ == '__main__':
    main()
