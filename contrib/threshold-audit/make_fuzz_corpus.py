#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate public TAC2/TAG1/TAP1 seeds for the native threshold_audit fuzz target."""

import argparse
import hashlib
import os
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test' / 'functional'))

from chunked import encrypt_chunked
from curve import Curve, random_scalar
from governance import AuditConfig, AuditKey, PreparedTransition, Transition, make_readiness
from native_governance import policy_binding, prepared_to_bytes
from recovery import Opening, Statement
from threshold import simulate_handoff, simulate_keygen


def number(value):
    return value.to_bytes(4, 'big')


def blob(value):
    return number(len(value)) + value


def statement_vector(statement, packet):
    return (statement.chain_id + statement.tx_digest + number(statement.output_index)
            + blob(statement.script) + statement.asset_commitment + statement.value_commitment
            + statement.audit_key + number(len(statement.assets)) + b''.join(statement.assets) + blob(packet))


def generate(curve):
    chain = hashlib.sha256(b'audit fuzz chain').digest()
    asset = hashlib.sha256(b'audit fuzz asset').digest()
    old, shares = simulate_keygen(curve, tuple(range(1, 11)), 7)
    opening = Opening(asset, 0, random_scalar(), random_scalar())
    asset_commitment = curve.asset_commitment(asset, opening.asset_blinder)
    statement = Statement(chain, bytes(32), 0, b'\x51', asset_commitment,
                          curve.value_commitment(asset_commitment, opening.amount, opening.value_blinder),
                          old.public_key, (asset,))
    packet = encrypt_chunked(curve, statement, opening).to_bytes()
    identities = {member: random_scalar() for member in old.members}
    program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
    policy = policy_binding(program, 108, program, b'\x51', [b''])
    initial = AuditConfig(0, policy, tuple((member, curve.mul(secret)[1:]) for member, secret in identities.items()),
                          1, (AuditKey(1, 2, old),))
    incoming, new_shares = simulate_handoff(curve, old, shares[:7], tuple(range(101, 116)), 11)
    new_identities = {member: random_scalar() for member in incoming.members}
    handed = AuditConfig(1, policy, tuple((member, curve.mul(secret)[1:]) for member, secret in new_identities.items()),
                         1, (AuditKey(1, 2, incoming),))
    transition = Transition(initial.binding(), 10, handed)
    ready = tuple(make_readiness(curve, chain, transition, 1, share, new_identities[share.member])
                  for share in new_shares[:11])
    prepared = PreparedTransition(transition, ready)
    return {'packet': statement_vector(statement, packet), 'genesis': initial.to_bytes(),
            'committee': handed.to_bytes(),
            'handoff': b'TAPF' + chain + number(10) + blob(initial.to_bytes())
                       + blob(handed.to_bytes()) + blob(prepared_to_bytes(prepared))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', default=os.environ.get('THRESHOLD_AUDIT_SECP256K1'), required=False)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mutations', type=int, default=16)
    options = parser.parse_args()
    if not options.library or not 0 <= options.mutations <= 1000:
        parser.error('a shared library and mutation count 0..1000 are required')
    options.output.mkdir(parents=True, exist_ok=True)
    curve = Curve(options.library)
    try:
        seeds = generate(curve)
    finally:
        curve.close()
    rng = random.Random(0)
    count = 0
    for name, seed in seeds.items():
        variants = [seed, b'', seed[:4], seed[:-1], seed + b'\x00']
        for _ in range(options.mutations):
            mutated = bytearray(seed)
            position = rng.randrange(len(mutated))
            mutated[position] ^= 1 << rng.randrange(8)
            variants.append(bytes(mutated))
        for index, value in enumerate(variants):
            (options.output / f'{name}-{index:04d}').write_bytes(value)
            count += 1
    print(f'Wrote {count} public fuzz seeds to {options.output}')


if __name__ == '__main__':
    main()
