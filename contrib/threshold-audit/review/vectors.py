#!/usr/bin/env python3
"""Reproduce and verify PUBLIC TEST-ONLY TAC2/TAG1/TAP1 review vectors.

All keys, polynomial coefficients and randomness in this file are deliberately
public. Never import this generator into a wallet, guardian service or chain.
It patches randomness only inside this standalone test process so generation is
byte-for-byte reproducible with the bundled libsecp256k1-zkp implementation.
"""

import argparse
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PROTOTYPE = HERE.parent
REPOSITORY = HERE.parents[2]
sys.path.insert(0, str(PROTOTYPE))
sys.path.insert(0, str(REPOSITORY / 'test' / 'functional'))

import chunked
import curve
import recovery
from curve import Curve, ORDER
from governance import AuditConfig, AuditKey, PreparedTransition, Transition, make_readiness, verify_readiness
from native_governance import policy_binding, prepared_from_bytes, prepared_to_bytes
from recovery import Opening, Statement
from threshold import Committee, SecretShare, polynomial_value


FORMAT = 'elements-threshold-audit-public-review-v1'
PUBLIC_SEED = b'PUBLIC TEST ONLY / Elements threshold audit review vectors / v1'
FIXTURE = HERE / 'vectors' / 'public-v1.json'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class PublicRandom:
    """Not a production RNG. Every byte is reconstructible from PUBLIC_SEED."""
    def __init__(self):
        self.counter = 0

    def bytes(self, length):
        result = bytearray()
        while len(result) < length:
            result.extend(hashlib.sha256(PUBLIC_SEED + self.counter.to_bytes(8, 'big')).digest())
            self.counter += 1
        return bytes(result[:length])

    def scalar(self):
        return int.from_bytes(self.bytes(32), 'big') % (ORDER - 1) + 1


def fixed_committee(engine, epoch, members, coefficients):
    committee = Committee(epoch, tuple(members), tuple(engine.mul(value) for value in coefficients))
    committee.validate(engine)
    shares = tuple(SecretShare(member, polynomial_value(coefficients, member), committee.binding()) for member in members)
    return committee, shares


def statement_json(statement):
    return {'chain_id_raw': statement.chain_id.hex(), 'tx_digest_raw': statement.tx_digest.hex(),
            'output_index': statement.output_index, 'script': statement.script.hex(),
            'asset_commitment': statement.asset_commitment.hex(), 'value_commitment': statement.value_commitment.hex(),
            'audit_key': statement.audit_key.hex(), 'assets_raw': [asset.hex() for asset in statement.assets]}


def statement_from(value):
    return Statement(bytes.fromhex(value['chain_id_raw']), bytes.fromhex(value['tx_digest_raw']), value['output_index'],
                     bytes.fromhex(value['script']), bytes.fromhex(value['asset_commitment']),
                     bytes.fromhex(value['value_commitment']), bytes.fromhex(value['audit_key']),
                     tuple(bytes.fromhex(asset) for asset in value['assets_raw']))


def generate(engine):
    rng = PublicRandom()
    with ExitStack() as patches:
        # Functions imported these names directly; patch only this generator's
        # temporary test execution, restoring every name on exit.
        patches.enter_context(patch.object(chunked, 'random_scalar', rng.scalar))
        patches.enter_context(patch.object(recovery, 'random_scalar', rng.scalar))
        patches.enter_context(patch.object(curve.secrets, 'token_bytes', rng.bytes))
        old, old_shares = fixed_committee(engine, 0, (1, 2, 3), (17, 29))
        incoming, incoming_shares = fixed_committee(engine, 1, (11, 12, 13, 14), (17, 31, 37))
        assets = tuple(sorted(hashlib.sha256(b'PUBLIC asset ' + label).digest() for label in (b'EUR', b'USD')))
        chain = hashlib.sha256(b'PUBLIC synthetic chain id; not a live chain').digest()
        opening = Opening(assets[0], 123456789, 43, 47)
        asset_commitment = engine.asset_commitment(opening.asset, opening.asset_blinder)
        statement = Statement(chain, hashlib.sha256(b'PUBLIC synthetic transaction template').digest(), 2, b'\x00\x14' + bytes(range(20)),
                              asset_commitment, engine.value_commitment(asset_commitment, opening.amount, opening.value_blinder),
                              old.public_key, assets)
        packet = chunked.encrypt_chunked(engine, statement, opening)
        script = b'\x51'
        program = b'\x00\x20' + hashlib.sha256(script).digest()
        initial_policy = policy_binding(program, 108, program, script, [b''])
        old_identities = tuple((member, engine.mul(100 + member)[1:]) for member in old.members)
        incoming_identities = tuple((member, engine.mul(100 + member)[1:]) for member in incoming.members)
        initial = AuditConfig(0, initial_policy, old_identities, 1, (AuditKey(1, 2, old),))
        handoff = AuditConfig(1, initial_policy, incoming_identities, 1, (AuditKey(1, 2, incoming),))
        appended = tuple(sorted((*assets, hashlib.sha256(b'PUBLIC asset JPY').digest())))
        append_policy = policy_binding(program, 108, program, script, [b''], appended, 1)
        registration = replace(initial, generation=1, signer_policy=append_policy)

        def transition_vector(name, target, shares, target_assets, target_version):
            transition = Transition(initial.binding(), 10, target)
            ready = tuple(make_readiness(engine, chain, transition, 1, share, 100 + share.member)
                          for share in shares[:target.active_key.committee.threshold])
            prepared = PreparedTransition(transition, ready)
            verify_readiness(engine, chain, prepared)
            return {'id': name, 'chain_id_raw': chain.hex(), 'activation_height': 10,
                    'source_config': initial.to_bytes().hex(), 'source_config_binding': initial.binding().hex(),
                    'target_config': target.to_bytes().hex(), 'target_config_binding': target.binding().hex(),
                    'prepared': prepared_to_bytes(prepared).hex(), 'transition_binding': transition.binding(chain).hex(),
                    'source_assets_raw': [asset.hex() for asset in assets], 'source_assets_version': 0,
                    'target_assets_raw': [asset.hex() for asset in target_assets], 'target_assets_version': target_version,
                    'source_policy_binding_raw': initial.signer_policy.hex(), 'target_policy_binding_raw': target.signer_policy.hex()}

        request_binding = hashlib.sha256(b'PUBLIC synthetic disclosure request').digest()
        partials = tuple(chunked.partial_decrypt_chunked(engine, statement, packet, incoming, share, request_binding)
                         for share in incoming_shares[:incoming.threshold])
        recovered = chunked.combine_chunked(engine, statement, packet, incoming, partials, request_binding)
        if recovered != opening:
            raise AssertionError('fixed incoming committee did not recover fixed opening')
        vector = {'format': FORMAT, 'public_test_only': True,
                  'warning': 'ALL secrets and randomness are deliberately PUBLIC TEST VALUES. NEVER use for funds, live chains or real disclosure.',
                  'public_seed_utf8': PUBLIC_SEED.decode(),
                  'known_public_values': {'audit_secret': 17, 'old_polynomial_coefficients': [17, 29],
                                          'incoming_polynomial_coefficients': [17, 31, 37],
                                          'identity_secret_rule': '100 + member_id',
                                          'old_members': list(old.members), 'incoming_members': list(incoming.members),
                                          'asset_blinder': 43, 'value_blinder': 47},
                  'packet': {'statement': statement_json(statement), 'statement_binding': statement.binding().hex(),
                             'packet_hex': packet.to_bytes().hex(), 'packet_sha256': hashlib.sha256(packet.to_bytes()).hexdigest(),
                             'packet_bytes': len(packet.to_bytes()), 'envelope_context': chunked.envelope_context(statement, packet).hex(),
                             'range_proof_context': chunked.proof_context(statement, packet).hex(),
                             'consistency_context': chunked.consistency_context(statement, packet).hex(),
                             'expected_opening': {'asset_raw': opening.asset.hex(), 'amount_base': opening.amount,
                                                  'asset_blinder_be': f'{opening.asset_blinder:064x}', 'value_blinder_be': f'{opening.value_blinder:064x}'}},
                  'governance': [transition_vector('handoff_2_of_3_to_3_of_4', handoff, incoming_shares, assets, 0),
                                 transition_vector('append_registry_v0_to_v1', registration, old_shares, appended, 1)],
                  'recovery': {'request_binding': request_binding.hex(), 'incoming_committee_binding': incoming.binding().hex(),
                               'partial_members': [partial.member for partial in partials],
                               'partial_points_sha256': [hashlib.sha256(b''.join(partial.points)).hexdigest() for partial in partials],
                               'recovered_opening_matches': True},
                  'native_policy': {'signblockscript': program.hex(), 'max_block_witness': 108,
                                    'fedpeg_program': program.hex(), 'fedpegscript': script.hex(), 'extension_space': ['']}}
        return vector


def verify(engine, vector):
    if vector.get('format') != FORMAT or vector.get('public_test_only') is not True:
        raise ValueError('expected explicitly PUBLIC TEST ONLY review fixture')
    statement = statement_from(vector['packet']['statement'])
    encoded = bytes.fromhex(vector['packet']['packet_hex'])
    packet = chunked.ChunkPacket.from_bytes(encoded, statement, engine)
    if not chunked.verify_chunked(engine, statement, packet):
        raise AssertionError('public packet does not verify in Python')
    if statement.binding().hex() != vector['packet']['statement_binding']:
        raise AssertionError('statement binding mismatch')
    for governance in vector['governance']:
        config = AuditConfig.from_bytes(bytes.fromhex(governance['target_config']), engine)
        prepared = prepared_from_bytes(bytes.fromhex(governance['prepared']), config)
        verify_readiness(engine, bytes.fromhex(governance['chain_id_raw']), prepared)
        if config.binding().hex() != governance['target_config_binding']:
            raise AssertionError('configuration binding mismatch')
    # Regeneration is stronger than parsing: catches accidental changes in
    # fixed randomness, transcript encoding or native range-proof bytes.
    regenerated = generate(engine)
    if canonical(regenerated) != canonical(vector):
        raise AssertionError('public vector differs from deterministic regeneration')
    return {'status': 'passed', 'format': FORMAT, 'packet_bytes': len(encoded),
            'governance_cases': len(vector['governance']), 'deterministic_regeneration': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', default=os.environ.get('THRESHOLD_AUDIT_SECP256K1') or os.environ.get('SECP256K1_ZKP_LIBRARY'))
    parser.add_argument('--output', type=Path, help='write a new public vector JSON')
    parser.add_argument('--check', action='store_true', help='verify checked-in fixture and exact regeneration')
    parser.add_argument('--fixture', type=Path, default=FIXTURE)
    options = parser.parse_args()
    if not options.library or not (options.output or options.check):
        parser.error('--library plus --output or --check is required')
    engine = Curve(options.library)
    try:
        if options.output:
            options.output.parent.mkdir(parents=True, exist_ok=True)
            options.output.write_text(json.dumps(generate(engine), sort_keys=True, indent=2) + '\n')
        if options.check:
            print(json.dumps(verify(engine, json.loads(options.fixture.read_text())), sort_keys=True))
    finally:
        engine.close()


if __name__ == '__main__':
    main()
