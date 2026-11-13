"""Recipient-side package verification, using native TAC2 verification.

python -m settlement.disclosure_recipient --key KEY.json --bundle CASE.json --out OPENINGS.json
Add --node-config PRIVATE_RPC_CONFIG to verify chain inclusion and both policy eras
against your own Elements node. The key password is prompted locally, never sent.
"""
import argparse
import getpass
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from chunked import ChunkPacket, combine_chunked, verify_partial_chunked
from curve import Curve
from disclosure import Approval, Policy, authorize
from governance import AuditConfig
from guardian_client import verify_checkpoint
from guardian_service import atomic_write, disclosure_from, statement_from
from recovery import digest
from sealed_delivery import canonical, unseal
from threshold import Committee, PartialDecryption


def verify_chain(curve, output, node):
    from .federation_audit import full_policy_at
    from native_transactions import output_statement
    from test_framework import messages
    from test_framework.messages import tx_from_hex
    messages.THRESHOLD_AUDIT = True
    if (node.getblockhash(output['creation_height']) != output['creation_block']
            or node.getblockhash(output['approval_height']) != output['approval_block']):
        raise ValueError('package block ancestry differs from the trusted node')
    creation = full_policy_at(node, output['creation_height'])
    approved = full_policy_at(node, output['approval_height'])
    configuration = AuditConfig.from_bytes(bytes.fromhex(approved['audit_config']), curve)
    key = configuration.key(output['key_version'])
    if (configuration.to_bytes().hex() != output['configuration_bytes']
            or key.committee != Committee(output['committee']['epoch'], tuple(output['committee']['members']), tuple(bytes.fromhex(p) for p in output['committee']['commitments']))
            or list(configuration.identities) != [(member, bytes.fromhex(public)) for member, public in output['identities']]):
        raise ValueError('package committee differs from its on-chain approval policy')
    transaction = tx_from_hex(node.getrawtransaction(output['txid']))
    assets = tuple(sorted(bytes.fromhex(a)[::-1] for a in creation['audit_assets']))
    statement = output_statement(transaction, output['output_index'], bytes.fromhex(node.getblockhash(0))[::-1], key.public_key, assets)
    if (statement.binding() != statement_from(output['statement']).binding()
            or transaction.wit.vtxoutwit[output['output_index']].vchAuditProof.hex() != output['packet']):
        raise ValueError('package output differs from the trusted chain')


def open_bundle(curve, secret, user_id, bundle, node=None):
    manifest = bundle['manifest']
    manifest_hash = digest(b'settlement-disclosure-case', canonical(manifest))
    if (bundle.get('format') != 'concord-sealed-disclosure-v1'
            or manifest['recipient']['id'] != user_id
            or manifest['recipient']['public_key'] != curve.mul(secret).hex()
            or manifest_hash.hex() != bundle['manifest_hash']
            or len(bundle['outputs']) != len(manifest['targets']) or not 1 <= len(bundle['outputs']) <= 4):
        raise ValueError('invalid package manifest, recipient or scope')
    results, unavailable = [], []
    for output in bundle['outputs']:
        target = next((t for t in manifest['targets'] if t['txid'] == output['txid'] and t['output_index'] == output['output_index']), None)
        if (target is None or target['statement'] != output['statement'] or target['creation_block'] != output['creation_block']
                or target.get('approval_block') != output.get('approval_block') or target.get('approval_height') != output.get('approval_height')):
            raise ValueError('output differs from its approved manifest')
        if node is not None:
            verify_chain(curve, output, node)
        statement = statement_from(output['statement'])
        packet = ChunkPacket.from_bytes(bytes.fromhex(output['packet']), statement, curve)
        committee = Committee(output['committee']['epoch'], tuple(output['committee']['members']), tuple(bytes.fromhex(p) for p in output['committee']['commitments']))
        committee.validate(curve)
        policy, request = disclosure_from(output)
        if (request.case_reference != manifest_hash or request.recipient_key != curve.mul(secret)
                or request.statement_binding != statement.binding() or request.packet_binding != digest(b'packet', packet.to_bytes())
                or target['packet_hash'] != request.packet_binding.hex() or request.delivery != 'sealed-v1'
                or request.expires_at != manifest['expires_at'] or request.binding().hex() != output['request_binding']
                or policy != Policy(committee.binding(), committee.threshold, tuple((m,bytes.fromhex(p)) for m,p in output['identities']))):
            raise ValueError('package request is not the approved exact scope')
        identities = dict(policy.approvers)
        partials = []
        approvals = tuple(Approval(int(member), bytes.fromhex(value['signature'])) for member, value in output['approvals'].items())
        for member, envelope in output['sealed_partials'].items():
            try:
                member = int(member)
                if not manifest['created_at'] <= envelope['released_at'] < request.expires_at:
                    raise ValueError('release is outside the approved validity period')
                authorize(curve, policy, request, approvals, envelope['released_at'])
                value = unseal(curve, secret, identities[member], envelope, request.binding(), member)
                if value['member'] != member or value['checkpoint']['member'] != member or not verify_checkpoint(curve, identities[member], value['checkpoint']):
                    raise ValueError('invalid guardian checkpoint or identity')
                partial = PartialDecryption(value['member'], bytes.fromhex(value['committee_binding']), bytes.fromhex(value['request_binding']),
                               tuple(bytes.fromhex(p) for p in value['points']), tuple(tuple(int(s,16) for s in pair) for pair in value['proofs']))
                if not verify_partial_chunked(curve, statement, packet, committee, partial, request.binding()) or any(p.member == member for p in partials):
                    raise ValueError('invalid or duplicate guardian contribution')
                partials.append(partial)
            except Exception:
                continue  # An additional bad guardian cannot veto a valid quorum.
        if len(partials) < committee.threshold:
            unavailable.append({'txid':output['txid'],'output_index':output['output_index']})
            continue
        opening = combine_chunked(curve, statement, packet, committee, tuple(partials), request.binding())
        results.append({'txid':output['txid'],'output_index':output['output_index'],'asset_id':opening.asset[::-1].hex(),
                        'amount_base_units':str(opening.amount),'asset_blinder':f'{opening.asset_blinder:064x}',
                        'value_blinder':f'{opening.value_blinder:064x}','verified_guardians':len(partials)})
    if not results: raise ValueError('package has no valid recipient recovery quorum')
    return {'case_id':manifest['id'],'manifest_hash':bundle['manifest_hash'],'chain_verified':node is not None,'outputs':results,'unavailable_outputs':unavailable}


def unlock_key(value, password):
    if (value.get('format') != 'concord-recipient-key-v1' or len(value['salt']) != 32 or len(value['nonce']) != 24 or len(value['ciphertext']) != 96):
        raise ValueError('invalid encrypted recipient key file')
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(value['salt']), iterations=210000).derive(password.encode())
    aad = canonical({name:value[name] for name in ('format','user_id','public_key')})
    return int.from_bytes(AESGCM(key).decrypt(bytes.fromhex(value['nonce']), bytes.fromhex(value['ciphertext']), aad),'big')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key',required=True);parser.add_argument('--bundle',required=True);parser.add_argument('--out',required=True)
    parser.add_argument('--node-config');parser.add_argument('--library',default='/tmp/elements-audit-secp/lib/libsecp256k1.so')
    args=parser.parse_args()
    if Path(args.key).stat().st_size>8192 or Path(args.bundle).stat().st_size>4*1024*1024:
        raise ValueError('input exceeds recipient format limits')
    key=json.loads(Path(args.key).read_text());bundle=json.loads(Path(args.bundle).read_text())
    secret=unlock_key(key,getpass.getpass('Recipient key password: '))
    node=None
    if args.node_config:
        from .elements_adapter import RPC
        from .runtime import load_config
        node=RPC(load_config(args.node_config)['rpc_url'])
    curve=Curve(args.library)
    try:
        if curve.mul(secret).hex()!=key['public_key']: raise ValueError('recipient key does not match its public key')
        result=open_bundle(curve,secret,key['user_id'],bundle,node)
        atomic_write(Path(args.out),result)
        print(json.dumps({'verified_outputs':len(result['outputs']),'chain_verified':result['chain_verified'],'output_file':args.out}))
    finally:curve.close()

if __name__=='__main__':main()
