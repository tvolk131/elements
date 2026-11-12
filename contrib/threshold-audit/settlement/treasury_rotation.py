"""Fixed-transaction treasury handovers on the existing Elements chain.

Rotation approval is independent of ordinary financial approvals. Each source
UTXO moves in its entirety to one incoming federation output. A confirmed
handover record links an immutable original escrow reference to its new spend
location without rewriting bank receipts or economic authorizations.
"""

from decimal import Decimal
import hashlib
import json

from test_framework import messages
from test_framework.messages import tx_from_hex
from test_framework.script import CScript, SegwitV0SignatureHash, SIGHASH_ALL, OP_CHECKMULTISIG

from .approval import canonical
from .treasury import InstitutionClient, NativeECDSA, public_outputs, template_hash


# Backwards-compatible imports; the public boundary is shared with the adapter.
from .policy import POLICY_FIELDS, public_policy, validate_policy, validate_successor


def packet_summary(packet):
    return {key: packet[key] for key in ('migration_id', 'source_txid', 'source_vout', 'asset_id',
            'amount_base', 'kind', 'case_id', 'original_escrow_txid', 'transaction_template_hash',
            'target_output_index', 'target_script', 'target_policy_version')}


def rotation_verifier(curve, config, operation):
    from .rotation_approval import RotationVerifier
    version = operation['source_policy_version']
    own_version = config.get('policy_version', 'sandbox-v1')
    if version == own_version:
        keys, threshold = config['approval_public_keys'], config['threshold']
    else:
        history = config.get('historical_approval_policies', {})
        policy = history.get(version)
        if policy is None:
            raise ValueError('rotation source approval policy is not trusted')
        keys = policy.get('public_keys', policy.get('approval_public_keys'))
        threshold = policy['threshold']
    return RotationVerifier(curve, keys, threshold, version)


def validate_packet(curve, rpc, config, operation, packet, *, require_own_source=True):
    """Independently verify all clear migration claims against actual commitments."""
    if operation['genesis_hash'] != config['genesis_hash']:
        raise ValueError('rotation belongs to another chain')
    source = validate_policy(operation['manifest']['source_policy'])
    target = validate_successor(source, operation['manifest']['target_policy'])
    if source['policy_version'] != operation['source_policy_version'] or target['policy_version'] != operation['target_policy_version']:
        raise ValueError('rotation policy version mismatch')
    if require_own_source:
        if any(source[key] != public_policy(config)[key] for key in
               ('policy_version', 'approval_public_keys', 'threshold', 'guardian_order', 'treasury_script', 'witness_script')):
            raise ValueError('rotation does not migrate this institution policy')
    if packet_summary(packet) not in operation['manifest']['migrations']:
        raise ValueError('migration transaction was not approved in rotation manifest')
    transaction = tx_from_hex(packet['rawtx'])
    if template_hash(transaction) != packet['transaction_template_hash']:
        raise ValueError('migration template differs from approved transaction')
    if packet['target_script'] != target['treasury_script'] or packet['target_policy_version'] != target['policy_version']:
        raise ValueError('migration destination differs from approved incoming federation')
    index = packet['input_index']
    txin = transaction.vin[index]
    if f'{txin.prevout.hash:064x}' != packet['source_txid'] or txin.prevout.n != packet['source_vout']:
        raise ValueError('migration source outpoint differs from manifest')
    previous = tx_from_hex(rpc.getrawtransaction(packet['source_txid']))
    prevout = previous.vout[packet['source_vout']]
    if bytes(prevout.scriptPubKey).hex() != source['treasury_script']:
        raise ValueError('migration source is not outgoing federation treasury')
    verified = public_outputs(curve, type('OneOutput', (), {'vout': [prevout]})(), {'0': packet['input_opening']})[0]
    if verified['asset'] != packet['asset_id'] or verified['amount'] != packet['amount_base']:
        raise ValueError('migration amount or asset differs from previous output')
    outputs = public_outputs(curve, transaction, packet['openings'])
    moved = [out for out in outputs if out['asset'] == packet['asset_id']]
    if len(moved) != 1 or moved[0]['amount'] != packet['amount_base'] or moved[0]['script'] != target['treasury_script']:
        raise ValueError('entire authority or escrow must move to incoming federation')
    moved_index = packet['target_output_index']
    if outputs[moved_index] != moved[0]:
        raise ValueError('migration output locator is incorrect')
    if any(out['asset'] not in {packet['asset_id'], config['policy_asset']} for out in outputs):
        raise ValueError('migration contains unrelated output asset')
    fees = [out for out in outputs if not out['script']]
    if len(fees) != 1 or fees[0]['asset'] != config['policy_asset'] or not 0 < fees[0]['amount'] <= 1_000_000:
        raise ValueError('migration fee exceeds institutional policy')
    for position, inp in enumerate(transaction.vin):
        if not inp.assetIssuance.isNull():
            raise ValueError('a handover cannot issue currency or authority tokens')
        if position != index:
            prev = tx_from_hex(rpc.getrawtransaction(f'{inp.prevout.hash:064x}')).vout[inp.prevout.n]
            if bytes(prev.scriptPubKey).hex() == source['treasury_script']:
                raise ValueError('unlisted treasury input in migration')
    return transaction, prevout


def current_escrow(config, rpc, curve, operation, requested, records):
    """Verify signed, confirmed links from the original bank escrow to current UTXO."""
    original = operation['escrow_txid']
    case_id = operation['cash_receipt_id'] if operation['kind'] == 'refund' else operation['id']
    candidates = []
    for record in records:
        packet = record['packet']
        if packet.get('case_id') != case_id or packet.get('original_escrow_txid') != original:
            continue
        candidates.append(record)
    if len(candidates) > 16:
        raise ValueError('escrow migration history exceeds sandbox bound')
    if requested['txid'] == original:
        if candidates:
            raise ValueError('migrated escrow cannot return to its original outpoint')
        if operation['kind'] != 'refund' and operation['policy_version'] != config.get('policy_version', 'sandbox-v1'):
            raise ValueError('historic escrow requires a confirmed migration link')
        return requested
    locator = None
    txid = original
    consumed = set()
    last_target = None
    while txid != requested['txid']:
        matches = [record for record in candidates if record['packet']['source_txid'] == txid
                   and (locator is None or record['packet']['source_vout'] == locator['vout'])]
        if len(matches) != 1:
            raise ValueError('missing or ambiguous original escrow migration link')
        record = matches[0]
        identity = record['packet']['migration_id']
        if identity in consumed:
            raise ValueError('cyclic escrow migration history')
        consumed.add(identity)
        rotation, packet = record['rotation'], record['packet']
        if rotation['genesis_hash'] != operation['genesis_hash']:
            raise ValueError('escrow migration belongs to a different economic chain')
        rotation_verifier(curve, config, rotation).verify_certificate(rotation, record['certificate'], allow_expired=True)
        validate_packet(curve, rpc, config, rotation, packet, require_own_source=False)
        if packet['asset_id'] != operation['asset_id'] or packet['amount_base'] != operation['amount_minor'] * 1_000_000:
            raise ValueError('migration does not preserve original redemption value')
        decoded = rpc.getrawtransaction(record['prepared']['txid'], True)
        if int(decoded.get('confirmations', 0)) < 1:
            raise ValueError('escrow migration is not confirmed on current chain')
        actual = tx_from_hex(decoded['hex'])
        actual.rehash()
        if actual.hash != record['prepared']['txid'] or decoded['txid'] != actual.hash:
            raise ValueError('confirmed migration transaction ID is inconsistent')
        if template_hash(actual) != packet['transaction_template_hash']:
            raise ValueError('confirmed migration differs from approved template')
        txid = decoded['txid']
        locator = {'txid': txid, 'vout': packet['target_output_index']}
        last_target = rotation['manifest']['target_policy']
    if locator != requested:
        raise ValueError('escrow spend does not use confirmed incoming-federation outpoint')
    current = public_policy(config)
    if last_target is None or public_policy(last_target) != current:
        raise ValueError('escrow migration does not terminate at the current federation')
    return locator


class TreasuryRotation:
    def __init__(self, adapter):
        self.adapter = adapter

    def prepare(self, rotation_id, target, escrows):
        """Prepare/persist all exact native transactions before quorum approval.

        The caller holds settlement execution and supplies distinct sponsor fee
        UTXOs beforehand. Escrows are immutable operations with escrow_txid;
        a previously migrated operation can include current_escrow locator.
        """
        validate_policy(target)
        adapter, packets = self.adapter, []
        with adapter.lock:
            # Wallet UTXO locks are not durable. Restore every already-fixed
            # migration reservation before funding a later packet on resume.
            existing = adapter.db.execute("SELECT packet FROM prepared WHERE stage='migration' AND case_id LIKE ?",
                                           (f'rotation:{rotation_id}:%',)).fetchall()
            for row in existing:
                packet = json.loads(row[0])
                if packet['target_script'] != target['treasury_script']:
                    raise ValueError('rotation already prepared for another destination')
                adapter._reserve({}, packet)
            sources = []
            for currency, asset in adapter.config['assets'].items():
                coins = [coin for coin in adapter.sponsor.listunspent(1) if coin['asset'] == asset['token_id']
                         and adapter.sponsor.validateaddress(coin['address'])['scriptPubKey'] == adapter.config['treasury_script']]
                if len(coins) != 1:
                    # Existing durable packet reserves its source, so reload it.
                    rows = adapter.db.execute("SELECT packet FROM prepared WHERE stage='migration' AND case_id LIKE ?",
                                              (f'rotation:{rotation_id}:%',)).fetchall()
                    old = [json.loads(row[0]) for row in rows if json.loads(row[0])['asset_id'] == asset['token_id']]
                    if len(old) == 1:
                        sources.append({'packet': old[0]})
                        continue
                    raise ValueError('exactly one complete authority output is required per currency')
                coin = coins[0]
                sources.append({'txid': coin['txid'], 'vout': coin['vout'], 'asset_id': asset['token_id'],
                                'kind': 'authority', 'case_id': None, 'original_escrow_txid': None})
            for operation in escrows:
                locator = operation.get('current_escrow') or adapter.config.get('escrow_migrations', {}).get(operation['escrow_txid'])
                original = operation['escrow_txid']
                if locator:
                    txid, vout = locator['txid'], locator['vout']
                else:
                    txid = original
                    transaction = tx_from_hex(adapter.node.getrawtransaction(txid))
                    matching = [(i, adapter._opening(transaction, i)) for i, out in enumerate(transaction.vout)
                                if bytes(out.scriptPubKey).hex() == adapter.config['treasury_script']]
                    matching = [(i, opening) for i, opening in matching if opening['asset'] == operation['asset_id']
                                and opening['amount'] == operation['amount_minor'] * 1_000_000]
                    if len(matching) != 1:
                        raise ValueError('original escrow output is missing or ambiguous')
                    vout = matching[0][0]
                sources.append({'txid': txid, 'vout': vout, 'asset_id': operation['asset_id'], 'kind': 'escrow',
                                'case_id': operation['id'], 'original_escrow_txid': original})
            for source in sources:
                if 'packet' in source:
                    packets.append(source['packet'])
                    continue
                identity = f"rotation:{rotation_id}:{source['txid']}:{source['vout']}"
                row = adapter.db.execute("SELECT packet FROM prepared WHERE case_id=? AND stage='migration'", (identity,)).fetchone()
                if row:
                    packet = json.loads(row[0])
                    if packet['target_script'] != target['treasury_script']:
                        raise ValueError('rotation already prepared for another destination')
                    packets.append(packet)
                    continue
                previous = tx_from_hex(adapter.node.getrawtransaction(source['txid']))
                opening = adapter._opening(previous, source['vout'])
                if opening['asset'] != source['asset_id']:
                    raise ValueError('migration source asset differs from expected authority or escrow')
                raw = adapter.sponsor.createrawtransaction([{'txid': source['txid'], 'vout': source['vout']}],
                        [{target['treasury_address']: Decimal(opening['amount']) / 100_000_000, 'asset': source['asset_id']}])
                funded = adapter.sponsor.fundrawtransaction(raw, {'fee_rate': 2, 'includeWatching': True,
                         'changeAddress': adapter.sponsor.getrawchangeaddress('blech32'), 'lockUnspents': False})['hex']
                blinded = adapter.sponsor.blindrawtransaction(funded, False, [], False)
                partial = adapter.sponsor.signrawtransactionwithwallet(blinded)['hex']
                transaction = tx_from_hex(partial)
                input_index = next(i for i, inp in enumerate(transaction.vin)
                                   if f'{inp.prevout.hash:064x}' == source['txid'] and inp.prevout.n == source['vout'])
                outputs = adapter._all_openings(transaction)
                target_index = next(i for i, out in enumerate(transaction.vout)
                                    if bytes(out.scriptPubKey).hex() == target['treasury_script']
                                    and outputs[str(i)]['asset'] == source['asset_id'])
                packet = {'migration_id': identity, 'stage': 'migration', 'rawtx': partial, 'input_index': input_index,
                          'input_opening': opening, 'openings': outputs, 'source_txid': source['txid'],
                          'source_vout': source['vout'], 'asset_id': source['asset_id'], 'amount_base': opening['amount'],
                          'kind': source['kind'], 'case_id': source['case_id'], 'original_escrow_txid': source['original_escrow_txid'],
                          'transaction_template_hash': template_hash(transaction), 'target_output_index': target_index,
                          'target_script': target['treasury_script'], 'target_policy_version': target['policy_version']}
                adapter.db.execute('INSERT INTO prepared VALUES(?,?,?,NULL)', (identity, 'migration', json.dumps(packet, sort_keys=True)))
                adapter._reserve({}, packet)
                packets.append(packet)
        return packets

    def sign(self, packet, rotation, certificate):
        adapter = self.adapter
        with adapter.lock:
            row = adapter.db.execute("SELECT signed FROM prepared WHERE case_id=? AND stage='migration'", (packet['migration_id'],)).fetchone()
            if row is None:
                raise ValueError('migration was not durably prepared')
            if row[0]:
                signed = row[0]
            else:
                source = rotation['manifest']['source_policy']
                transaction = tx_from_hex(packet['rawtx'])
                witness = CScript(bytes.fromhex(source['witness_script']))
                prev = tx_from_hex(adapter.node.getrawtransaction(packet['source_txid'])).vout[packet['source_vout']]
                digest = SegwitV0SignatureHash(witness, transaction, packet['input_index'], SIGHASH_ALL, prev.nValue)
                public_keys = dict(zip(source['guardian_order'], list(witness)[1:-2]))
                signatures = {}
                for approval in certificate['signatures']:
                    guardian = approval['guardian_id']
                    try:
                        result = adapter.institutions.request(guardian, 'sign_migration', rotation=rotation, certificate=certificate, packet=packet)
                        signature = bytes.fromhex(result['signature'])
                        if result['guardian_id'] != guardian or not NativeECDSA(adapter.curve).verify(public_keys[guardian], digest, signature):
                            continue
                        signatures[guardian] = signature
                    except (OSError, ValueError, KeyError):
                        continue
                    if len(signatures) >= source['threshold']:
                        break
                if len(signatures) < source['threshold']:
                    raise ValueError('outgoing treasury signing quorum unavailable')
                while len(transaction.wit.vtxinwit) < len(transaction.vin):
                    transaction.wit.vtxinwit.append(messages.CTxInWitness())
                ordered = [signatures[key] for key in source['guardian_order'] if key in signatures][:source['threshold']]
                transaction.wit.vtxinwit[packet['input_index']].scriptWitness.stack = [b'', *ordered, bytes(witness)]
                signed = transaction.serialize().hex()
                accepted = adapter.node.testmempoolaccept([signed], 0)[0]
                if not accepted['allowed']:
                    raise ValueError('Elements rejected migration: ' + accepted.get('reject-reason', str(accepted)))
                adapter.db.execute("UPDATE prepared SET signed=? WHERE case_id=? AND stage='migration'", (signed, packet['migration_id']))
            transaction = tx_from_hex(signed)
            transaction.rehash()
            return {'stage': 'migration', 'rawtx': signed, 'txid': transaction.hash}
