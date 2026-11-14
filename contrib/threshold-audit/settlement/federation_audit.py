"""Durable public audit-key handoff plans for the same-chain local pilot.

Plan files contain public configurations, session IDs and readiness proofs.
Secret coefficients, evaluations and decryption shares stay in the isolated
guardian processes. This retains the existing research-ceremony assumptions.
"""

from dataclasses import replace
import hashlib
from pathlib import Path
import re
import secrets

from chunked import ChunkPacket
from governance import AuditConfig, AuditKey, verify_readiness
from guardian_service import atomic_write, parse_json
from native_governance import policy_binding, prepared_from_bytes, prepared_to_bytes
from native_transactions import output_statement
from test_framework import messages
from test_framework.messages import CBlock, from_hex, tx_from_hex


def full_policy_at(node, height, epoch_length=10):
    """Find the full authenticated DynaFed policy governing a creation block."""
    if type(height) is not int or height < 0:
        raise ValueError('invalid policy lookup height')
    for candidate in range(height, max(-1, height - epoch_length - 1), -1):
        block = node.getblock(node.getblockhash(candidate))
        entry = block.get('dynamic_parameters', {}).get('current', {})
        if entry.get('audit_config') is not None and entry.get('fedpegscript') is not None:
            return entry
    raise ValueError('no full authenticated audit policy found for block')


class AuditRotation:
    def __init__(self, cluster, node, directory, epoch_length=10):
        messages.THRESHOLD_AUDIT = True
        self.cluster, self.node, self.curve = cluster, node, cluster.curve
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.epoch_length = epoch_length

    def current_config(self):
        return AuditConfig.from_bytes(bytes.fromhex(self.node.getblockchaininfo()['audit_config']), self.curve)

    def _path(self, rotation_id):
        if not isinstance(rotation_id, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', rotation_id) is None:
            raise ValueError('invalid audit rotation ID')
        return self.directory / (rotation_id + '.json')

    def _save(self, record):
        atomic_write(self._path(record['id']), record)
        return record

    def load(self, rotation_id):
        return parse_json(self._path(rotation_id).read_bytes())

    def _begin(self, rotation_id, mode, signblockscript, witness_limit, activation_height, members=None, threshold=None,
               tx_authorization=None):
        script = bytes.fromhex(signblockscript) if isinstance(signblockscript, str) else bytes(signblockscript)
        if len(script) != 34 or script[:2] != b'\x00\x20':
            raise ValueError('rotation pilot requires a P2WSH block signing script')
        if type(witness_limit) is not int or not 1 <= witness_limit <= 100_000:
            raise ValueError('invalid block witness limit')
        path = self._path(rotation_id)
        if path.exists():
            record = self.load(rotation_id)
            if (record['mode'] != mode or record['signblockscript'] != script.hex()
                    or record['witness_limit'] != witness_limit
                    or (activation_height is not None and record['activation_height'] != activation_height)
                    or record.get('incoming_members') != (None if members is None else list(members))
                    or record.get('incoming_threshold') != threshold
                    or record['genesis_hash'] != self.node.getblockhash(0)
                    or (tx_authorization is not None and record.get('tx_authorization', '') != tx_authorization)):
                raise ValueError('audit rotation ID cannot be rebound')
            return record
        height = self.node.getblockcount()
        if height % self.epoch_length:
            raise ValueError('align to a DynaFed epoch before preparing audit rotation')
        expected_activation = height + self.epoch_length
        if activation_height is not None and activation_height != expected_activation:
            raise ValueError('activation must target the next complete voting epoch')
        info = self.node.getblockchaininfo()
        previous = self.current_config()
        source_policy = full_policy_at(self.node, height, self.epoch_length)
        raw_fedpeg = bytes.fromhex(source_policy['fedpegscript'])
        program = bytes.fromhex(source_policy['fedpeg_program'])
        if program != b'\x00\x20' + hashlib.sha256(raw_fedpeg).digest():
            raise ValueError('pilot cannot propose this fedpeg program')
        assets = tuple(sorted(bytes.fromhex(asset)[::-1] for asset in info['audit_assets']))
        # Who may authorize transactions carries over unless this rotation replaces it.
        if tx_authorization is None:
            tx_authorization = source_policy.get('tx_authorization', '')
        target_binding = policy_binding(script, witness_limit, program, raw_fedpeg,
                                       [bytes.fromhex(item) for item in source_policy['extension_space']],
                                       audit_assets=assets, audit_assets_version=info['audit_assets_version'],
                                       tx_authorization=bytes.fromhex(tx_authorization))
        record = {'id': rotation_id, 'mode': mode, 'phase': 'staging', 'genesis_hash': self.node.getblockhash(0),
                  'source_height': height, 'source_block': self.node.getblockhash(height),
                  'previous_config': previous.to_bytes().hex(), 'previous_hash': previous.binding().hex(),
                  'outgoing_members': [member for member, _ in previous.identities],
                  'incoming_members': None if members is None else list(members), 'incoming_threshold': threshold,
                  'activation_height': expected_activation, 'signblockscript': script.hex(),
                  'witness_limit': witness_limit, 'fedpeg_program': program.hex(), 'fedpegscript': raw_fedpeg.hex(),
                  'extension_space': source_policy['extension_space'], 'audit_assets': [asset[::-1].hex() for asset in assets],
                  'audit_assets_version': info['audit_assets_version'], 'tx_authorization': tx_authorization,
                  'signer_policy': target_binding.hex(),
                  'sessions': {str(key.version): secrets.token_hex(32) for key in previous.keys} if mode == 'handoff' else {},
                  'plans': {}}
        return self._save(record)

    def _previous(self, record):
        previous = AuditConfig.from_bytes(bytes.fromhex(record['previous_config']), self.curve)
        if previous.binding().hex() != record['previous_hash']:
            raise ValueError('stored audit predecessor binding differs')
        if self.node.getblockhash(record['source_height']) != record['source_block']:
            raise ValueError('audit rotation source block was reorganized')
        return previous

    def _prepared(self, record):
        config = AuditConfig.from_bytes(bytes.fromhex(record['audit_config']), self.curve)
        prepared = prepared_from_bytes(bytes.fromhex(record['audit_prepared']), config)
        if (prepared.transition.previous.hex() != record['previous_hash']
                or prepared.transition.activation_height != record['activation_height']):
            raise ValueError('stored audit transition binding differs')
        if (config.signer_policy.hex() != record['signer_policy']
                or config.active_key.public_key.hex() != record['audit_pubkey']
                or config.active_version != record['audit_version']):
            raise ValueError('stored audit target policy differs')
        verify_readiness(self.curve, bytes.fromhex(record['genesis_hash'])[::-1], prepared)
        return prepared

    def prepared(self, record):
        """Return the validated public PreparedTransition for a saved record."""
        self._previous(record)
        return self._prepared(record)

    def _finish_preparation(self, record, config, plans):
        previous = self._previous(record)
        if self.current_config() != previous:
            raise ValueError('audit preparation no longer extends current chain configuration')
        prepared = self.cluster.prepare(bytes.fromhex(record['genesis_hash'])[::-1], config, plans,
                                        previous=previous, activation_height=record['activation_height'])
        record.update(phase='prepared', audit_config=config.to_bytes().hex(), audit_prepared=prepared_to_bytes(prepared).hex(),
                      audit_pubkey=config.active_key.public_key.hex(), audit_version=config.active_version,
                      target_hash=config.binding().hex(), target_members=[member for member, _ in config.identities],
                      target_threshold=config.active_key.committee.threshold)
        return self._save(record)

    def prepare_policy(self, signblockscript, witness_limit=1024, activation_height=None, *, rotation_id='install-a',
                       tx_authorization=None):
        record = self._begin(rotation_id, 'policy', signblockscript, witness_limit, activation_height,
                             tx_authorization=tx_authorization)
        if record['phase'] != 'staging':
            self.prepared(record)
            return record
        previous = self._previous(record)
        config = replace(previous, generation=previous.generation + 1, signer_policy=bytes.fromhex(record['signer_policy']))
        return self._finish_preparation(record, config, {})

    def prepare_handoff(self, new_members, threshold, signblockscript, witness_limit=1024, activation_height=None,
                        *, rotation_id='handoff-b', tx_authorization=None):
        members = tuple(new_members)
        if (not members or tuple(sorted(set(members))) != members or type(threshold) is not int
                or not 1 <= threshold <= len(members)):
            raise ValueError('invalid incoming audit committee')
        record = self._begin(rotation_id, 'handoff', signblockscript, witness_limit, activation_height, members, threshold,
                             tx_authorization=tx_authorization)
        if record['phase'] != 'staging':
            self.prepared(record)
            return record
        previous = self._previous(record)
        if self.current_config() != previous:
            raise ValueError('audit handoff no longer extends current configuration')
        if (not record.get('enrollment_complete') or any(
                member not in self.cluster.guardians or self.cluster.guardians[member].process is None for member in members)):
            self.cluster.extend(members)
            record['enrollment_complete'] = True
            self._save(record)
        keys, plans = [], {}
        for old in previous.keys:
            plan, committee, _ = self.cluster.deal(bytes.fromhex(record['genesis_hash'])[::-1], members, threshold,
                old.version, previous=previous, mode='refresh', dealers=old.committee.members[:old.committee.threshold],
                session=record['sessions'][str(old.version)])
            plans[old.version] = plan
            record['plans'][str(old.version)] = plan
            self._save(record)
            keys.append(AuditKey(old.version, old.scheme, committee))
        config = AuditConfig(previous.generation + 1, bytes.fromhex(record['signer_policy']),
                             tuple((member, bytes.fromhex(self.cluster.guardians[member].identity)) for member in members),
                             previous.active_version, tuple(keys))
        return self._finish_preparation(record, config, plans)

    def proposal(self, record):
        self.prepared(record)
        return {'signblockscript': record['signblockscript'], 'max_block_witness': record['witness_limit'],
                'fedpegscript': record['fedpegscript'], 'extension_space': record['extension_space'],
                'audit_pubkey': record['audit_pubkey'], 'audit_version': record['audit_version'],
                'audit_config': record['audit_config'], 'audit_prepared': record['audit_prepared'],
                'audit_assets': record['audit_assets'], 'audit_assets_version': record['audit_assets_version'],
                **({'tx_authorization': record['tx_authorization']} if record.get('tx_authorization') else {})}

    def activate(self, record):
        prepared = self.prepared(record)
        if (self.node.getblockcount() < record['activation_height']
                or self.current_config() != prepared.transition.config):
            raise ValueError('target audit configuration is not active on the chain')
        checkpoints = self.cluster.activate(bytes.fromhex(record['genesis_hash'])[::-1], prepared)
        record.update(phase='activated', activation_block=self.node.getblockhash(record['activation_height']),
                      activation_checkpoints=checkpoints)
        return self._save(record)

    def proposal_hash(self, record):
        """Bind institution authorization to exact native proposal serialization."""
        block = from_hex(CBlock(), self.node.getnewblockhex(0, self.proposal(record)))
        return hashlib.sha256(block.m_dynafed_params.m_proposed.serialize()).hexdigest()

    def stop_outgoing(self, record):
        prepared = self.prepared(record)
        if record['phase'] != 'activated' or self.current_config() != prepared.transition.config:
            raise ValueError('incoming audit configuration must activate before retiring outgoing guardians')
        retired = sorted(set(record['outgoing_members']) - set(record['target_members']))
        self.cluster.stop_members(retired)
        record['retired_members'] = retired
        return self._save(record)

    def recover_output(self, txid, index, key_version=None):
        """Research fixture disclosure using current guardians and creation policy.

        This uses the existing fixture approver credentials; a production UI
        must replace the automatic approvals with institutional authorization.
        """
        decoded = self.node.getrawtransaction(txid, True)
        if not decoded.get('blockhash'):
            raise ValueError('historical disclosure requires a confirmed output')
        creation = self.node.getblock(decoded['blockhash'])
        policy = full_policy_at(self.node, creation['height'], self.epoch_length)
        assets = tuple(sorted(bytes.fromhex(asset)[::-1] for asset in policy['audit_assets']))
        transaction = tx_from_hex(decoded['hex'])
        if type(index) is not int or not 0 <= index < len(transaction.vout):
            raise ValueError('invalid disclosure output index')
        config = self.current_config()
        version = config.active_version if key_version is None else key_version
        statement = output_statement(transaction, index, bytes.fromhex(self.node.getblockhash(0))[::-1],
                                     config.key(version).public_key, assets)
        packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
        return self.cluster.recover(config, version, statement, packet, self.cluster.recipient_key)

    def disclosure_context(self, txid, index):
        """Public context only; never auto-approve or recover an opening."""
        from guardian_service import statement_json
        decoded = self.node.getrawtransaction(txid, True)
        if not decoded.get('blockhash') or decoded.get('confirmations', 0) < 1:
            raise ValueError('disclosure requires a confirmed output')
        creation = self.node.getblock(decoded['blockhash'])
        policy = full_policy_at(self.node, creation['height'], self.epoch_length)
        creation_config = AuditConfig.from_bytes(bytes.fromhex(policy['audit_config']), self.curve)
        config = self.current_config()
        key = config.key(creation_config.active_version)
        approval_head = self.node.getblock(self.node.getbestblockhash())
        assets = tuple(sorted(bytes.fromhex(asset)[::-1] for asset in policy['audit_assets']))
        transaction = tx_from_hex(decoded['hex'])
        if type(index) is not int or not 0 <= index < len(transaction.vout):
            raise ValueError('invalid output index')
        statement = output_statement(transaction, index, bytes.fromhex(self.node.getblockhash(0))[::-1], key.public_key, assets)
        packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
        from chunked import verify_chunked
        if not verify_chunked(self.curve, statement, packet):
            raise ValueError('output has no valid confidential recovery packet')
        return {'txid': txid, 'output_index': index, 'creation_block': decoded['blockhash'],
                'approval_height': approval_head['height'], 'approval_block': approval_head['hash'],
                'configuration_bytes': config.to_bytes().hex(),
                'creation_height': creation['height'], 'key_version': key.version,
                'configuration': config.binding().hex(), 'statement': statement_json(statement),
                'packet': packet.to_bytes().hex(),
                'committee': {'epoch': key.committee.epoch, 'members': list(key.committee.members),
                              'commitments': [p.hex() for p in key.committee.commitments]},
                'identities': [[member, public.hex()] for member, public in config.identities]}
