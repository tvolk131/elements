"""Durable, deliberately quiescent same-chain federation handover coordinator."""

import hashlib
import json
from pathlib import Path
import secrets
import time

from governance import AuditConfig
from guardian_service import atomic_write
from .approval import ApprovalVerifier
from .rotation_approval import RotationVerifier
from .store import Problem, FINAL
from .treasury_rotation import TreasuryRotation, packet_summary, public_policy
from .policy import policy_epoch, validate_successor
from .rotation_history import RotationHistory


STEPS = [('preparing', 'Prepare incoming guardians and exact treasury migrations'),
         ('awaiting_approval', 'Collect independent outgoing institution approvals'),
         ('voting', 'Activate incoming block signing and audit policy through DynaFed'),
         ('audit_activated', 'Activate incoming historical audit shares'),
         ('migrating', 'Confirm authority and outstanding escrow migrations'),
         ('activating', 'Activate incoming settlement policy and preserve pending cases'),
         ('retiring', 'Retire outgoing services and revoke their sessions'),
         ('complete', 'Resume settlement on the same chain')]


class FederationRotation:
    def __init__(self, sandbox, store):
        self.sandbox, self.store, self.adapter = sandbox, store, store.chain
        self.path = sandbox.directory / 'federation-rotation.json'
        self.state = json.loads(self.path.read_text()) if self.path.exists() else None
        self.treasury = TreasuryRotation(self.adapter)
        self.history = RotationHistory(sandbox.directory / 'federation-history')
        if self.state is not None:
            if self.state['stage'] == 'complete':
                if self.state['target']['policy']['policy_version'] != self.adapter.config.get('policy_version', 'sandbox-v1'):
                    raise ValueError('completed handover checkpoint differs from current federation policy')
                self._check_active_policy()
            self.history.record(self.state)
        self._history_summaries()

    def _history_summaries(self):
        if self.state is None:
            policy = self.adapter.config.get('policy_version', 'sandbox-v1')
        elif self.state['stage'] == 'complete':
            policy = self.state['target']['policy']['policy_version']
        else:
            policy = self.state['source_policy']['policy_version']
        return self.history.summaries(policy, self.sandbox.node.getblockhash(0))

    @property
    def held(self):
        return self.state is not None and self.state['stage'] != 'complete'

    def _save(self):
        self.state['updated_at'] = int(time.time())
        atomic_write(self.path, self.state)
        self.history.record(self.state)

    def _admin(self, user):
        if user['role'] != 'bankadmin' or user['tenant'] != self.store.config.get('bank_tenant', 'bank'):
            raise Problem('bank administrator membership is required for handover control', 403)

    def _get(self, rotation_id):
        if self.state is None or self.state['id'] != rotation_id:
            raise Problem('federation rotation not found', 404)
        return self.state

    def _verifier(self):
        policy = self.state['source_policy']
        return RotationVerifier(self.store.verifier.curve, policy['approval_public_keys'], policy['threshold'], policy['policy_version'])

    def _institution(self, user):
        if user['role'] != 'institutionguardian' or user.get('institution_id') not in self.state['source_policy']['approval_public_keys']:
            raise Problem('outgoing institution membership is required for rotation approval', 403)

    def _escrows(self):
        operations = [json.loads(row[0]) for row in self.store.db.execute("SELECT data FROM operations WHERE kind='redemption'")]
        return [operation for operation in operations if operation.get('escrow_txid') and operation['state'] not in FINAL]

    def prepare(self, user):
        self._admin(user)
        with self.store.lock, self.sandbox.mining_lock:
            if self.held:
                return self._prepare_or_resume(user)
            if self.store.advancing:
                raise Problem('requests are being sent to the chain; try the handover again in a moment', 409)
            operations = [json.loads(row[0]) for row in self.store.db.execute('SELECT data FROM operations')]
            if any(operation['state'] in {'preparing', 'chain_pending', 'burn_pending'} for operation in operations):
                raise Problem('confirm already prepared transactions before staging the handover', 409)
            if any(operation['kind'] == 'deposit' and operation['state'] not in FINAL and operation.get('cash_receipt_id') for operation in operations):
                raise Problem('complete credited deposits before staging the handover', 409)
            escrows = self._escrows()
            if len(escrows) > 6:
                raise Problem('this sandbox handover supports at most six outstanding escrows', 409)
            source = public_policy(self.adapter.config)
            epoch = policy_epoch(source['policy_version']) + 1
            if self.state is not None:
                self.history.archive(self.state)
            self.state = {'id': secrets.token_hex(16), 'stage': 'preparing', 'source_policy': source,
                          'target_epoch': epoch, 'created_at': int(time.time()), 'error': None,
                          'genesis_hash': self.sandbox.node.getblockhash(0),
                          'source_members': [member for member, _ in self.sandbox.audit.current_config().identities],
                          'escrows': escrows, 'signatures': [], 'prepared_migrations': [], 'confirmed_migrations': []}
            self._save()
            with self.store.transaction():
                self.store.evidence(user['id'], 'federation_handover_started', {'rotation_id': self.state['id']})
            return self._prepare_or_resume(user)

    def _prepare_or_resume(self, user):
        try:
            if self.state['stage'] != 'preparing':
                return self.status(user)
            if not self.state.get('target'):
                self.state['target'] = self.sandbox.create_incoming(self.state['target_epoch'])
                self._save()
            target = self.state['target']['policy']
            validate_successor(self.state['source_policy'], target)
            self.sandbox.blocks.register(dict(target, institutions=self.state['target']['institutions']))
            self.sandbox.blocks.align()
            if not self.state.get('fee_fanout'):
                count = len(self.state['escrows']) + 3
                sponsor = self.adapter.sponsor
                # Fee funding is public policy-asset bookkeeping. Explicit
                # fanout avoids the wallet's conservative per-CT-output limit.
                txid = sponsor.sendmany('', {sponsor.getnewaddress('', 'bech32'): '0.05' for _ in range(count)})
                self.state['fee_fanout'] = txid
                self._save()
                self.sandbox.blocks.mine()
                self.sandbox.blocks.align()
            fanout = self.sandbox.node.getrawtransaction(self.state['fee_fanout'], True)
            if fanout.get('confirmations', 0) < 1:
                self.sandbox.blocks.mine()
                self.sandbox.blocks.align()
            # Height is held while humans approve. Epoch-bound readiness and
            # the exact prepared transactions cannot age into a different vote.
            config = AuditConfig.from_bytes(bytes.fromhex(self.sandbox.node.getblockchaininfo()['audit_config']), self.store.verifier.curve)
            current_ids = [member for member, _ in config.identities]
            new_members = list(range(max(current_ids) + 1, max(current_ids) + 16))
            audit = self.sandbox.audit.prepare_handoff(new_members, 11, target['block_signing_script'],
                                                       rotation_id=self.state['id'])
            self.state['audit'] = audit
            self.adapter.config['audit_pool_members'] = sorted(set(audit['outgoing_members']) | set(audit['target_members']))
            self.sandbox.persist_adapter()
            packets = self.treasury.prepare(self.state['id'], target, self.state['escrows'])
            self.state['packets'] = packets
            operation = {'kind': 'federation_rotation', 'id': self.state['id'],
                         'chain': self.adapter.network()['chain'], 'genesis_hash': self.state['genesis_hash'],
                         'source_policy_version': self.state['source_policy']['policy_version'],
                         'target_policy_version': target['policy_version'], 'expires_at': int(time.time()) + 86400,
                         'manifest': {'source_policy': self.state['source_policy'], 'target_policy': target,
                                      'audit_config_hash': audit['target_hash'],
                                      'audit_prepared_hash': hashlib.sha256(bytes.fromhex(audit['audit_prepared'])).hexdigest(),
                                      'proposal_hash': self.sandbox.audit.proposal_hash(audit),
                                      'activation_height': audit['activation_height'],
                                      'incoming_audit_members': audit['target_members'], 'incoming_audit_threshold': 11,
                                      'migrations': [packet_summary(packet) for packet in packets]}}
            self.state.update(operation=operation, stage='awaiting_approval', error=None)
            self._save()
        except Exception as error:
            self.state['error'] = str(error)[:500]
            self._save()
        return self.status(user)

    def prepare_approval(self, user, rotation_id):
        with self.store.lock:
            self._get(rotation_id)
            self._institution(user)
            if self.state['stage'] != 'awaiting_approval':
                raise Problem('rotation is not awaiting institution authorization', 409)
            return {'approval_request': self.state['operation']}

    def add_signature(self, user, rotation_id, signature):
        with self.store.lock:
            self._get(rotation_id)
            self._institution(user)
            if self.state['stage'] != 'awaiting_approval':
                raise Problem('rotation is not awaiting institution authorization', 409)
            if (not isinstance(signature, dict) or signature.get('guardian_id') != user.get('institution_id')
                    or not self._verifier().verify_one(self.state['operation'], signature)):
                raise Problem('invalid outgoing institution rotation signature', 403)
            if self.state['operation']['expires_at'] <= int(time.time()):
                raise Problem('rotation authorization expired', 409)
            if signature['guardian_id'] not in {entry['guardian_id'] for entry in self.state['signatures']}:
                self.state['signatures'].append(signature)
                self._save()
                with self.store.transaction():
                    self.store.evidence(user['id'], 'federation_handover_approved', signature)
            return self.status(user)

    def advance(self, user, rotation_id):
        self._admin(user)
        with self.store.lock, self.sandbox.mining_lock:
            self._get(rotation_id)
            if self.state['stage'] == 'preparing':
                return self._prepare_or_resume(user)
            try:
                stage = self.state['stage']
                if stage in {'audit_activated', 'migrating', 'activating', 'retiring'}:
                    self._check_active_policy()
                if stage == 'awaiting_approval':
                    self.state['certificate'] = self._verifier().certificate(self.state['operation'], self.state['signatures'])
                    self.state['stage'] = 'voting'
                    self._save()
                elif stage == 'voting':
                    audit = self.state['audit']
                    if self.sandbox.node.getblockcount() < audit['activation_height']:
                        self._verifier().verify_certificate(self.state['operation'], self.state['certificate'])
                    while self.sandbox.node.getblockcount() < audit['activation_height'] - 1:
                        self.sandbox.blocks.mine(proposal=self.sandbox.audit.proposal(audit))
                    if self.sandbox.node.getblockcount() < audit['activation_height']:
                        self.sandbox.blocks.mine()
                    active = self.sandbox.audit.current_config()
                    if active.binding().hex() != audit['target_hash']:
                        raise ValueError('incoming policy did not activate on the same chain')
                    self.state['stage'] = 'audit_activated'
                    self._save()
                elif stage == 'audit_activated':
                    self.state['audit'] = self.sandbox.audit.activate(self.state['audit'])
                    self.state['stage'] = 'migrating'
                    self._save()
                elif stage == 'migrating':
                    for index, packet in enumerate(self.state['packets']):
                        while len(self.state['prepared_migrations']) <= index:
                            self.state['prepared_migrations'].append(None)
                        prepared = self.state['prepared_migrations'][index]
                        if prepared is None:
                            prepared = self.treasury.sign(packet, self.state['operation'], self.state['certificate'])
                            self.state['prepared_migrations'][index] = prepared
                            self._save()
                        status = self.adapter.inspect(prepared)
                        if status.get('confirmations', 0) < self.store.min_confirmations:
                            self.adapter.broadcast(prepared)
                            self.sandbox.blocks.mine()
                            status = self.adapter.inspect(prepared)
                        if status.get('confirmations', 0) < self.store.min_confirmations:
                            raise ValueError('treasury migration lacks current confirmations')
                        if prepared['txid'] not in self.state['confirmed_migrations']:
                            self.state['confirmed_migrations'].append(prepared['txid'])
                            self._save()
                    self.state['stage'] = 'activating'
                    self._save()
                elif stage == 'activating':
                    self._activate_settlement()
                    self.state['stage'] = 'retiring'
                    self._save()
                elif stage == 'retiring':
                    self.sandbox.audit.stop_outgoing(self.state['audit'])
                    self.sandbox.retire_institutions(self.state['source_policy']['guardian_order'])
                    self.adapter.config['audit_pool_members'] = self.state['audit']['target_members']
                    self.sandbox.persist_adapter()
                    self.state['stage'] = 'complete'
                    self.state['error'] = None
                    self._save()
                self.state['error'] = None
                self._save()
            except Exception as error:
                self.state['error'] = str(error)[:500]
                self._save()
            return self.status(user)

    def _activate_settlement(self):
        self._check_active_policy()
        if self.sandbox.node.getblockhash(0) != self.state['genesis_hash']:
            raise ValueError('chain genesis changed during handover')
        records = list(self.adapter.config.get('rotation_records', []))
        mappings = dict(self.adapter.config.get('escrow_migrations', {}))
        for packet, prepared in zip(self.state['packets'], self.state['prepared_migrations']):
            if self.adapter.inspect(prepared).get('confirmations', 0) < self.store.min_confirmations:
                raise ValueError('migration was reorganized before activation')
            if not any(record['packet']['migration_id'] == packet['migration_id'] for record in records):
                records.append({'rotation': self.state['operation'], 'certificate': self.state['certificate'],
                                'prepared': prepared, 'packet': packet})
            if packet['kind'] == 'escrow':
                mappings[packet['original_escrow_txid']] = {'txid': prepared['txid'], 'vout': packet['target_output_index']}
        target = self.state['target']
        self.adapter.configure_federation(target['policy'], target['institutions'], rotation_records=records, escrow_migrations=mappings)
        self.sandbox.persist_adapter()
        self.store.verifier.activate(ApprovalVerifier(self.store.verifier.curve, target['policy']['approval_public_keys'],
                                                    target['policy']['threshold'], target['policy']['policy_version']))
        self.store.config['institution_approval_urls'] = {guardian: service['url'] for guardian, service in target['institutions'].items()}
        if self.store.disclosures is not None:
            from .capability_demo import enroll
            enroll(self.sandbox, self.store.config, self.adapter.config)
        with self.store.transaction():
            for row in list(self.store.db.execute('SELECT data FROM operations')):
                operation = json.loads(row[0])
                if operation['state'] in {'awaiting_bank', 'awaiting_approval', 'ready'}:
                    operation['policy_version'] = target['policy']['policy_version']
                    operation['expires_at'] = int(time.time()) + 86400
                    self.store.db.execute('DELETE FROM signatures WHERE operation_id=?', (operation['id'],))
                    self.store.db.execute('DELETE FROM user_approvals WHERE operation_id=?', (operation['id'],))
                    operation['state'] = 'awaiting_bank' if operation['state'] == 'awaiting_bank' else 'awaiting_approval'
                if operation.get('escrow_txid') in mappings:
                    operation['current_escrow'] = mappings[operation['escrow_txid']]
                self.store.save(operation)
            for guardian in self.state['source_policy']['guardian_order']:
                row = self.store.db.execute('SELECT data FROM users WHERE id=?', (guardian,)).fetchone()
                if row:
                    data = json.loads(row[0]); data['disabled'] = True
                    self.store.db.execute('UPDATE users SET data=? WHERE id=?', (self.store.encode(data), guardian))
                    self.store.db.execute('DELETE FROM sessions WHERE user_id=?', (guardian,))
            self.store.evidence('federation', 'incoming_membership_activated', {'rotation_id': self.state['id']})
        atomic_write(self.sandbox.directory / 'web.json', self.store.config)

    def _check_active_policy(self):
        audit = self.state['audit']
        if (self.sandbox.node.getblockcount() < audit['activation_height']
                or self.sandbox.audit.current_config().binding().hex() != audit['target_hash']
                or (audit.get('activation_block') and self.sandbox.node.getblockhash(audit['activation_height']) != audit['activation_block'])):
            raise ValueError('incoming chain policy or activation ancestry changed; handover remains held')

    def status(self, user):
        config = self.sandbox.audit.current_config()
        current = self._describe(public_policy(self.adapter.config), [member for member, _ in config.identities], config.active_key.committee.threshold)
        result = {'id': self.adapter.config.get('policy_version', 'sandbox-v1'), 'genesis_hash': self.sandbox.node.getblockhash(0),
                  'current': current, 'incoming': None, 'rotation': None, 'history': self._history_summaries(), 'allowed_actions': []}
        admin = user['role'] == 'bankadmin' and user['tenant'] == self.store.config.get('bank_tenant', 'bank')
        if self.state is None:
            if admin:
                result['allowed_actions'] = ['prepare']
            return result
        state = self.state
        if admin and state['stage'] == 'complete':
            result['allowed_actions'] = ['prepare']
        target = state.get('target')
        if target:
            incoming = self._describe(target['policy'], state.get('audit', {}).get('target_members', []), 11)
            result['incoming'] = incoming if self.held else None
            if state.get('audit') and config.binding().hex() == state['audit']['target_hash']:
                # The native signing/audit policy activates before treasury
                # migration. Report each layer's actual owner during overlap.
                result['current']['block_signing'] = incoming['block_signing']
                if self.held:
                    result['current']['label'] = 'Handover in progress'
                    result['current']['detail'] = 'Incoming block/audit policy is active; settlement treasury changes after confirmed migrations.'
        actions = []
        if admin and state['stage'] != 'complete':
            actions = ['retry' if state.get('error') else 'advance']
        if (user['role'] == 'institutionguardian' and state['stage'] == 'awaiting_approval'
                and user.get('institution_id') in state['source_policy']['approval_public_keys']
                and user['institution_id'] not in {signature['guardian_id'] for signature in state['signatures']}):
            actions.append('guardian-approve')
        stage_index = next(index for index, step in enumerate(STEPS) if step[0] == state['stage'])
        steps = [{'id': key, 'label': label, 'state': 'complete' if state['stage'] == 'complete' or index < stage_index else ('active' if index == stage_index else 'pending')}
                 for index, (key, label) in enumerate(STEPS)]
        visible_escrows = [operation for operation in state['escrows'] if self.store.can_view(user, self.store.account(operation['account_id']))]
        result['rotation'] = {'id': state['id'], 'state': state['stage'], 'stage': state['stage'], 'created_at': state['created_at'],
                              'error': state.get('error'), 'allowed_actions': actions, 'steps': steps,
                              'hold_reason': 'Settlement execution and automatic block production are paused for the prepared handover.' if self.held else None,
                              'approval_count': len(state['signatures']), 'approval_threshold': state['source_policy']['threshold'],
                              'approvals': [signature['guardian_id'] for signature in state['signatures']],
                              'outstanding_cases': [{key: operation.get(key) for key in ('id', 'kind', 'state', 'currency', 'amount_minor')} for operation in visible_escrows],
                              'readiness': [{'id': 'audit', 'label': 'Historical audit shares', 'state': 'ready' if state.get('audit') else 'pending',
                                             'detail': 'All retained keys have incoming share-possession certificates.' if state.get('audit') else 'Preparation pending.'}],
                              'migrations': [dict(packet_summary(packet), txid=(state['prepared_migrations'][index]['txid'] if index < len(state['prepared_migrations']) and state['prepared_migrations'][index] else None),
                                                 currency=next((currency for currency, asset in self.adapter.config['assets'].items() if packet['asset_id'] in (asset['asset_id'], asset['token_id'])), ''),
                                                 state='confirmed' if index < len(state['prepared_migrations']) and state['prepared_migrations'][index] and state['prepared_migrations'][index]['txid'] in state['confirmed_migrations'] else 'prepared')
                                             for index, packet in enumerate(state.get('packets', []))]}
        return result

    @staticmethod
    def _describe(policy, audit_members, audit_threshold):
        epoch = policy_epoch(policy['policy_version'])
        return {'label': 'Federation ' + chr(64 + epoch), 'epoch': epoch, 'policy_version': policy['policy_version'],
                'audit': {'threshold': audit_threshold, 'count': len(audit_members), 'members': audit_members},
                'treasury': {'threshold': policy['threshold'], 'count': len(policy['guardian_order']), 'members': policy['guardian_order'], 'script': policy['treasury_script']},
                'block_signing': {'threshold': policy['threshold'], 'count': len(policy['guardian_order']), 'members': policy['guardian_order'], 'script': policy.get('block_signing_script')}}
