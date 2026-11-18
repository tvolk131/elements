"""Actual same-chain A->B rotation acceptance scenario, using simulated payments.

Run --phase seed, restart the sandbox if desired, --phase stage, restart again
with incoming chain policy active, then --phase finish. Fixture credentials are
read by this test driver, not by the web application.
"""

import argparse
import json
from pathlib import Path
import urllib.request

from curve import Curve
from guardian_client import GuardianCluster
from test_framework import messages
from .elements_adapter import RPC
from .federation_audit import AuditRotation
from governance import AuditConfig
from guardian_service import atomic_write
from .smoke import Pilot


class RotationPilot(Pilot):
    @property
    def scenario_path(self):
        return self.directory / 'rotation-smoke.json'

    def save(self, state):
        atomic_write(self.scenario_path, state)

    def state(self):
        state = json.loads(self.scenario_path.read_text())
        checkpoint = self.directory / 'federation-rotation.json'
        if state.get('rotation_id') and checkpoint.exists():
            record = json.loads(checkpoint.read_text())
            if record['id'] == state['rotation_id'] and record.get('target'):
                state.setdefault('target_policy_version', record['target']['policy']['policy_version'])
                state.setdefault('target_institutions', record['target']['policy']['guardian_order'])
                state.setdefault('rotation_sources', {}).setdefault(record['id'], record['source_policy']['guardian_order'])
        return state

    def assert_identity(self, state, dashboard=None):
        dashboard = self.call('auditor', '/api/dashboard') if dashboard is None else dashboard
        assert dashboard['network']['genesis_hash'] == state['genesis_hash']
        assert {asset['currency']: asset['asset_id'] for asset in dashboard['assets']} == state['asset_ids']
        return dashboard

    def seed(self):
        before = self.call('auditor', '/api/dashboard')
        eur = self.deposit('EUR', '400.00')
        usd = self.deposit('USD', '250.00')
        self.bank_mode('EUR', 'unknown')
        payout = self.wait(self.redeem('EUR', '20.00'), states=('bank_unknown',))
        refund = self.wait(self.redeem('EUR', '10.00'), states=('bank_unknown',))
        state = {'genesis_hash': before['network']['genesis_hash'],
                 'asset_ids': {asset['currency']: asset['asset_id'] for asset in before['assets']},
                 'historical_txid': eur['txid'], 'usd_txid': usd['txid'],
                 'payout_case': payout['id'], 'refund_case': refund['id'],
                 'initial_policy_version': before['network']['operational_policy_version'],
                 'initial_audit_members': before['network']['audit_guardians'],
                 'initial_audit_threshold': before['network']['audit_threshold'],
                 'original_escrows': {payout['id']: payout['escrow_txid'], refund['id']: refund['escrow_txid']}}
        config = json.loads((self.directory / 'adapter.json').read_text())
        node = RPC(config['rpc_url'])
        current = node.getblock(node.getbestblockhash())['dynamic_parameters']['current']
        assert current['signblockscript'] == config['block_signing_script']
        self.save(state)
        print('PASS seed: real EUR/USD issuance, federation block signatures, two unresolved confirmed escrows', flush=True)

    def stage(self):
        state = self.state()
        federation = self.call('bank-admin', '/api/federation/prepare', {})
        rotation = federation['rotation']
        # A restart may follow this driver's intentional missing-quorum probe.
        # It is recoverable by collecting the still-missing source approvals.
        if rotation.get('error') and not (rotation['stage'] == 'awaiting_approval'
                and rotation['error'] == 'source federation rotation quorum not reached'):
            raise AssertionError(rotation['error'])
        assert rotation['stage'] in {'awaiting_approval', 'voting', 'audit_activated', 'migrating'}, rotation
        rotation_id = state['rotation_id'] = rotation['id']
        dashboard = self.assert_identity(state)
        source_members = [member['id'] for member in dashboard['guardians']]
        state.setdefault('rotation_sources', {})[rotation_id] = source_members
        if federation.get('incoming'):
            state['target_policy_version'] = federation['incoming']['policy_version']
            state['target_institutions'] = federation['incoming']['treasury']['members']
        self.credentials.update({user['username']: user for user in json.loads((self.directory / 'credentials.json').read_text())})
        self.save(state)
        # Lack of quorum must preserve the stage and hold the financial path.
        if rotation['stage'] == 'awaiting_approval' and not rotation['approval_count']:
            early = self.call('bank-admin', f'/api/federation/rotations/{rotation_id}/advance', {})
            assert early['rotation']['stage'] == 'awaiting_approval'
        try:
            self.call('bank-maker', '/api/deposits', {'account_id': 'acme-main', 'currency': 'EUR', 'amount': '1.00'})
        except RuntimeError:
            pass
        else:
            raise AssertionError('new issuance escaped rotation hold')
        missing = [guardian for guardian in source_members if guardian not in rotation['approvals']]
        required = max(0, rotation['approval_threshold'] - rotation['approval_count'])
        for guardian in missing[:required] if rotation['stage'] == 'awaiting_approval' else ():
            review = self.call(guardian, f'/api/federation/rotations/{rotation_id}/prepare-approval', {})['approval_request']
            state['target_policy_version'] = review['target_policy_version']
            state['target_institutions'] = review['manifest']['target_policy']['guardian_order']
            self.save(state)
            dashboard = self.call(guardian, '/api/dashboard')
            service = next(member for member in dashboard['guardians'] if member['id'] == guardian)['approval_url']
            signature = self.request(urllib.request.build_opener(), service + 'approve', {
                'operation': review, 'passphrase': self.credentials[guardian]['institution_approval_passphrase']})
            self.call(guardian, f'/api/federation/rotations/{rotation_id}/certificates', {'signature': signature})
        # Authorize, activate native B policy, activate B historical shares; stop
        # here so an actual launcher restart exercises the intermediate state.
        status = self.call('auditor', '/api/dashboard')['federation']['rotation']
        transitions = {'awaiting_approval': 'voting', 'voting': 'audit_activated', 'audit_activated': 'migrating'}
        while status['stage'] != 'migrating':
            expected = transitions[status['stage']]
            status = self.call('bank-admin', f'/api/federation/rotations/{rotation_id}/advance', {})['rotation']
            if status.get('error'):
                raise AssertionError(status['error'])
            assert status['stage'] == expected, status
        self.assert_identity(state)
        print('PASS stage: source quorum authorized exact proposal; incoming native policy/shares active, treasury migration held for restart', flush=True)

    def complete_rotation(self, rotation_id):
        status = self.call('auditor', '/api/dashboard')['federation']['rotation']
        assert status['id'] == rotation_id
        for _ in range(8):
            if status['stage'] == 'complete':
                break
            status = self.call('bank-admin', f'/api/federation/rotations/{rotation_id}/advance', {})['rotation']
            if status.get('error'):
                raise AssertionError(status['error'])
        assert status['stage'] == 'complete', status
        return status

    def recover_currency(self, txid, currency, amount_base):
        config = json.loads((self.directory / 'adapter.json').read_text())
        node = RPC(config['rpc_url'])
        messages.THRESHOLD_AUDIT = True
        transaction = messages.tx_from_hex(node.getrawtransaction(txid))
        from .elements_adapter import ElementsAdapter
        adapter = ElementsAdapter(config)
        try:
            asset_id = config['assets'][currency]['asset_id']
            index = next(index for index in range(len(transaction.vout)) if adapter._opening(transaction, index)['asset'] == asset_id)
        finally:
            adapter.db.close(); adapter.curve.close()
        curve = Curve(config['library'])
        try:
            current = AuditConfig.from_bytes(bytes.fromhex(node.getblockchaininfo()['audit_config']), curve)
            members = [member for member, _ in current.identities]
            with GuardianCluster.attach(self.directory / 'audit-guardians', curve, members=members) as cluster:
                recovered, checkpoints = AuditRotation(cluster, node, self.directory / 'audit-transitions').recover_output(txid, index)
            assert recovered.amount == amount_base and recovered.asset[::-1].hex() == asset_id
            assert len(checkpoints) == current.active_key.committee.threshold
            return {'txid': txid, 'output_index': index, 'guardian_checkpoints': len(checkpoints), 'current_members': members}
        finally:
            curve.close()

    def finish(self):
        state = self.state()
        rotation_id = state['rotation_id']
        status = self.complete_rotation(rotation_id)
        dashboard = self.assert_identity(state)
        assert dashboard['network']['operational_policy_version'] == state['target_policy_version']
        assert {member['id'] for member in dashboard['guardians']} == set(state['target_institutions'])
        for retired in state['rotation_sources'][rotation_id]:
            try:
                self.call(retired, '/api/dashboard')
            except RuntimeError:
                pass
            else:
                raise AssertionError('retired operator session remained active')
        for oid, outcome in ((state['payout_case'], 'settled'), (state['refund_case'], 'failed')):
            self.call('bank-admin', '/api/bank/events', {'event_id': 'post-rotation-' + oid, 'kind': 'payout_result',
                      'currency': 'EUR', 'operation_id': oid, 'outcome': outcome})
        payout = self.wait({'id': state['payout_case']})
        failed = self.call('bank-approver', '/api/operations/' + state['refund_case'])
        assert payout['escrow_txid'] == state['original_escrows'][payout['id']]
        if not state.get('refund_operation'):
            failed = self.wait(failed, states=('payment_failed',))
            refund = self.call('acme-maker', f"/api/operations/{failed['id']}/cancel", {})
            state['refund_operation'] = refund['id']; self.save(state)
        refund = self.call('acme-approver', '/api/operations/' + state['refund_operation'])
        if refund['state'] in {'awaiting_approval', 'ready'}:
            refund = self.approve(refund, 'acme-approver')
        refunded = self.wait(refund)
        self.bank_mode('EUR', 'settled')
        if not state.get('incoming_issuance'):
            new_issue = self.deposit('EUR', '1.00')
            state['incoming_issuance'] = new_issue['id']; self.save(state)
        new_issue = self.call('bank-approver', '/api/operations/' + state['incoming_issuance'])
        assert new_issue['policy_version'] == state['target_policy_version']
        recovery = self.recover_currency(state['historical_txid'], 'EUR', 400 * 100_000_000)
        final = self.call('auditor', '/api/dashboard')
        assert all(balance['chain_reconciles'] for balance in final['balances'])
        assert all(row['cash_reconciles'] and row['liabilities_reconcile'] and row['supply_reconciles'] for row in final['reserves'])
        state.update(status='passed', completed_rotation=rotation_id, payout_burn_txid=payout['txid'],
                     refund_txid=refunded['txid'], incoming_issuance_txid=new_issue['txid'],
                     historical_recovery=recovery,
                     migration_txids=status.get('migrations'), final_reserves=final['reserves'])
        self.save(state)
        print('PASS finish: same genesis/assets, old services retired, incoming group completed old payout/refund and new issuance, current guardians recovered original output, all balances reconcile', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--phase', choices=('seed', 'stage', 'finish'), required=True)
    options = parser.parse_args()
    getattr(RotationPilot(options.directory), options.phase)()
