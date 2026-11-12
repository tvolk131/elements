"""A -> B -> C acceptance with original escrows unresolved until C.

The process-owning verification runner starts/resumes the sandbox between the
exported phases. This driver only uses authenticated HTTP, native read RPC and
fixture disclosure credentials; it never edits chain, wallet or workflow state.
"""

import argparse
from pathlib import Path

from .rotation_smoke import RotationPilot


PHASES = ('seed', 'stage-b', 'stage-c', 'finish')


class RepeatedRotationPilot(RotationPilot):
    @property
    def scenario_path(self):
        return self.directory / 'repeated-rotation-smoke.json'

    def stage_b(self):
        state = self.state()
        if state.get('rotation_b'):
            current = self.call('auditor', '/api/dashboard')['federation']['rotation']
            assert current['id'] == state['rotation_b'] and current['stage'] in {'migrating', 'activating', 'retiring', 'complete'}
            return
        self.stage()
        state = self.state()
        state['rotation_b'] = state['rotation_id']
        state['policy_b'] = state['target_policy_version']
        self.save(state)
        print('PASS first handover staged; restart before its treasury migration', flush=True)

    def stage_c(self):
        state = self.state()
        if not state.get('rotation_c'):
            if state.get('rotation_id') != state['rotation_b']:
                # The previous attempt durably created C but the driver was
                # interrupted before recording the phase-completion marker.
                self.stage()
                staged = self.state()
                staged['rotation_c'] = staged['rotation_id']
                staged['policy_c'] = staged['target_policy_version']
                self.save(staged)
                return
            self.complete_rotation(state['rotation_b'])
            dashboard = self.assert_identity(state)
            assert dashboard['network']['operational_policy_version'] == state['policy_b']
            for oid in (state['payout_case'], state['refund_case']):
                operation = self.call('bank-approver', '/api/operations/' + oid)
                assert operation['state'] == 'bank_unknown'
                assert operation['escrow_txid'] == state['original_escrows'][oid]
            if not state.get('historical_b_txid'):
                issued = self.deposit('USD', '2.00')
                state['historical_b_txid'] = issued['txid']
                state['historical_b_case'] = issued['id']
                self.save(state)
            self.stage()
            staged = self.state()
            staged['rotation_c'] = staged['rotation_id']
            staged['policy_c'] = staged['target_policy_version']
            self.save(staged)
        else:
            current = self.call('auditor', '/api/dashboard')['federation']['rotation']
            assert current['id'] == state['rotation_c'] and current['stage'] == 'migrating'
        print('PASS second handover staged with original ambiguous escrows still locked; restart before C treasury migration', flush=True)

    def finish(self):
        state = self.state()
        assert state['rotation_id'] == state['rotation_c']
        super().finish()
        state = self.state()
        historical_b = self.recover_currency(state['historical_b_txid'], 'USD', 2 * 100_000_000)
        dashboard = self.assert_identity(state)
        history = dashboard['federation']['history']
        by_id = {entry['id']: entry for entry in history}
        assert state['rotation_b'] in by_id and state['rotation_c'] in by_id
        assert by_id[state['rotation_b']]['target_policy_version'] == by_id[state['rotation_c']]['source_policy_version']
        assert by_id[state['rotation_c']]['target_policy_version'] == state['policy_c']
        assert all(entry['genesis_hash'] == state['genesis_hash'] for entry in history)
        assert len(history) >= 2
        for oid in (state['payout_case'], state['refund_case']):
            operation = self.call('bank-approver', '/api/operations/' + oid)
            assert operation['escrow_txid'] == state['original_escrows'][oid]
        for retired in set().union(*[set(ids) for ids in state['rotation_sources'].values()]):
            try:
                self.call(retired, '/api/dashboard')
            except RuntimeError:
                pass
            else:
                raise AssertionError('an older institutional credential survived repeated retirement')
        state.update(status='passed', historical_b_recovery=historical_b, completed_history=history,
                     final_reserves=dashboard['reserves'])
        self.save(state)
        print('PASS A -> B -> C: C recovered A and B outputs, completed twice-migrated A payout/refund, preserved both completed handovers and all reconciliations', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--phase', choices=PHASES, required=True)
    args = parser.parse_args()
    getattr(RepeatedRotationPilot(args.directory), args.phase.replace('-', '_'))()
