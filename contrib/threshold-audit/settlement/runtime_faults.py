"""Owned real-chain fault fixture: stale ledger restore and lost-key refusal.

All chain data and test credentials are created under --work-dir. No existing
sandbox is modified. The driver closes every launcher it creates, including
expected failed starts. Bank payments remain simulated.
"""

import argparse
import json
from pathlib import Path
import shutil
import sqlite3

from .runtime import load_config, save_config
from .sandbox import Sandbox
from .smoke import Pilot


def database_backup(source, destination):
    with sqlite3.connect(source) as original, sqlite3.connect(destination) as backup:
        original.backup(backup)
    Path(destination).chmod(0o600)


def restore_database(runtime, backup):
    # This function is called only after Sandbox.close has joined workers,
    # closed the store connection and stopped its owned child services.
    for suffix in ('-wal', '-shm'):
        (runtime / ('settlement.sqlite' + suffix)).unlink(missing_ok=True)
    shutil.copyfile(backup, runtime / 'settlement.sqlite')
    (runtime / 'settlement.sqlite').chmod(0o600)


def run(work_dir, daemon, library):
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime = work_dir / 'runtime'
    if runtime.exists():
        raise ValueError('fault fixture runtime already exists; choose a new work directory')
    sandbox = Sandbox(runtime, daemon, library)
    checks = []
    try:
        sandbox.start()
        pilot = Pilot(runtime)
        first = pilot.deposit('EUR', '10.00')
        genesis = pilot.ready['genesis_hash']
        database_backup(runtime / 'settlement.sqlite', work_dir / 'before.sqlite')
        second = pilot.deposit('EUR', '1.00')
        database_backup(runtime / 'settlement.sqlite', work_dir / 'after.sqlite')
        sandbox.close()

        restore_database(runtime, work_dir / 'before.sqlite')
        sandbox = Sandbox(runtime, daemon, library)
        sandbox.resume()
        pilot = Pilot(runtime)
        try:
            pilot.call('bank-maker', '/api/deposits', {'account_id': 'acme-main', 'currency': 'EUR', 'amount': '1.00'})
        except RuntimeError as error:
            if 'account_reconciliation_hold' not in str(error):
                raise
        else:
            raise AssertionError('stale restored customer ledger authorized new settlement')
        view = pilot.call('auditor', '/api/dashboard')
        assert any(not balance['chain_reconciles'] for balance in view['balances'])
        checks.append('restored-ledger-divergence-holds-new-settlement')
        sandbox.close()

        restore_database(runtime, work_dir / 'after.sqlite')
        adapter_path = runtime / 'adapter.json'
        original_adapter = load_config(adapter_path)
        corrupted = dict(original_adapter, schema_version=999)
        # Deliberately preserve the unsupported version (save_config always
        # writes the current version for normal callers).
        from guardian_service import atomic_write
        atomic_write(adapter_path, corrupted)
        sandbox = Sandbox(runtime, daemon, library)
        try:
            sandbox.resume()
        except ValueError as error:
            assert 'unsupported runtime schema' in str(error)
        else:
            raise AssertionError('future runtime schema was silently reinterpreted')
        finally:
            sandbox.close(); save_config(adapter_path, original_adapter)
        checks.append('unknown-runtime-schema-refused')

        guardian = original_adapter['guardian_order'][0]
        key_path = runtime / guardian / 'service.json'
        original_service = load_config(key_path)
        atomic_write(key_path, dict(original_service, schema_version=999))
        sandbox = Sandbox(runtime, daemon, library)
        try:
            sandbox.resume()
        except ValueError as error:
            assert 'unsupported runtime schema' in str(error)
            assert json.loads(key_path.read_text())['schema_version'] == 999
        else:
            raise AssertionError('future operator service schema was silently rewritten')
        finally:
            sandbox.close(); save_config(key_path, original_service)
        checks.append('unknown-institution-schema-refused-before-rewrite')

        missing = dict(original_service); del missing['block_secret']
        save_config(key_path, missing)
        sandbox = Sandbox(runtime, daemon, library)
        try:
            sandbox.resume()
        except ValueError as error:
            assert 'block identity is missing' in str(error)
        else:
            raise AssertionError('missing active block key was silently replaced')
        finally:
            sandbox.close(); save_config(key_path, original_service)
        checks.append('lost-active-block-key-refused-without-replacement')

        sandbox = Sandbox(runtime, daemon, library)
        sandbox.resume()
        pilot = Pilot(runtime)
        final = pilot.call('auditor', '/api/dashboard')
        assert pilot.ready['genesis_hash'] == genesis
        assert all(balance['chain_reconciles'] for balance in final['balances'])
        assert all(row['cash_reconciles'] and row['liabilities_reconcile'] and row['supply_reconciles'] for row in final['reserves'])
        for operation in (first, second):
            assert pilot.call('bank-approver', '/api/operations/' + operation['id'])['txid'] == operation['txid']
        checks.append('correct-backup-restores-original-chain-and-transaction-identities')
        report = {'status': 'passed', 'checks': checks, 'genesis_hash': genesis,
                  'issuance_txids': [first['txid'], second['txid']]}
        save_config(work_dir / 'result.json', report)
        print(json.dumps({'status': 'passed', 'checks': len(checks), 'report': str(work_dir / 'result.json')}), flush=True)
    finally:
        sandbox.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--daemon', required=True)
    parser.add_argument('--library', required=True)
    options = parser.parse_args()
    run(options.work_dir, options.daemon, options.library)
