"""Idempotent demo enrollment, retaining existing users, wallets and payments."""
import json
import secrets

from curve import random_scalar
from .elements_adapter import RPC
from .runtime import load_config, save_config
from guardian_service import atomic_write
from .directory import Directory
from .disclosures import Disclosures
from .receipts import Receipts


def enroll(sandbox, config, adapter_config):
    store, adapter, node = sandbox.store, sandbox.adapter, sandbox.node
    account_id = 'initech-main'
    exists = store.db.execute('SELECT 1 FROM accounts WHERE id=?', (account_id,)).fetchone()
    if not exists:
        if account_id not in {item['name'] for item in node.listwalletdir()['wallets']}:
            node.createwallet(account_id, False, False, '', False, False)
        if account_id not in node.listwallets():
            node.loadwallet(account_id)
        url = adapter_config['rpc_url'] + '/wallet/' + account_id
        wallet = RPC(url)
        address = wallet.getnewaddress('initech-operating', 'blech32')
        account = {'id': account_id, 'name': 'Initech · Operating', 'tenant': 'initech', 'bank_tenant': 'bank-b',
                   'addresses': {'EUR': address, 'USD': address}, 'bank_account_ref': 'SIMULATED-initech-main',
                   'beneficiaries': [{'id': 'initech-main-' + currency, 'name': 'Initech · ' + currency + ' bank account',
                                     'currency': currency, 'bank_account_ref': 'SIMULATED-' + currency + '-initech-main'} for currency in ('EUR', 'USD')]}
        config['accounts'] = [a for a in config.get('accounts', []) if a['id'] != account_id] + [account]
        adapter_config['wallets'][account_id], adapter_config['addresses'][account_id] = url, address
        save_config(sandbox.directory / 'adapter.json', adapter_config)
        save_config(sandbox.directory / 'web.json', config)
        with store.transaction():
            store.db.execute('INSERT INTO accounts VALUES(?,?)', (account_id, store.encode(account)))
        adapter.wallets[account_id] = wallet
    # Persist a funding marker before broadcasting and retain the exact txid.
    # This fixture funds transaction fees only, never fiat tokens or reserves.
    fee_path = sandbox.directory / 'capability-demo-fees.json'
    if not fee_path.exists():
        destination = adapter.wallets[account_id].getnewaddress('demo-fees', 'bech32')
        save_config(fee_path, {'destination': destination, 'txid': None})
    fee = load_config(fee_path)
    if not fee.get('txid'):
        # Recover a prior send with a lost launcher acknowledgement by checking
        # this dedicated receiving address before creating another fee payment.
        received = [t for t in adapter.wallets[account_id].listtransactions('*', 1000) if t.get('address') == fee['destination'] and t.get('category') == 'receive']
        fee['txid'] = received[0]['txid'] if received else adapter.sponsor.sendtoaddress(fee['destination'], 1)
        save_config(fee_path, fee)
    credentials_path = sandbox.directory / 'credentials.json'
    credentials = json.loads(credentials_path.read_text())
    roles = [('bank-compliance', 'bankcompliance', 'bank'), ('bank-b-compliance', 'bankcompliance', 'bank-b'),
             ('demo-recipient', 'auditor', 'bank'),
             ('federation-compliance', 'federationcompliance', 'federation'),
             ('bank-b-maker', 'bankmaker', 'bank-b'), ('bank-b-approver', 'bankapprover', 'bank-b'),
             ('bank-b-admin', 'bankadmin', 'bank-b'),
             ('initech-maker', 'corporatemaker', 'initech'), ('initech-approver', 'corporateapprover', 'initech')]
    members = sandbox.audit.current_config().active_key.committee.members
    roles += [(f'audit-guardian-{member}', 'auditguardian', 'federation') for member in members]
    users = []
    for username, role, tenant in roles:
        known = next((c for c in credentials if c['username'] == username), None)
        if known is None:
            known = {'username': username, 'password': secrets.token_urlsafe(18), 'role': role}
            credentials.append(known)
        users.append({'id': username, 'username': username, 'name': username.replace('-', ' ').title(),
                      'role': role, 'tenant': tenant, 'password': known['password'],
                      **({'audit_member': int(username.rsplit('-', 1)[1])} if role == 'auditguardian' else {})})
    atomic_write(credentials_path, credentials)
    store.register_users(users)
    with store.transaction():
        for row in list(store.db.execute('SELECT id,data FROM users')):
            data = json.loads(row['data'])
            if data.get('role') == 'auditguardian' and data.get('audit_member') not in members:
                data['disabled'] = True
                store.db.execute('UPDATE users SET data=? WHERE id=?', (store.encode(data), row['id']))
                store.db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
    config['users'] = [*config.get('users', []), *[u for u in users if u['id'] not in {v['id'] for v in config.get('users', [])}]]
    save_config(sandbox.directory / 'web.json', config)
    directory_path = sandbox.directory / 'directory-demo-keys.json'
    banks = {json.loads(row[0]).get('bank_tenant', 'bank') for row in store.db.execute('SELECT data FROM accounts')}
    keys = load_config(directory_path) if directory_path.exists() else {}
    for bank in banks:
        keys.setdefault(bank, f'{random_scalar():064x}')
    save_config(directory_path, keys)
    store.directory = Directory(store, {bank: int(value, 16) for bank, value in keys.items() if bank != 'schema_version'})
    store.disclosures = Disclosures(store, sandbox.audit)
    store.receipts = Receipts(store)
