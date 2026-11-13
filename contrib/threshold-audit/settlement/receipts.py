"""Observe non-application receipts from managed wallets, once per outpoint.

Confirmed reorged receipts are quarantined for reconciliation, not compensated.
Out-of-band spending likewise leaves the existing balance-divergence hold active.
"""
import hashlib
import json
import time
from decimal import Decimal


class Receipts:
    def __init__(self, store):
        self.store = store
        store.db.executescript('''CREATE TABLE IF NOT EXISTS receipt_cursors(account_id TEXT PRIMARY KEY, blockhash TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS observed_receipts(account_id TEXT NOT NULL, txid TEXT NOT NULL, vout INTEGER NOT NULL,
            operation_id TEXT NOT NULL, PRIMARY KEY(account_id,txid,vout));''')

    def poll(self):
        store = self.store
        assets = {a['asset_id']: a['currency'] for a in store.chain.assets() if a.get('registered')}
        known = {json.loads(row[0])['txid'] for row in store.db.execute('SELECT data FROM outbox')}
        genesis = store.chain.network()['genesis_hash']
        for account_id, wallet in store.chain.wallets.items():
            cursor = store.db.execute('SELECT blockhash FROM receipt_cursors WHERE account_id=?', (account_id,)).fetchone()
            batch = wallet.listsinceblock(cursor[0]) if cursor else wallet.listsinceblock()
            for event in batch.get('transactions', []):
                if (event.get('category') != 'receive' or event.get('txid') in known
                        or event.get('asset') not in assets or event.get('confirmations', 0) < store.min_confirmations):
                    continue
                amount = Decimal(str(event['amount'])) * 100
                if amount <= 0 or amount != amount.to_integral_value():
                    continue  # Unsupported sub-cent receipts keep reconciliation held.
                txid, vout = event['txid'], event['vout']
                if store.db.execute('SELECT 1 FROM observed_receipts WHERE account_id=? AND txid=? AND vout=?', (account_id,txid,vout)).fetchone():
                    continue
                account = store.account(account_id)
                operation_id = hashlib.sha256(f'{genesis}:{account_id}:{txid}:{vout}'.encode()).hexdigest()[:32]
                operation = {'id':operation_id,'kind':'receipt','state':'settled','account_id':account_id,
                             'tenant':account['tenant'],'currency':assets[event['asset']],'asset_id':event['asset'],
                             'amount_minor':int(amount),'created_at':int(event.get('time',time.time())),
                             'updated_at':int(time.time()),'maker':'chain-observer','txid':txid,'output_index':vout,
                             'stage':'receipt','policy_version':store.verifier.policy_version,'expires_at':0,
                             'reference':'Received from an external wallet','destination':event.get('address',''),
                             'destination_name':account['name'],'to_account_id':None,'external_receipt':True}
                with store.transaction():
                    store.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)', (operation_id,'receipt','settled',account['tenant'],store.encode(operation)))
                    store.db.execute('INSERT INTO observed_receipts VALUES(?,?,?,?)',(account_id,txid,vout,operation_id))
                    store.tokens(operation,'received',account_id,int(amount))
                    store.evidence('chain-observer','external_receipt_confirmed',{'txid':txid,'vout':vout},operation_id)
            for removed in batch.get('removed', []):
                row = store.db.execute('SELECT operation_id FROM observed_receipts WHERE account_id=? AND txid=? AND vout=?',(account_id,removed['txid'],removed['vout'])).fetchone()
                if row:
                    with store.transaction():
                        operation=store._operation(row[0]); operation['state']='reconciliation_required'; operation['error']='Observed receipt was reorganized; reconcile the wallet before spending.'; store.save(operation)
            with store.transaction():
                store.db.execute('INSERT OR REPLACE INTO receipt_cursors VALUES(?,?)',(account_id,batch['lastblock']))
