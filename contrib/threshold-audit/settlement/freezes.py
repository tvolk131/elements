"""Relay a case authority's freeze and release orders to the operators.

The regulator signs each order in its own browser. This server checks the
signature only to reject mistakes early, then forwards the order to every
operator, which checks it again against its own trusted keys and returns a
signed receipt. The server also keeps frozen coins out of the holder's wallet
and out of the blocks it proposes, so the operators' refusals don't stall
payments or block production.
"""

from decimal import Decimal
import json
import time

from .approval import canonical
from .freeze_orders import receipt_digest, validate, verify
from .store import Problem, ROLES
from .treasury import InstitutionClient, InstitutionRefused


class Freezes:
    def __init__(self, store, adapter):
        self.store, self.adapter, self.curve = store, adapter, adapter.curve
        self.db = store.db
        self.db.execute('CREATE TABLE IF NOT EXISTS freeze_orders(id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        # Read without locks by the block producer and the wallet adapter,
        # which may hold the mining lock; replaced whole, never mutated.
        self._active = {}
        self.refresh()
        # Payments built later must not pick a frozen coin, and an abandoned
        # payment must not hand one back to its wallet.
        adapter.frozen = self.active_outpoints
        self.apply_locks()

    # Records -------------------------------------------------------------

    def records(self):
        with self.store.lock:
            return [json.loads(row[0]) for row in self.db.execute('SELECT data FROM freeze_orders ORDER BY rowid')]

    def record(self, order_id):
        with self.store.lock:
            row = self.db.execute('SELECT data FROM freeze_orders WHERE id=?', (order_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, record):
        self.db.execute('INSERT OR REPLACE INTO freeze_orders(id,data) VALUES(?,?)',
                        (record['order']['id'], canonical(record).decode()))

    def active(self):
        return [r for r in self.records() if r['order']['kind'] == 'freeze' and not r.get('released_by')]

    def refresh(self):
        self._active = {f"{o['txid']}:{o['vout']}": r['order']['id'] for r in self.active() for o in r['order']['outputs']}

    def active_outpoints(self):
        return self._active

    def authorities(self):
        return dict(self.store.config.get('case_authority_keys', {}))

    # Submission ----------------------------------------------------------

    def submit(self, user, body):
        if 'order_freeze' not in ROLES.get(user['role'], set()):
            raise Problem('only a case authority can order a freeze', 403)
        order, signature = body.get('order'), body.get('signature')
        # Same lock order as handovers: store, then mining.
        with self.store.lock:
            return self._submit(user, order, signature)

    def _submit(self, user, order, signature):
        genesis = self.adapter.node.getblockhash(0)
        try:
            target = validate(order, genesis)
            authority = verify(self.curve, self.authorities(), order, signature)
        except (ValueError, KeyError, TypeError) as error:
            raise Problem(str(error)) from None
        if order['authority'] != authority:
            raise Problem('the order names a different authority than its key')
        with self.store.transaction():
            prior = self.record(order['id'])
            if prior and prior['order'] != order:
                raise Problem('a different order already uses this ID', 409)
            if not prior:
                if order['kind'] == 'freeze':
                    for item in order['outputs']:
                        if self.adapter.node.gettxout(item['txid'], item['vout'], False) is None:
                            raise Problem(f"output {item['txid']}:{item['vout']} is already spent or does not exist; "
                                          'follow the funds to where they went', 409)
                else:
                    lifted = self.record(target)
                    if lifted is None or lifted['order']['kind'] != 'freeze':
                        raise Problem('release names an unknown freeze', 404)
                    if lifted.get('released_by'):
                        raise Problem('that freeze was already released', 409)
                prior = {'order': order, 'signature': signature, 'submitted_by': user['id'],
                         'received_at': int(time.time()), 'receipts': {}, 'errors': {}, 'released_by': None}
                if order['kind'] == 'freeze':
                    prior['holdings'] = self._holdings(order)
                self.save(prior)
                if order['kind'] == 'release':
                    lifted['released_by'] = order['id']
                    self.save(lifted)
                self.store.evidence(user['id'], 'freeze_ordered' if order['kind'] == 'freeze' else 'freeze_released',
                                    {'order_id': order['id'], 'case_reference': order['case_reference'],
                                     **({'outputs': order['outputs']} if order['kind'] == 'freeze' else {'releases': target})})
        # Relay while no block is being signed, so no operator commits to a
        # block with a frozen spend in the moment before it learns the order.
        mining = getattr(getattr(self.store, 'demo_runtime', None), 'mining_lock', None)
        if mining is not None:
            with mining:
                self.refresh()
                self.relay(order['id'])
        else:
            self.refresh()
            self.relay(order['id'])
        self.apply_locks()
        return self.public(user, self.record(order['id']))

    def relay(self, order_id):
        """Send the order to every operator that hasn't returned a valid receipt."""
        record = self.record(order_id)
        for key, (guardian, service) in self.adapter.authorizer_services().items():
            if guardian in record['receipts']:
                continue
            try:
                result = InstitutionClient({guardian: service}).request(
                    guardian, 'apply_freeze_order', order=record['order'], signature=record['signature'])
                if (result.get('guardian_id') != guardian or result.get('order_id') != order_id
                        or not self.curve.verify_signature(bytes.fromhex(key), receipt_digest(record['order'], guardian),
                                                           bytes.fromhex(result['signature']))):
                    raise InstitutionRefused('returned an invalid receipt')
                record['receipts'][guardian] = {'signature': result['signature'], 'at': int(time.time())}
                record['errors'].pop(guardian, None)
            except InstitutionRefused as error:
                record['errors'][guardian] = str(error)
            except (OSError, ValueError, KeyError):
                record['errors'][guardian] = 'unreachable; will retry'
        with self.store.transaction():
            self.save(record)

    def retry(self):
        """Deliver orders to operators that were offline when they were issued."""
        expected = {guardian for guardian, _ in self.adapter.authorizer_services().values()}
        for record in self.records():
            if expected - set(record['receipts']):
                self.relay(record['order']['id'])

    # Wallets and blocks --------------------------------------------------

    def _wallets(self):
        return {'sponsor': self.adapter.sponsor, **self.adapter.wallets}

    def _holdings(self, order):
        """Which of our customers hold the frozen outputs, and how much (bank-side view)."""
        assets = {value['asset_id']: currency for currency, value in self.adapter.config['assets'].items()}
        wanted = {(o['txid'], o['vout']) for o in order['outputs']}
        holdings = {}
        for account, wallet in self._wallets().items():
            try:
                coins = wallet.listunspent(0)
            except (OSError, ValueError, RuntimeError):
                continue
            for coin in coins:
                if (coin['txid'], coin['vout']) in wanted and coin.get('asset') in assets:
                    holdings[f"{coin['txid']}:{coin['vout']}"] = {
                        'account_id': account, 'currency': assets[coin['asset']],
                        'amount_minor': int((Decimal(str(coin['amount'])) * 100).to_integral_value())}
        return holdings

    def apply_locks(self):
        """Lock frozen coins in whichever of our wallets holds them; unlock released ones."""
        frozen = set(self.active_outpoints())
        released = {f"{o['txid']}:{o['vout']}" for r in self.records() if r['order']['kind'] == 'freeze'
                    and r.get('released_by') for o in r['order']['outputs']} - frozen
        for wallet in self._wallets().values():
            try:
                locked = {f"{c['txid']}:{c['vout']}" for c in wallet.listlockunspent()}
                for item in frozen - locked:
                    txid, vout = item.split(':')
                    try:
                        wallet.lockunspent(False, [{'txid': txid, 'vout': int(vout)}])
                    except (OSError, ValueError, RuntimeError):
                        pass  # not this wallet's coin (the node answers with an RPC error)
                for item in released & locked:
                    txid, vout = item.split(':')
                    wallet.lockunspent(True, [{'txid': txid, 'vout': int(vout)}])
            except (OSError, ValueError, RuntimeError):
                continue

    def excluded(self, block):
        """Transactions in a candidate block that spend frozen outputs."""
        frozen = self.active_outpoints()
        # Transactions read from a template carry no cached hash until rehashed.
        return [tx.rehash() for tx in block.vtx[1:]
                if any(f'{inp.prevout.hash:064x}:{inp.prevout.n}' in frozen for inp in tx.vin)]

    def frozen_balance(self, account_id, currency):
        return sum(h['amount_minor'] for r in self.active() for h in r.get('holdings', {}).values()
                   if h['account_id'] == account_id and h['currency'] == currency)

    def frozen_funds(self, user):
        """Frozen amounts on the accounts this user can see."""
        result = []
        for record in self.active():
            for item, holding in record.get('holdings', {}).items():
                if holding['account_id'] in self.adapter.wallets and self.store.can_view(user, self.store.account(holding['account_id'])):
                    result.append(dict(holding, outpoint=item, order_id=record['order']['id'],
                                       authority=record['order']['authority'], case_reference=record['order']['case_reference']))
        return result

    # Views ---------------------------------------------------------------

    def _status(self, item):
        if self.adapter.node.gettxout(item['txid'], item['vout'], True) is not None:
            return 'unspent'
        if self.adapter.node.gettxout(item['txid'], item['vout'], False) is not None:
            return 'spend_pending'
        return 'spent'

    def public(self, user, record):
        order = record['order']
        operators = sorted({guardian for guardian, _ in self.adapter.authorizer_services().values()})
        view = {'id': order['id'], 'kind': order['kind'], 'authority': order['authority'],
                'case_reference': order['case_reference'], 'reason': order['reason'], 'issued_at': order['issued_at'],
                'applied_by': sorted(record['receipts']), 'errors': record['errors'], 'operators': operators,
                'threshold': self.adapter.config['threshold'], 'released_by': record.get('released_by')}
        if order['kind'] == 'freeze':
            bank = 'view_bank' in ROLES.get(user['role'], set())
            view['outputs'] = [dict(item, status=self._status(item),
                                    **({'holding': record.get('holdings', {}).get(f"{item['txid']}:{item['vout']}")} if bank else {}))
                               for item in order['outputs']]
        else:
            view['releases'] = order['releases']
        return view

    def overview(self, user):
        if not ROLES.get(user['role'], set()) & {'order_freeze', 'view_bank'}:
            raise Problem('freeze orders are not available to this account', 403)
        return {'orders': [self.public(user, r) for r in reversed(self.records())],
                'authorities': self.authorities(), 'genesis_hash': self.adapter.node.getblockhash(0),
                'can_order': 'order_freeze' in ROLES.get(user['role'], set())}
