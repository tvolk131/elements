"""Relay a case authority's freeze and release orders to the operators.

The regulator signs each order in its own browser. This server checks the
signature only to reject mistakes early, then forwards the order to every
operator, which checks it again against its own trusted keys and returns a
signed receipt. The server also keeps frozen coins out of the holder's wallet
and out of the blocks it proposes, so the operators' refusals don't stall
payments or block production.
"""

from decimal import Decimal
import hashlib
import json
import time

from test_framework.messages import tx_from_hex

from .approval import canonical
from .authorization import is_recovery, quarantine_script
from .freeze_orders import quarantine_case, receipt_digest, validate, verify
from .store import Problem, ROLES

COIN = 100_000_000
# One fiat minor unit is 1,000,000 base units (0.01 token).
BASE_PER_MINOR = 1_000_000
RECOVERY_FEE = Decimal('0.01')


def blinder(value):
    """RPC hex for a blinding factor (uint256 display order)."""
    return value.to_bytes(32, 'big')[::-1].hex()
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
                acted = None if order['kind'] == 'freeze' else self.record(target)
                if order['kind'] == 'freeze':
                    for item in order['outputs']:
                        if self.adapter.node.gettxout(item['txid'], item['vout'], False) is None:
                            raise Problem(f"output {item['txid']}:{item['vout']} is already spent or does not exist; "
                                          'follow the funds to where they went', 409)
                elif order['kind'] == 'release':
                    if acted is None or acted['order']['kind'] != 'freeze':
                        raise Problem('release names an unknown freeze', 404)
                    if acted.get('released_by'):
                        raise Problem('that freeze was already released', 409)
                    if acted.get('quarantined_by'):
                        raise Problem('those funds are already in quarantine; restore them instead', 409)
                elif order['kind'] == 'quarantine':
                    if acted is None or acted['order']['kind'] != 'freeze' or acted.get('released_by'):
                        raise Problem('quarantine names no freeze in force', 404)
                    if acted.get('quarantined_by'):
                        raise Problem('those funds are already quarantined', 409)
                else:
                    if acted is None or acted['order']['kind'] != 'quarantine':
                        raise Problem('restore names no quarantine', 404)
                    if acted.get('state') not in ('broadcast', 'confirmed'):
                        raise Problem('the quarantine has not completed yet', 409)
                    if acted.get('restored_by'):
                        raise Problem('that quarantine was already restored', 409)
                    self._account_for(order['destination'])
                prior = {'order': order, 'signature': signature, 'submitted_by': user['id'],
                         'received_at': int(time.time()), 'receipts': {}, 'errors': {}, 'released_by': None}
                if order['kind'] == 'freeze':
                    prior['holdings'] = self._holdings(order)
                if order['kind'] in ('quarantine', 'restore'):
                    prior.update(state='ordered', error=None)
                self.save(prior)
                if acted is not None:
                    acted[{'release': 'released_by', 'quarantine': 'quarantined_by', 'restore': 'restored_by'}[order['kind']]] = order['id']
                    self.save(acted)
                event = {'freeze': 'freeze_ordered', 'release': 'freeze_released', 'quarantine': 'quarantine_ordered',
                         'restore': 'restore_ordered'}[order['kind']]
                self.store.evidence(user['id'], event, {'order_id': order['id'], 'case_reference': order['case_reference'],
                                                        **({'outputs': order['outputs']} if order['kind'] == 'freeze'
                                                           else {'acts_on': target})})
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
        """Deliver orders to operators that were offline, then advance recoveries."""
        expected = {guardian for guardian, _ in self.adapter.authorizer_services().values()}
        for record in self.records():
            if expected - set(record['receipts']):
                self.relay(record['order']['id'])
        self.advance()

    # Recovery ------------------------------------------------------------

    def _account_for(self, reference):
        directory = self.store.directory
        for row in self.db.execute('SELECT data FROM accounts'):
            account = json.loads(row[0])
            if directory is not None and directory.reference(account).lower() == reference and account['id'] in self.adapter.wallets:
                return account
        raise Problem('no member bank account answers to that reference', 404)

    def advance(self):
        """Carry out quarantine and restore orders (from the worker, never a request)."""
        for record in self.records():
            if record['order']['kind'] not in ('quarantine', 'restore'):
                continue
            state = record.get('state')
            try:
                if state == 'broadcast':
                    seen = self.adapter.node.getrawtransaction(record['txid'], True)
                    if seen.get('confirmations', 0) >= 1:
                        record['state'] = 'confirmed'
                        with self.store.transaction():
                            self.save(record)
                elif state in ('ordered', 'built') and time.time() >= record.get('retry_at', 0):
                    self._execute(record)
            except Exception as error:  # noqa: BLE001 - recorded and retried, never lost
                record.update(error=str(error)[:300], retry_at=time.time() + 30)
                with self.store.transaction():
                    self.save(record)

    def _execute(self, record):
        order, node = record['order'], self.adapter.node
        if record['state'] == 'ordered':
            # Decrypt with the operators' key pieces, then fix the exact
            # transaction once: operators sign only one per order.
            plan = self._plan(order)
            record.update(plan=plan, rawtx=self._build(plan), state='built')
            with self.store.transaction():
                self.save(record)
        plan = record['plan']
        fee = plan.get('fee')
        if fee and (self.adapter.node.gettxout(fee['txid'], fee['vout'], True) or {}).get('confirmations', 0) < 1:
            # A recovery may replace a thief's pending spend, and a replacement
            # may not add unconfirmed inputs: wait a block for the fee coin.
            return
        final = self.adapter.authorize_recovery(record['rawtx'], plan['recovered'], order['id'], plan.get('registrations'))
        txid = node.sendrawtransaction(final, 0)
        with self.store.transaction():
            # Each customer of ours sees the move in their own history.
            if order['kind'] == 'quarantine':
                shown = [self._record_quarantine(order, txid, index, item, plan['outputs'][index])
                         for index, item in enumerate(plan['inputs'])]
            else:
                shown = [self._record_return(order, txid, index, item) for index, item in enumerate(plan['outputs'])]
            record.update(state='broadcast', txid=txid, error=None)
            self.save(record)
            if not any(shown):  # held outside our customers' accounts: still on the bank's record
                self.store.evidence('federation', 'funds_quarantined' if order['kind'] == 'quarantine' else 'funds_restored',
                                    {'order_id': order['id'], 'txid': txid})

    def _record_quarantine(self, order, txid, index, item, output):
        """Debit a quarantined output once, with a record in the holder's own
        history: which order moved it, on whose authority, and where."""
        if not item.get('account_id') or not item.get('currency'):
            return False
        store = self.store
        account = store.account(item['account_id'])
        genesis = self.adapter.node.getblockhash(0)
        operation_id = hashlib.sha256(f"{genesis}:quarantine:{account['id']}:{txid}:{index}".encode()).hexdigest()[:32]
        if store.db.execute('SELECT 1 FROM operations WHERE id=?', (operation_id,)).fetchone():
            return True
        now = int(time.time())
        operation = {'id': operation_id, 'kind': 'quarantine', 'state': 'settled', 'account_id': account['id'],
                     'tenant': account['tenant'], 'currency': item['currency'], 'asset_id': item['asset'],
                     'amount_minor': item['amount_minor'], 'created_at': now, 'updated_at': now,
                     'maker': 'federation', 'txid': txid, 'output_index': index, 'stage': 'quarantine',
                     'policy_version': store.verifier.policy_version, 'expires_at': 0,
                     'reference': f"Moved to quarantine by order of {order['authority']}",
                     'destination': output['address'], 'destination_name': 'Quarantine', 'to_account_id': None,
                     'recovery_order': order['id'], 'authority': order['authority'],
                     'case_reference': order['case_reference'], 'source_output': f"{item['txid']}:{item['vout']}"}
        store.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',
                         (operation_id, 'quarantine', 'settled', account['tenant'], store.encode(operation)))
        store.tokens(operation, 'quarantined', account['id'], -item['amount_minor'])
        store.evidence('federation', 'funds_quarantined', {'order_id': order['id'], 'txid': txid}, operation_id)
        return True

    def _record_return(self, order, txid, vout, item):
        """Credit a restored output once, as the receipt watcher would, so it
        neither credits it again nor leaves the customer without a record."""
        if not item.get('account_id') or not item.get('currency'):
            return False
        store = self.store
        account = store.account(item['account_id'])
        genesis = self.adapter.node.getblockhash(0)
        operation_id = hashlib.sha256(f"{genesis}:{account['id']}:{txid}:{vout}".encode()).hexdigest()[:32]
        if store.db.execute('SELECT 1 FROM observed_receipts WHERE account_id=? AND txid=? AND vout=?',
                            (account['id'], txid, vout)).fetchone():
            return True
        now = int(time.time())
        operation = {'id': operation_id, 'kind': 'receipt', 'state': 'settled', 'account_id': account['id'],
                     'tenant': account['tenant'], 'currency': item['currency'], 'asset_id': item['asset'],
                     'amount_minor': item['amount_minor'], 'created_at': now, 'updated_at': now,
                     'maker': 'federation', 'txid': txid, 'output_index': vout, 'stage': 'receipt',
                     'policy_version': store.verifier.policy_version, 'expires_at': 0,
                     'reference': f"Returned from quarantine by order of {order['authority']}",
                     'destination': item['address'], 'destination_name': account['name'], 'to_account_id': None,
                     'external_receipt': False, 'recovery_order': order['id'], 'authority': order['authority'],
                     'case_reference': order['case_reference']}
        store.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',
                         (operation_id, 'receipt', 'settled', account['tenant'], store.encode(operation)))
        store.db.execute('INSERT INTO observed_receipts VALUES(?,?,?,?)', (account['id'], txid, vout, operation_id))
        store.tokens(operation, 'received', account['id'], item['amount_minor'])
        store.evidence('federation', 'funds_restored', {'order_id': order['id'], 'txid': txid}, operation_id)
        return True

    def _plan(self, order):
        sandbox = self.store.demo_runtime
        currencies = {value['asset_id']: currency for currency, value in self.adapter.config['assets'].items()}
        if order['kind'] == 'quarantine':
            freeze = self.record(order['freeze'])
            sources = [(item['txid'], item['vout']) for item in freeze['order']['outputs']]
            holdings = freeze.get('holdings', {})
            fence = quarantine_script(quarantine_case(order['id'])).hex()
        else:
            held = self.record(order['quarantine'])
            sources = [(held['txid'], index) for index in range(len(held['plan']['inputs']))]
            holdings = {}
            account = self._account_for(order['destination'])
        inputs, outputs, registrations = [], [], {}
        for txid, vout in sources:
            opening, _ = sandbox.audit.recover_output(txid, vout)  # (opening, guardian checkpoints)
            asset = opening.asset[::-1].hex()
            holding = holdings.get(f'{txid}:{vout}', {})
            inputs.append({'txid': txid, 'vout': vout, 'asset': asset, 'amount': opening.amount,
                           'value_blinder': blinder(opening.value_blinder), 'asset_blinder': blinder(opening.asset_blinder),
                           'account_id': holding.get('account_id'), 'currency': currencies.get(asset),
                           'amount_minor': opening.amount // BASE_PER_MINOR})
            if order['kind'] == 'quarantine':
                address, script = self.adapter.sponsor.getnewaddress('quarantine', 'blech32'), fence
            else:
                address = self.adapter.wallets[account['id']].getnewaddress('restored', 'blech32')
                script = self.adapter.node.validateaddress(address)['scriptPubKey']
                if self.adapter.registrar is not None:
                    registration = self.adapter.registrar(bytes.fromhex(script))
                    if registration is not None:
                        registrations[script] = registration.hex()
            outputs.append({'address': address, 'script': script, 'asset': asset, 'amount': opening.amount,
                            'account_id': None if order['kind'] == 'quarantine' else account['id'],
                            'currency': currencies.get(asset), 'amount_minor': opening.amount // BASE_PER_MINOR})
        return {'inputs': inputs, 'outputs': outputs, 'recovered': list(range(len(inputs))),
                'registrations': registrations}

    def _fee_coin(self):
        """An exact, explicit federation coin that pays the recovery's fee."""
        sponsor, node = self.adapter.sponsor, self.adapter.node
        address = sponsor.getnewaddress('recovery-fee', 'bech32')  # unblinded
        txid = self.adapter.wallet_send(sponsor, {address: str(RECOVERY_FEE)})
        script = node.validateaddress(address)['scriptPubKey']
        decoded = node.getrawtransaction(txid, True)
        vout = next(out['n'] for out in decoded['vout'] if out['scriptPubKey']['hex'] == script)
        sponsor.lockunspent(False, [{'txid': txid, 'vout': vout}])
        return {'txid': txid, 'vout': vout, 'asset': node.gettxout(txid, vout, True)['asset']}

    def _build(self, plan):
        node, sponsor = self.adapter.node, self.adapter.sponsor
        fee = plan['fee'] = self._fee_coin()
        coins = [{'txid': item['txid'], 'vout': item['vout']} for item in plan['inputs']]
        raw = node.createrawtransaction(coins + [{'txid': fee['txid'], 'vout': fee['vout']}],
                                        [{out['address']: Decimal(out['amount']) / COIN, 'asset': out['asset']}
                                         for out in plan['outputs']] + [{'fee': RECOVERY_FEE}])
        transaction = tx_from_hex(raw)
        for index, out in enumerate(plan['outputs']):
            transaction.vout[index].scriptPubKey = bytes.fromhex(out['script'])
        inputs = plan['inputs']
        blinded = node.rawblindrawtransaction(
            transaction.serialize().hex(), [item['value_blinder'] for item in inputs] + ['00' * 32],
            [Decimal(item['amount']) / COIN for item in inputs] + [RECOVERY_FEE],
            [item['asset'] for item in inputs] + [fee['asset']], [item['asset_blinder'] for item in inputs] + ['00' * 32])
        # Signs only the fee input; recovered inputs carry no owner signature.
        return sponsor.signrawtransactionwithwallet(blinded)['hex']

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
        # Recoveries move frozen funds into quarantine under the quorum's own
        # signatures, so they are the one way frozen funds may move.
        return [tx.rehash() for tx in block.vtx[1:] if not is_recovery(tx)
                and any(f'{inp.prevout.hash:064x}:{inp.prevout.n}' in frozen for inp in tx.vin)]

    def _moved(self, record):
        """The freeze's funds have left the holder: its quarantine was sent."""
        held = self.record(record['quarantined_by']) if record.get('quarantined_by') else None
        return bool(held and held.get('state') in ('broadcast', 'confirmed'))

    def frozen_balance(self, account_id, currency):
        # Once quarantined, the ledger has already moved the funds out.
        return sum(h['amount_minor'] for r in self.active() if not self._moved(r)
                   for h in r.get('holdings', {}).values() if h['account_id'] == account_id and h['currency'] == currency)

    def frozen_funds(self, user):
        """Frozen amounts on the accounts this user can see."""
        result = []
        for record in self.active():
            if self._moved(record):
                continue
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
            for kind, link in (('quarantine', 'quarantined_by'), ('restore', None)):
                linked = self.record(record[link]) if link and record.get(link) else None
                if kind == 'restore':
                    held = self.record(record['quarantined_by']) if record.get('quarantined_by') else None
                    linked = self.record(held['restored_by']) if held and held.get('restored_by') else None
                if linked:
                    view[kind] = {'id': linked['order']['id'], 'state': linked.get('state'), 'txid': linked.get('txid'),
                                  'error': linked.get('error'), 'reason': linked['order']['reason'],
                                  **({'destination': linked['order']['destination']} if kind == 'restore' else {})}
        else:
            view['acts_on'] = order.get('releases') or order.get('freeze') or order.get('quarantine')
            if order['kind'] in ('quarantine', 'restore'):
                view.update(state=record.get('state'), txid=record.get('txid'), error=record.get('error'))
        return view

    def overview(self, user):
        if not ROLES.get(user['role'], set()) & {'order_freeze', 'view_bank'}:
            raise Problem('freeze orders are not available to this account', 403)
        return {'orders': [self.public(user, r) for r in reversed(self.records())],
                'authorities': self.authorities(), 'genesis_hash': self.adapter.node.getblockhash(0),
                'can_order': 'order_freeze' in ROLES.get(user['role'], set())}
