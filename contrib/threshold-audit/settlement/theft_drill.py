"""Demo only: play a thief who has stolen a customer's key.

Only the thief is simulated. "Steal" signs a payment of one of the customer's
outputs with the customer's own wallet, exactly as whoever held the key could,
to an account the thief opened at another member bank. The operators
authorize it like any other payment: the signature is valid and the
destination is registered. The drill holds the signed bytes.

Everything else is real. The regulator freezes, quarantines and restores
through its own screen with signed orders; the operators refuse the frozen
spend on their own; consensus decides what the bytes are worth. The
independent node, which keeps its own copy of the chain, gives the final
verdict on the very same bytes.
"""

from decimal import Decimal
import json
import threading
import time

from guardian_service import atomic_write
from test_framework.messages import tx_from_hex
from .authorization import AuthorizationRefused, AuthorizationUnavailable
from .store import Problem

# A customer at another member bank on the network (see sandbox.py).
MULE_WALLET = 'other-member-bank'


class TheftDrill:
    def __init__(self, store, runtime):
        self.store, self.runtime = store, runtime
        self.adapter = runtime.adapter
        self.path = runtime.directory / 'theft-drill.json'
        self.lock = threading.Lock()

    # State ---------------------------------------------------------------

    def _load(self):
        return json.loads(self.path.read_text()) if self.path.exists() else None

    def _save(self, drill):
        if drill is None:
            self.path.unlink(missing_ok=True)
        else:
            atomic_write(self.path, drill)

    def _assets(self):
        return {value['asset_id']: currency for currency, value in self.adapter.config['assets'].items()}

    def _covered(self):
        """Outputs the regulator can see through a delivered disclosure case."""
        covered = {}
        with self.store.lock:
            rows = self.store.db.execute('SELECT data FROM disclosure_cases').fetchall()
        for (data,) in rows:
            case = json.loads(data)
            if case.get('state') != 'delivered':
                continue
            for target in case['manifest']['targets']:
                covered[f"{target['txid']}:{target['output_index']}"] = case['id']
        return covered

    def _account_name(self, account_id):
        with self.store.lock:
            try:
                return self.store.account(account_id).get('name', account_id)
            except Problem:
                return account_id

    def targets(self):
        """Customer outputs a thief with that customer's key could spend."""
        assets, covered = self._assets(), self._covered()
        frozen = self.store.freezes.active_outpoints() if self.store.freezes else {}
        found = []
        for account, wallet in self.adapter.wallets.items():
            try:
                coins = wallet.listunspent(1)
            except (OSError, RuntimeError, ValueError):
                continue
            for coin in coins:
                outpoint = f"{coin['txid']}:{coin['vout']}"
                if coin.get('asset') not in assets or outpoint in frozen:
                    continue
                found.append({'txid': coin['txid'], 'vout': coin['vout'], 'account_id': account,
                              'account': self._account_name(account), 'currency': assets[coin['asset']],
                              'amount_minor': int((Decimal(str(coin['amount'])) * 100).to_integral_value()),
                              'case_id': covered.get(outpoint)})
        found.sort(key=lambda t: (t['case_id'] is None, -t['amount_minor']))
        return found[:8]

    # Steps ---------------------------------------------------------------

    def steal(self, user, txid, vout):
        with self.lock:
            if self._load() is not None:
                raise Problem('a drill is already running; start over first', 409)
            target = next((t for t in self.targets() if t['txid'] == txid and t['vout'] == vout), None)
            if target is None:
                raise Problem('choose an unfrozen customer output from the list', 404)
            wallet = self.adapter.wallets[target['account_id']]
            coin = next(c for c in wallet.listunspent(1) if c['txid'] == txid and c['vout'] == vout)
            mule = self.runtime._wallet(self.adapter.config['rpc_url'], MULE_WALLET).getnewaddress('mule', 'blech32')
            # The customer's own wallet signs: that is what a stolen key allows.
            psbt = wallet.walletcreatefundedpsbt([{'txid': txid, 'vout': vout}],
                                                 [{mule: coin['amount'], 'asset': coin['asset']}], 0,
                                                 {'fee_rate': 2, 'add_inputs': True, 'lockUnspents': False})['psbt']
            final = wallet.finalizepsbt(wallet.walletprocesspsbt(psbt)['psbt'])
            if not final.get('complete'):
                raise Problem('the customer wallet could not sign the payment', 503)
            try:
                raw = self.adapter.authorize(final['hex'])
            except (AuthorizationRefused, AuthorizationUnavailable) as error:
                raise Problem(f'the operators did not authorize the payment: {error}', 409) from None
            transaction = tx_from_hex(raw)
            authorization = bytes(transaction.wit.vchAuthorization)
            drill = {'started_at': int(time.time()), 'started_by': user['id'], 'target': target,
                     'mule': {'address': mule, 'bank': 'another member bank'},
                     'raw': raw, 'txid': transaction.rehash(),
                     'authorized_until': int.from_bytes(authorization[:4], 'little'),
                     'stolen': {'at': int(time.time()), 'height': self.adapter.node.getblockcount(),
                                'independent_node': self._verdict(raw)},
                     'broadcasts': [], 'replays': []}
            self._save(drill)
        self._evidence(user, 'demo_theft_signed', {'txid': drill['txid'], 'outpoint': f'{txid}:{vout}'})
        return self.view(user)

    def broadcast(self, user):
        """The thief sends the held bytes to the network."""
        with self.lock:
            drill = self._require()
            target = drill['target']
            if f"{target['txid']}:{target['vout']}" not in self._frozen_outpoints():
                raise Problem('have the regulator freeze this output first: an unfrozen spend '
                              'confirms in the next block and the drill ends there', 409)
            node = self.adapter.node
            attempt = {'at': int(time.time()), 'height': node.getblockcount()}
            try:
                node.sendrawtransaction(drill['raw'], 0)
                attempt.update(accepted=True, reason=None)
            except RuntimeError as error:
                attempt.update(accepted=False, reason=str(error)[:300])
                if 'authorization-expired' in attempt['reason']:
                    # The thief's only option: ask the operators again.
                    try:
                        self.adapter.authorize(drill['raw'])
                        attempt['reauthorization'] = {'refused': False, 'reason': None}
                    except (AuthorizationRefused, AuthorizationUnavailable) as refusal:
                        attempt['reauthorization'] = {'refused': True, 'reason': str(refusal)[:300]}
            drill['broadcasts'].append(attempt)
            self._save(drill)
        self._evidence(user, 'demo_theft_broadcast', {'txid': drill['txid'], 'accepted': attempt['accepted']})
        return self.view(user)

    def replay(self, user):
        """Submit the same bytes to the independent node."""
        observer = self.runtime.observer
        if observer is None:
            raise Problem('the independent node is not running in this runtime', 503)
        with self.lock:
            drill = self._require()
            target = drill['target']
            verdict = observer.verdict(drill['raw'])
            replay = {'at': int(time.time()), 'height': observer.node.getblockcount(), **verdict,
                      'output_spent': observer.output_spent(target['txid'], target['vout'])}
            if not verdict['accepted']:
                # Show the refusal is the node's, not a dry run: the actual
                # submission is turned down too. Accepted bytes are not sent,
                # so the drill cannot complete a theft by accident.
                sent = observer.broadcast(drill['raw'])
                replay['submission'] = sent['reason'] if not sent['accepted'] else 'accepted'
            spender = self._quarantine_txid(target)
            if spender:
                try:
                    found = observer.node.getrawtransaction(spender, True)
                    replay['spent_by'] = {'txid': spender, 'confirmations': found.get('confirmations', 0)}
                except RuntimeError:
                    replay['spent_by'] = {'txid': spender, 'confirmations': 0}
            drill['replays'].append(replay)
            self._save(drill)
        self._evidence(user, 'demo_theft_replayed', {'txid': drill['txid'], 'accepted': verdict['accepted'],
                                                     'reason': verdict['reason']})
        return self.view(user)

    def reset(self, user):
        with self.lock:
            self._save(None)
        return self.view(user)

    # Views ---------------------------------------------------------------

    def _require(self):
        drill = self._load()
        if drill is None:
            raise Problem('start the drill by stealing an output first', 409)
        return drill

    def _verdict(self, raw):
        observer = self.runtime.observer
        if observer is None:
            return None
        try:
            return observer.verdict(raw)
        except (OSError, RuntimeError, ValueError):
            return None

    def _frozen_outpoints(self):
        return self.store.freezes.active_outpoints() if self.store.freezes else {}

    def _freeze(self, target):
        """The freeze order on the target output, and what followed it."""
        if not self.store.freezes:
            return None
        outpoint = (target['txid'], target['vout'])
        for record in reversed(self.store.freezes.records()):
            order = record['order']
            if order['kind'] == 'freeze' and any((o['txid'], o['vout']) == outpoint for o in order['outputs']):
                return record
        return None

    def _quarantine_txid(self, target):
        record = self._freeze(target)
        held = self.store.freezes.record(record['quarantined_by']) if record and record.get('quarantined_by') else None
        return held.get('txid') if held else None

    def _regulator(self, target):
        record = self._freeze(target)
        if record is None:
            return {'frozen': None, 'quarantine': None, 'restore': None}
        freezes = self.store.freezes
        operators = len(self.adapter.authorizer_services())
        frozen = {'order_id': record['order']['id'], 'applied_by': len(record['receipts']), 'operators': operators,
                  'released': bool(record.get('released_by'))}
        held = freezes.record(record['quarantined_by']) if record.get('quarantined_by') else None
        quarantine = held and {'order_id': held['order']['id'], 'state': held.get('state'), 'txid': held.get('txid')}
        returned = freezes.record(held['restored_by']) if held and held.get('restored_by') else None
        restore = returned and {'order_id': returned['order']['id'], 'state': returned.get('state'),
                                'txid': returned.get('txid'), 'destination': returned['order']['destination']}
        return {'frozen': frozen, 'quarantine': quarantine, 'restore': restore}

    def _thief_status(self, drill):
        node = self.adapter.node
        try:
            found = node.getrawtransaction(drill['txid'], True)
            if found.get('confirmations'):
                return 'confirmed'
        except RuntimeError:
            pass
        return 'in_mempool' if drill['txid'] in node.getrawmempool() else 'not_in_mempool'

    def view(self, user):
        drill = self._load()
        observer = self.runtime.observer is not None
        if drill is None:
            return {'drill': None, 'targets': self.targets(), 'independent_node': observer}
        target = drill['target']
        public = {key: drill[key] for key in ('started_at', 'target', 'mule', 'txid', 'authorized_until',
                                              'stolen', 'broadcasts', 'replays')}
        public.update(height=self.adapter.node.getblockcount(), thief_transaction=self._thief_status(drill),
                      output_spent=self.adapter.node.gettxout(target['txid'], target['vout'], False) is None,
                      raw_size=len(drill['raw']) // 2, **self._regulator(target))
        return {'drill': public, 'targets': [], 'independent_node': observer}

    def _evidence(self, user, event, data):
        with self.store.transaction():
            self.store.evidence(user['id'], event, data)
