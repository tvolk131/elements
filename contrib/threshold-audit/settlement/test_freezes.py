"""Freeze orders end to end: regulator signature, relay, operator receipts, wallets and blocks."""
from decimal import Decimal
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from curve import Curve
from test_framework import messages
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn
from .approval import ApprovalVerifier
from .freeze_orders import case_authority_secret, sign, validate, verify
from .freezes import Freezes
from .receipts import Receipts
from .store import Problem, Settlement
from .test_settlement import TestChain
from .treasury import Institution, InstitutionRefused

LIBRARY = os.environ.get('THRESHOLD_AUDIT_SECP256K1', '/tmp/elements-audit-secp/lib/libsecp256k1.so')
GENESIS = 'cc' * 32
FROZEN_TXID = 'ab' * 32
REGULATOR = 777


class Wallet:
    def __init__(self, coins):
        self.coins, self.locked = coins, set()

    def listunspent(self, minconf=0):
        return [c for c in self.coins if (c['txid'], c['vout']) not in self.locked]

    def listlockunspent(self):
        return [{'txid': t, 'vout': v} for t, v in sorted(self.locked)]

    def lockunspent(self, unlock, outputs):
        for item in outputs:
            key = (item['txid'], item['vout'])
            if not any((c['txid'], c['vout']) == key for c in self.coins):
                # The node's RPC client raises RPCError, a RuntimeError.
                raise RuntimeError('Invalid parameter, unknown transaction')
            (self.locked.discard if unlock else self.locked.add)(key)
        return True


class Node:
    def __init__(self):
        self.spent, self.pending = set(), set()

    def getblockhash(self, height):
        return GENESIS

    def gettxout(self, txid, vout, include_mempool=True):
        if (txid, vout) in self.spent or (include_mempool and (txid, vout) in self.pending):
            return None
        return {'value': 0}


class FreezeRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists():
            raise unittest.SkipTest('native secp256k1 library required')
        cls.curve = Curve(LIBRARY)
        messages.THRESHOLD_AUDIT = True

    @classmethod
    def tearDownClass(cls):
        cls.curve.close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='concord-freeze-test-')
        self.authority = self.curve.mul(REGULATOR)[1:].hex()
        keys = {f'i{i}': self.curve.mul(100 + i)[1:].hex() for i in (1, 2, 3)}
        self.operators = {
            f'i{i}': Institution({'library': LIBRARY, 'guardian_id': f'i{i}', 'approval_secret': f'{100 + i:064x}',
                                  'approval_public_keys': keys, 'threshold': 2, 'genesis_hash': GENESIS,
                                  'database': str(Path(self.temp.name) / f'i{i}.sqlite'),
                                  'case_authority_keys': {'Regulator': self.authority}}, rpc=None)
            for i in (1, 2, 3)}
        self.offline = set()
        accounts = [{'id': 'a', 'name': 'A Customer', 'tenant': 'a', 'bank_tenant': 'bank', 'addresses': {'EUR': 'conf-a'}}]
        users = [{'id': 'regulator', 'username': 'regulator', 'role': 'regulator', 'tenant': 'regulator'},
                 {'id': 'bank-admin', 'username': 'bank-admin', 'role': 'bankadmin', 'tenant': 'bank'},
                 {'id': 'maker', 'username': 'maker', 'role': 'corporatemaker', 'tenant': 'a'}]
        for user in users:
            user.update(name=user['id'], password='fixture-password')
        self.users = {u['id']: u for u in users}
        self.store = Settlement(Path(self.temp.name) / 'store.sqlite', TestChain(), ApprovalVerifier(self.curve, keys, 2),
                                config={'accounts': accounts, 'users': users, 'case_authority_keys': {'Regulator': self.authority}})
        self.wallet = Wallet([{'txid': FROZEN_TXID, 'vout': 1, 'amount': Decimal('12750.00'), 'asset': 'bb' * 32},
                              {'txid': 'cd' * 32, 'vout': 0, 'amount': Decimal('5.00'), 'asset': 'bb' * 32}])
        self.node = Node()
        services = {key: (guardian, {'url': 'in-process'}) for guardian, key in keys.items()}
        self.adapter = type('Adapter', (), {})()
        self.adapter.curve, self.adapter.node, self.adapter.sponsor = self.curve, self.node, Wallet([])
        self.adapter.wallets = {'a': self.wallet}
        self.adapter.config = {'assets': {'EUR': {'asset_id': 'bb' * 32}}, 'threshold': 2}
        self.adapter.authorizer_services = lambda: services
        operators, offline = self.operators, self.offline

        class Client:
            """The operators' HTTP API, in process: refusals become InstitutionRefused."""
            def __init__(self, configured):
                self.guardian = next(iter(configured))

            def request(self, guardian, method, **values):
                if guardian in offline:
                    raise OSError('connection refused')
                try:
                    return getattr(operators[guardian], method)(values)
                except ValueError as error:
                    raise InstitutionRefused(str(error)) from None
        patcher = patch('settlement.freezes.InstitutionClient', Client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.freezes = Freezes(self.store, self.adapter)
        self.store.freezes = self.freezes

    def tearDown(self):
        for operator in self.operators.values():
            operator.db.close(); operator.curve.close()
        self.store.close()
        self.temp.cleanup()

    def order(self, **changes):
        value = {'format': 'concord-freeze-order-v1', 'kind': 'freeze', 'id': 'f1' * 16, 'genesis_hash': GENESIS,
                 'authority': 'Regulator', 'authority_key': self.authority, 'case_reference': 'case-7',
                 'reason': 'Proceeds of a reported theft', 'issued_at': int(time.time()),
                 'outputs': [{'txid': FROZEN_TXID, 'vout': 1}]}
        value.update(changes)
        return value

    def submit(self, order, user='regulator', secret=REGULATOR):
        return self.freezes.submit(self.users[user], {'order': order, 'signature': sign(self.curve, secret, order)})

    def spending_block(self):
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(FROZEN_TXID, 16), 1))]
        # Like a transaction read from a block template: no cached hash yet.
        expected = CTransaction(spend).rehash()
        block = CBlock()
        block.vtx = [CTransaction(), spend]
        return block, expected

    def test_regulator_freeze_reaches_operators_wallets_and_blocks(self):
        order = self.order()
        with self.assertRaises(Problem) as denied:
            self.submit(order, user='bank-admin')
        self.assertEqual(denied.exception.status, 403)
        with self.assertRaisesRegex(Problem, 'signature is invalid'):
            self.submit(order, secret=REGULATOR + 1)
        self.offline.add('i3')
        view = self.submit(order)
        self.assertEqual(view['applied_by'], ['i1', 'i2'])
        self.assertIn('i3', view['errors'])
        # The holder's wallet won't pick the coin, its spendable balance drops,
        # and the block producer leaves any spend of it out.
        self.assertEqual(self.wallet.locked, {(FROZEN_TXID, 1)})
        self.assertEqual(self.freezes.frozen_balance('a', 'EUR'), 1_275_000)
        self.assertEqual(self.store.available_balance('a', 'EUR'), -1_275_000)
        block, txid = self.spending_block()
        self.assertEqual(self.freezes.excluded(block), [txid])
        self.assertEqual(self.adapter.frozen(), {f'{FROZEN_TXID}:1': order['id']})
        # An operator that was offline gets the order on the next retry.
        self.offline.clear()
        self.freezes.retry()
        self.assertEqual(self.freezes.public(self.users['regulator'], self.freezes.record(order['id']))['applied_by'],
                         ['i1', 'i2', 'i3'])
        # Only bank staff see which customer holds the frozen funds.
        regulator = self.freezes.overview(self.users['regulator'])['orders'][0]
        self.assertNotIn('holding', regulator['outputs'][0])
        self.assertEqual(regulator['outputs'][0]['status'], 'unspent')
        bank = self.freezes.overview(self.users['bank-admin'])['orders'][0]
        self.assertEqual(bank['outputs'][0]['holding'], {'account_id': 'a', 'currency': 'EUR', 'amount_minor': 1_275_000})
        with self.assertRaises(Problem):
            self.freezes.overview(self.users['maker'])
        self.assertEqual(self.freezes.frozen_funds(self.users['maker'])[0]['amount_minor'], 1_275_000)
        # Locks survive a restart of the settlement server.
        self.wallet.locked.clear()
        Freezes(self.store, self.adapter)
        self.assertEqual(self.wallet.locked, {(FROZEN_TXID, 1)})

        release = self.order(kind='release', id='e1' * 16, reason='Owner verified; funds returned')
        del release['outputs']
        release['releases'] = order['id']
        self.assertEqual(self.submit(release)['applied_by'], ['i1', 'i2', 'i3'])
        self.assertEqual(self.wallet.locked, set())
        self.assertEqual(self.freezes.excluded(block), [])
        self.assertEqual(self.freezes.frozen_balance('a', 'EUR'), 0)
        with self.assertRaisesRegex(Problem, 'already released'):
            self.submit(dict(release, id='e2' * 16))

    def test_quarantine_and_restore_orders_follow_their_freeze(self):
        freeze = self.order()
        self.submit(freeze)
        def follow(kind, order_id, **fields):
            order = self.order(kind=kind, id=order_id, reason='Recover the frozen funds', **fields)
            del order['outputs']
            return order
        with self.assertRaisesRegex(Problem, 'no freeze in force'):
            self.submit(follow('quarantine', 'a1' * 16, freeze='00' * 16))
        quarantine = follow('quarantine', 'a2' * 16, freeze=freeze['id'])
        view = self.submit(quarantine)
        self.assertEqual((view['state'], view['applied_by']), ('ordered', ['i1', 'i2', 'i3']))
        # Operators recorded it, so each will sign only that quarantine.
        self.assertEqual(self.operators['i1'].db.execute('SELECT kind FROM freeze_orders WHERE id=?',
                                                          (quarantine['id'],)).fetchone()[0], 'quarantine')
        with self.assertRaisesRegex(Problem, 'already quarantined'):
            self.submit(follow('quarantine', 'a3' * 16, freeze=freeze['id']))
        release = follow('release', 'a4' * 16, releases=freeze['id'])
        with self.assertRaisesRegex(Problem, 'restore them instead'):
            self.submit(release)
        with self.assertRaisesRegex(Problem, 'not completed yet'):
            self.submit(follow('restore', 'a5' * 16, quarantine=quarantine['id'], destination='acme-main@bank'))
        self.assertEqual(self.freezes.public(self.users['regulator'], self.freezes.record(freeze['id']))['quarantine']['state'],
                         'ordered')
        # Still frozen until the quarantine is actually sent.
        self.assertEqual(self.freezes.frozen_balance('a', 'EUR'), 1_275_000)
        with self.assertRaisesRegex(Problem, 'bank reference'):
            self.submit(follow('restore', 'a6' * 16, quarantine=quarantine['id'], destination='not a reference'))

    def test_quarantine_and_return_appear_in_the_holders_history(self):
        Receipts(self.store)  # the receipt watcher's tables, which a return also records in
        with self.store.transaction():
            self.store.tokens({'id': 'seed', 'currency': 'EUR'}, 'seed', 'a', 1_275_000)
        coin = {'asset': 'bb' * 32, 'account_id': 'a', 'currency': 'EUR', 'amount_minor': 1_275_000}
        quarantine = {'id': 'a2' * 16, 'authority': 'Regulator', 'case_reference': 'case-7'}
        for _ in range(2):  # a retried broadcast records and debits once
            with self.store.transaction():
                self.assertTrue(self.freezes._record_quarantine(quarantine, 'ee' * 32, 0,
                                                                dict(coin, txid=FROZEN_TXID, vout=1),
                                                                {'address': 'quarantine-address'}))
        self.assertEqual(self.store.token_balance('a', 'EUR'), 0)
        restore = {'id': 'a5' * 16, 'authority': 'Regulator', 'case_reference': 'case-7'}
        with self.store.transaction():
            self.assertTrue(self.freezes._record_return(restore, 'ff' * 32, 0, dict(coin, address='conf-a-2')))
            # Funds held by no customer of ours leave no customer record.
            self.assertFalse(self.freezes._record_quarantine(quarantine, 'ee' * 32, 1, {'amount_minor': 5},
                                                             {'address': 'quarantine-address'}))
        self.assertEqual(self.store.token_balance('a', 'EUR'), 1_275_000)

        holder = self.store.dashboard({'user': self.users['maker']})
        moved, returned = sorted((op for op in holder['operations'] if op.get('recovery_order')),
                                 key=lambda op: op['kind'])
        self.assertEqual((moved['kind'], moved['amount_minor'], moved['destination'], moved['recovery_order']),
                         ('quarantine', 1_275_000, 'Quarantine', quarantine['id']))
        self.assertEqual((moved['authority'], moved['case_reference']), ('Regulator', 'case-7'))
        self.assertEqual(moved['reference'], 'Moved to quarantine by order of Regulator')
        self.assertEqual((returned['kind'], returned['recovery_order'], returned['amount_minor']),
                         ('receipt', restore['id'], 1_275_000))
        self.assertTrue(returned['reference'].startswith('Returned from quarantine'))
        events = {(e['event'], e['operation_id']) for e in holder['activity']}
        self.assertIn(('funds_quarantined', moved['id']), events)
        self.assertIn(('funds_restored', returned['id']), events)
        # Nobody outside the holder's own tenant sees the account's history.
        regulator = self.store.dashboard({'user': self.users['regulator']})
        self.assertFalse([op for op in regulator['operations'] if op.get('recovery_order')])
        # The bank's ledger view names both moves beside what the chain shows.
        self.store.ledger_view = type('Ledger', (), {'recent': lambda _: {
            'transactions': [{'txid': 'ee' * 32}, {'txid': 'ff' * 32}, {'txid': '00' * 32}]}})()
        known = [t['known'] for t in self.store.ledger(self.users['bank-admin'])['transactions']]
        self.assertEqual([k and (k['stage'], k['from'], k['authority'], k['amount_minor']) for k in known],
                         [('quarantine', 'A Customer', 'Regulator', 1_275_000),
                          ('restore', 'A Customer', 'Regulator', 1_275_000), None])

    def test_spent_outputs_and_reused_ids_are_refused(self):
        self.node.spent.add((FROZEN_TXID, 1))
        with self.assertRaisesRegex(Problem, 'already spent'):
            self.submit(self.order())
        # A spend still waiting in the mempool can be stopped, so it may be frozen.
        self.node.spent.clear()
        self.node.pending.add((FROZEN_TXID, 1))
        view = self.submit(self.order())
        self.assertEqual(view['outputs'][0]['status'], 'spend_pending')
        with self.assertRaisesRegex(Problem, 'different order'):
            self.submit(self.order(reason='Another reason, same ID'))

    def test_signing_key_derivation_matches_the_browser(self):
        # The browser derives the same key (recipient-crypto.test.ts).
        self.assertEqual(f'{case_authority_secret(1):064x}', '23b8cc6122f8e30aec62f6cdb6d4262a17b74d621d42c2d4ffd3f407cf31df3f')
        self.assertEqual(self.curve.mul(case_authority_secret(1))[1:].hex(),
                         '5d027bd59943981e1c762a33f03db253e6b403a1722a5905758348259852c4cb')
        # An order signed in the browser (recipient-crypto.test.ts) verifies here.
        browser = self.order(authority_key='5d027bd59943981e1c762a33f03db253e6b403a1722a5905758348259852c4cb',
                             issued_at=1795000000)
        signature = ('356e2823dbe896b1fa2c4af277b045e9f261989761e2fdf8fc50c6d0335574a0'
                     '0a6e457994738ce317f943cd6788cf4158032e6145f688f345f6a215a68e6f9d')
        self.assertEqual(verify(self.curve, {'Regulator': browser['authority_key']}, browser, signature), 'Regulator')
        with self.assertRaisesRegex(ValueError, 'signature is invalid'):
            verify(self.curve, {'Regulator': browser['authority_key']}, dict(browser, case_reference='case-8'), signature)
        order = self.order()
        self.assertEqual(validate(order, GENESIS), [f'{FROZEN_TXID}:1'])
        with self.assertRaisesRegex(ValueError, 'issue time'):
            validate(self.order(issued_at=int(time.time()) + 3600), GENESIS)


if __name__ == '__main__':
    unittest.main()
