"""The independent node's launch arguments and the theft drill's guard rails."""
from pathlib import Path
import tempfile
import unittest

from .observer import observer_args
from .store import Problem
from .theft_drill import TheftDrill

MAIN = ['/bin/elementsd', '-datadir=/runtime/node', '-chain=auditregtest', '-server=1', '-listen=0',
        '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-rpcport=43577', '-rpcuser=sandbox', '-rpcpassword=secret',
        '-con_threshold_audit=1', '-evbparams=dynafed:-1:::', '-con_audit_config=5441', '-initialfreecoins=2100000000000000',
        '-dynamic_epoch_length=10', '-txindex=1', '-blindedaddresses=1', '-connect=0', '-deprecatedrpc=create_bdb']


class ObserverArgumentTests(unittest.TestCase):
    def test_same_chain_parameters_with_its_own_process_settings(self):
        args = observer_args(MAIN, Path('/runtime/observer/node'), 5000, 'other', 6000)
        self.assertEqual(args[0], MAIN[0])
        for chain in ('-chain=auditregtest', '-con_threshold_audit=1', '-evbparams=dynafed:-1:::',
                      '-con_audit_config=5441', '-initialfreecoins=2100000000000000', '-dynamic_epoch_length=10'):
            self.assertIn(chain, args)
        for local in ('-datadir=/runtime/node', '-rpcport=43577', '-rpcpassword=secret', '-listen=0',
                      '-rpcuser=sandbox', '-blindedaddresses=1', '-deprecatedrpc=create_bdb'):
            self.assertNotIn(local, args)
        self.assertIn('-datadir=/runtime/observer/node', args)
        self.assertIn('-listen=1', args)
        self.assertIn('-bind=127.0.0.1:6000', args)
        self.assertIn('-disablewallet', args)
        # Only the demo node's own connection reaches it.
        self.assertIn('-connect=0', args)
        self.assertEqual(sum(arg.startswith('-rpcport=') for arg in args), 1)


class FakeNode:
    def __init__(self):
        self.sent = []

    def getblockcount(self):
        return 300

    def sendrawtransaction(self, raw, fee):
        self.sent.append(raw)
        return 'aa' * 32


class DrillGuardTests(unittest.TestCase):
    def setUp(self):
        directory = Path(tempfile.mkdtemp())
        node = FakeNode()
        adapter = type('Adapter', (), {'node': node, 'config': {'assets': {}}, 'wallets': {}})()
        runtime = type('Runtime', (), {'adapter': adapter, 'directory': directory, 'observer': None})()
        freezes = type('Freezes', (), {'frozen': {}, 'active_outpoints': lambda self: self.frozen})()
        store = type('Store', (), {'freezes': freezes})()
        self.node, self.freezes = node, freezes
        self.drill = TheftDrill(store, runtime)
        self.drill._evidence = lambda *_: None
        self.drill._save({'target': {'txid': 'ab' * 32, 'vout': 1}, 'raw': '00', 'txid': 'cd' * 32,
                          'broadcasts': [], 'replays': []})
        self.drill.view = lambda user: self.drill._load()

    def test_thief_cannot_broadcast_before_the_freeze(self):
        with self.assertRaises(Problem) as refused:
            self.drill.broadcast({'id': 'bank-admin'})
        self.assertEqual(refused.exception.status, 409)
        self.assertEqual(self.node.sent, [])
        self.freezes.frozen = {f"{'ab' * 32}:1": 'order'}
        drill = self.drill.broadcast({'id': 'bank-admin'})
        self.assertEqual(self.node.sent, ['00'])
        self.assertTrue(drill['broadcasts'][0]['accepted'])

    def test_replay_needs_the_independent_node(self):
        with self.assertRaises(Problem) as refused:
            self.drill.replay({'id': 'bank-admin'})
        self.assertEqual(refused.exception.status, 503)


if __name__ == '__main__':
    unittest.main()
