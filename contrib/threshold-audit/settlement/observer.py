"""An independent node: a second Elements node with its own copy of the chain.

It runs the same consensus rules from the same chain parameters, downloads
every block from the demo node over the peer-to-peer network and checks each
one itself: block signatures, the operators' authorizations, confidential
proofs and recovery records. It has no wallet and holds no keys, so it can
only say what the rules allow. Its verdict on a transaction is therefore
evidence that does not depend on the demo node, the app or the operators.
"""

import secrets
import time

from .elements_adapter import RPC
from .runtime import load_config, save_config

# Arguments that belong to one node's process rather than to the chain.
LOCAL = ('-datadir=', '-rpcport=', '-rpcpassword=', '-rpcuser=', '-listen=', '-connect=', '-bind=', '-port=',
         '-blindedaddresses=', '-deprecatedrpc=', '-disablewallet', '-whitelist=')


def observer_args(main_args, datadir, rpc_port, rpc_password, p2p_port):
    """The demo node's chain parameters with this node's own process settings."""
    chain = [arg for arg in main_args[1:] if not arg.startswith(LOCAL)]
    return [main_args[0], *chain, '-datadir=' + str(datadir), '-rpcport=' + str(rpc_port), '-rpcuser=observer',
            '-rpcpassword=' + rpc_password, '-listen=1', f'-bind=127.0.0.1:{p2p_port}', '-connect=0',
            '-disablewallet', '-whitelist=noban@127.0.0.1']


class Observer:
    def __init__(self, directory, processes, free_port):
        self.directory = directory / 'observer'
        self.processes, self.free_port = processes, free_port
        self.node = self.process = self.main = None
        self.address = None

    def start(self, main_node, main_args):
        """Start (or restart) the node and connect the demo node to it."""
        self.directory.mkdir(mode=0o700, exist_ok=True)
        datadir = self.directory / 'node'
        datadir.mkdir(mode=0o700, exist_ok=True)
        path = self.directory / 'observer.json'
        secret = load_config(path)['rpc_password'] if path.exists() else secrets.token_hex(24)
        save_config(path, {'rpc_password': secret})
        rpc_port, p2p_port = self.free_port(), self.free_port()
        args = observer_args(main_args, datadir, rpc_port, secret, p2p_port)
        self.process = self.processes.spawn(args, self.directory / 'daemon.log')
        self.node = RPC(f'http://observer:{secret}@127.0.0.1:{rpc_port}')
        deadline = time.monotonic() + 60
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('the independent node exited; see observer/daemon.log')
            try:
                self.node.getblockchaininfo()
                break
            except (OSError, RuntimeError, ValueError):
                if time.monotonic() > deadline:
                    raise RuntimeError('the independent node did not start')
                time.sleep(.1)
        if self.node.getblockhash(0) != main_node.getblockhash(0):
            raise RuntimeError('the independent node derived a different genesis block')
        # The demo node accepts no inbound connections; it dials this node.
        self.main, self.address = main_node, f'127.0.0.1:{p2p_port}'
        main_node.addnode(self.address, 'add')
        return self

    def connect(self):
        """Ask the demo node to dial again, e.g. after either restarted."""
        try:
            self.main.addnode(self.address, 'onetry')
        except Exception:
            pass

    def status(self):
        node, main = self.node, self.main
        info = node.getblockchaininfo()
        main_height = main.getblockcount()
        height = info['blocks']
        agrees = main_height >= height and main.getblockhash(height) == info['bestblockhash']
        peers = node.getconnectioncount()
        if not peers:
            self.connect()
        return {
            'height': height,
            'best_block': info['bestblockhash'],
            'demo_node_height': main_height,
            'behind': max(0, main_height - height),
            'same_chain': agrees,
            'peers': peers,
            'mempool': node.getmempoolinfo()['size'],
            'authorization_rule': bool(info.get('tx_authorization')),
            'registry_version': info.get('audit_assets_version', 0),
            'wallet': False,
        }

    def verdict(self, raw):
        """Would this node accept these exact bytes? Nothing is broadcast."""
        result = self.node.testmempoolaccept([raw], 0)[0]
        reason = result.get('reject-reason')
        if reason == 'txn-already-in-mempool':
            return {'accepted': True, 'in_mempool': True, 'reason': None}
        return {'accepted': bool(result.get('allowed')), 'in_mempool': False, 'reason': reason}

    def broadcast(self, raw):
        """Submit the bytes to this node, which relays them if it accepts them."""
        try:
            return {'accepted': True, 'txid': self.node.sendrawtransaction(raw, 0), 'reason': None}
        except RuntimeError as error:
            return {'accepted': False, 'txid': None, 'reason': str(error)[:300]}

    def output_spent(self, txid, vout):
        """Whether this node's own chain shows the output as spent (or never created)."""
        return self.node.gettxout(txid, vout, False) is None

    def close(self):
        if self.node is not None:
            try:
                self.node.stop()
            except Exception:
                pass
        if self.process is not None:
            self.processes.stop(self.process, timeout=30)
