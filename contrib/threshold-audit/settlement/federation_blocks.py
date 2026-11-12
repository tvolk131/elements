"""Real P2WSH federation block signatures for the local rotation pilot.

The coordinator owns public policy manifests and service credentials only.
Individual institution processes validate candidates with Elements and produce
their own ECDSA signatures. The candidate header chooses its signing policy,
including the first block at a DynaFed activation boundary.
"""

import hashlib
from pathlib import Path

from guardian_service import atomic_write, parse_json

from test_framework import messages
from test_framework.messages import CBlock, from_hex, ser_uint256
from test_framework.script import CScript
from .treasury import InstitutionClient, NativeECDSA


BOOTSTRAP_SCRIPT = b'\x00\x20' + hashlib.sha256(b'\x51').digest()


class BlockFederation:
    def __init__(self, node, curve, manifests=(), *, allow_bootstrap=True, directory=None):
        messages.THRESHOLD_AUDIT = True
        self.node, self.curve = node, curve
        self.allow_bootstrap = allow_bootstrap
        self.directory = None if directory is None else Path(directory)
        if self.directory is not None:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.pending = None
        if self.directory is not None and (self.directory / 'pending.json').exists():
            self.pending = parse_json((self.directory / 'pending.json').read_bytes())
        self.manifests = {}
        for manifest in manifests:
            self.register(manifest)

    def register(self, manifest):
        script = manifest.get('signblockscript', manifest.get('block_signing_script'))
        witness = manifest['block_witness_script']
        if not isinstance(script, str) or bytes.fromhex(script) != b'\x00\x20' + hashlib.sha256(bytes.fromhex(witness)).digest():
            raise ValueError('block federation script does not match witness script')
        order, threshold = manifest['guardian_order'], manifest['threshold']
        if (type(threshold) is not int or not 1 <= threshold <= len(order)
                or len(set(order)) != len(order)):
            raise ValueError('invalid block federation threshold or roster')
        from test_framework.script import OP_CHECKMULTISIG
        public_keys = manifest['block_public_keys']
        expected = bytes(CScript([threshold, *[bytes.fromhex(public_keys[guardian]) for guardian in order], len(order), OP_CHECKMULTISIG]))
        if bytes.fromhex(witness) != expected:
            raise ValueError('block public keys do not match canonical multisig script')
        previous = self.manifests.get(script)
        if previous and (previous['block_witness_script'] != witness or previous['guardian_order'] != order
                         or previous['block_public_keys'] != public_keys or previous['threshold'] != threshold):
            raise ValueError('block policy cannot be rebound')
        self.manifests[script] = dict(manifest, signblockscript=script)
        return script

    def sign(self, raw):
        block = from_hex(CBlock(), raw)
        script = block.m_dynafed_params.m_current.m_signblockscript
        if script == BOOTSTRAP_SCRIPT and self.allow_bootstrap:
            if block.m_signblock_witness.stack not in ([], [b'\x51']):
                raise ValueError('bootstrap block has unexpected witness')
            block.m_signblock_witness.stack = [b'\x51']
            return block.serialize().hex()
        manifest = self.manifests.get(script.hex())
        if manifest is None:
            raise ValueError('no live federation for candidate block policy')
        block.m_signblock_witness.stack = []
        block.rehash()
        digest = ser_uint256(block.sha256)
        expected_hash = block.hash
        unsigned = block.serialize().hex()
        client = InstitutionClient(manifest['institutions'])
        verifier = NativeECDSA(self.curve)
        signatures = []
        for guardian in manifest['guardian_order']:
            try:
                response = client.sign_block(guardian, unsigned)
                signature = bytes.fromhex(response['signature'])
                if (response['guardian_id'] != guardian or response['header_hash'] != expected_hash
                        or not verifier.verify(bytes.fromhex(manifest['block_public_keys'][guardian]), digest, signature)):
                    continue
            except (OSError, ValueError, KeyError):
                continue
            signatures.append(signature)
            if len(signatures) == manifest['threshold']:
                break
        if len(signatures) != manifest['threshold']:
            raise ValueError('block-signing quorum unavailable')
        block.m_signblock_witness.stack = [b'', *signatures, bytes.fromhex(manifest['block_witness_script'])]
        return block.serialize().hex()

    def mine(self, count=1, proposal=None, min_tx_age=0):
        if type(count) is not int or count < 1:
            raise ValueError('positive block count required')
        hashes = []
        for _ in range(count):
            if self.pending is not None:
                block = from_hex(CBlock(), self.pending['raw'])
                block.rehash()
                if self.node.getblockcount() >= block.block_height:
                    if self.node.getblockhash(block.block_height) != block.hash:
                        raise ValueError('pending block conflicts with active chain; reconcile signing history')
                    if block.m_dynafed_params.m_current.m_signblockscript != BOOTSTRAP_SCRIPT:
                        self.allow_bootstrap = False
                    hashes.append(block.hash)
                    self._store_pending(None)
                    continue
                if (self.node.getbestblockhash() != f'{block.hashPrevBlock:064x}'
                        or self.node.getblockcount() + 1 != block.block_height):
                    raise ValueError('pending block parent differs from active chain')
                if self.pending['proposal'] != proposal:
                    raise ValueError('retry the original pending block proposal before changing it')
                raw = self.pending['raw']
            else:
                raw = self.node.getnewblockhex(min_tx_age) if proposal is None else self.node.getnewblockhex(min_tx_age, proposal)
                self._store_pending({'raw': raw, 'proposal': proposal})
            signed = self.sign(raw)
            result = self.node.submitblock(signed)
            if result is not None:
                raise RuntimeError('federation block rejected: ' + str(result))
            if from_hex(CBlock(), signed).m_dynafed_params.m_current.m_signblockscript != BOOTSTRAP_SCRIPT:
                self.allow_bootstrap = False
            hashes.append(self.node.getbestblockhash())
            self._store_pending(None)
        return hashes

    def _store_pending(self, pending):
        self.pending = pending
        if self.directory is not None:
            # Persist a tombstone as well: unlink without directory fsync could
            # resurrect an already accepted candidate after a host crash.
            atomic_write(self.directory / 'pending.json', pending)

    def align(self, epoch_length=10):
        while self.node.getblockcount() % epoch_length:
            self.mine()
        return self.node.getblockcount() + epoch_length
