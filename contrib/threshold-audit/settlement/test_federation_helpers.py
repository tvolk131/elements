"""Focused signed-header and durable guardian-pool rotation checks."""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from chunked import encrypt_chunked
from curve import Curve, random_scalar
from guardian_client import GuardianCluster
from recovery import Opening, Statement
from settlement.federation_blocks import BlockFederation
from settlement.treasury import NativeECDSA
from test_framework import messages
from test_framework.messages import CBlock, DynaFedParamEntry, from_hex, ser_uint256
from test_framework.script import CScript, OP_CHECKMULTISIG


LIBRARY = os.environ.get('THRESHOLD_AUDIT_SECP256K1', '/tmp/elements-audit-secp/lib/libsecp256k1.so')


def named(label):
    return hashlib.sha256(label.encode()).digest()


class FederationHelpersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists():
            raise unittest.SkipTest('native shared library required')
        cls.curve = Curve(LIBRARY)
        cls.addClassCleanup(cls.curve.close)
        messages.THRESHOLD_AUDIT = True

    def manifest(self, label):
        keys = {f'{label}-{i}': i + (100 if label == 'A' else 200) for i in range(1, 6)}
        publics = {guardian: self.curve.mul(secret).hex() for guardian, secret in keys.items()}
        witness = bytes(CScript([3, *[bytes.fromhex(value) for value in publics.values()], 5, OP_CHECKMULTISIG]))
        return {'signblockscript': (b'\x00\x20' + hashlib.sha256(witness).digest()).hex(),
                'block_witness_script': witness.hex(), 'guardian_order': list(keys), 'threshold': 3,
                'block_public_keys': publics, 'institutions': {}}, keys

    def block(self, script):
        block = CBlock()
        block.block_height = 10
        block.nTime = 1000
        block.m_dynafed_params.m_current = DynaFedParamEntry(bytes.fromhex(script), 1024, m_elided_root=42)
        return block

    def client(self, keys, calls, failures=()):
        curve = self.curve
        class Client:
            def __init__(self, _):
                pass

            def sign_block(self, guardian, raw):
                calls.append(guardian)
                if guardian in failures:
                    raise OSError('fixture offline')
                block = from_hex(CBlock(), raw)
                block.rehash()
                signature = NativeECDSA(curve).signature(f'{keys[guardian]:064x}', ser_uint256(block.sha256))
                return {'guardian_id': guardian, 'header_hash': block.hash, 'signature': signature.hex()}
        return Client

    def test_activation_boundary_uses_candidate_incoming_script(self):
        outgoing, old_keys = self.manifest('A')
        incoming, new_keys = self.manifest('B')
        signer = BlockFederation(None, self.curve, [outgoing, incoming], allow_bootstrap=False)
        block = self.block(incoming['signblockscript'])
        calls = []
        with patch('settlement.federation_blocks.InstitutionClient', self.client(old_keys | new_keys, calls)):
            signed = from_hex(CBlock(), signer.sign(block.serialize().hex()))
        self.assertEqual(calls, ['B-1', 'B-2', 'B-3'])
        self.assertEqual(signed.m_signblock_witness.stack[-1], bytes.fromhex(incoming['block_witness_script']))
        self.assertEqual(len(signed.m_signblock_witness.stack), 5)

    def test_two_offline_block_signers_still_leave_actual_ecdsa_quorum(self):
        manifest, keys = self.manifest('B')
        signer = BlockFederation(None, self.curve, [manifest], allow_bootstrap=False)
        calls = []
        with patch('settlement.federation_blocks.InstitutionClient', self.client(keys, calls, ('B-1', 'B-2'))):
            signed = from_hex(CBlock(), signer.sign(self.block(manifest['signblockscript']).serialize().hex()))
        self.assertEqual(calls, list(keys))
        self.assertEqual(len(signed.m_signblock_witness.stack), 5)

    def test_missing_quorum_fails_closed(self):
        manifest, keys = self.manifest('B')
        signer = BlockFederation(None, self.curve, [manifest], allow_bootstrap=False)
        with patch('settlement.federation_blocks.InstitutionClient', self.client(keys, [], ('B-1', 'B-2', 'B-3'))):
            with self.assertRaisesRegex(ValueError, 'quorum unavailable'):
                signer.sign(self.block(manifest['signblockscript']).serialize().hex())

    def test_public_manifest_cannot_substitute_keys_under_same_script(self):
        manifest, _ = self.manifest('A')
        manifest['block_public_keys']['A-1'] = self.curve.mul(999).hex()
        with self.assertRaisesRegex(ValueError, 'public keys'):
            BlockFederation(None, self.curve, [manifest])

    def test_partial_signing_restart_reuses_exact_candidate(self):
        manifest, keys = self.manifest('A')
        initial = self.block(manifest['signblockscript'])
        initial.hashPrevBlock = int('11' * 32, 16)
        class Node:
            height = 9
            tip = '11' * 32
            created = 0
            hashes = {9: tip}

            def getblockcount(self):
                return self.height

            def getbestblockhash(self):
                return self.tip

            def getblockhash(self, height):
                return self.hashes[height]

            def getnewblockhex(self, *_):
                self.created += 1
                initial.nTime += 1
                return initial.serialize().hex()

            def submitblock(self, raw):
                candidate = from_hex(CBlock(), raw)
                candidate.rehash()
                self.height, self.tip = candidate.block_height, candidate.hash
                self.hashes[self.height] = self.tip
        node = Node()
        calls = []
        with tempfile.TemporaryDirectory(prefix='elements-pending-block-') as directory:
            first = BlockFederation(node, self.curve, [manifest], directory=directory, allow_bootstrap=False)
            with patch('settlement.federation_blocks.InstitutionClient', self.client(keys, calls, ('A-3', 'A-4', 'A-5'))):
                with self.assertRaisesRegex(ValueError, 'quorum unavailable'):
                    first.mine()
            pending = first.pending['raw']
            resumed = BlockFederation(node, self.curve, [manifest], directory=directory, allow_bootstrap=False)
            self.assertEqual(resumed.pending['raw'], pending)
            with self.assertRaisesRegex(ValueError, 'original pending'):
                resumed.mine(proposal={'unexpected': 'substitution'})
            with patch('settlement.federation_blocks.InstitutionClient', self.client(keys, calls)):
                resumed.mine()
            self.assertEqual(node.created, 1)
            self.assertEqual(node.tip, from_hex(CBlock(), pending).hash or f'{from_hex(CBlock(), pending).rehash():064x}')
            self.assertIsNone(BlockFederation(node, self.curve, [manifest], directory=directory).pending)

    def test_pool_enrollment_resume_preserves_old_ciphertext_recovery(self):
        if shutil.which('openssl') is None:
            self.skipTest('OpenSSL fixture CA required')
        old, incoming = (1, 2, 3), (4, 5, 6)
        chain = named('durable pool chain')
        recipient = self.curve.mul(random_scalar())
        with tempfile.TemporaryDirectory(prefix='elements-audit-pool-') as directory:
            with GuardianCluster(directory, old, LIBRARY, self.curve, recipient) as cluster:
                initial = cluster.genesis(chain, old, 2, named('A signer policy'))
                initial_identity = cluster.guardians[1].identity
                initial_ca = cluster.ca.ca.read_bytes()
                opening = Opening(named('fiat asset'), 125, random_scalar(), random_scalar())
                generator = self.curve.asset_commitment(opening.asset, opening.asset_blinder)
                value = self.curve.value_commitment(generator, opening.amount, opening.value_blinder)
                statement = Statement(chain, named('old transaction'), 0, b'\x51', generator, value,
                                      initial.active_key.public_key, (opening.asset,))
                packet = encrypt_chunked(self.curve, statement, opening)
                cluster.extend(incoming)
                self.assertEqual(cluster.guardians[1].identity, initial_identity)
                self.assertEqual(cluster.ca.ca.read_bytes(), initial_ca)
                prepared, _ = cluster.handoff(chain, initial, incoming, 2, named('B signer policy'), activate=False)
                cluster.activate(chain, prepared)
                cluster.stop_members(old)
                recovered, _ = cluster.recover(prepared.transition.config, 1, statement, packet, recipient)
                self.assertEqual(recovered, opening)
                target = prepared.transition.config
                with GuardianCluster.attach(directory, self.curve, members=incoming) as attached:
                    self.assertTrue(all(guardian.process is None for guardian in attached.guardians.values()))
                    recovered, _ = attached.recover(target, 1, statement, packet, recipient)
                    self.assertEqual(recovered, opening)
                    with self.assertRaisesRegex(ValueError, 'does not own'):
                        attached.stop_members(incoming)
                self.assertTrue(all(cluster.guardians[member].process.poll() is None for member in incoming))
                with GuardianCluster.attach(directory, self.curve) as attached:
                    self.assertEqual(set(attached.guardians), set(incoming))
            with GuardianCluster.resume(directory, self.curve, members=incoming) as resumed:
                self.assertEqual(resumed.ca.ca.read_bytes(), initial_ca)
                self.assertTrue(all(resumed.guardians[member].process is None for member in old))
                recovered, _ = resumed.recover(target, 1, statement, packet, recipient)
                self.assertEqual(recovered, opening)


if __name__ == '__main__':
    unittest.main()
