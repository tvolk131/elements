#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native TAC2 consensus enforcement and DynaFed lifecycle on two local nodes.

The nodes construct and validate C++ recovery proofs on real wallet/PSET
transactions. Committee ceremonies remain Python simulations in this test;
feature_threshold_audit_guardians.py uses isolated guardian processes instead.
"""

import copy
import base64
from dataclasses import replace
from decimal import Decimal
import hashlib
from io import BytesIO
import os
from pathlib import Path
import sys

from test_framework import messages, util
from test_framework.blocktools import add_witness_commitment
from test_framework.key import ECKey
from test_framework.messages import CBlock, DynaFedParamEntry, deser_compact_size, from_hex, ser_uint256, tx_from_hex
from test_framework.psbt import PSBTMap
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

PROTOTYPE = Path(__file__).resolve().parents[2] / 'contrib' / 'threshold-audit'
sys.path.insert(0, str(PROTOTYPE))

from chunked import ChunkPacket, _encrypt_unchecked, combine_chunked, partial_decrypt_chunked, verify_chunked
from curve import Curve, random_scalar
from governance import AuditConfig, AuditKey, PreparedTransition, Transition, make_readiness
from native_governance import policy_binding, prepared_to_bytes
from native_transactions import attach_recovery, output_statement, wallet_openings
from recovery import Opening
from threshold import simulate_handoff, simulate_keygen


def named(value):
    return hashlib.sha256(value.encode()).digest()


class ThresholdAuditTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The framework writes one explicit loopback bind into each config.
        # Do not repeat the multi-valued -bind option on the command line.
        self.bind_to_localhost_only = True
        self.chain = 'auditregtest'
        self.rpc_timeout = 180
        messages.THRESHOLD_AUDIT = True
        library = os.environ.get('THRESHOLD_AUDIT_SECP256K1', '/tmp/elements-audit-secp/lib/libsecp256k1.so')
        self.library = library
        # The Python prototype needs a secp256k1-zkp build with the audit
        # modules. Without one, skip rather than fail inside the constructor,
        # so test_runner.py can list these tests on machines that lack it.
        self.missing_library = not Path(library).is_file()
        if self.missing_library:
            return
        self.curve = Curve(library)
        initial_script = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        initial_policy = policy_binding(initial_script, 108, initial_script, b'\x51', [b''])
        self.genesis_config = self.initialize_audit_committee(initial_policy)
        # A test functionary signs header hashes directly. The legacy signblock
        # RPC cannot serve descriptor wallets or deliberately invalid blocks.
        self.block_signer = ECKey()
        self.block_signer.generate()
        self.replacement_script = bytes(key_to_p2wpkh_script(self.block_signer.get_pubkey().get_bytes()))
        args = [
            '-con_threshold_audit=1',
            '-evbparams=dynafed:-1:::',
            '-blindedaddresses=1',
            '-con_audit_pubkey=' + self.committee.public_key.hex(),
            '-con_audit_config=' + self.genesis_config.to_bytes().hex(),
            '-con_start_p2wsh_script=1',
            '-con_max_block_sig_size=108',
            '-pak=',
            '-enforce_pak=0',
            '-initialfreecoins=2100000000000000',
            '-anyonecanspendaremine=1',
            '-con_blocksubsidy=0',
            '-con_connect_genesis_outputs=1',
            '-dynamic_epoch_length=10',
            '-txindex=1',
            '-creatediscountct=0',
            '-acceptdiscountct=0',
            '-rpcbind=127.0.0.1',
            '-rpcallowip=127.0.0.1',
            '-connect=0',
            '-listenonion=0',
            '-dnsseed=0',
            '-fixedseeds=0',
            '-limitancestorsize=1000',
            '-limitdescendantsize=1000',
        ]
        self.extra_args = [list(args) for _ in range(self.num_nodes)]

    def initialize_audit_committee(self, initial_policy):
        self.committee, self.shares = simulate_keygen(self.curve, tuple(range(1, 11)), 7)
        self.identity_secrets = {member: random_scalar() for member in self.committee.members}
        return AuditConfig(0, initial_policy,
                           tuple((member, self.curve.mul(secret)[1:])
                                 for member, secret in self.identity_secrets.items()),
                           1, (AuditKey(1, 2, self.committee),))

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def skip_test_if_missing_module(self):
        if self.missing_library:
            raise SkipTest('secp256k1-zkp audit library not found; set THRESHOLD_AUDIT_SECP256K1')
        self.skip_if_no_wallet()

    def build_transaction(self, audit_key):
        sender, recipient = self.nodes
        # In this checkout explicit "bech32" requests an UNBLINDED address;
        # request blech32 for both payment and change to guarantee two targets.
        address = recipient.getnewaddress('', 'blech32')
        raw = sender.createrawtransaction([], [{address: Decimal('1.0')}])
        funded = sender.fundrawtransaction(raw, {'fee_rate': 2,
                                                'changeAddress': sender.getrawchangeaddress('blech32')})['hex']
        blinded = sender.blindrawtransaction(funded, False)
        transaction = tx_from_hex(blinded)
        current_key = bytes.fromhex(sender.getblockchaininfo()['audit_pubkey'])
        openings = wallet_openings(self.curve, transaction, self.nodes, self.chain_id, current_key, self.assets)
        for index in openings:
            statement = output_statement(transaction, index, self.chain_id, current_key, self.assets)
            packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
            assert verify_chunked(self.curve, statement, packet)
        if audit_key != current_key:
            # Only adversarial stale-key cases use the external Python prover.
            attach_recovery(self.curve, transaction, self.nodes, self.chain_id, audit_key, self.assets)
        signed = sender.signrawtransactionwithwallet(transaction.serialize().hex())
        assert signed['complete']
        transaction = tx_from_hex(signed['hex'])
        return transaction, openings, address

    def direct_block(self, transaction):
        block = from_hex(CBlock(), self.nodes[0].getnewblockhex())
        block.vtx.append(copy.deepcopy(transaction))
        add_witness_commitment(block)
        # The custom chain's policy asset is genesis-bound and intentionally
        # differs from the test framework's legacy default asset constant.
        block.vtx[0].vout[-1].nAsset.vchCommitment = b'\x01' + getattr(self, 'policy_asset', self.assets[0])
        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        return self.sign_block(block.serialize().hex())

    def sign_block(self, raw):
        block = from_hex(CBlock(), raw)
        if block.m_dynafed_params.m_current.m_signblockscript != self.initial_signblock:
            assert_equal(block.m_dynafed_params.m_current.m_signblockscript, self.replacement_script)
            block.rehash()
            signature = self.block_signer.sign_ecdsa(ser_uint256(block.sha256), low_s=True) + b'\x01'
            block.m_signblock_witness.stack = [signature, self.block_signer.get_pubkey().get_bytes()]
            return block.serialize().hex()
        return raw

    def assert_rejected_by_nodes_and_blocks(self, transaction, reason):
        raw = transaction.serialize().hex()
        for node in self.nodes:
            accepted = node.testmempoolaccept([raw], 0)[0]
            assert not accepted['allowed'], accepted
            assert_equal(accepted['reject-reason'], reason)
        block = from_hex(CBlock(), self.direct_block(transaction))
        heights = [node.getblockcount() for node in self.nodes]
        for ordinal, (node, height) in enumerate(zip(self.nodes, heights)):
            # Nodes may relay the first invalid candidate before its connection
            # failure reaches the second RPC. Give each node a unique header so
            # its direct-submit assertion observes the actual rejection reason.
            candidate = copy.deepcopy(block)
            candidate.nTime += ordinal + 1
            candidate.rehash()
            assert_equal(node.submitblock(self.sign_block(candidate.serialize().hex())), reason)
            assert_equal(node.getblockcount(), height)

    def mine_proposal(self, proposal=None):
        node = self.nodes[0]
        raw = node.getnewblockhex() if proposal is None else node.getnewblockhex(0, proposal)
        # Initial OP_TRUE needs no private signer. The replacement policy uses
        # an independent test functionary's real P2WPKH key.
        raw = self.sign_block(raw)
        assert_equal(node.submitblock(raw), None)
        self.sync_blocks()
        return node.getbestblockhash()

    def current_config(self):
        return AuditConfig.from_bytes(bytes.fromhex(self.nodes[0].getblockchaininfo()['audit_config']), self.curve)

    def proposal(self, prepared, signblock):
        return {
            'signblockscript': signblock.hex(),
            'max_block_witness': 108,
            'fedpegscript': '51',
            'extension_space': [],
            'audit_pubkey': prepared.transition.config.active_key.public_key.hex(),
            'audit_version': prepared.transition.config.active_version,
            'audit_config': prepared.transition.config.to_bytes().hex(),
            'audit_prepared': prepared_to_bytes(prepared).hex(),
        }

    def prepare_transition(self, config, share_sets, identities, signblock):
        node = self.nodes[0]
        while node.getblockcount() % 10 != 0:
            self.mine_proposal()
        previous = self.current_config()
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        config = replace(config, generation=previous.generation + 1,
                         signer_policy=policy_binding(signblock, 108, program, b'\x51', []))
        transition = Transition(previous.binding(), node.getblockcount() + 10, config)
        ready = tuple(make_readiness(self.curve, self.chain_id, transition, key.version,
                                     share, identities[share.member])
                      for key in config.keys for share in share_sets[key.version][:key.committee.threshold])
        return PreparedTransition(transition, ready)

    def activate(self, prepared, signblock):
        proposal = self.proposal(prepared, signblock)
        # The boundary block already uses the winning configuration. It must not
        # repeat the previous generation's prepared vote for another boundary.
        while self.nodes[0].getblockcount() < prepared.transition.activation_height - 1:
            self.mine_proposal(proposal)
        self.mine_proposal()
        node = self.nodes[0]
        assert_equal(self.current_config(), prepared.transition.config)
        return node.getblockcount()

    def assert_governance_rejected(self, prepared, signblock, *, config=None, certificate=None):
        """Bypass proposal RPC preflight and exercise both nodes' header checks."""
        block = from_hex(CBlock(), self.nodes[0].getnewblockhex())
        entry = DynaFedParamEntry(signblock, 108,
                                 b'\x00\x20' + hashlib.sha256(b'\x51').digest(), b'\x51', [],
                                 m_audit_pubkey=prepared.transition.config.active_key.public_key,
                                 m_audit_version=prepared.transition.config.active_version,
                                 m_audit_config=prepared.transition.config.to_bytes() if config is None else config,
                                 m_audit_prepared=prepared_to_bytes(prepared) if certificate is None else certificate)
        assert_equal(entry.m_serialize_type, 2)
        block.m_dynafed_params.m_proposed = entry
        for ordinal, node in enumerate(self.nodes):
            candidate = copy.deepcopy(block)
            candidate.nTime += 20 + ordinal
            candidate.rehash()
            result = node.submitblock(self.sign_block(candidate.serialize().hex()))
            assert_equal(result, 'invalid-audit-governance')

    def assert_bad_compact_policy_rejected(self):
        block = from_hex(CBlock(), self.nodes[0].getnewblockhex())
        assert_equal(block.m_dynafed_params.m_current.m_serialize_type, 1)
        block.m_dynafed_params.m_current.m_elided_root ^= 1
        for ordinal, node in enumerate(self.nodes):
            candidate = copy.deepcopy(block)
            candidate.nTime += 30 + ordinal
            candidate.rehash()
            assert_equal(node.submitblock(self.sign_block(candidate.serialize().hex())), 'invalid-audit-governance')

    def recover(self, transaction, index, committee, shares):
        statement = output_statement(transaction, index, self.chain_id, committee.public_key, self.assets)
        packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
        request = named('functional test disclosure')
        partials = tuple(partial_decrypt_chunked(self.curve, statement, packet, committee, share, request)
                         for share in shares[:committee.threshold])
        return combine_chunked(self.curve, statement, packet, committee, partials, request)

    def run_test(self):
        try:
            self.exercise()
        finally:
            self.curve.close()

    def exercise_block_budget(self):
        sender = self.nodes[0]
        self.log.info('Mine a pool exceeding the per-block confidential-output budget across two blocks')
        queued = set()
        current_key = bytes.fromhex(sender.getblockchaininfo()['audit_pubkey'])
        for _ in range(9):
            candidate, candidate_openings, _ = self.build_transaction(current_key)
            assert_equal(len(candidate_openings), 2)
            queued.add(sender.sendrawtransaction(candidate.serialize().hex(), 0))
        self.sync_mempools()
        assert_equal(len(queued), 9)
        template = from_hex(CBlock(), sender.getnewblockhex())
        audit_outputs = sum(output.nValue.vchCommitment[0] in (8, 9)
                            for candidate in template.vtx for output in candidate.vout)
        assert 0 < audit_outputs <= 16
        first_hash = self.mine_proposal()
        first = from_hex(CBlock(), sender.getblock(first_hash, 0))
        actual_outputs = sum(output.nValue.vchCommitment[0] in (8, 9)
                             for candidate in first.vtx for output in candidate.vout)
        assert 0 < actual_outputs <= 16
        remaining = queued.intersection(sender.getrawmempool())
        assert 0 < len(remaining) < len(queued)
        self.mine_proposal()
        assert_equal(queued.intersection(sender.getrawmempool()), set())
        for txid in queued:
            assert sender.getrawtransaction(txid, True)['confirmations'] >= 1

    def exercise_native_wallet(self):
        sender, recipient = self.nodes
        self.log.info('Native sendtoaddress generates recovery proofs and budgets their fees')
        txid = sender.sendtoaddress(recipient.getnewaddress('', 'blech32'), Decimal('0.25'), fee_rate=2)
        self.sync_mempools()
        transaction = tx_from_hex(sender.getrawtransaction(txid))
        key = bytes.fromhex(sender.getblockchaininfo()['audit_pubkey'])
        openings = wallet_openings(self.curve, transaction, self.nodes, self.chain_id, key, self.assets)
        for index in openings:
            statement = output_statement(transaction, index, self.chain_id, key, self.assets)
            packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
            assert verify_chunked(self.curve, statement, packet)
        self.mine_proposal()

        self.log.info('Native single-owner PSET blinding, signing, merge, and extraction preserve recovery proofs')
        address = recipient.getnewaddress('', 'blech32')
        created = sender.walletcreatefundedpsbt([], [{address: Decimal('0.5')}], 0,
                                               {'fee_rate': 2, 'changeAddress': sender.getrawchangeaddress('blech32')})
        processed = sender.walletprocesspsbt(created['psbt'], True, 'ALL', True, False)
        merged = sender.combinepsbt([processed['psbt'], processed['psbt']])
        final = sender.finalizepsbt(merged)
        assert final['complete']
        transaction = tx_from_hex(final['hex'])
        openings = wallet_openings(self.curve, transaction, self.nodes, self.chain_id, key, self.assets)
        for index in openings:
            statement = output_statement(transaction, index, self.chain_id, key, self.assets)
            packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
            assert verify_chunked(self.curve, statement, packet)

        # Independent generic PSET map decoding preserves every field while
        # mutating one packet. Finalization must not emit an invalid complete tx.
        stream = BytesIO(base64.b64decode(merged))
        magic = stream.read(5)
        global_map = PSBTMap()
        global_map.deserialize(stream)
        n_inputs = deser_compact_size(BytesIO(global_map.map[4]))
        n_outputs = deser_compact_size(BytesIO(global_map.map[5]))
        maps = [global_map]
        for _ in range(n_inputs + n_outputs):
            row = PSBTMap()
            row.deserialize(stream)
            maps.append(row)
        assert_equal(stream.read(), b'')
        audit_key = b'\xfc\x0fthreshold-audit\x01'
        output_map = next(row for row in maps[1 + n_inputs:] if audit_key in row.map)
        proof = output_map.map[audit_key]
        output_map.map[audit_key] = proof[:-1] + bytes([proof[-1] ^ 1])
        tampered = base64.b64encode(magic + b''.join(row.serialize() for row in maps)).decode()
        assert_raises_rpc_error(-26, 'audit', sender.finalizepsbt, tampered)
        sender.sendrawtransaction(final['hex'], 0)
        self.sync_mempools()
        self.mine_proposal()

    def exercise(self):
        sender, recipient = self.nodes
        util.node_fastmerkle = sender
        self.chain_id = bytes.fromhex(sender.getblockhash(0))[::-1]
        self.assets = tuple(sorted(bytes.fromhex(asset)[::-1]
                                   for asset in sender.getblockchaininfo()['audit_assets']))
        assert_equal(len(self.assets), 1)
        assert_equal(sender.getblockchaininfo()['audit_pubkey'], self.committee.public_key.hex())
        assert_equal(sender.getblockchaininfo()['audit_version'], 1)
        assert_equal(self.current_config(), self.genesis_config)
        self.log.info('Wrong-network snapshot inspection must not mutate active serialization flags')
        snapshot = Path(self.options.tmpdir) / 'wrong-network-snapshot.dat'
        snapshot.write_bytes(b'utxo\xff' + (2).to_bytes(2, 'little')
                             + bytes.fromhex('f9beb4d9') + bytes(32) + bytes(8))
        assert_raises_rpc_error(-22, 'The network of the snapshot (main) does not match',
                               sender.loadtxoutset, str(snapshot))
        assert_equal(sender.getblockchaininfo()['audit_pubkey'], self.committee.public_key.hex())
        assert_equal(sender.getblockchaininfo()['audit_version'], 1)
        self.initial_signblock = bytes.fromhex(sender.decodescript('51')['segwit']['hex'])
        self.generatetoaddress(sender, 101, sender.getnewaddress())

        self.log.info('Generate a wallet transaction with native full-opening TAC2 witnesses')
        transaction, openings, recipient_address = self.build_transaction(self.committee.public_key)
        assert len(openings) >= 2
        for node in self.nodes:
            result = node.testmempoolaccept([transaction.serialize().hex()], 0)[0]
            assert result['allowed'], result
        index = min(openings)

        self.log.info('Reject opt-outs and tampering in mempool and direct block validation')
        missing = copy.deepcopy(transaction)
        missing.wit.vtxoutwit[index].vchAuditProof = b''
        self.assert_rejected_by_nodes_and_blocks(missing, 'bad-threshold-audit-missing-proof')
        malformed = copy.deepcopy(transaction)
        proof = malformed.wit.vtxoutwit[index].vchAuditProof
        malformed.wit.vtxoutwit[index].vchAuditProof = proof[:-1] + bytes([proof[-1] ^ 1])
        self.assert_rejected_by_nodes_and_blocks(malformed, 'bad-threshold-audit-proof')
        false_opening = copy.deepcopy(transaction)
        opening = openings[index]
        false = Opening(opening.asset, opening.amount + 1, opening.asset_blinder, opening.value_blinder)
        statement = output_statement(transaction, index, self.chain_id, self.committee.public_key, self.assets)
        false_opening.wit.vtxoutwit[index].vchAuditProof = _encrypt_unchecked(self.curve, statement, false).to_bytes()
        self.assert_rejected_by_nodes_and_blocks(false_opening, 'bad-threshold-audit-proof')
        changed = copy.deepcopy(transaction)
        changed.nLockTime += 1
        changed.rehash()
        self.assert_rejected_by_nodes_and_blocks(changed, 'bad-threshold-audit-proof')
        fee_index = next(i for i, output in enumerate(transaction.vout) if len(output.scriptPubKey) == 0)
        unexpected = copy.deepcopy(transaction)
        unexpected.wit.vtxoutwit[fee_index].vchAuditProof = proof
        self.assert_rejected_by_nodes_and_blocks(unexpected, 'bad-threshold-audit-unexpected-proof')

        self.log.info('Confirm the valid transaction and verify witness propagation and recipient access')
        txid = sender.sendrawtransaction(transaction.serialize().hex(), 0)
        self.sync_mempools()
        confirmed_block = self.mine_proposal()
        self.log.info('Compact headers must authenticate the omitted audit policy exactly')
        self.assert_bad_compact_policy_rejected()
        for node in self.nodes:
            confirmed = tx_from_hex(node.getrawtransaction(txid))
            assert_equal(confirmed.wit.vtxoutwit[index].vchAuditProof, proof)
        received = tx_from_hex(recipient.unblindrawtransaction(transaction.serialize().hex())['hex'])
        recipient_script = bytes.fromhex(recipient.getaddressinfo(recipient_address)['scriptPubKey'])
        destination_index = next(i for i, output in enumerate(received.vout) if bytes(output.scriptPubKey) == recipient_script)
        assert_equal(received.vout[destination_index].nValue.getAmount(), 100_000_000)
        assert_equal(self.recover(transaction, index, self.committee, self.shares), openings[index])

        self.log.info('Rotate actual block-signing policy and hand audit shares to a new 11-of-15 committee')
        replacement_script = self.replacement_script
        handed, handed_shares = simulate_handoff(self.curve, self.committee, self.shares[:7], tuple(range(101, 116)), 11)
        handed_identities = {member: random_scalar() for member in handed.members}
        handed_config = AuditConfig(1, bytes(32),
                                   tuple((member, self.curve.mul(secret)[1:])
                                         for member, secret in handed_identities.items()),
                                   1, (AuditKey(1, 2, handed),))
        handoff = self.prepare_transition(handed_config, {1: handed_shares}, handed_identities, replacement_script)
        self.log.info('Require valid incoming share readiness and transition bindings before voting')
        self.assert_governance_rejected(handoff, replacement_script, certificate=b'')
        self.assert_governance_rejected(replace(handoff, readiness=handoff.readiness[:-1]), replacement_script)
        corrupted = handoff.readiness[0]
        corrupted = replace(corrupted, signature=bytes([corrupted.signature[0] ^ 1]) + corrupted.signature[1:])
        self.assert_governance_rejected(replace(handoff, readiness=(corrupted,) + handoff.readiness[1:]), replacement_script)
        self.assert_governance_rejected(replace(handoff, transition=replace(handoff.transition,
                                                                          activation_height=handoff.transition.activation_height + 10)),
                                        replacement_script)
        self.assert_governance_rejected(replace(handoff, transition=replace(handoff.transition, previous=bytes(32))), replacement_script)
        self.activate(handoff, replacement_script)
        assert_equal(sender.getblockchaininfo()['current_signblock_hex'], replacement_script.hex())
        assert_equal(sender.getblockchaininfo()['audit_pubkey'], self.committee.public_key.hex())
        assert_equal(self.recover(transaction, index, handed, handed_shares), openings[index])

        assert_equal(recipient.getblock(confirmed_block)['confirmations'] > 0, True)

        self.log.info('Roll audit public key, reject stale new outputs, and preserve historical recovery')
        pending_old, _, _ = self.build_transaction(self.committee.public_key)
        fresh, fresh_shares = simulate_keygen(self.curve, handed.members, 11)
        rolled_config = replace(self.current_config(), active_version=2,
                                keys=self.current_config().keys + (AuditKey(2, 2, fresh),))
        rollover = self.prepare_transition(rolled_config, {1: handed_shares, 2: fresh_shares}, handed_identities, replacement_script)
        self.log.info('A fresh active key must not bypass readiness for retained historical keys')
        fresh_only = replace(rollover, readiness=tuple(entry for entry in rollover.readiness if entry.version == 2))
        self.assert_governance_rejected(fresh_only, replacement_script)
        rollover_height = self.activate(rollover, replacement_script)
        assert_equal(sender.getblockchaininfo()['audit_pubkey'], fresh.public_key.hex())
        assert_equal(sender.getblockchaininfo()['audit_version'], 2)
        self.assert_rejected_by_nodes_and_blocks(pending_old, 'bad-threshold-audit-proof')
        pending_new, _, _ = self.build_transaction(fresh.public_key)
        for node in self.nodes:
            accepted = node.testmempoolaccept([pending_new.serialize().hex()], 0)[0]
            assert accepted['allowed'], accepted
        assert_equal(self.recover(transaction, index, handed, handed_shares), openings[index])

        self.log.info('Restart both daemons and retain the authenticated historical-key registry')
        self.restart_node(0)
        self.restart_node(1)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(self.current_config(), rollover.transition.config)
        assert_equal(len(self.current_config().keys), 2)
        pending_new, new_openings, _ = self.build_transaction(fresh.public_key)
        new_index = min(new_openings)
        assert_equal(self.recover(pending_new, new_index, fresh, fresh_shares), new_openings[new_index])

        self.log.info('Reorg the rollover and verify native public-policy rollback on both nodes')
        rollback_start = sender.getblockhash(rollover_height - 3)
        for node in self.nodes:
            node.invalidateblock(rollback_start)
        self.sync_blocks()
        assert_equal(sender.getblockchaininfo()['audit_version'], 1)
        assert_equal(sender.getblockchaininfo()['audit_pubkey'], self.committee.public_key.hex())
        for node in self.nodes:
            restored = node.testmempoolaccept([pending_old.serialize().hex()], 0)[0]
            assert restored['allowed'], restored
            stale = node.testmempoolaccept([pending_new.serialize().hex()], 0)[0]
            assert not stale['allowed'], stale
            assert_equal(stale['reject-reason'], 'bad-threshold-audit-proof')
        assert_equal(self.recover(transaction, index, handed, handed_shares), openings[index])
        self.exercise_block_budget()
        self.exercise_native_wallet()


if __name__ == '__main__':
    ThresholdAuditTest(__file__).main()
