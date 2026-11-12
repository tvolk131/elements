#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Versioned recovery registries, native issued assets, history and rollback.

EUR/USD labels are test fixtures. Consensus authenticates asset registration;
this does not attest to fiat reserves, issuer identity or redemption rights.
"""

import copy
from dataclasses import replace
from decimal import Decimal
import hashlib

from feature_threshold_audit import ThresholdAuditTest, named
from test_framework import util
from test_framework.messages import CBlock, from_hex, tx_from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error

from chunked import ChunkPacket, verify_chunked
from governance import PreparedTransition, Transition, make_readiness
from native_governance import policy_binding
from native_transactions import output_statement, wallet_openings


class ThresholdAuditAssetsTest(ThresholdAuditTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        super().run_test()

    def proposal(self, prepared, signblock):
        proposal = super().proposal(prepared, signblock)
        assets, version = self.registration_target
        proposal.update(audit_assets=[asset[::-1].hex() for asset in assets], audit_assets_version=version)
        return proposal

    def registry_transition(self, assets, version):
        node = self.nodes[0]
        while node.getblockcount() % 10:
            self.mine_proposal()
        previous = self.current_config()
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        config = replace(previous, generation=previous.generation + 1,
                         signer_policy=policy_binding(self.initial_signblock, 108, program, b'\x51', [],
                                                      audit_assets=assets, audit_assets_version=version))
        transition = Transition(previous.binding(), node.getblockcount() + 10, config)
        ready = tuple(make_readiness(self.curve, self.chain_id, transition, 1, share,
                                     self.identity_secrets[share.member]) for share in self.shares[:7])
        self.registration_target = assets, version
        return PreparedTransition(transition, ready)

    def explicit_issue(self, currency):
        """Bootstrap with a witnessed explicit input before its asset ID is approved."""
        sender = self.nodes[0]
        address = sender.getnewaddress('', 'bech32')
        seed = sender.sendtoaddress(address, Decimal('10'), fee_rate=2)
        self.sync_mempools()
        self.mine_proposal()
        coin = next(coin for coin in sender.listunspent() if coin['txid'] == seed and coin['address'] == address)
        raw = sender.createrawtransaction([{'txid': seed, 'vout': coin['vout']}], [{address: Decimal('9')}])
        funded = sender.fundrawtransaction(raw, {'fee_rate': 2,
                                                'changeAddress': sender.getrawchangeaddress('bech32')})['hex']
        issued = sender.rawissueasset(funded, [{'asset_amount': 1000, 'asset_address': address,
                                               'token_amount': 1, 'token_address': address,
                                               'blind': False, 'contract_hash': named('sandbox ' + currency).hex()}])[0]
        signed = sender.signrawtransactionwithwallet(issued['hex'])
        assert signed['complete']
        txid = sender.sendrawtransaction(signed['hex'], 0)
        self.sync_mempools()
        self.mine_proposal()
        transaction = tx_from_hex(sender.getrawtransaction(txid))
        assert all(not witness.vchAuditProof for witness in transaction.wit.vtxoutwit)
        return issued

    def reject_registry(self, valid_proposal, assets, version):
        """Mutate a readiness-certified proposal directly, bypassing RPC defaults."""
        block = from_hex(CBlock(), self.nodes[0].getnewblockhex(0, valid_proposal))
        block.m_dynafed_params.m_proposed.m_audit_assets = [int.from_bytes(asset, 'little') for asset in assets]
        block.m_dynafed_params.m_proposed.m_audit_assets_version = version
        for ordinal, node in enumerate(self.nodes):
            candidate = copy.deepcopy(block)
            candidate.nTime += 100 + ordinal
            candidate.rehash()
            assert_equal(node.submitblock(self.sign_block(candidate.serialize().hex())), 'invalid-audit-governance')

    def verify_native(self, transaction, assets):
        openings = wallet_openings(self.curve, transaction, self.nodes, self.chain_id,
                                   self.committee.public_key, assets)
        for index in openings:
            statement = output_statement(transaction, index, self.chain_id, self.committee.public_key, assets)
            packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof, statement, self.curve)
            assert verify_chunked(self.curve, statement, packet)
        return openings

    def exercise(self):
        sender, recipient = self.nodes
        util.node_fastmerkle = sender
        self.chain_id = bytes.fromhex(sender.getblockhash(0))[::-1]
        self.assets = tuple(bytes.fromhex(asset)[::-1] for asset in sender.getblockchaininfo()['audit_assets'])
        initial_assets = self.assets
        self.policy_asset = self.assets[0]
        self.initial_signblock = bytes.fromhex(sender.decodescript('51')['segwit']['hex'])
        assert_equal(sender.getblockchaininfo()['audit_assets_version'], 0)
        self.generatetoaddress(sender, 101, sender.getnewaddress())

        self.log.info('Confirm a creation-registry proof before new currency registration')
        historical, historical_openings, _ = self.build_transaction(self.committee.public_key)
        historical_id = sender.sendrawtransaction(historical.serialize().hex(), 0)
        self.sync_mempools()
        historical_block = self.mine_proposal()

        self.log.info('Bootstrap explicit EUR/USD and reissuance token IDs without confidential opt-outs')
        issued = {currency: self.explicit_issue(currency) for currency in ('EUR', 'USD')}
        for currency in issued.values():
            assert_raises_rpc_error(-6, 'Unable to blind', sender.sendtoaddress, recipient.getnewaddress('', 'blech32'),
                                    Decimal('1'), assetlabel=currency['asset'], fee_rate=2)
        approved = tuple(sorted(set(initial_assets).union(bytes.fromhex(record[field])[::-1]
                                                        for record in issued.values() for field in ('asset', 'token'))))
        assert_equal(len(approved), 5)
        prepared = self.registry_transition(approved, 1)
        valid_proposal = self.proposal(prepared, self.initial_signblock)
        self.reject_registry(valid_proposal, tuple(reversed(approved)), 1)
        self.reject_registry(valid_proposal, approved + (approved[-1],), 1)
        self.reject_registry(valid_proposal, approved, 0)
        self.reject_registry(valid_proposal, approved, 2)
        self.reject_registry(valid_proposal, tuple(asset for asset in approved if asset != self.policy_asset), 1)
        # Readiness for this exact registry cannot authorize a different valid superset.
        substituted = tuple(sorted(approved + (named('uncertified extra asset'),)))
        self.reject_registry(valid_proposal, substituted, 1)
        self.reject_registry(valid_proposal, approved, 0xffffffff)
        self.reject_registry(valid_proposal, (), 1)
        self.reject_registry(valid_proposal, tuple(sorted(approved + (bytes(32),))), 1)
        assert_raises_rpc_error(-8, '1 to 256', sender.getnewblockhex, 0,
                                dict(valid_proposal, audit_assets=[approved[0][::-1].hex()] * 257))
        assert_raises_rpc_error(-8, 'uint32', sender.getnewblockhex, 0,
                                dict(valid_proposal, audit_assets_version=0x100000000))

        self.log.info('Evict old-registry mempool outputs at the next-block activation boundary')
        while sender.getblockcount() < prepared.transition.activation_height - 2:
            self.mine_proposal(valid_proposal)
        pending, _, _ = self.build_transaction(self.committee.public_key)
        pending_id = sender.sendrawtransaction(pending.serialize().hex(), 0)
        self.sync_mempools()
        # Keep the last old-registry block empty so eviction is observable.
        boundary_vote = from_hex(CBlock(), sender.getnewblockhex(3600, valid_proposal))
        assert_equal(len(boundary_vote.vtx), 1)
        assert_equal(sender.submitblock(self.sign_block(boundary_vote.serialize().hex())), None)
        self.sync_blocks()
        for node in self.nodes:
            assert pending_id not in node.getrawmempool()
            assert_equal(node.getblockchaininfo()['audit_assets_version'], 1)
        self.assets = approved
        self.assert_rejected_by_nodes_and_blocks(pending, 'bad-threshold-audit-proof')
        activation_hash = self.mine_proposal()
        assert_equal(self.current_config(), prepared.transition.config)
        assert_equal(sender.getblock(activation_hash)['dynamic_parameters']['current']['audit_assets_version'], 1)

        self.log.info('Reject registry deletion, duplicate IDs, reordering and skipped versions after activation')
        unchanged = self.registry_transition(approved, 1)
        unchanged_proposal = self.proposal(unchanged, self.initial_signblock)
        self.reject_registry(unchanged_proposal, initial_assets, 2)
        self.reject_registry(unchanged_proposal, tuple(reversed(approved)), 1)
        self.reject_registry(unchanged_proposal, approved + (approved[-1],), 2)
        self.reject_registry(unchanged_proposal, approved, 2)

        self.log.info('Native wallet and PSET construct proofs under the registered EUR/USD policy')
        self.exercise_native_wallet()
        for record in issued.values():
            txid = sender.sendtoaddress(recipient.getnewaddress('', 'blech32'), Decimal('2'),
                                       assetlabel=record['asset'], fee_rate=2)
            self.sync_mempools()
            self.verify_native(tx_from_hex(sender.getrawtransaction(txid)), approved)
            self.mine_proposal()

        self.log.info('Historical proof remains recoverable under its creation registry and survives full revalidation')
        index = min(historical_openings)
        self.assets = initial_assets
        assert_equal(self.recover(historical, index, self.committee, self.shares), historical_openings[index])
        self.assets = approved
        assert_equal(sender.getrawtransaction(historical_id, True)['blockhash'], historical_block)
        for node in self.nodes:
            assert node.verifychain(4, 0)

        self.log.info('Rollback selects the old next-block registry; old proof can enter a new old-policy block')
        boundary_vote_hash = sender.getblockhash(prepared.transition.activation_height - 1)
        for node in self.nodes:
            node.invalidateblock(boundary_vote_hash)
            assert_equal(node.getblockchaininfo()['audit_assets_version'], 0)
            assert_equal(node.getblockchaininfo()['audit_assets'], [self.policy_asset[::-1].hex()])
            assert node.testmempoolaccept([pending.serialize().hex()], 0)[0]['allowed']
        for node in self.nodes:
            node.reconsiderblock(boundary_vote_hash)
        self.sync_blocks()
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()['audit_assets_version'], 1)
            assert not node.testmempoolaccept([pending.serialize().hex()], 0)[0]['allowed']
            assert node.verifychain(4, 0)


if __name__ == '__main__':
    ThresholdAuditAssetsTest(__file__).main()
