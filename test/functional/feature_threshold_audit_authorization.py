#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Consensus-enforced federation authorization of every transaction.

A DynaFed proposal names a quorum of BIP340 authorizer keys. From its
activation, both nodes reject any non-coinbase transaction, in the mempool or
in a block, that lacks an unexpired quorum authorization over its template.
"""

import copy
from dataclasses import replace
import hashlib

from feature_threshold_audit import ThresholdAuditTest
from test_framework import util
from test_framework.blocktools import add_witness_commitment
from test_framework.messages import CBlock, from_hex, tx_from_hex
from test_framework.util import assert_equal, assert_raises_rpc_error

from curve import random_scalar
from governance import PreparedTransition, Transition, make_readiness
from native_governance import policy_binding, prepared_to_bytes
from settlement.authorization import MAX_LIFETIME as LIFETIME, authorization_digest, decode_policy, encode


class TransactionAuthorizationTest(ThresholdAuditTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        super().run_test()

    def policy(self, secrets, threshold):
        return bytes([threshold]) + b''.join(self.curve.mul(secret)[1:] for secret in secrets)

    def prepare_authorization(self, policy):
        """A policy-only transition whose audit configuration binds `policy`."""
        node = self.nodes[0]
        while node.getblockcount() % 10 != 0:
            self.mine_proposal()
        previous = self.current_config()
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        config = replace(previous, generation=previous.generation + 1,
                         signer_policy=policy_binding(self.initial_signblock, 108, program, b'\x51', [],
                                                      tx_authorization=policy))
        transition = Transition(previous.binding(), node.getblockcount() + 10, config)
        ready = tuple(make_readiness(self.curve, self.chain_id, transition, key.version, share,
                                     self.identity_secrets[share.member])
                      for key in config.keys for share in self.shares[:key.committee.threshold])
        return PreparedTransition(transition, ready)

    def install(self, policy):
        prepared = self.prepare_authorization(policy)
        proposal = dict(self.proposal(prepared, self.initial_signblock), tx_authorization=policy.hex())
        while self.nodes[0].getblockcount() < prepared.transition.activation_height - 1:
            self.mine_proposal(proposal)
        self.mine_proposal()
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()['tx_authorization'], policy.hex())

    def authorize(self, transaction, secrets, policy, *, expiry=None, signers=None):
        """Return a copy carrying signatures from `signers` (indexes into the policy)."""
        node = self.nodes[0]
        threshold, _ = decode_policy(policy)
        expiry = node.getblockcount() + 5 if expiry is None else expiry
        signers = range(threshold) if signers is None else signers
        digest = authorization_digest(node.getblockhash(0), policy, transaction, expiry)
        result = copy.deepcopy(transaction)
        result.wit.vchAuthorization = encode(expiry, {index: self.curve.sign(secrets[index], digest) for index in signers})
        return result

    def assert_accepted(self, transaction):
        for node in self.nodes:
            result = node.testmempoolaccept([transaction.serialize().hex()], 0)[0]
            assert result['allowed'], result

    def exercise(self):
        sender, recipient = self.nodes
        util.node_fastmerkle = sender
        self.chain_id = bytes.fromhex(sender.getblockhash(0))[::-1]
        self.assets = tuple(sorted(bytes.fromhex(asset)[::-1] for asset in sender.getblockchaininfo()['audit_assets']))
        self.initial_signblock = bytes.fromhex(sender.decodescript('51')['segwit']['hex'])
        self.generatetoaddress(sender, 101, sender.getnewaddress())
        audit_key = self.committee.public_key
        secrets = [random_scalar() for _ in range(3)]
        policy = self.policy(secrets, 2)

        self.log.info('Before any policy is set, transactions need no authorization and may not carry one')
        assert_equal(sender.getblockchaininfo()['tx_authorization'], '')
        plain, _, _ = self.build_transaction(audit_key)
        self.assert_accepted(plain)
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, secrets, policy), 'bad-tx-authorization-unexpected')

        self.log.info('Proposal preflight rejects malformed authorizer sets')
        template = self.proposal(self.prepare_authorization(policy), self.initial_signblock)
        for bad in (b'\x04' + policy[1:], policy[:33] + policy[1:33], policy[:-1], b'\x01' + bytes(32)):
            assert_raises_rpc_error(-8, 'tx_authorization must be', sender.getnewblockhex, 0,
                                    dict(template, tx_authorization=bad.hex()))

        self.log.info('Activate a 2-of-3 authorizer quorum through DynaFed')
        self.install(policy)

        self.log.info('Unauthorized transactions are refused by the mempool and by blocks')
        self.assert_rejected_by_nodes_and_blocks(plain, 'bad-tx-authorization-missing')

        self.log.info('Only a correctly encoded, unexpired quorum over this exact transaction is accepted')
        height = sender.getblockcount()
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, secrets, policy, signers=[0]),
                                                 'bad-tx-authorization-malformed')
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, secrets, policy, signers=[0, 1, 2]),
                                                 'bad-tx-authorization-malformed')
        outsider = [random_scalar(), secrets[1], secrets[2]]
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, outsider, policy), 'bad-tx-authorization-signature')
        swapped = self.authorize(plain, secrets, policy)
        body = swapped.wit.vchAuthorization
        swapped.wit.vchAuthorization = body[:4] + body[69:134] + body[4:69]
        self.assert_rejected_by_nodes_and_blocks(swapped, 'bad-tx-authorization-malformed')
        extended = self.authorize(plain, secrets, policy, expiry=height + 5)
        extended.wit.vchAuthorization = (height + 6).to_bytes(4, 'little') + extended.wit.vchAuthorization[4:]
        self.assert_rejected_by_nodes_and_blocks(extended, 'bad-tx-authorization-signature')
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, secrets, policy, expiry=height),
                                                 'bad-tx-authorization-expired')

        self.log.info('Consensus caps how long an authorization stays usable, whatever the quorum signs')
        # The next block is height + 1, so expiry height + LIFETIME is the last
        # usable one and one more is refused as premature, not invalid forever.
        self.assert_accepted(self.authorize(plain, secrets, policy, expiry=height + LIFETIME))
        distant = self.authorize(plain, secrets, policy, expiry=height + LIFETIME + 1)
        self.assert_rejected_by_nodes_and_blocks(distant, 'bad-tx-authorization-lifetime')
        self.assert_rejected_by_nodes_and_blocks(self.authorize(plain, secrets, policy, expiry=0xffffffff),
                                                 'bad-tx-authorization-lifetime')
        self.mine_proposal()
        self.assert_accepted(distant)
        other, _, _ = self.build_transaction(audit_key)
        borrowed = copy.deepcopy(other)
        borrowed.wit.vchAuthorization = self.authorize(plain, secrets, policy).wit.vchAuthorization
        self.assert_rejected_by_nodes_and_blocks(borrowed, 'bad-tx-authorization-signature')
        coinbase = from_hex(CBlock(), sender.getnewblockhex())
        coinbase.vtx[0].wit.vchAuthorization = self.authorize(plain, secrets, policy).wit.vchAuthorization
        add_witness_commitment(coinbase)
        coinbase.vtx[0].vout[-1].nAsset.vchCommitment = b'\x01' + self.assets[0]
        coinbase.vtx[0].rehash()
        coinbase.hashMerkleRoot = coinbase.calc_merkle_root()
        coinbase.rehash()
        assert_equal(sender.submitblock(coinbase.serialize().hex()), 'bad-tx-authorization-unexpected')

        self.log.info('Any two of the three authorizers suffice, and the authorization relays and confirms')
        authorized = self.authorize(plain, secrets, policy, signers=[0, 2])
        self.assert_accepted(authorized)
        txid = sender.sendrawtransaction(authorized.serialize().hex(), 0)
        self.sync_mempools()
        self.mine_proposal()
        for node in self.nodes:
            confirmed = node.getrawtransaction(txid, True)
            assert confirmed['confirmations'] >= 1
            assert_equal(tx_from_hex(confirmed['hex']).wit.vchAuthorization, authorized.wit.vchAuthorization)

        self.log.info('An authorization that expires while waiting leaves the mempool')
        waiting, _, _ = self.build_transaction(audit_key)
        waiting = self.authorize(waiting, secrets, policy, expiry=sender.getblockcount() + 1)
        waiting_id = sender.sendrawtransaction(waiting.serialize().hex(), 0)
        self.sync_mempools()
        raw = sender.getnewblockhex(1_000_000)
        assert_equal(len(from_hex(CBlock(), raw).vtx), 1)
        assert_equal(sender.submitblock(self.sign_block(raw)), None)
        self.sync_blocks()
        for node in self.nodes:
            assert waiting_id not in node.getrawmempool()
            result = node.testmempoolaccept([waiting.serialize().hex()], 0)[0]
            assert_equal(result['reject-reason'], 'bad-tx-authorization-expired')
        self.log.info('The same transaction can simply be authorized again')
        self.assert_accepted(self.authorize(waiting, secrets, policy))

        self.log.info('A policy can be re-keyed but never cleared')
        successor_secrets = [random_scalar(), random_scalar()]
        successor = self.policy(successor_secrets, 2)
        # Proposal RPCs always carry the current policy forward, so build the
        # header by hand with an audit configuration that binds an empty one.
        kept = self.prepare_authorization(policy)
        block = from_hex(CBlock(), sender.getnewblockhex(0, self.proposal(kept, self.initial_signblock)))
        entry = block.m_dynafed_params.m_proposed
        assert_equal(entry.m_tx_authorization, policy)
        cleared = self.prepare_authorization(b'')
        entry.m_audit_config = cleared.transition.config.to_bytes()
        entry.m_audit_prepared = prepared_to_bytes(cleared)
        entry.m_tx_authorization = b''
        block.rehash()
        assert_equal(sender.submitblock(self.sign_block(block.serialize().hex())), 'invalid-tx-authorization-policy')
        # Prepare first: it mines to the epoch start, and the pending
        # authorization must outlive the boundary to show re-keying kills it.
        prepared = self.prepare_authorization(successor)
        pending = self.authorize(waiting, secrets, policy, expiry=sender.getblockcount() + LIFETIME)
        pending_id = sender.sendrawtransaction(pending.serialize().hex(), 0)
        self.sync_mempools()
        proposal = dict(self.proposal(prepared, self.initial_signblock), tx_authorization=successor.hex())
        while sender.getblockcount() < prepared.transition.activation_height - 1:
            raw = sender.getnewblockhex(1_000_000, proposal)
            assert_equal(sender.submitblock(self.sign_block(raw)), None)
        self.sync_blocks()

        self.log.info('Authorizations under the outgoing keys die at the boundary')
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()['tx_authorization'], successor.hex())
            assert pending_id not in node.getrawmempool()
            result = node.testmempoolaccept([pending.serialize().hex()], 0)[0]
            assert_equal(result['reject-reason'], 'bad-tx-authorization-signature')
        reissued = self.authorize(waiting, successor_secrets, successor)
        txid = sender.sendrawtransaction(reissued.serialize().hex(), 0)
        self.sync_mempools()
        self.mine_proposal()
        assert recipient.getrawtransaction(txid, True)['confirmations'] >= 1

        self.log.info('Restarted nodes keep enforcing the active policy')
        self.restart_node(0)
        self.restart_node(1)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        late, _, _ = self.build_transaction(audit_key)
        self.assert_rejected_by_nodes_and_blocks(late, 'bad-tx-authorization-missing')
        self.assert_accepted(self.authorize(late, successor_secrets, successor))


if __name__ == '__main__':
    TransactionAuthorizationTest(__file__).main()
