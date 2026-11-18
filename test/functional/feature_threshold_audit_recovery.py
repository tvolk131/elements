#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Federation recovery: quarantine an output without its owner, then restore it.

The authorizer quorum may sign a recovery authorization, in its own signature
domain, naming inputs whose owner signatures are waived. A recovery that takes
ordinary funds may pay only into quarantine, a burn or the fee; a quarantine
output can be spent only by another recovery, which may pay anywhere. A spend
the thief signed and had authorized beforehand then fails on every node.
"""

import copy
from decimal import Decimal

from feature_threshold_audit_authorization import TransactionAuthorizationTest
from test_framework.messages import CBlock, from_hex, tx_from_hex
from test_framework.util import assert_equal

from curve import random_scalar
from settlement.authorization import (MAX_LIFETIME as LIFETIME, authorization_digest, encode, encode_recovery,
                                      quarantine_script, recovery_bitmap, recovery_digest)

COIN = 100_000_000
FEE = Decimal('0.01')


def blinder(value):
    """RPC hex for a blinding factor (uint256 display order)."""
    return value.to_bytes(32, 'big')[::-1].hex()


class RecoveryTest(TransactionAuthorizationTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        super().run_test()

    def recovery(self, transaction, secrets, policy, inputs, *, expiry=None, domain='recovery'):
        node = self.nodes[0]
        expiry = node.getblockcount() + 5 if expiry is None else expiry
        bitmap = recovery_bitmap(inputs) if isinstance(inputs, (list, tuple)) else inputs
        if domain == 'recovery':
            digest = recovery_digest(node.getblockhash(0), policy, transaction, bitmap, expiry)
        else:
            digest = authorization_digest(node.getblockhash(0), policy, transaction, expiry)
        result = copy.deepcopy(transaction)
        result.wit.vchAuthorization = encode_recovery(bitmap, expiry, {i: self.curve.sign(secrets[i], digest)
                                                                       for i in range(policy[0])})
        return result

    def send(self, transaction):
        txid = self.nodes[0].sendrawtransaction(transaction.serialize().hex(), 0)
        self.sync_mempools()
        self.mine_proposal()
        for node in self.nodes:
            assert node.getrawtransaction(txid, True)['confirmations'] >= 1
        return txid

    def fee_coin(self, secrets, policy):
        """A small explicit policy-asset coin the federation spends to pay fees."""
        sender = self.nodes[0]
        address = sender.getnewaddress('', 'bech32')  # unblinded in this checkout
        raw = sender.createrawtransaction([], [{address: FEE}])
        funded = sender.fundrawtransaction(raw, {'fee_rate': 2, 'changeAddress': sender.getrawchangeaddress('blech32')})['hex']
        signed = sender.signrawtransactionwithwallet(sender.blindrawtransaction(funded, False))['hex']
        transaction = self.authorize(tx_from_hex(signed), secrets, policy)
        txid = self.send(transaction)
        script = sender.getaddressinfo(address)['scriptPubKey']
        vout = next(i for i, out in enumerate(transaction.vout) if bytes(out.scriptPubKey).hex() == script)
        return {'txid': txid, 'vout': vout}

    def build_recovery(self, coin, opening, fee, destination_script=None, nonce_address=None):
        """Move `coin` (opened by the operators) to quarantine or a destination, paying `fee`."""
        sender = self.nodes[0]
        asset = opening.asset[::-1].hex()
        amount = Decimal(opening.amount) / COIN
        nonce_address = nonce_address or sender.getnewaddress('', 'blech32')
        raw = sender.createrawtransaction([coin, fee], [{nonce_address: amount, 'asset': asset}, {'fee': FEE}])
        transaction = tx_from_hex(raw)
        if destination_script is not None:
            transaction.vout[0].scriptPubKey = destination_script
        policy_asset = sender.getblockchaininfo()['audit_assets'][0]
        blinded = sender.rawblindrawtransaction(transaction.serialize().hex(),
                                                [blinder(opening.value_blinder), '00' * 32], [amount, FEE],
                                                [asset, policy_asset], [blinder(opening.asset_blinder), '00' * 32])
        # The wallet signs only the federation's fee input; the recovered
        # input carries no owner signature at all.
        signed = sender.signrawtransactionwithwallet(blinded)
        assert not signed['complete']
        return tx_from_hex(signed['hex'])

    def assert_mempool_rejected(self, transaction, reason):
        for node in self.nodes:
            result = node.testmempoolaccept([transaction.serialize().hex()], 0)[0]
            assert not result['allowed'], result
            assert result['reject-reason'].startswith(reason), result

    def assert_spent_everywhere(self, transaction):
        """Both nodes refuse it in the mempool and in a block: its coin is gone."""
        self.assert_mempool_rejected(transaction, 'missing-inputs')
        block = from_hex(CBlock(), self.direct_block(transaction))
        for ordinal, node in enumerate(self.nodes):
            candidate = copy.deepcopy(block)
            candidate.nTime += ordinal + 1
            candidate.rehash()
            assert_equal(node.submitblock(self.sign_block(candidate.serialize().hex())), 'bad-txns-inputs-missingorspent')

    def exercise(self):
        sender, recipient = self.nodes
        from test_framework import util
        util.node_fastmerkle = sender
        self.chain_id = bytes.fromhex(sender.getblockhash(0))[::-1]
        self.assets = tuple(sorted(bytes.fromhex(asset)[::-1] for asset in sender.getblockchaininfo()['audit_assets']))
        self.initial_signblock = bytes.fromhex(sender.decodescript('51')['segwit']['hex'])
        self.generatetoaddress(sender, 101, sender.getnewaddress())
        audit_key = self.committee.public_key
        secrets = [random_scalar() for _ in range(3)]
        policy = self.policy(secrets, 2)
        self.install(policy)

        self.log.info('A customer receives a confidential payment')
        payment, _, address = self.build_transaction(audit_key)
        paid = self.send(self.authorize(payment, secrets, policy))
        script = recipient.getaddressinfo(address)['scriptPubKey']
        index = next(i for i, out in enumerate(payment.vout) if bytes(out.scriptPubKey).hex() == script)
        coin = {'txid': paid, 'vout': index}

        self.log.info('A thief holds a spend of it, signed with the stolen key and authorized')
        thief = recipient.getnewaddress('', 'blech32')
        raw = recipient.createrawtransaction([coin], [{thief: Decimal('1.0')}])
        funded = recipient.fundrawtransaction(raw, {'fee_rate': 2, 'add_inputs': False, 'subtractFeeFromOutputs': [0]})['hex']
        stolen = tx_from_hex(recipient.signrawtransactionwithwallet(recipient.blindrawtransaction(funded, False))['hex'])
        stolen = self.authorize(stolen, secrets, policy, expiry=sender.getblockcount() + LIFETIME)
        # Valid on the chain as it stands: the control case for later.
        self.assert_accepted(stolen)

        self.log.info('The operators open the output with the disclosure key, then build the quarantine')
        opening = self.recover(payment, index, self.committee, self.shares)
        case = bytes(range(32))
        fee = self.fee_coin(secrets, policy)
        quarantine = self.build_recovery(coin, opening, fee, quarantine_script(case))

        self.log.info('Without a recovery authorization the missing owner signature fails')
        self.assert_mempool_rejected(self.authorize(quarantine, secrets, policy), 'mandatory-script-verify-flag-failed')
        self.log.info('A recovery is signed in its own domain and must name real inputs')
        self.assert_rejected_by_nodes_and_blocks(self.recovery(quarantine, secrets, policy, [0], domain='ordinary'),
                                                 'bad-tx-authorization-signature')
        self.assert_rejected_by_nodes_and_blocks(self.recovery(quarantine, secrets, policy, [5]), 'bad-tx-recovery-inputs')
        self.assert_rejected_by_nodes_and_blocks(self.recovery(quarantine, secrets, policy, bytes(32)),
                                                 'bad-tx-recovery-inputs')
        swapped = self.recovery(quarantine, secrets, policy, [0])
        swapped.wit.vchAuthorization = encode(sender.getblockcount() + 5, {})  # length no longer a quorum
        self.assert_rejected_by_nodes_and_blocks(swapped, 'bad-tx-authorization-malformed')

        self.log.info('A first-hop recovery may not pay an ordinary address')
        elsewhere = self.build_recovery(coin, opening, fee, bytes.fromhex(sender.getaddressinfo(
            sender.getnewaddress('', 'blech32'))['scriptPubKey']))
        self.assert_rejected_by_nodes_and_blocks(self.recovery(elsewhere, secrets, policy, [0]),
                                                 'bad-tx-recovery-destination')

        self.log.info('The quarantine confirms; the thief\'s signed bytes now fail on both nodes')
        quarantined = self.recovery(quarantine, secrets, policy, [0])
        self.assert_accepted(quarantined)
        held_txid = self.send(quarantined)
        self.assert_spent_everywhere(stolen)

        self.log.info('A quarantine output cannot be spent like an ordinary one')
        held = {'txid': held_txid, 'vout': 0}
        held_opening = self.recover(quarantined, 0, self.committee, self.shares)
        assert_equal(held_opening.amount, opening.amount)
        owner = recipient.getnewaddress('', 'blech32')
        owner_script = bytes.fromhex(recipient.getaddressinfo(owner)['scriptPubKey'])
        fee = self.fee_coin(secrets, policy)
        restore = self.build_recovery(held, held_opening, fee, owner_script, nonce_address=owner)
        self.assert_rejected_by_nodes_and_blocks(self.authorize(restore, secrets, policy), 'bad-tx-quarantine-spend')

        self.log.info('A recovery from quarantine may pay anywhere: the owner gets the funds back')
        restored = self.recovery(restore, secrets, policy, [0])
        txid = self.send(restored)
        received = [entry for entry in recipient.listunspent(1) if entry['txid'] == txid]
        assert_equal([Decimal(entry['amount']) * COIN for entry in received], [opening.amount])

        self.log.info('Restarted nodes keep the rules')
        self.restart_node(0)
        self.restart_node(1)
        self.connect_nodes(0, 1)
        self.assert_spent_everywhere(stolen)


if __name__ == '__main__':
    RecoveryTest(__file__).main()
