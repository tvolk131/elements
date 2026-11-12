#!/usr/bin/env python3
# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Native historical recovery using isolated guardians and signed readiness.

Two Elements nodes and 25 loopback-only guardians exercise real transactions,
two historical audit keys, 7-of-10 -> 11-of-15 handoff, and recovery after the
outgoing processes stop. This remains a research ceremony, not reviewed DPSS.
"""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import tempfile

from feature_threshold_audit import ThresholdAuditTest
from test_framework import util
from test_framework.messages import tx_from_hex
from test_framework.util import assert_equal

from chunked import ChunkPacket
from curve import random_scalar
from disclosure import Policy, Request
from governance import AuditConfig, AuditKey
from guardian_client import GuardianCluster, verify_checkpoint, verify_log
from native_governance import policy_binding
from native_transactions import output_statement
from recovery import digest


class GuardianNativeTest(ThresholdAuditTest):
    def set_test_params(self):
        super().set_test_params()

    def initialize_audit_committee(self, initial_policy):
        self.old_members, self.new_members = tuple(range(1, 11)), tuple(range(101, 116))
        self.guardian_directory = tempfile.mkdtemp(prefix='elements-native-guardians-')
        self.recipient_key = self.curve.mul(random_scalar())
        self.cluster = GuardianCluster(self.guardian_directory, self.old_members + self.new_members,
                                       self.library, self.curve, self.recipient_key)
        # The genesis hash commits to this public configuration. The initial
        # private ceremony therefore uses an independent bootstrap identifier;
        # activation/readiness bind the actual genesis hash once it exists.
        try:
            plan, committee, _ = self.cluster.deal(secrets.token_bytes(32), self.old_members, 7, 1)
            self.genesis_plans, self.committee = {1: plan}, committee
            identities = tuple((member, bytes.fromhex(self.cluster.guardians[member].identity))
                               for member in self.old_members)
            return AuditConfig(0, initial_policy, identities, 1, (AuditKey(1, 2, committee),))
        except BaseException:
            # Framework main/setup has not started yet, so its shutdown hook
            # cannot clean a failed bootstrap ceremony for us.
            self.cluster.close()
            raise

    def align(self):
        while self.nodes[0].getblockcount() % 10:
            self.mine_proposal()
        return self.nodes[0].getblockcount() + 10

    def target_policy(self):
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        return policy_binding(self.replacement_script, 108, program, b'\x51', [])

    def recover_with_current_guardians(self, transaction, openings, version):
        config = self.current_config()
        for index, expected in openings.items():
            statement = output_statement(transaction, index, self.chain_id,
                                         config.key(version).public_key, self.assets)
            packet = ChunkPacket.from_bytes(transaction.wit.vtxoutwit[index].vchAuditProof,
                                             statement, self.curve)
            opening, checkpoints = self.cluster.recover(config, version, statement, packet, self.recipient_key)
            assert_equal(opening, expected)
            identities = dict(config.identities)
            for checkpoint in checkpoints:
                assert verify_checkpoint(self.curve, identities[checkpoint['member']], checkpoint)
                # An independent observer can verify retained authorization
                # evidence without reading private-state.json or any opening.
                guardian = self.cluster.guardians[checkpoint['member']]
                log_path = Path(guardian.config['directory']) / 'disclosures.jsonl'
                assert verify_log(log_path, checkpoint)
                events = [json.loads(line)['event'] for line in log_path.read_text().splitlines()]
                authorized = next(event for event in reversed(events)
                                  if event.get('status') == 'authorized'
                                  and event['request_scope']['statement_binding'] == statement.binding().hex())
                scope = authorized['request_scope']
                request = Request(*(bytes.fromhex(scope[name]) for name in (
                    'policy_binding', 'statement_binding', 'packet_binding', 'case_reference', 'recipient_key')),
                                  scope['expires_at'])
                request.validate(self.curve)
                assert_equal(request.binding().hex(), authorized['request'])
                policy = Policy(config.key(version).committee.binding(),
                                config.key(version).committee.threshold, config.identities)
                assert_equal(request.policy_binding, policy.binding())
                assert_equal(request.packet_binding, digest(b'packet', packet.to_bytes()))
                assert_equal(request.recipient_key, self.recipient_key)
                assert_equal(authorized['output_reference'], {
                    'chain_id': statement.chain_id.hex(), 'transaction_template': statement.tx_digest.hex(),
                    'output_index': statement.output_index})
                seen = set()
                for approval in authorized['approvals']:
                    assert approval['member'] not in seen
                    seen.add(approval['member'])
                    assert self.curve.verify_signature(identities[approval['member']], request.binding(),
                                                       bytes.fromhex(approval['signature']))
                assert len(seen) >= policy.threshold

    def run_test(self):
        try:
            self.exercise_guardians()
        finally:
            self.cluster.close()
            self.curve.close()
            if not self.options.nocleanup:
                shutil.rmtree(self.guardian_directory)

    def shutdown(self):
        # Guardians start before the Elements genesis configuration exists.
        # Close them even if framework setup fails before run_test is entered.
        self.cluster.close()
        return super().shutdown()

    def exercise_guardians(self):
        sender = self.nodes[0]
        util.node_fastmerkle = sender
        self.chain_id = bytes.fromhex(sender.getblockhash(0))[::-1]
        self.assets = tuple(sorted(bytes.fromhex(asset)[::-1]
                                   for asset in sender.getblockchaininfo()['audit_assets']))
        self.initial_signblock = bytes.fromhex(sender.decodescript('51')['segwit']['hex'])
        initial = self.cluster.prepare(self.chain_id, self.genesis_config, self.genesis_plans)
        self.cluster.activate(self.chain_id, initial)
        self.generatetoaddress(sender, 101, sender.getnewaddress())

        self.log.info('Create and recover a native transaction using the distributed genesis key')
        old_tx, old_openings, _ = self.build_transaction(self.committee.public_key)
        old_txid = sender.sendrawtransaction(old_tx.serialize().hex(), 0)
        self.sync_mempools()
        self.mine_proposal()
        self.recover_with_current_guardians(old_tx, old_openings, 1)

        self.log.info('Create a second audit key and activate it with readiness for both keys')
        boundary = self.align()
        previous = self.current_config()
        plan, fresh, _ = self.cluster.deal(self.chain_id, self.old_members, 7, 2,
                                            previous=previous, mode='new-key')
        rolled = replace(previous, generation=previous.generation + 1, signer_policy=self.target_policy(),
                         active_version=2, keys=previous.keys + (AuditKey(2, 2, fresh),))
        prepared = self.cluster.prepare(self.chain_id, rolled, {2: plan}, previous=previous,
                                         activation_height=boundary)
        self.activate(prepared, self.replacement_script)
        self.cluster.activate(self.chain_id, prepared)
        new_tx, new_openings, _ = self.build_transaction(fresh.public_key)
        sender.sendrawtransaction(new_tx.serialize().hex(), 0)
        self.sync_mempools()
        self.mine_proposal()

        self.log.info('Transfer both historical keys to 11-of-15 incoming guardian processes')
        boundary = self.align()
        previous = self.current_config()
        handed, _ = self.cluster.handoff(self.chain_id, previous, self.new_members, 11,
                                         self.target_policy(), activation_height=boundary, activate=False)
        missing_old_key = replace(handed, readiness=tuple(item for item in handed.readiness if item.version == 2))
        self.assert_governance_rejected(missing_old_key, self.replacement_script)
        self.activate(handed, self.replacement_script)
        self.cluster.activate(self.chain_id, handed)

        self.log.info('Stop every outgoing guardian; recover transactions from both audit-key eras')
        for member in self.old_members:
            self.cluster.guardians[member].stop()
        assert all(self.cluster.guardians[member].process is None for member in self.old_members)
        self.recover_with_current_guardians(old_tx, old_openings, 1)
        self.recover_with_current_guardians(new_tx, new_openings, 2)

        self.log.info('Restart the incoming guardians and a node, then recover both eras again')
        for member in self.new_members:
            self.cluster.guardians[member].stop()
            self.cluster.guardians[member].start()
        self.restart_node(0)
        self.connect_nodes(0, 1)
        assert_equal(self.current_config(), handed.transition.config)
        self.recover_with_current_guardians(old_tx, old_openings, 1)
        self.recover_with_current_guardians(new_tx, new_openings, 2)
        assert tx_from_hex(sender.getrawtransaction(old_txid))
        self.log.info('Guardian private state and disclosure records: %s', self.guardian_directory)


if __name__ == '__main__':
    GuardianNativeTest(__file__).main()
