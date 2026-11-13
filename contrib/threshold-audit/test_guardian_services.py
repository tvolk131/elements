# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real isolated guardian processes: history, failures and durable disclosure."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from chunked import encrypt_chunked
from curve import Curve, random_scalar
from governance import AuditConfig, AuditKey
from guardian_client import GuardianCluster, verify_checkpoint, verify_log
from guardian_service import (
    DurableLog, atomic_write, load_private, raw, ready_json, transition_json,
)
from recovery import Opening, Statement


def named(value):
    return hashlib.sha256(value.encode()).digest()


class GuardianServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('openssl') is None:
            raise unittest.SkipTest('OpenSSL executable required for ephemeral mutual-TLS fixtures')
        cls.library = os.environ['THRESHOLD_AUDIT_SECP256K1']
        cls.curve = Curve(cls.library)
        cls.addClassCleanup(cls.curve.close)

    def packet(self, config, version, label):
        opening = Opening(named('service asset'), 125_000_000, random_scalar(), random_scalar())
        asset = self.curve.asset_commitment(opening.asset, opening.asset_blinder)
        value = self.curve.value_commitment(asset, opening.amount, opening.value_blinder)
        statement = Statement(named('service chain'), named(label), 0, b'\x51', asset, value,
                              config.key(version).public_key, (opening.asset,))
        return statement, encrypt_chunked(self.curve, statement, opening), opening

    def test_explicit_sealed_release_to_an_unregistered_recipient_key(self):
        from disclosure import Policy, Request
        from guardian_service import statement_json
        from recovery import digest
        from sealed_delivery import unseal
        from threshold import PartialDecryption
        from chunked import combine_chunked
        members = (1, 2, 3)
        recipient_secret = random_scalar()
        recipient = self.curve.mul(recipient_secret)
        chain = named('service chain')
        with tempfile.TemporaryDirectory(prefix='elements-sealed-guardian-') as directory:
            with GuardianCluster(directory, members, self.library, self.curve, self.curve.mul(random_scalar())) as cluster:
                config, plans = cluster.bootstrap_genesis(members, 2, named('signer policy'))
                prepared = cluster.prepare(chain, config, plans)
                cluster.activate(chain, prepared)
                statement, packet, expected = self.packet(config, 1, 'sealed recipient output')
                key = config.key(1)
                policy = Policy(key.committee.binding(), key.committee.threshold, config.identities)
                import time
                request = Request(policy.binding(), statement.binding(), digest(b'packet', packet.to_bytes()), named('case'), recipient, int(time.time())+120, 'sealed-v1')
                payload = {'key_version':1, 'policy':{'committee_binding':policy.committee_binding.hex(),'threshold':2,'approvers':[(i,p.hex()) for i,p in policy.approvers]},
                           'request':{'policy_binding':policy.binding().hex(),'statement_binding':statement.binding().hex(),'packet_binding':request.packet_binding.hex(),'case_reference':request.case_reference.hex(),'recipient_key':recipient.hex(),'expires_at':request.expires_at,'delivery':'sealed-v1'},
                           'statement':statement_json(statement),'packet':packet.to_bytes().hex(),'approvals':[]}
                with self.assertRaises(ValueError):cluster.guardians[1].request('approve', **payload)
                with self.assertRaises(ValueError):cluster.guardians[1].request('disclose-sealed', **payload)
                for member in members[:2]:
                    approved = cluster.guardians[member].request('approve', credentials=cluster.approvers[member], **payload)
                    payload['approvals'].append({'member':member,'signature':approved['signature']})
                partials = []
                for member in members[:2]:
                    envelope = cluster.guardians[member].request('disclose-sealed', **payload)
                    self.assertNotIn('points', envelope)
                    identity = dict(config.identities)[member]
                    with self.assertRaises(ValueError):unseal(self.curve, random_scalar(), identity, envelope, request.binding(), member)
                    value = unseal(self.curve, recipient_secret, identity, envelope, request.binding(), member)
                    partials.append(PartialDecryption(value['member'],bytes.fromhex(value['committee_binding']),bytes.fromhex(value['request_binding']),tuple(bytes.fromhex(p) for p in value['points']),tuple(tuple(int(s,16) for s in proof) for proof in value['proofs'])))
                self.assertEqual(combine_chunked(self.curve,statement,packet,key.committee,tuple(partials),request.binding()),expected)

    def test_7_of_10_to_11_of_15_retains_every_historical_key(self):
        old, new = tuple(range(1, 11)), tuple(range(101, 116))
        recipient = self.curve.mul(random_scalar())
        chain = named('service chain')
        with tempfile.TemporaryDirectory(prefix='elements-guardian-history-') as directory:
            with GuardianCluster(directory, old + new, self.library, self.curve, recipient) as cluster:
                initial = cluster.genesis(chain, old, 7, named('initial block signing'))
                historical = [self.packet(initial, 1, 'first membership output')]
                rolled = cluster.rollover(chain, initial, named('initial block signing'))
                historical.append(self.packet(rolled, 2, 'fresh audit key output'))
                # Retained rollback snapshots support explicit trusted-observer
                # restoration without reconstructing missing private shares.
                old_guard = cluster.guardians[old[0]]
                old_guard.request('restore', chain_id=chain.hex(), configuration=initial.binding().hex())
                self.assertEqual(old_guard.request('status')['active'], initial.to_bytes().hex())
                old_guard.request('restore', chain_id=chain.hex(), configuration=rolled.binding().hex())
                self.assertEqual(old_guard.request('status')['active'], rolled.to_bytes().hex())

                # An incoming guardian restart preserves its institution identity,
                # private staged evaluations and received dealer contributions.
                prepared, plans = cluster.handoff(chain, rolled, new, 11, named('replacement signing'), activate=False)
                guard = cluster.guardians[new[0]]
                identity = guard.identity
                guard.stop()
                guard.start()
                self.assertEqual(guard.identity, identity)
                self.assertIn(prepared.transition.binding(chain).hex(), guard.request('status')['prepared'])

                # Missing readiness for a historical-only key blocks activation,
                # even if the latest audit key has a full ready quorum.
                missing_history = [ready_json(value) for value in prepared.readiness if value.version != 1]
                with self.assertRaises(ValueError):
                    guard.request('activate', chain_id=chain.hex(), transition=transition_json(prepared.transition),
                                  readiness=missing_history)
                self.assertIsNone(guard.request('status')['active'])

                # Fault-inject one recipient's private disk state, never collect
                # a quorum of shares into the test coordinator.
                guard.stop()
                private_path = Path(guard.config['directory']) / 'private-state.json'
                original = load_private(private_path)
                corrupted = deepcopy(original)
                second_plan = next(value for value in corrupted['incoming'].values() if value['plan']['version'] == 2)
                second_plan['evaluations'].pop(next(iter(second_plan['evaluations'])))
                corrupted['prepared'] = {}
                atomic_write(private_path, corrupted)
                guard.start()
                with self.assertRaises(ValueError):
                    guard.request('prepare', chain_id=chain.hex(), transition=transition_json(prepared.transition),
                                  previous=rolled.to_bytes().hex(), plans={str(k): v for k, v in plans.items()})
                self.assertIsNone(guard.request('status')['active'])
                guard.stop()
                atomic_write(private_path, original)
                guard.start()

                checkpoints = cluster.activate(chain, prepared)
                self.assertEqual(len(checkpoints), 15)
                # Cross-node commit can be resumed safely after a partial network
                # failure: committing the same prepared certificate is idempotent.
                self.assertTrue(guard.request('activate', chain_id=chain.hex(),
                    transition=transition_json(prepared.transition),
                    readiness=[ready_json(v) for v in prepared.readiness])['idempotent'])
                for member in old:
                    cluster.guardians[member].stop()
                current = prepared.transition.config

                for version, (statement, packet, expected) in enumerate(historical, 1):
                    actual, receipts = cluster.recover(current, version, statement, packet, recipient)
                    self.assertEqual(actual, expected)
                    for checkpoint in receipts:
                        guardian = cluster.guardians[checkpoint['member']]
                        self.assertTrue(verify_checkpoint(self.curve, raw(guardian.identity, 32), checkpoint))
                        log = Path(guardian.config['directory']) / 'disclosures.jsonl'
                        self.assertTrue(verify_log(log, checkpoint))
                        # The independent checkpoint lives outside private state.
                        atomic_write(Path(directory) / f"witness-{version}-{checkpoint['member']}.json", checkpoint)
                # Restart current guardians with every retained share on disk and
                # recover the oldest output again without any old process.
                for member in new[:11]:
                    cluster.guardians[member].stop()
                    cluster.guardians[member].start()
                statement, packet, expected = historical[0]
                self.assertEqual(cluster.recover(current, 1, statement, packet, recipient)[0], expected)

    def test_transport_request_scope_and_session_failures(self):
        old, new = (1, 2, 3), (11, 12, 13, 14)
        recipient = self.curve.mul(random_scalar())
        chain = named('service chain')
        with tempfile.TemporaryDirectory(prefix='elements-guardian-failures-') as directory:
            with GuardianCluster(directory, old + new, self.library, self.curve, recipient) as cluster:
                initial = cluster.genesis(chain, old, 2, named('signing'))
                statement, packet, expected = self.packet(initial, 1, 'scope test')
                guardian = cluster.guardians[old[0]]
                request, payload = cluster.disclosure(initial, 1, statement, packet, recipient)
                self.assertEqual(cluster.recover(initial, 1, statement, packet, recipient)[0], expected)

                # Coordinator credentials do not authorize institutional approvals
                # or release partials to an arbitrary requester.
                with self.assertRaises(ValueError):
                    guardian.request('approve', **{key: value for key, value in payload.items()
                                                  if key not in ('approvals', 'statement', 'packet')})
                with self.assertRaises(ValueError):
                    guardian.request('disclose', **payload)
                denied = deepcopy(payload)
                denied['approvals'] = denied['approvals'][:1]
                with self.assertRaises(ValueError):
                    guardian.request('disclose', credentials=cluster.recipient, **denied)
                denied = deepcopy(payload)
                denied['request']['case_reference'] = named('different case').hex()
                with self.assertRaises(ValueError):
                    guardian.request('disclose', credentials=cluster.recipient, **denied)
                denied = deepcopy(payload)
                denied['request']['recipient_key'] = self.curve.mul(random_scalar()).hex()
                with self.assertRaises(ValueError):
                    guardian.request('disclose', credentials=cluster.recipient, **denied)

                session = named('resume same handoff').hex()
                plan, committee, contributions = cluster.deal(chain, new, 3, 1, previous=initial,
                    mode='refresh', dealers=old[:2], session=session)
                public = guardian.request('begin_deal', plan=plan)
                guardian.stop()
                guardian.start()
                self.assertEqual(guardian.request('begin_deal', plan=plan), public)
                rebound = dict(plan, threshold=2)
                with self.assertRaises(ValueError):
                    guardian.request('begin_deal', plan=rebound)

                # Authenticated old dealer with a wrong private evaluation is
                # rejected before its recipient changes staged state.
                target = cluster.guardians[new[0]]
                with self.assertRaises(ValueError):
                    target.request('receive_evaluation', credentials=guardian.config, plan=plan,
                        contributions=contributions,
                        identities={str(member): cluster.guardians[member].identity for member in old[:2]},
                        dealer=old[0], evaluation=bytes(32).hex())

                # A public manifest cannot silently drop historical keys or change
                # the identity/epoch binding on a ready transition.
                config = AuditConfig(1, named('new signing'),
                    tuple((member, raw(cluster.guardians[member].identity, 32)) for member in new),
                    1, (AuditKey(1, 2, committee),))
                prepared = cluster.prepare(chain, config, {1: plan}, previous=initial)
                wrong_chain = named('another chain')
                with self.assertRaises(ValueError):
                    target.request('activate', chain_id=wrong_chain.hex(), transition=transition_json(prepared.transition),
                                   readiness=[ready_json(value) for value in prepared.readiness])
                bad = replace(prepared.transition, activation_height=20)
                with self.assertRaises(ValueError):
                    target.request('activate', chain_id=chain.hex(), transition=transition_json(bad),
                                   readiness=[ready_json(value) for value in prepared.readiness])

    def test_durable_log_checkpoint_detects_rewrite_and_truncation(self):
        with tempfile.TemporaryDirectory(prefix='elements-guardian-log-') as directory:
            path = Path(directory) / 'audit.jsonl'
            log = DurableLog(path)
            log.append({'status': 'authorized', 'request': named('a').hex()})
            log.append({'status': 'partial-released', 'request': named('a').hex()})
            checkpoint = {'sequence': log.sequence, 'head': log.head.hex()}
            self.assertTrue(verify_log(path, checkpoint))
            self.assertEqual(DurableLog(path).head, log.head)
            original = path.read_bytes()
            path.write_bytes(original.splitlines(keepends=True)[0])
            self.assertFalse(verify_log(path, checkpoint))
            altered = original.replace(b'authorized', b'authorizex')
            path.write_bytes(altered)
            self.assertFalse(verify_log(path, checkpoint))
            with self.assertRaises(ValueError):
                DurableLog(path)


if __name__ == '__main__':
    unittest.main()
