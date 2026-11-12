# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regressions for independently reproduced guardian storage/listener failures."""

import os
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from curve import Curve, random_scalar
from guardian_client import GuardianCluster
from guardian_service import Guardian
import guardian_service


class GuardianRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = os.environ['THRESHOLD_AUDIT_SECP256K1']

    def test_exclusive_directory_writer_and_clean_restart(self):
        with tempfile.TemporaryDirectory(prefix='elements-guardian-lock-') as directory:
            config = {'member': 1, 'directory': directory, 'library': self.library}
            first = Guardian(config)
            try:
                with self.assertRaisesRegex(ValueError, 'already in use'):
                    Guardian(config)
                first.log.append({'event': 'first writer'})
            finally:
                first.close()
            second = Guardian(config)
            try:
                self.assertEqual(second.log.sequence, 1)
                second.log.append({'event': 'after restart'})
            finally:
                second.close()
            final = Guardian(config)
            try:
                self.assertEqual(final.log.sequence, 2)
            finally:
                final.close()

    def test_failed_private_write_cannot_acknowledge_cached_deal(self):
        with tempfile.TemporaryDirectory(prefix='elements-guardian-write-fault-') as directory:
            fingerprint = '0' * 64
            config = {'member': 1, 'directory': directory, 'library': self.library,
                      'trusted_clients': {fingerprint: {'role': 'coordinator'}}}
            guardian = Guardian(config)
            plan = {'chain_id': '1' * 64, 'session': '2' * 64, 'mode': 'genesis',
                    'version': 1, 'members': [1], 'threshold': 1, 'dealers': [1], 'epoch': 0, 'old': None}
            try:
                with patch('guardian_service.atomic_write', side_effect=OSError('injected storage failure')):
                    with self.assertRaisesRegex(ValueError, 'private storage requires recovery'):
                        guardian.dispatch({'operation': 'begin_deal', 'plan': plan}, fingerprint)
                self.assertTrue(guardian.dispatch({'operation': 'status'}, fingerprint)['storage_fault'])
                with self.assertRaisesRegex(ValueError, 'durable storage requires recovery'):
                    guardian.dispatch({'operation': 'begin_deal', 'plan': plan}, fingerprint)
            finally:
                guardian.close()
            recovered = Guardian(config)
            try:
                self.assertEqual(recovered.state['deals'], {})
            finally:
                recovered.close()

    def test_failed_log_fsync_blocks_future_operations(self):
        with tempfile.TemporaryDirectory(prefix='elements-guardian-log-fault-') as directory:
            fingerprint = '0' * 64
            guardian = Guardian({'member': 1, 'directory': directory, 'library': self.library,
                                 'trusted_clients': {fingerprint: {'role': 'coordinator'}}})
            try:
                with patch('guardian_service.os.fsync', side_effect=OSError('injected log fsync failure')):
                    with self.assertRaisesRegex(ValueError, 'audit log requires recovery'):
                        guardian.log.append({'status': 'authorized'})
                with self.assertRaisesRegex(ValueError, 'audit log requires recovery'):
                    guardian.log.append({'status': 'partial-released'})
                self.assertTrue(guardian.dispatch({'operation': 'status'}, fingerprint)['storage_fault'])
                with self.assertRaisesRegex(ValueError, 'durable storage requires recovery'):
                    guardian.dispatch({'operation': 'begin_deal'}, fingerprint)
            finally:
                guardian.close()

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for ephemeral TLS fixtures')
    def test_stalled_tls_handshake_does_not_block_authenticated_requests(self):
        curve = Curve(self.library)
        try:
            with tempfile.TemporaryDirectory(prefix='elements-guardian-handshake-') as directory:
                with GuardianCluster(directory, (1,), self.library, curve, curve.mul(random_scalar())) as cluster:
                    guardian = cluster.guardians[1]
                    endpoint = urlsplit(guardian.endpoint)
                    # This peer deliberately never sends a TLS ClientHello. A
                    # listener-wide SSL accept used to stall the next request.
                    with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5):
                        self.assertEqual(guardian.request('status')['member'], 1)
        finally:
            curve.close()

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for ephemeral TLS fixtures')
    def test_lost_dealer_ack_resumes_without_retrying_validation_errors(self):
        curve = Curve(self.library)
        original = guardian_service.http.client.HTTPSConnection.getresponse
        responses = []

        def lose_first_ack(connection):
            response = original(connection)
            responses.append(response.status)
            if len(responses) == 1:
                # The guardian has already persisted its dealer contribution;
                # lose only the coordinator's receipt, then resume the same deal.
                raise ConnectionResetError('injected lost dealer acknowledgement')
            return response

        try:
            with tempfile.TemporaryDirectory(prefix='elements-guardian-ack-') as directory:
                with GuardianCluster(directory, (1, 2), self.library, curve, curve.mul(random_scalar())) as cluster:
                    with patch('guardian_service.http.client.HTTPSConnection.getresponse', new=lose_first_ack):
                        config = cluster.genesis(bytes([1]) * 32, (1, 2), 2, bytes([2]) * 32)
                    self.assertGreater(len(responses), 1)
                    for guardian in cluster.guardians.values():
                        self.assertEqual(guardian.request('status')['active'], config.to_bytes().hex())

                    invalid_responses = []

                    def count_invalid(connection):
                        response = original(connection)
                        invalid_responses.append(response.status)
                        return response

                    with patch('guardian_service.http.client.HTTPSConnection.getresponse', new=count_invalid):
                        with self.assertRaises(ValueError):
                            cluster.guardians[1].request('begin_deal', plan={'session': '0' * 64})
                    self.assertEqual(invalid_responses, [400])
        finally:
            curve.close()
