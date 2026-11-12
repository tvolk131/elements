# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the combined recovery, disclosure, governance and rollback workflow."""

import os
import unittest

from curve import Curve
from lifecycle_demo import run


class LifecycleTests(unittest.TestCase):
    def test_optimized_recovery_across_governance_and_genuine_key_rollover(self):
        curve = Curve(os.environ['THRESHOLD_AUDIT_SECP256K1'])
        try:
            result = run(curve)
        finally:
            curve.close()
        self.assertTrue(result['full_opening_matches_for_both_schemes'])
        self.assertTrue(result['handoff']['current_committee_recovers_history'])
        self.assertTrue(result['genuine_rollover']['old_output_recovered_after_rollover'])
        self.assertTrue(result['genuine_rollover']['stale_pending_key_rejected'])
        self.assertTrue(result['reorg']['orphan_policy_reference_rejected'])
        self.assertTrue(result['reorg']['approving_votes_undo_restores_prior_policy'])
        self.assertEqual(result['payload_bytes']['TAC2'], 54628)


if __name__ == '__main__':
    unittest.main()
