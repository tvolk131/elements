"""Failure-oriented workflow tests. TestChain is never a demo chain adapter."""

import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from curve import Curve
from settlement.approval import ApprovalVerifier, approval_digest, sign_approval
from settlement.bank import verify_cancellation_receipt, verify_credit_receipt, verify_payout_receipt
from settlement.server import create_server
from settlement.store import Problem, Settlement, minor_units


LIBRARY = os.environ.get("SECP256K1_ZKP_LIBRARY", "/tmp/elements-audit-secp/lib/libsecp256k1.so")


class TestChain:
    """Explicit unit-test stub; its hashes represent no blockchain transactions."""
    __test__ = False

    def __init__(self):
        self.registered = True
        self.prepared = []
        self.broadcasts = []
        self.confirmations = {}
        self.lose_reply = False

    def network(self):
        return {"chain": "unit-test-only", "genesis_hash": "a" * 64, "height": 1, "simulated": True}

    def assets(self):
        return [{"currency": currency, "asset_id": character * 64, "registered": self.registered,
                 "registry_version": 1} for currency, character in (("EUR", "b"), ("USD", "c"))]

    def prepare(self, operation, stage, certificate):
        data = (operation["id"] + stage).encode()
        result = {"txid": hashlib.sha256(data).hexdigest(), "rawtx": data.hex(), "stage": stage,
                  "unit_test_stub": True}
        self.prepared.append(result)
        return result

    def broadcast(self, prepared):
        self.broadcasts.append(copy.deepcopy(prepared))
        if self.lose_reply:
            self.lose_reply = False
            raise TimeoutError("unit-test lost RPC response")
        return prepared["txid"]

    def inspect(self, prepared):
        return {"confirmations": self.confirmations.get(prepared["txid"], 0), "conflicted": False}

    def confirm_all(self):
        for transaction in self.prepared:
            self.confirmations[transaction["txid"]] = 1


class SettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists():
            raise unittest.SkipTest("set SECP256K1_ZKP_LIBRARY to libsecp256k1-zkp shared library")
        cls.curve = Curve(LIBRARY)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "curve"):
            cls.curve.close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="settlement-unit-")
        self.path = Path(self.temp.name) / "workflow.sqlite"
        self.chain = TestChain()
        self.secrets = {"guardian-1": 101, "guardian-2": 102, "guardian-3": 103}
        keys = {name: self.curve.mul(secret)[1:].hex() for name, secret in self.secrets.items()}
        self.verifier = ApprovalVerifier(self.curve, keys, 2)
        self.bank_secret = 999
        accounts = [
            {"id": "alpha", "name": "Alpha treasury", "tenant": "corp-alpha", "bank_tenant": "bank",
             "addresses": {"EUR": "conf-eur-alpha", "USD": "conf-usd-alpha"}, "bank_account_ref": "private-alpha",
             "beneficiaries": [{"id": "beneficiary-alpha", "name": "Alpha reserve bank", "currency": "EUR",
                                "bank_account_ref": "private-account-alpha"}]},
            {"id": "alpha-2", "name": "Alpha operations", "tenant": "corp-alpha", "bank_tenant": "bank",
             "addresses": {"EUR": "conf-eur-alpha-2", "USD": "conf-usd-alpha-2"}, "bank_account_ref": "private-alpha-2"},
            {"id": "beta", "name": "Beta treasury", "tenant": "corp-beta", "bank_tenant": "other-bank",
             "addresses": {"EUR": "conf-eur-beta", "USD": "conf-usd-beta"}, "bank_account_ref": "private-beta"},
        ]
        roles = [("admin", "bankadmin", "bank"), ("maker", "bankmaker", "bank"),
                 ("approver", "bankapprover", "bank"), ("corp-maker", "corporatemaker", "corp-alpha"),
                 ("corp-approver", "corporateapprover", "corp-alpha"), ("auditor", "auditor", "bank")]
        self.users = {name: {"id": name, "username": name, "name": name, "password": "sandbox-password-123",
                             "role": role, "tenant": tenant} for name, role, tenant in roles}
        for guardian in self.secrets:
            self.users[guardian] = {"id": guardian, "username": guardian, "name": guardian,
                                    "password": "sandbox-password-123", "role": "institutionguardian",
                                    "institution_id": guardian, "tenant": "bank"}
        self.config = {"accounts": accounts, "users": list(self.users.values())}
        self.store = self.open()

    def open(self):
        return Settlement(self.path, self.chain, self.verifier, self.config,
                          approval_signer=lambda operation, user: sign_approval(
                              self.curve, user["institution_id"], self.secrets[user["institution_id"]], operation),
                          bank_signing_secret=self.bank_secret)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def create_deposit(self, amount="10.00"):
        return self.store.create(self.users["maker"], "deposit", {"account_id": "alpha", "currency": "EUR", "amount": amount})

    def test_failed_preparation_keeps_token_reservation(self):
        self.issue("10.00")
        transfer = self.store.create(self.users["corp-maker"], "transfer", {
            "account_id": "alpha", "to_account_id": "alpha-2", "currency": "EUR", "amount": "8.00"})
        self.authorize(transfer)
        def unavailable(*_):
            raise RuntimeError("temporary native preparation failure")
        self.chain.prepare = unavailable
        self.store.execute(self.users["approver"], transfer["id"])
        self.assertEqual(self.store._operation(transfer["id"])["state"], "preparing")
        self.assertEqual(self.store.available_balance("alpha", "EUR"), 200)
        with self.assertRaises(Problem):
            self.store.create(self.users["corp-maker"], "transfer", {
                "account_id": "alpha", "to_account_id": "alpha-2", "currency": "EUR", "amount": "3.00"})

    def credit(self, operation):
        return self.store.bank_event(self.users["admin"], {"event_id": "cash:" + operation["id"], "kind": "credit",
                                    "operation_id": operation["id"], "currency": "EUR", "amount": operation["amount"]})

    def authorize(self, operation):
        self.store.approve(self.users["approver"], operation["id"])
        self.store.add_signature(self.users["guardian-1"], operation["id"])
        return self.store.add_signature(self.users["guardian-2"], operation["id"])

    def issue(self, amount="10.00"):
        operation = self.create_deposit(amount)
        self.credit(operation)
        credited = self.store._operation(operation["id"])
        self.assertTrue(verify_credit_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], credited,
                                            credited["credit_receipt"]))
        different_case = dict(credited, id="different-case")
        self.assertFalse(verify_credit_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], different_case,
                                             credited["credit_receipt"]))
        self.authorize(operation)
        self.store.execute(self.users["approver"], operation["id"])
        self.chain.confirm_all()
        self.store.poll()
        self.assertEqual(self.store.operation(self.users["maker"], operation["id"])["state"], "settled")
        return operation

    def redeem(self, amount="3.00"):
        operation = self.store.create(self.users["corp-maker"], "redemption",
                                      {"account_id": "alpha", "currency": "EUR", "amount": amount,
                                       "beneficiary_id": "beneficiary-alpha"})
        self.authorize(operation)
        self.store.execute(self.users["approver"], operation["id"])
        self.chain.confirm_all()
        self.store.poll()
        return operation

    def assert_reconciled(self):
        for reserve in self.store.reconcile():
            self.assertTrue(reserve["cash_reconciles"])
            self.assertTrue(reserve["liabilities_reconcile"])
            self.assertTrue(reserve["supply_reconciles"])
            self.assertTrue(reserve["journal_balances"])

    def test_issue_requires_receipt_distinct_threshold_and_second_person(self):
        operation = self.create_deposit()
        with self.assertRaises(Problem):
            self.store.approve(self.users["approver"], operation["id"])
        with self.assertRaises(Problem):
            self.store.execute(self.users["approver"], operation["id"])
        self.credit(operation)
        self.store.add_signature(self.users["guardian-1"], operation["id"])
        self.store.add_signature(self.users["guardian-1"], operation["id"])
        self.store.approve(self.users["approver"], operation["id"])
        with self.assertRaises(Problem):
            self.store.execute(self.users["approver"], operation["id"])
        self.assertEqual(self.store.operation(self.users["maker"], operation["id"])["guardian_approvals"], 1)
        self.store.add_signature(self.users["guardian-2"], operation["id"])
        self.store.execute(self.users["approver"], operation["id"])
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 0)
        self.chain.confirm_all()
        self.store.poll()
        self.store.poll()
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 1000)
        self.assert_reconciled()

    def test_lost_broadcast_reply_restart_reuses_persisted_transaction(self):
        operation = self.create_deposit()
        self.credit(operation)
        self.authorize(operation)
        self.chain.lose_reply = True
        self.store.execute(self.users["approver"], operation["id"])
        prepared = copy.deepcopy(self.chain.prepared[0])
        self.store.close()
        self.store = self.open()
        self.store.execute(self.users["approver"], operation["id"])
        self.assertEqual(self.chain.prepared, [prepared])
        self.assertEqual(self.chain.broadcasts, [prepared, prepared])
        self.chain.confirm_all()
        self.store.poll()
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 1000)
        self.assert_reconciled()

    def test_unknown_payout_keeps_escrow_and_never_double_pays(self):
        self.issue()
        self.store.bank_event(self.users["admin"], {"event_id": "mode", "kind": "payout_mode", "currency": "EUR", "outcome": "unknown"})
        operation = self.redeem()
        self.assertEqual(self.store.operation(self.users["approver"], operation["id"])["state"], "bank_unknown")
        for _ in range(4):
            self.store.execute(self.users["approver"], operation["id"])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 1)
        self.assertFalse(any(tx["stage"] == "burn" for tx in self.chain.prepared))
        with self.assertRaises(Problem):
            self.store.reject(self.users["approver"], operation["id"])
        with self.assertRaises(Problem):
            self.store.request_refund(self.users["corp-maker"], operation["id"])
        self.assert_reconciled()
        self.store.bank_event(self.users["admin"], {"event_id": "resolved", "kind": "payout_result", "currency": "EUR",
                                                    "operation_id": operation["id"], "outcome": "settled"})
        stored = self.store._operation(operation["id"])
        self.assertTrue(verify_payout_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored, stored["payout_receipt"]))
        self.store.poll()
        self.chain.confirm_all()
        self.store.poll()
        self.assertEqual(self.store.operation(self.users["approver"], operation["id"])["state"], "settled")
        self.assertEqual(self.store.db.execute("SELECT balance FROM bank_accounts WHERE currency='EUR'").fetchone()[0], 700)
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 700)
        self.assert_reconciled()

    def test_definite_failure_has_no_automatic_refund(self):
        self.issue()
        self.store.bank_event(self.users["admin"], {"event_id": "mode-fail", "kind": "payout_mode", "currency": "EUR", "outcome": "failed"})
        operation = self.redeem()
        self.assertEqual(self.store.operation(self.users["approver"], operation["id"])["state"], "payment_failed")
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 700)
        self.assertEqual(self.store.db.execute("SELECT balance FROM bank_accounts WHERE currency='EUR'").fetchone()[0], 1000)
        with self.assertRaises(Problem):
            self.store.execute(self.users["approver"], operation["id"])
        self.assert_reconciled()
        refund = self.store.request_refund(self.users["corp-maker"], operation["id"])
        stored = self.store._operation(refund["id"])
        self.assertTrue(verify_cancellation_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored,
                                                  stored["cancellation_receipt"]))
        self.assertEqual(self.store.db.execute("SELECT status FROM payments").fetchone()[0], "cancelled")
        with self.assertRaises(Problem):
            self.store.bank_event(self.users["admin"], {"event_id": "bad-after-cancel", "kind": "payout_result", "currency": "EUR",
                                                        "operation_id": operation["id"], "outcome": "settled"})
        with self.assertRaises(Problem):
            self.store.execute(self.users["approver"], refund["id"])
        self.authorize(refund)
        self.store.execute(self.users["approver"], refund["id"])
        self.chain.confirm_all()
        self.store.poll()
        self.assertEqual(self.store.token_balance("alpha", "EUR"), 1000)
        self.assertEqual(self.store.operation(self.users["approver"], operation["id"])["state"], "cancelled")
        self.assert_reconciled()

    def test_reorged_escrow_blocks_first_payout(self):
        self.issue()
        self.store.bank_event(self.users["admin"], {"event_id": "freeze-reorg", "kind": "freeze", "currency": "EUR"})
        operation = self.redeem()
        escrow_id = self.store._operation(operation["id"])["escrow_txid"]
        self.chain.confirmations[escrow_id] = 0
        self.store.bank_event(self.users["admin"], {"event_id": "unfreeze-reorg", "kind": "unfreeze", "currency": "EUR"})
        self.store.poll()
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 0)

    def test_frozen_custody_blocks_payout_until_unfrozen(self):
        self.issue()
        self.store.bank_event(self.users["admin"], {"event_id": "freeze", "kind": "freeze", "currency": "EUR"})
        operation = self.redeem()
        self.assertEqual(self.store.operation(self.users["approver"], operation["id"])["state"], "escrow_confirmed")
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 0)
        self.store.bank_event(self.users["admin"], {"event_id": "unfreeze", "kind": "unfreeze", "currency": "EUR"})
        self.store.poll()
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 1)
        self.assert_reconciled()

    def test_idempotent_receipt_and_token_reservations(self):
        operation = self.create_deposit()
        self.credit(operation)
        self.assertTrue(self.credit(operation)["duplicate"])
        with self.assertRaises(Problem):
            self.store.bank_event(self.users["admin"], {"event_id": "cash:" + operation["id"], "kind": "credit",
                                                       "operation_id": operation["id"], "currency": "EUR", "amount": "11.00"})
        self.authorize(operation)
        self.store.execute(self.users["approver"], operation["id"])
        self.chain.confirm_all()
        self.store.poll()
        first = self.store.create(self.users["corp-maker"], "transfer", {"account_id": "alpha", "to_account_id": "alpha-2", "currency": "EUR", "amount": "8.00"})
        with self.assertRaises(Problem):
            self.store.create(self.users["corp-maker"], "transfer", {"account_id": "alpha", "to_account_id": "alpha-2", "currency": "EUR", "amount": "3.00"})
        self.store.reject(self.users["corp-approver"], first["id"])
        self.assertEqual(self.store.available_balance("alpha", "EUR"), 1000)

    def test_restored_ledger_divergence_holds_new_settlement(self):
        self.issue("10.00")
        self.chain.balance = lambda account, asset: 1100
        with self.assertRaises(Problem) as caught:
            self.create_deposit("1.00")
        self.assertEqual(caught.exception.code, "account_reconciliation_hold")
        self.chain.balance = lambda account, asset: 1000
        operation = self.create_deposit("1.00")
        self.assertEqual(operation["state"], "awaiting_bank")

    def test_tenant_and_role_boundaries_and_registered_assets(self):
        operation = self.create_deposit()
        with self.assertRaises(Problem):
            self.store.create(self.users["corp-maker"], "deposit", {"account_id": "alpha", "currency": "EUR", "amount": "2.00"})
        with self.assertRaises(Problem):
            self.store.create(self.users["maker"], "deposit", {"account_id": "beta", "currency": "EUR", "amount": "2.00"})
        with self.assertRaises(Problem):
            self.store.add_signature(self.users["approver"], operation["id"])
        self.credit(operation)
        signature = sign_approval(self.curve, "guardian-2", self.secrets["guardian-2"], self.store._operation(operation["id"]))
        with self.assertRaises(Problem):
            self.store.add_signature(self.users["guardian-1"], operation["id"], signature)
        token, session = self.store.login("corp-maker", "sandbox-password-123")
        dashboard = self.store.dashboard(session)
        self.assertEqual({account["id"] for account in dashboard["accounts"]}, {"alpha", "alpha-2"})
        self.assertEqual(dashboard["reserves"], [])
        self.chain.registered = False
        with self.assertRaises(Problem):
            self.create_deposit()

    def test_certificate_binds_case_network_asset_amount_destination_and_receipt(self):
        operation = self.create_deposit()
        self.credit(operation)
        stored = self.store._operation(operation["id"])
        signatures = [sign_approval(self.curve, name, self.secrets[name], stored) for name in ("guardian-1", "guardian-2")]
        certificate = self.verifier.certificate(stored, signatures)
        for field in ("id", "genesis_hash", "currency", "asset_id", "amount_minor", "destination_hash", "cash_receipt_id"):
            changed = copy.deepcopy(stored)
            changed[field] = changed[field] + 1 if isinstance(changed[field], int) else changed[field] + "x"
            with self.assertRaises(ValueError):
                self.verifier.verify_certificate(changed, certificate)
        with self.assertRaises(ValueError):
            self.verifier.certificate(stored, [signatures[0], signatures[0]])
        expired = dict(stored, expires_at=1)
        with self.assertRaises(ValueError):
            self.verifier.certificate(expired, signatures)
        substituted = dict(stored, destination="attacker-confidential-address")
        with self.assertRaises(ValueError):
            self.verifier.verify_certificate(substituted, certificate)
        for malformed in (None, [], "receipt"):
            with self.assertRaises(ValueError):
                self.verifier.verify_certificate(stored, malformed)
            self.assertFalse(verify_credit_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored, malformed))
            self.assertFalse(verify_payout_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored, malformed))
            self.assertFalse(verify_cancellation_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored, malformed))

    def test_issue_template_is_durable_before_first_institution_approval(self):
        operation = self.create_deposit()
        self.credit(operation)
        template = "d" * 64
        self.chain.bind_authorization = lambda operation, stage: template
        def signer(operation, user):
            self.assertEqual(self.store._operation(operation["id"])["transaction_template_hash"], template)
            return sign_approval(self.curve, user["institution_id"], self.secrets[user["institution_id"]], operation)
        self.store.approval_signer = signer
        self.store.add_signature(self.users["guardian-1"], operation["id"])
        stored = self.store._operation(operation["id"])
        self.assertEqual(stored["transaction_template_hash"], template)
        self.assertEqual(stored["credit_receipt"]["payload"]["transaction_template_hash"], template)
        self.assertTrue(verify_credit_receipt(self.curve, self.curve.mul(self.bank_secret)[1:], stored,
                                            stored["credit_receipt"]))
        self.assertTrue(self.verifier.verify_one(stored, self.store.signatures(operation["id"])[0]))
        changed = dict(stored, transaction_template_hash="e" * 64)
        self.assertFalse(self.verifier.verify_one(changed, self.store.signatures(operation["id"])[0]))
        with self.assertRaises(Problem):
            self.store._bind_approval(changed)

    def test_independent_institution_review_prepares_but_does_not_sign(self):
        operation = self.create_deposit()
        self.credit(operation)
        self.chain.bind_authorization = lambda operation, stage: "f" * 64
        self.store.approval_signer = None
        ordinary = self.store.operation(self.users["maker"], operation["id"])
        self.assertNotIn("approval_request", ordinary)
        with self.assertRaises(Problem):
            self.store.prepare_approval(self.users["approver"], operation["id"])
        prepared = self.store.prepare_approval(self.users["guardian-1"], operation["id"])
        self.assertEqual(prepared["guardian_approvals"], 0)
        self.assertEqual(prepared["approval_request"]["destination"], "conf-eur-alpha")
        self.assertEqual(prepared["approval_request"]["transaction_template_hash"], "f" * 64)
        with self.assertRaises(Problem):
            self.store.add_signature(self.users["guardian-1"], operation["id"])
        signature = sign_approval(self.curve, "guardian-1", self.secrets["guardian-1"], prepared["approval_request"])
        result = self.store.add_signature(self.users["guardian-1"], operation["id"], signature)
        self.assertEqual(result["guardian_approvals"], 1)

    def test_exact_amount_parsing(self):
        for amount in ("1.001", "1e3", -1, 1.2, "-1", "0", "NaN"):
            with self.assertRaises(Problem):
                minor_units(amount)
        self.assertEqual(minor_units("001.20"), 120)

    def test_approval_workflow_names_only_account_scoped_active_actors(self):
        operation = self.create_deposit()
        workflow = operation["approval_workflow"]
        self.assertEqual(workflow["maker"]["id"], "maker")
        self.assertEqual({actor["id"] for actor in workflow["user_reviewers"]}, {"approver", "corp-approver"})
        self.assertEqual({actor["id"] for actor in workflow["submitters"]}, {"approver", "corp-approver"})
        self.assertEqual(set(workflow["institution_ids"]), set(self.secrets))
        self.assertEqual(workflow["required_institutions"], self.verifier.threshold)
        self.assertEqual(workflow["approved_institution_ids"], [])
        self.assertNotIn("password", json.dumps(workflow))
        # Disabled and unrelated reviewers must not appear in the handoff.
        disabled = dict(self.users["approver"], disabled=True)
        unrelated = dict(self.users["corp-approver"], id="other-reviewer", username="other-reviewer", tenant="corp-beta")
        self.store.register_users([unrelated])
        with self.store.transaction():
            self.store.db.execute("UPDATE users SET data=? WHERE id=?",
                (self.store.encode({key: value for key, value in disabled.items() if key != "password"}), disabled["id"]))
        workflow = self.store.operation(self.users["maker"], operation["id"])["approval_workflow"]
        self.assertEqual([actor["id"] for actor in workflow["user_reviewers"]], ["corp-approver"])
        self.assertEqual([actor["id"] for actor in workflow["submitters"]], ["corp-approver"])
        self.assertEqual(self.store.operation(self.users["maker"], operation["id"])["state"], "awaiting_bank")

    def test_http_auth_csrf_and_origin(self):
        server = create_server(self.store)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            connection.request("GET", "/api/dashboard")
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            connection.request("POST", "/api/login", json.dumps({"username": "maker", "password": "sandbox-password-123"}),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            session = json.loads(response.read())
            self.assertEqual(session["user"]["role"], "bankmaker")
            body = json.dumps({"account_id": "alpha", "currency": "EUR", "amount": "2.00", "role": "bankadmin"})
            connection.request("POST", "/api/deposits", body, {"Content-Type": "application/json", "Cookie": cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            headers = {"Content-Type": "application/json", "Cookie": cookie, "X-CSRF-Token": session["csrf"], "Origin": "https://attacker.invalid"}
            connection.request("POST", "/api/deposits", body, headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            headers.pop("Origin")
            connection.request("POST", "/api/deposits", body, headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 201)
            response.read()
            connection.request("POST", "/api/bank/events", json.dumps({"kind": "freeze", "currency": "EUR", "event_id": "bad"}), headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
