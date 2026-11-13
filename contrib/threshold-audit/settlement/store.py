"""Durable local reserve simulator, authorization and settlement workflows.

Bank events are explicitly simulated. Blockchain progress comes exclusively
from ChainAdapter.inspect; no HTTP action can assert a transaction confirmed.
All quantities are integer fiat minor units (100 cents per EUR/USD).
"""

from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from .approval import approval_digest, approval_payload, canonical, reference_hash
from .bank import sign_cancellation_receipt, sign_credit_receipt, sign_payout_receipt


ROLES = {
    "bankadmin": {"view_bank", "simulate_bank", "create_deposit", "reconcile"},
    "bankmaker": {"view_bank", "create_deposit", "create_transfer", "create_redemption", "create_refund"},
    "bankapprover": {"view_bank", "approve", "execute"},
    "corporatemaker": {"create_transfer", "create_redemption", "create_refund"},
    "corporateapprover": {"approve", "execute"},
    "auditor": {"view_bank", "reconcile", "receive_disclosure"},
    "institutionguardian": {"guardian_approve", "view_bank"},
    "bankcompliance": {"view_bank", "request_disclosure", "receive_disclosure"},
    "federationcompliance": {"view_bank", "request_disclosure", "receive_disclosure", "network_disclosures"},
    "auditguardian": {"review_disclosure"},
}
FINAL = {"settled", "rejected", "failed", "cancelled"}
PENDING_TOKEN = {"awaiting_approval", "ready", "preparing", "chain_pending"}


class Problem(ValueError):
    def __init__(self, message, status=400, code="invalid_request"):
        super().__init__(message)
        self.status, self.code = status, code


def minor_units(value):
    """Require exact decimal cents, rejecting float JSON and scientific notation."""
    if not isinstance(value, str) or not value or len(value) > 24:
        raise Problem("amount must be a decimal string")
    if any(character not in "0123456789." for character in value) or value.count(".") > 1:
        raise Problem("amount must be a positive decimal amount")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise Problem("invalid amount") from error
    if not amount.is_finite() or amount <= 0 or amount * 100 != (amount * 100).to_integral_value():
        raise Problem("amount must have at most two decimal places")
    result = int(amount * 100)
    if result > 1_000_000_000_000:
        raise Problem("sandbox amount limit exceeded")
    return result


def money(amount):
    return f"{amount // 100}.{amount % 100:02d}"


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 10 <= len(password) <= 512:
        raise Problem("password must be 10 to 512 characters")
    salt = secrets.token_bytes(16) if salt is None else salt
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return salt.hex() + ":" + value.hex()


class Settlement:
    def __init__(self, database, chain, verifier, config=None, approval_signer=None, bank_signing_secret=None):
        self.config = config or {}
        path = Path(database)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.lock = threading.RLock()
        self.chain, self.verifier, self.approval_signer = chain, verifier, approval_signer
        self.federation = None
        self.disclosures, self.directory = None, None
        self.receipts = None
        self.bank_signing_secret = bank_signing_secret
        self.min_confirmations = self.config.get("min_confirmations", 1)
        if type(self.min_confirmations) is not int or self.min_confirmations < 1:
            raise ValueError("min_confirmations must be positive")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
            csrf TEXT NOT NULL, expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL,
            tenant TEXT NOT NULL, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS signatures(operation_id TEXT NOT NULL REFERENCES operations(id),
            guardian_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(operation_id,guardian_id));
          CREATE TABLE IF NOT EXISTS user_approvals(operation_id TEXT PRIMARY KEY REFERENCES operations(id),
            user_id TEXT NOT NULL, approved_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS bank_accounts(currency TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0,
            frozen INTEGER NOT NULL DEFAULT 0, payout_mode TEXT NOT NULL DEFAULT 'settled');
          CREATE TABLE IF NOT EXISTS bank_events(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS bank_authorizations(receipt_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL, template_hash TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
            currency TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS journal(id INTEGER PRIMARY KEY, operation_id TEXT NOT NULL,
            event TEXT NOT NULL, currency TEXT NOT NULL, debit TEXT NOT NULL, credit TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK(amount>0), created INTEGER NOT NULL,
            UNIQUE(operation_id,event));
          CREATE TABLE IF NOT EXISTS token_balances(account_id TEXT NOT NULL, currency TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK(amount>=0), PRIMARY KEY(account_id,currency));
          CREATE TABLE IF NOT EXISTS token_movements(operation_id TEXT NOT NULL, stage TEXT NOT NULL,
            account_id TEXT NOT NULL, currency TEXT NOT NULL, delta INTEGER NOT NULL,
            PRIMARY KEY(operation_id,stage,account_id));
          CREATE TABLE IF NOT EXISTS outbox(operation_id TEXT NOT NULL REFERENCES operations(id),
            stage TEXT NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(operation_id,stage));
          CREATE TABLE IF NOT EXISTS evidence(seq INTEGER PRIMARY KEY, created INTEGER NOT NULL,
            operation_id TEXT, actor TEXT NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL,
            previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE);
        """)
        with self.transaction():
            for currency in ("EUR", "USD"):
                self.db.execute("INSERT OR IGNORE INTO bank_accounts(currency) VALUES(?)", (currency,))
            for account in self.config.get("accounts", []):
                self.db.execute("INSERT OR IGNORE INTO accounts VALUES(?,?)", (account["id"], self.encode(account)))
            for user in self.config.get("users", []):
                if user["role"] not in ROLES:
                    raise ValueError("unknown role")
                safe = {key: value for key, value in user.items() if key not in {"password", "password_hash"}}
                exists = self.db.execute("SELECT 1 FROM users WHERE id=?", (user["id"],)).fetchone()
                if not exists:
                    hashed = user.get("password_hash") or password_hash(user["password"])
                    self.db.execute("INSERT INTO users VALUES(?,?,?,?)",
                                    (user["id"], user["username"], hashed, self.encode(safe)))

    def close(self):
        self.db.close()

    @staticmethod
    def encode(value):
        return canonical(value).decode()

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def evidence(self, actor, event, data, operation_id=None):
        row = self.db.execute("SELECT entry_hash FROM evidence ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "0" * 64
        now = int(time.time())
        entry = {"created": now, "actor": actor, "event": event, "operation_id": operation_id,
                 "data": data, "previous_hash": previous}
        digest = hashlib.sha256(canonical(entry)).hexdigest()
        self.db.execute("INSERT INTO evidence(created,operation_id,actor,event,data,previous_hash,entry_hash) "
                        "VALUES(?,?,?,?,?,?,?)", (now, operation_id, actor, event, self.encode(data), previous, digest))

    def login(self, username, password):
        with self.transaction():
            row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                # Perform the expensive calculation for nonexistent users as well.
                password_hash(password if isinstance(password, str) and 10 <= len(password) <= 512 else "invalid-password")
                raise Problem("invalid username or password", 401, "authentication_failed")
            try:
                salt, digest = row["password"].split(":")
                candidate = password_hash(password, bytes.fromhex(salt)).split(":")[1]
            except (ValueError, TypeError):
                candidate, digest = "", "!"
            if not hmac.compare_digest(candidate, digest):
                raise Problem("invalid username or password", 401, "authentication_failed")
            if json.loads(row["data"]).get("disabled"):
                raise Problem("institution membership is no longer active", 401, "membership_inactive")
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (reference_hash(token), row["id"], csrf,
                                                                   int(time.time()) + 8 * 3600))
            self.evidence(row["id"], "login", {})
            return token, {"user": json.loads(row["data"]), "csrf": csrf,
                           "permissions": sorted(ROLES[json.loads(row["data"])["role"]])}

    def session(self, token):
        with self.lock:
            row = self.db.execute("SELECT u.data,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id "
                                  "WHERE s.token=? AND s.expires>?", (reference_hash(token), int(time.time()))).fetchone()
        if not row:
            raise Problem("sign in required", 401, "authentication_required")
        user = json.loads(row["data"])
        if user.get("disabled"):
            raise Problem("institution membership is no longer active", 401, "membership_inactive")
        return {"user": user, "csrf": row["csrf"], "permissions": sorted(ROLES[user["role"]])}

    def check_rotation_hold(self):
        if self.federation is not None and self.federation.held:
            raise Problem("settlement is held during federation handover; existing cases are preserved", 409, "federation_handover")

    def check_chain_balance(self, account_id, currency):
        """Hold new execution on stale restored ledgers or unmanaged wallet changes."""
        if not hasattr(self.chain, 'balance'):
            return  # Explicit unit-test adapters may not have a real wallet.
        asset = next((item for item in self.chain.assets() if item['currency'] == currency), None)
        if asset is None:
            raise Problem('currency wallet is not configured', 409)
        try:
            actual = self.chain.balance(account_id, asset['asset_id'])
        except Exception as error:
            raise Problem('wallet reconciliation is unavailable; new settlement is held', 409,
                          'account_reconciliation_hold') from error
        if actual != self.token_balance(account_id, currency):
            raise Problem('chain wallet and customer ledger differ; reconcile before new settlement', 409,
                          'account_reconciliation_hold')

    def register_users(self, users):
        """Install fixture accounts without changing existing credentials."""
        with self.transaction():
            for user in users:
                safe = {key: value for key, value in user.items() if key not in {"password", "password_hash"}}
                if self.db.execute("SELECT 1 FROM users WHERE id=?", (user["id"],)).fetchone():
                    continue
                self.db.execute("INSERT INTO users VALUES(?,?,?,?)", (user["id"], user["username"],
                    user.get("password_hash") or password_hash(user["password"]), self.encode(safe)))

    def logout(self, token):
        with self.transaction():
            self.db.execute("DELETE FROM sessions WHERE token=?", (reference_hash(token),))

    @staticmethod
    def require(user, permission):
        if permission not in ROLES.get(user.get("role"), set()):
            raise Problem("this account does not have permission for that action", 403, "forbidden")

    def account(self, account_id):
        row = self.db.execute("SELECT data FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise Problem("account not found", 404)
        return json.loads(row[0])

    @staticmethod
    def can_view(user, account):
        return (user.get('role') == 'institutionguardian' or user["tenant"] == account["tenant"] or
                ("view_bank" in ROLES[user["role"]] and user["tenant"] == account.get("bank_tenant")))

    def accessible_account(self, user, account_id):
        account = self.account(account_id)
        if not self.can_view(user, account):
            raise Problem("account not found", 404)
        return account

    def _operation(self, operation_id):
        row = self.db.execute("SELECT data FROM operations WHERE id=?", (operation_id,)).fetchone()
        if not row:
            raise Problem("operation not found", 404)
        return json.loads(row[0])

    def operation(self, user, operation_id):
        with self.lock:
            operation = self._operation(operation_id)
            if not self.can_view(user, self.account(operation["account_id"])):
                if not operation.get('to_account_id') or not self.can_view(user, self.account(operation['to_account_id'])):
                    raise Problem('operation not found', 404)
            return self.public_operation(user, operation)

    def save(self, operation):
        operation["updated_at"] = int(time.time())
        self.db.execute("UPDATE operations SET state=?,data=? WHERE id=?",
                        (operation["state"], self.encode(operation), operation["id"]))

    def signatures(self, operation_id):
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT data FROM signatures WHERE operation_id=? ORDER BY guardian_id", (operation_id,))]

    def certificate(self, operation, allow_expired=False):
        return self.verifier.certificate(operation, self.signatures(operation["id"]), allow_expired=allow_expired)

    def approved(self, operation):
        return bool(self.db.execute("SELECT 1 FROM user_approvals WHERE operation_id=?", (operation["id"],)).fetchone())

    def refresh_ready(self, operation):
        if operation["state"] not in {"awaiting_approval", "ready"}:
            return
        try:
            self.certificate(operation)
            operation["state"] = "ready" if self.approved(operation) else "awaiting_approval"
        except ValueError:
            operation["state"] = "awaiting_approval"
        self.save(operation)

    def token_balance(self, account_id, currency):
        row = self.db.execute("SELECT amount FROM token_balances WHERE account_id=? AND currency=?",
                              (account_id, currency)).fetchone()
        return row[0] if row else 0

    def available_balance(self, account_id, currency):
        reserved = 0
        for row in self.db.execute("SELECT data FROM operations WHERE kind IN ('transfer','redemption')"):
            operation = json.loads(row[0])
            if (operation["account_id"] == account_id and operation["currency"] == currency
                    and operation["state"] in PENDING_TOKEN):
                reserved += operation["amount_minor"]
        return self.token_balance(account_id, currency) - reserved

    def create(self, user, kind, body):
        self.check_rotation_hold()
        if kind not in {"deposit", "transfer", "redemption"}:
            raise Problem("unknown operation")
        self.require(user, "create_" + kind)
        amount = minor_units(body.get("amount"))
        currency = body.get("currency")
        if currency not in {"EUR", "USD"}:
            raise Problem("supported currencies are EUR and USD")
        assets = [asset for asset in self.chain.assets() if asset["currency"] == currency and asset.get("registered")]
        if len(assets) != 1:
            raise Problem("currency asset is not approved in the active on-chain registry", 409, "asset_unregistered")
        network = self.chain.network()
        if not network.get("genesis_hash"):
            raise Problem("Elements chain is unavailable", 503, "chain_unavailable")
        with self.transaction():
            self.check_rotation_hold()
            account = self.accessible_account(user, body.get("account_id"))
            self.check_chain_balance(account['id'], currency)
            if currency not in account.get("addresses", {}):
                raise Problem("account has no registered wallet for that currency")
            operation_id = secrets.token_hex(16)
            destination = account["addresses"][currency]
            to_account = None
            beneficiary_id = None
            routing = None
            destination_name = None
            if kind == "transfer":
                selectors = [name for name in ('route_id', 'address', 'to_account_id') if body.get(name)]
                if len(selectors) != 1 or not isinstance(body[selectors[0]], str):
                    raise Problem('choose exactly one managed account, beneficiary confirmation or confidential address')
                if body.get('route_id') and self.directory is not None:
                    to_account, destination, destination_name, routing = self.directory.consume(user, account, currency, body['route_id'], operation_id)
                elif body.get('address') and self.directory is not None:
                    destination = body['address'].strip()
                    to_account = self.directory.address(destination)
                    destination_name = 'Confidential wallet address (identity not verified)'
                else:
                    to_account = self.accessible_account(user, body.get("to_account_id"))
                    destination = to_account.get("addresses", {}).get(currency)
                    destination_name = to_account.get('name', to_account['id'])
                if to_account and to_account["id"] == account["id"]:
                    raise Problem("choose a different destination account")
                if not destination:
                    raise Problem("destination wallet not configured")
            if kind == "redemption":
                beneficiaries = account.get("beneficiaries", [])
                beneficiary = next((item for item in beneficiaries if item["id"] == body.get("beneficiary_id")), None)
                if beneficiary is None:
                    raise Problem("choose an approved beneficiary")
                if beneficiary.get("currency") not in {None, currency}:
                    raise Problem("beneficiary is not approved for that currency")
                beneficiary_id = beneficiary["id"]
                destination = beneficiary["bank_account_ref"]
            if kind != "deposit" and self.available_balance(account["id"], currency) < amount:
                raise Problem("insufficient available token balance", 409, "insufficient_balance")
            now = int(time.time())
            operation = {"id": operation_id, "kind": kind, "currency": currency,
                         "asset_id": assets[0]["asset_id"], "registry_version": assets[0].get("registry_version"),
                         "amount_minor": amount, "account_id": account["id"], "tenant": account["tenant"],
                         "destination": destination, "to_account_id": to_account["id"] if to_account else None,
                         "beneficiary_id": beneficiary_id,
                         "source_account_hash": reference_hash(account["id"]),
                         "destination_hash": reference_hash(destination),
                         "bank_account_ref_hash": reference_hash(destination if kind == "redemption" else account.get("bank_account_ref", "")),
                         "cash_receipt_id": None, "chain": network["chain"],
                         "transaction_template_hash": None,
                         "genesis_hash": network["genesis_hash"], "policy_version": self.verifier.policy_version,
                         "expires_at": now + self.config.get("approval_ttl", 24 * 3600),
                         "state": "awaiting_bank" if kind == "deposit" else "awaiting_approval",
                         "created_at": now, "updated_at": now, "maker": user["id"],
                         "txid": None, "stage": None, "error": None}
            if kind == 'transfer':
                operation['destination_name'] = destination_name
                operation['beneficiary_verified'] = routing is not None
                operation['beneficiary_route'] = routing
            reference = body.get("reference", "")
            if not isinstance(reference, str) or len(reference) > 120:
                raise Problem("reference must be at most 120 characters")
            operation["reference"] = reference
            self.db.execute("INSERT INTO operations VALUES(?,?,?,?,?)", (operation["id"], kind,
                            operation["state"], operation["tenant"], self.encode(operation)))
            self.evidence(user["id"], "operation_created", {"kind": kind, "currency": currency, "amount_minor": amount}, operation["id"])
            return self.public_operation(user, operation)

    def approve(self, user, operation_id):
        self.require(user, "approve")
        with self.transaction():
            self.check_rotation_hold()
            operation = self._operation(operation_id)
            self.accessible_account(user, operation["account_id"])
            if operation["maker"] == user["id"]:
                raise Problem("a different user must approve this operation", 403)
            if operation["state"] not in {"awaiting_approval", "ready"}:
                raise Problem("operation is not awaiting approval", 409)
            self.db.execute("INSERT OR IGNORE INTO user_approvals VALUES(?,?,?)",
                            (operation_id, user["id"], int(time.time())))
            self.evidence(user["id"], "user_approved", {}, operation_id)
            self.refresh_ready(operation)
            return self.public_operation(user, operation)

    def add_signature(self, user, operation_id, signature=None):
        self.check_rotation_hold()
        self.require(user, "guardian_approve")
        with self.lock:
            self.check_rotation_hold()
            operation = self._operation(operation_id)
            self.accessible_account(user, operation["account_id"])
            if operation["state"] not in {"awaiting_approval", "ready"}:
                raise Problem("operation is not awaiting guardian approval", 409)
            if operation["expires_at"] <= int(time.time()):
                raise Problem("operation approval expired", 409)
            self._bind_approval(operation)
            if signature is None:
                if self.approval_signer is None:
                    raise Problem("institution signer is unavailable", 503)
                signature = self.approval_signer(operation, user)
            if not isinstance(signature, dict) or signature.get("guardian_id") != user.get("institution_id"):
                raise Problem("institution credential does not match signed approval", 403)
            if not self.verifier.verify_one(operation, signature):
                raise Problem("invalid institution signature", 403)
            with self.transaction():
                previous = self.db.execute("SELECT data FROM signatures WHERE operation_id=? AND guardian_id=?",
                                           (operation_id, signature["guardian_id"])).fetchone()
                if previous:
                    # A repeated valid approval is idempotent even if Schnorr aux randomness differs.
                    return self.public_operation(user, operation)
                self.db.execute("INSERT INTO signatures VALUES(?,?,?)",
                                (operation_id, signature["guardian_id"], self.encode(signature)))
                self.evidence(user["id"], "institution_approved", signature, operation_id)
                self.refresh_ready(operation)
                return self.public_operation(user, operation)

    def _bind_approval(self, operation):
        if (operation["kind"] == "deposit" and operation.get("transaction_template_hash") is None
                and hasattr(self.chain, "bind_authorization")):
            template = self.chain.bind_authorization(operation, "issue")
            if (not isinstance(template, str) or len(template) != 64
                    or any(character not in "0123456789abcdef" for character in template)):
                raise Problem("institution issuance template could not be bound", 503)
            operation["transaction_template_hash"] = template
            # This is committed before any institution is asked to approve.
            with self.transaction():
                self.save(operation)
                self.evidence("chain", "issuance_template_bound", {"transaction_template_hash": template}, operation["id"])
        if operation["kind"] == "deposit" and operation.get("transaction_template_hash") is not None:
            sealed = operation.get("credit_receipt", {}).get("payload", {}).get("transaction_template_hash")
            if sealed == operation["transaction_template_hash"]:
                return
            if sealed is not None:
                raise Problem("bank receipt was already sealed for a different issuance template", 409)
            if self.bank_signing_secret is None:
                raise Problem("simulated custodian signing service is unavailable", 503)
            with self.transaction():
                previous = self.db.execute("SELECT operation_id,template_hash FROM bank_authorizations WHERE receipt_id=?",
                                           (operation["cash_receipt_id"],)).fetchone()
                binding = (operation["id"], operation["transaction_template_hash"])
                if previous and tuple(previous) != binding:
                    raise Problem("bank cash receipt is permanently bound to another issuance", 409)
                self.db.execute("INSERT OR IGNORE INTO bank_authorizations VALUES(?,?,?)",
                                (operation["cash_receipt_id"], *binding))
                operation["credit_receipt"] = sign_credit_receipt(self.verifier.curve, self.bank_signing_secret, operation)
                self.save(operation)
                self.evidence("bank-simulator", "credit_receipt_sealed", {"receipt_id": operation["cash_receipt_id"],
                              "transaction_template_hash": operation["transaction_template_hash"]}, operation["id"])

    def prepare_approval(self, user, operation_id):
        """Bind an issuance template without authorizing or signing anything."""
        self.require(user, "guardian_approve")
        with self.lock:
            self.check_rotation_hold()
            operation = self._operation(operation_id)
            self.accessible_account(user, operation["account_id"])
            if operation["state"] not in {"awaiting_approval", "ready"} or operation["expires_at"] <= int(time.time()):
                raise Problem("operation is not awaiting a current institution approval", 409)
            self._bind_approval(operation)
            return self.public_operation(user, operation)

    def reject(self, user, operation_id, reason=""):
        self.require(user, "approve")
        with self.transaction():
            operation = self._operation(operation_id)
            self.accessible_account(user, operation["account_id"])
            if operation["state"] not in {"awaiting_bank", "awaiting_approval", "ready"}:
                raise Problem("execution has started; cancellation needs the recovery workflow", 409)
            if operation["kind"] == "deposit" and operation["cash_receipt_id"]:
                raise Problem("cash has been received; its deposit payable requires a separate refund workflow", 409)
            operation["state"], operation["error"] = "rejected", str(reason)[:500]
            self.save(operation)
            self.evidence(user["id"], "operation_rejected", {"reason": operation["error"]}, operation_id)
            return self.public_operation(user, operation)

    def request_refund(self, user, operation_id):
        """Create fresh quorum authorization only after definitive non-payment.

        The simulated custodian atomically changes the original payment to a
        permanent cancelled state before signing cancellation evidence. An
        ambiguous or pending payment can never enter this path.
        """
        self.require(user, "create_refund")
        with self.transaction():
            self.check_rotation_hold()
            original = self._operation(operation_id)
            account = self.accessible_account(user, original["account_id"])
            payment = self.db.execute("SELECT * FROM payments WHERE operation_id=?", (operation_id,)).fetchone()
            if original["kind"] != "redemption" or original["state"] != "payment_failed" or not payment or payment["status"] != "failed":
                raise Problem("cancellation requires definitive bank non-payment; unresolved payments cannot be refunded", 409)
            if self.bank_signing_secret is None:
                raise Problem("simulated custodian signing service is unavailable", 503)
            now = int(time.time())
            destination = account["addresses"][original["currency"]]
            operation = {"id": secrets.token_hex(16), "kind": "refund", "currency": original["currency"],
                         "asset_id": original["asset_id"], "registry_version": original.get("registry_version"),
                         "amount_minor": original["amount_minor"], "account_id": account["id"], "tenant": account["tenant"],
                         "destination": destination, "to_account_id": None, "beneficiary_id": None,
                         "source_account_hash": reference_hash(account["id"]), "destination_hash": reference_hash(destination),
                         "bank_account_ref_hash": original["bank_account_ref_hash"], "cash_receipt_id": operation_id,
                         "escrow_txid": original["escrow_txid"], "chain": original["chain"],
                         "genesis_hash": original["genesis_hash"], "policy_version": self.verifier.policy_version,
                         "transaction_template_hash": None,
                         "expires_at": now + self.config.get("approval_ttl", 24 * 3600),
                         "state": "awaiting_approval", "created_at": now, "updated_at": now,
                         "maker": user["id"], "txid": None, "stage": None, "error": None}
            operation["cancellation_receipt"] = sign_cancellation_receipt(self.verifier.curve, self.bank_signing_secret, operation)
            self.db.execute("UPDATE payments SET status='cancelled',data=? WHERE operation_id=?",
                            (self.encode({"simulated": True, "cancellation_receipt": operation["cancellation_receipt"]}), operation_id))
            self.db.execute("INSERT INTO operations VALUES(?,?,?,?,?)", (operation["id"], "refund", operation["state"],
                                                                       operation["tenant"], self.encode(operation)))
            original["state"], original["refund_case_id"] = "refund_requested", operation["id"]
            self.save(original)
            self.evidence(user["id"], "refund_requested_after_definite_failure", {"original_id": operation_id,
                          "cancellation_receipt": operation["cancellation_receipt"]}, operation["id"])
            return self.public_operation(user, operation)

    def journal(self, operation, event, debit, credit):
        self.db.execute("INSERT OR IGNORE INTO journal(operation_id,event,currency,debit,credit,amount,created) "
                        "VALUES(?,?,?,?,?,?,?)", (operation["id"], event, operation["currency"], debit, credit,
                                                  operation["amount_minor"], int(time.time())))

    def tokens(self, operation, stage, account_id, delta):
        row = self.db.execute("SELECT 1 FROM token_movements WHERE operation_id=? AND stage=? AND account_id=?",
                              (operation["id"], stage, account_id)).fetchone()
        if row:
            return
        balance = self.token_balance(account_id, operation["currency"]) + delta
        if balance < 0:
            raise Problem("token ledger balance would become negative", 409)
        self.db.execute("INSERT INTO token_balances VALUES(?,?,?) ON CONFLICT(account_id,currency) "
                        "DO UPDATE SET amount=excluded.amount", (account_id, operation["currency"], balance))
        self.db.execute("INSERT INTO token_movements VALUES(?,?,?,?,?)", (operation["id"], stage, account_id,
                                                                       operation["currency"], delta))

    def bank_event(self, user, body):
        self.require(user, "simulate_bank")
        if user["tenant"] != self.config.get("bank_tenant", "bank"):
            raise Problem("reserve account is outside this bank workspace", 403)
        event_id, kind = body.get("event_id"), body.get("kind")
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 100:
            raise Problem("a stable event_id is required")
        with self.transaction():
            previous = self.db.execute("SELECT data FROM bank_events WHERE id=?", (event_id,)).fetchone()
            encoded = self.encode(body)
            if previous:
                if previous[0] != encoded:
                    raise Problem("bank event ID was already used for different data", 409)
                return {"event_id": event_id, "duplicate": True, "simulated": True}
            currency = body.get("currency")
            if currency not in {"EUR", "USD"}:
                raise Problem("unknown reserve currency")
            if kind == "credit":
                operation = self._operation(body.get("operation_id"))
                self.accessible_account(user, operation["account_id"])
                amount = minor_units(body.get("amount"))
                if operation["kind"] != "deposit" or operation["state"] != "awaiting_bank":
                    raise Problem("deposit is not awaiting a bank receipt", 409)
                if currency != operation["currency"] or amount != operation["amount_minor"]:
                    raise Problem("receipt currency/amount differs from requested deposit", 409)
                if self.bank_signing_secret is None:
                    raise Problem("simulated custodian signing service is unavailable", 503)
                self.db.execute("UPDATE bank_accounts SET balance=balance+? WHERE currency=?", (amount, currency))
                operation["cash_receipt_id"], operation["state"] = event_id, "awaiting_approval"
                operation["credit_receipt"] = sign_credit_receipt(self.verifier.curve, self.bank_signing_secret, operation)
                operation["expires_at"] = int(time.time()) + self.config.get("approval_ttl", 24 * 3600)
                self.journal(operation, "bank_credit", "reserve_cash", "deposit_payable")
                self.save(operation)
            elif kind in {"freeze", "unfreeze"}:
                self.db.execute("UPDATE bank_accounts SET frozen=? WHERE currency=?", (int(kind == "freeze"), currency))
            elif kind == "payout_mode":
                if body.get("outcome") not in {"settled", "failed", "unknown", "pending"}:
                    raise Problem("invalid simulated payout outcome")
                self.db.execute("UPDATE bank_accounts SET payout_mode=? WHERE currency=?", (body["outcome"], currency))
            elif kind == "payout_result":
                payment = self.db.execute("SELECT * FROM payments WHERE operation_id=?", (body.get("operation_id"),)).fetchone()
                if not payment:
                    raise Problem("payment not found", 404)
                operation = self._operation(payment["operation_id"])
                self.accessible_account(user, operation["account_id"])
                if currency != operation["currency"]:
                    raise Problem("bank result currency differs from payment", 409)
                outcome = body.get("outcome")
                if outcome not in {"settled", "failed"} or payment["status"] not in {"pending", "unknown"}:
                    raise Problem("only an unresolved payment can receive a definitive result", 409)
                self._payment_result(operation, outcome)
            else:
                raise Problem("unknown simulator bank event")
            self.db.execute("INSERT INTO bank_events VALUES(?,?)", (event_id, encoded))
            self.evidence(user["id"], "simulated_bank_" + kind, body, body.get("operation_id"))
            return {"event_id": event_id, "duplicate": False, "simulated": True}

    def _payment_result(self, operation, outcome):
        if outcome == "settled" and self.bank_signing_secret is None:
            raise Problem("simulated custodian signing service is unavailable", 503)
        self.db.execute("UPDATE payments SET status=? WHERE operation_id=?", (outcome, operation["id"]))
        if outcome == "settled":
            self.db.execute("UPDATE bank_accounts SET balance=balance-? WHERE currency=?",
                            (operation["amount_minor"], operation["currency"]))
            self.journal(operation, "bank_paid", "redemption_payable", "reserve_cash")
            operation["payout_receipt"] = sign_payout_receipt(self.verifier.curve, self.bank_signing_secret,
                                                            operation, "settlement:" + operation["id"])
            operation["state"] = "burn_pending"
        elif outcome == "failed":
            # Escrow remains locked. No refund or second payment is authorized by this transition.
            operation["state"] = "payment_failed"
            operation["error"] = "Bank confirmed payment failed; escrow recovery requires a new authorized case."
        else:
            operation["state"] = "bank_unknown" if outcome == "unknown" else "bank_pending"
        self.save(operation)

    def _pay(self, operation):
        row = self.db.execute("SELECT data FROM outbox WHERE operation_id=? AND stage='escrow'", (operation["id"],)).fetchone()
        if not row:
            raise RuntimeError("durable escrow transaction is missing")
        escrow_status = self.chain.inspect(json.loads(row[0]))
        if escrow_status.get("conflicted") or escrow_status.get("confirmations", 0) < self.min_confirmations:
            with self.transaction():
                operation["error"] = "Escrow lacks current chain confirmations; no bank payment was initiated."
                self.save(operation)
            return
        with self.transaction():
            previous = self.db.execute("SELECT * FROM payments WHERE operation_id=?", (operation["id"],)).fetchone()
            if previous:
                return  # Query the same payment ID; never initiate another payout after uncertainty.
            self.verifier.verify_certificate(operation, operation["certificate"])
            bank = self.db.execute("SELECT * FROM bank_accounts WHERE currency=?", (operation["currency"],)).fetchone()
            if bank["frozen"]:
                operation["error"] = "Simulated custody account is frozen; escrow remains locked."
                self.save(operation)
                return
            held = self.db.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE currency=? AND status IN ('pending','unknown')",
                                   (operation["currency"],)).fetchone()[0]
            if bank["balance"] - held < operation["amount_minor"]:
                operation["error"] = "Simulated reserve account has insufficient available cash."
                self.save(operation)
                return
            payment_id = "settlement:" + operation["id"]
            self.db.execute("INSERT INTO payments VALUES(?,?,?,?,?,?)", (payment_id, operation["id"],
                            operation["currency"], operation["amount_minor"], "pending",
                            self.encode({"beneficiary_hash": operation["bank_account_ref_hash"], "simulated": True,
                                         "certificate_hash": operation["certificate"]["payload_hash"]})))
            self._payment_result(operation, bank["payout_mode"])
            self.evidence("bank-simulator", "payment_initiated", {"payment_id": payment_id,
                          "outcome": bank["payout_mode"], "simulated": True}, operation["id"])

    def _prepare(self, operation, stage):
        row = self.db.execute("SELECT data FROM outbox WHERE operation_id=? AND stage=?",
                              (operation["id"], stage)).fetchone()
        if row:
            return json.loads(row[0])
        network = self.chain.network()
        if network.get("chain") != operation["chain"] or network.get("genesis_hash") != operation["genesis_hash"]:
            raise RuntimeError("active chain no longer matches the approved operation")
        if not any(asset.get("registered") and asset.get("currency") == operation["currency"]
                   and asset.get("asset_id") == operation["asset_id"] for asset in self.chain.assets()):
            raise RuntimeError("operation asset is not approved in the current registry")
        prepared = self.chain.prepare(operation, stage, operation["certificate"])
        if (not isinstance(prepared, dict) or not prepared.get("txid") or not prepared.get("rawtx")
                or prepared.get("stage") != stage):
            raise RuntimeError("chain adapter returned an invalid prepared transaction")
        with self.transaction():
            self.db.execute("INSERT INTO outbox VALUES(?,?,?,'prepared',0)",
                            (operation["id"], stage, self.encode(prepared)))
            operation["stage"], operation["txid"] = stage, prepared["txid"]
            operation["state"] = "burn_pending" if stage == "burn" else "chain_pending"
            operation[stage + "_txid"] = prepared["txid"]
            operation["error"] = None
            self.save(operation)
            self.evidence("chain", "transaction_prepared", {"stage": stage, "txid": prepared["txid"]}, operation["id"])
        return prepared

    def execute(self, user, operation_id):
        self.check_rotation_hold()
        self.require(user, "execute")
        with self.lock:
            self.check_rotation_hold()
            operation = self._operation(operation_id)
            self.accessible_account(user, operation["account_id"])
            if operation["state"] == "ready":
                self.check_chain_balance(operation['account_id'], operation['currency'])
                try:
                    certificate = self.certificate(operation)
                except ValueError as error:
                    raise Problem(str(error), 409, "approval_invalid") from error
                if not self.approved(operation):
                    raise Problem("second-person approval is missing", 409)
                if operation["kind"] == "deposit" and not operation["cash_receipt_id"]:
                    raise Problem("bank receipt is missing", 409)
                with self.transaction():
                    operation["certificate"], operation["execution_started_at"] = certificate, int(time.time())
                    operation["state"] = "preparing"
                    self.save(operation)
                    self.evidence(user["id"], "execution_authorized", {"payload_hash": certificate["payload_hash"]}, operation_id)
            elif operation["state"] not in {"preparing", "chain_pending", "escrow_confirmed", "bank_pending", "bank_unknown", "burn_pending"}:
                raise Problem("operation is not executable in its current state", 409)
            self._advance(operation)
            return self.public_operation(user, self._operation(operation_id))

    def _advance(self, operation):
        try:
            if operation["state"] == "preparing":
                if operation["kind"] == "deposit":
                    frozen = self.db.execute("SELECT frozen FROM bank_accounts WHERE currency=?", (operation["currency"],)).fetchone()[0]
                    if frozen:
                        raise RuntimeError("simulated custody account is frozen; issuance is held")
                stage = {"deposit": "issue", "transfer": "transfer", "redemption": "escrow", "refund": "refund"}[operation["kind"]]
                self._prepare(operation, stage)
            if operation["state"] in {"chain_pending", "burn_pending"}:
                stage = "burn" if operation["state"] == "burn_pending" else operation["stage"]
                prepared = self._prepare(operation, stage)
                # inspect first handles a lost broadcast response/process crash.
                status = self.chain.inspect(prepared)
                if status.get("conflicted"):
                    raise RuntimeError("prepared transaction conflicts with the active chain")
                if status.get("confirmations", 0) < self.min_confirmations:
                    try:
                        txid = self.chain.broadcast(prepared)
                        if txid != prepared["txid"]:
                            raise RuntimeError("broadcast returned a different transaction ID")
                        with self.transaction():
                            self.db.execute("UPDATE outbox SET status='broadcast',attempts=attempts+1 WHERE operation_id=? AND stage=?",
                                            (operation["id"], stage))
                    except Exception as error:
                        with self.transaction():
                            operation["error"] = "Broadcast outcome unknown; retry will query and reuse the same transaction: " + str(error)[:240]
                            self.save(operation)
                        return
                    status = self.chain.inspect(prepared)
                if status.get("confirmations", 0) >= self.min_confirmations:
                    self._confirmed(operation, stage, status)
            if operation["state"] == "escrow_confirmed":
                self._pay(operation)
            # bank_pending/unknown query the same durable simulator payment. A
            # definitive bank event is required before any burn or cancellation.
            if operation["state"] == "burn_pending" and operation.get("stage") != "burn":
                self._prepare(operation, "burn")
        except Exception as error:
            with self.transaction():
                changed = operation.get("error") != str(error)[:500]
                operation["error"] = str(error)[:500]
                self.save(operation)
                if changed:
                    self.evidence("worker", "execution_waiting", {"error": operation["error"]}, operation["id"])

    def _confirmed(self, operation, stage, status):
        with self.transaction():
            self.db.execute("UPDATE outbox SET status='confirmed' WHERE operation_id=? AND stage=?", (operation["id"], stage))
            amount = operation["amount_minor"]
            if stage == "issue":
                self.journal(operation, "issued", "deposit_payable", "token_liability")
                self.tokens(operation, "issued", operation["account_id"], amount)
                operation["state"] = "settled"
            elif stage == "transfer":
                self.tokens(operation, "transferred", operation["account_id"], -amount)
                if operation.get('to_account_id'):
                    self.tokens(operation, "transferred", operation["to_account_id"], amount)
                operation["state"] = "settled"
            elif stage == "escrow":
                self.journal(operation, "escrowed", "token_liability", "redemption_payable")
                self.tokens(operation, "escrowed", operation["account_id"], -amount)
                operation["state"] = "escrow_confirmed"
            elif stage == "burn":
                operation["state"] = "settled"
            elif stage == "refund":
                self.journal(operation, "refunded", "redemption_payable", "token_liability")
                self.tokens(operation, "refunded", operation["account_id"], amount)
                operation["state"] = "settled"
                original = self._operation(operation["cash_receipt_id"])
                original["state"] = "cancelled"
                self.save(original)
            operation["error"] = None
            self.save(operation)
            self.evidence("chain", "transaction_confirmed", {"stage": stage, "txid": operation["txid"],
                          "confirmations": status["confirmations"]}, operation["id"])

    def poll(self):
        """Resume only already-authorized executions; never approve new work."""
        with self.lock:
            if self.federation is not None and self.federation.held:
                return
            rows = list(self.db.execute("SELECT data FROM operations WHERE state IN "
                                       "('preparing','chain_pending','escrow_confirmed','bank_pending','bank_unknown','burn_pending')"))
            for row in rows:
                self._advance(json.loads(row[0]))
            if self.receipts is not None:
                self.receipts.poll()

    def reconcile(self):
        result = []
        for bank in self.db.execute("SELECT * FROM bank_accounts ORDER BY currency"):
            currency = bank["currency"]
            accounts = {}
            for row in self.db.execute("SELECT debit,credit,amount FROM journal WHERE currency=?", (currency,)):
                accounts[row["debit"]] = accounts.get(row["debit"], 0) + row["amount"]
                accounts[row["credit"]] = accounts.get(row["credit"], 0) - row["amount"]
            escrow = 0
            issued = burned = 0
            for row in self.db.execute("SELECT data FROM operations WHERE kind IN ('deposit','redemption')"):
                operation = json.loads(row[0])
                if operation["currency"] != currency:
                    continue
                confirmed = {item[0] for item in self.db.execute("SELECT stage FROM outbox WHERE operation_id=? AND status='confirmed'", (operation["id"],))}
                if "issue" in confirmed:
                    issued += operation["amount_minor"]
                if "escrow" in confirmed and "burn" not in confirmed and operation["state"] != "cancelled":
                    escrow += operation["amount_minor"]
                if "burn" in confirmed:
                    burned += operation["amount_minor"]
            token_liability = -accounts.get("token_liability", 0)
            deposits = -accounts.get("deposit_payable", 0)
            redemptions = -accounts.get("redemption_payable", 0)
            supply = issued - burned
            result.append({"currency": currency, "simulated": True, "cash_minor": bank["balance"],
                           "cash": money(bank["balance"]), "frozen": bool(bank["frozen"]),
                           "deposit_payable_minor": deposits, "token_liability_minor": token_liability,
                           "redemption_payable_minor": redemptions, "escrow_minor": escrow,
                           "issued_minor": issued, "burned_minor": burned, "tracked_supply_minor": supply,
                           "cash_reconciles": bank["balance"] == accounts.get("reserve_cash", 0),
                           "liabilities_reconcile": bank["balance"] == token_liability + deposits + redemptions,
                           "supply_reconciles": supply == token_liability + escrow,
                           "journal_balances": sum(accounts.values()) == 0,
                           "payout_mode": bank["payout_mode"]})
        return result

    def approval_workflow(self, operation):
        """Describe existing authority without granting it or exposing credentials."""
        account = self.account(operation["account_id"])
        users = [json.loads(row[0]) for row in self.db.execute("SELECT data FROM users ORDER BY id")]
        def identity(candidate):
            return {"id": candidate["id"], "name": candidate.get("name", candidate["id"]),
                    "role": candidate.get("role", "")}
        active = [candidate for candidate in users if not candidate.get("disabled")
                  and ROLES.get(candidate.get("role")) and self.can_view(candidate, account)]
        maker = next((candidate for candidate in users if candidate["id"] == operation["maker"]),
                     {"id": operation["maker"]})
        # A historic request describes its bound policy, not a later roster.
        policy = getattr(self.verifier, "history", {}).get(operation["policy_version"], self.verifier)
        return {"maker": identity(maker),
                "user_reviewers": [identity(candidate) for candidate in active
                    if "approve" in ROLES[candidate["role"]] and candidate["id"] != operation["maker"]],
                "submitters": [identity(candidate) for candidate in active
                    if "execute" in ROLES[candidate["role"]]],
                "institution_ids": sorted(policy.public_keys),
                "required_institutions": policy.threshold,
                "approved_institution_ids": sorted({signature["guardian_id"] for signature in self.signatures(operation["id"])})}

    def public_operation(self, user, operation):
        # Never return raw transactions or private account details in list views.
        result = {key: value for key, value in operation.items() if key not in {"certificate", "destination"}}
        result["amount"] = money(operation["amount_minor"])
        result["destination"] = ("Approved bank beneficiary" if operation["kind"] == "redemption"
                                 else operation.get("to_account_id") or operation.get('destination_name') or operation["account_id"])
        if operation['kind'] == 'transfer':
            result['destination_address'] = operation['destination']
        result["guardian_approvals"] = len(self.signatures(operation["id"]))
        result["guardian_threshold"] = self.verifier.threshold
        result["user_approved"] = self.approved(operation)
        result["approval_workflow"] = self.approval_workflow(operation)
        result["allowed_actions"] = []
        result['source_name'] = self.account(operation['account_id']).get('name', operation['account_id'])
        permissions = ROLES[user["role"]] if self.can_view(user, self.account(operation['account_id'])) else set()
        if not permissions:
            result['incoming'] = True
            result.pop('maker', None)
            result.pop('approval_workflow', None)
            result.pop('beneficiary_route', None)
        if operation["state"] in {"awaiting_approval", "ready"}:
            if "approve" in permissions and user["id"] != operation["maker"] and not result["user_approved"]:
                result["allowed_actions"].append("approve")
            if "guardian_approve" in permissions and user.get("institution_id") not in {s["guardian_id"] for s in self.signatures(operation["id"])}:
                result["allowed_actions"].append("guardian-approve")
        if "approve" in permissions and operation["state"] in {"awaiting_bank", "awaiting_approval", "ready"}:
            result["allowed_actions"].append("reject")
        if "execute" in permissions and operation["state"] in {"ready", "preparing", "chain_pending", "escrow_confirmed", "bank_pending", "bank_unknown", "burn_pending"}:
            result["allowed_actions"].append("execute")
        if "simulate_bank" in permissions and operation["state"] == "awaiting_bank":
            result["allowed_actions"].append("bank-credit")
        if "create_refund" in permissions and operation["state"] == "payment_failed":
            result["allowed_actions"].append("cancel")
        if "guardian_approve" in permissions and (operation["kind"] != "deposit" or (
                operation.get("transaction_template_hash") is not None
                and operation.get("credit_receipt", {}).get("payload", {}).get("transaction_template_hash") == operation["transaction_template_hash"])):
            result["approval_request"] = {key: value for key, value in operation.items()
                                          if key not in {"certificate", "error", "payout_receipt"}}
        return result

    def dashboard(self, session):
        user = session["user"]
        with self.lock:
            accounts = [json.loads(row[0]) for row in self.db.execute("SELECT data FROM accounts ORDER BY id")]
            accounts = [account for account in accounts if self.can_view(user, account)]
            ids = {account["id"] for account in accounts}
            operations = [json.loads(row[0]) for row in self.db.execute("SELECT data FROM operations ORDER BY rowid DESC")]
            operations = [self.public_operation(user, operation) for operation in operations if operation["account_id"] in ids or operation.get('to_account_id') in ids]
            balances, beneficiaries = [], []
            for account in accounts:
                chain_balances = None
                if hasattr(self.chain, "balances"):
                    try:
                        chain_balances = self.chain.balances(account["id"])
                    except Exception:
                        chain_balances = None
                for currency in account.get("addresses", {}):
                    balance = self.token_balance(account["id"], currency)
                    available = self.available_balance(account["id"], currency)
                    balances.append({"account_id": account["id"], "name": account.get("name", account["id"]),
                                     "tenant": account["tenant"], "currency": currency, "balance_minor": balance,
                                     "available_minor": available, "balance": money(balance), "available": money(available),
                                     "chain_balance_minor": chain_balances.get(currency) if chain_balances is not None else None,
                                     "chain_reconciles": chain_balances.get(currency) == balance if chain_balances is not None else None})
                for beneficiary in account.get("beneficiaries", []):
                    beneficiaries.append({"id": beneficiary["id"], "name": beneficiary.get("name", beneficiary["id"]), "kind": "bank",
                                          "account_id": account["id"], "currency": beneficiary.get("currency")})
            activity = []
            operation_ids = {operation["id"] for operation in operations}
            for row in self.db.execute("SELECT * FROM evidence ORDER BY seq DESC LIMIT 300"):
                if row["operation_id"] in operation_ids or (row["operation_id"] is None and "view_bank" in ROLES[user["role"]]):
                    activity.append({"id": row["seq"], "created_at": row["created"], "operation_id": row["operation_id"],
                                     "actor": row["actor"], "event": row["event"], "entry_hash": row["entry_hash"]})
            safe_accounts = [{"id": account["id"], "name": account.get("name", account["id"]),
                              "tenant": account["tenant"], "bank_id": account.get('bank_tenant'),
                              "payment_reference": self.directory.reference(account) if self.directory else None,
                              "currencies": sorted(account.get("addresses", {}))} for account in accounts]
            network = self.chain.network()
            network['disclosure_available'] = self.disclosures is not None
            network.update({"bank_mode": "simulated", "legal_issuer": "Undecided — sandbox only",
                            "operational_threshold": self.verifier.threshold,
                            "operational_guardians": len(self.verifier.public_keys)})
            return {"session": session, "network": network, "assets": self.chain.assets(),
                    "federation": self.federation.status(user) if self.federation is not None and "view_bank" in ROLES[user["role"]] and user["tenant"] == self.config.get("bank_tenant", "bank") else None,
                    "accounts": safe_accounts, "balances": balances,
                    "reserves": self.reconcile() if "view_bank" in ROLES[user["role"]] and user["tenant"] == self.config.get("bank_tenant", "bank") else [],
                    "operations": operations, "activity": activity[:100], "beneficiaries": beneficiaries,
                    "directory_banks": self.directory.public_banks() if self.directory else [],
                    "guardians": [{"id": guardian, "institution_id": guardian, "public_key": key,
                                   "approval_url": self.config.get("institution_approval_urls", {}).get(guardian),
                                   "name": guardian} for guardian, key in self.verifier.public_keys.items()]}
