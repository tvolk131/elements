"""Operation scoped BIP340 certificates, separate from audit disclosure keys.

Only public institution keys belong in the web application's configuration.
Private keys are inputs to ``sign_approval`` in the institution service.
"""

import hashlib
import json
import time


DOMAIN = b"ElementsInstitutionalSettlementApproval/v1\x00"
FIELDS = (
    "id", "kind", "chain", "genesis_hash", "currency", "asset_id",
    "amount_minor", "source_account_hash", "destination_hash",
    "bank_account_ref_hash", "cash_receipt_id", "policy_version", "expires_at",
    "transaction_template_hash",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def reference_hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def approval_payload(operation):
    """Canonical, immutable authorization. Account details remain off chain."""
    result = {name: operation.get(name) if name == "transaction_template_hash" else operation[name] for name in FIELDS}
    if type(result["amount_minor"]) is not int or result["amount_minor"] <= 0:
        raise ValueError("amount_minor must be a positive integer")
    if type(result["expires_at"]) is not int:
        raise ValueError("expires_at must be an integer UTC timestamp")
    # The signing service receives clear destinations only off chain. Binding
    # a hash is useful only if the supplied address is checked against it.
    if reference_hash(operation["destination"]) != result["destination_hash"]:
        raise ValueError("destination does not match its approved hash")
    if reference_hash(operation["account_id"]) != result["source_account_hash"]:
        raise ValueError("source account does not match its approved hash")
    if operation["kind"] == "redemption" and reference_hash(operation["destination"]) != result["bank_account_ref_hash"]:
        raise ValueError("payout account does not match its approved hash")
    template = result["transaction_template_hash"]
    if template is not None and (not isinstance(template, str) or len(template) != 64
                                 or any(character not in "0123456789abcdef" for character in template)):
        raise ValueError("invalid authorized transaction template hash")
    return result


def approval_digest(operation):
    return hashlib.sha256(DOMAIN + canonical(approval_payload(operation))).digest()


def sign_approval(curve, guardian_id, secret, operation):
    """Called by an institution service, never by the settlement web server."""
    return {"guardian_id": guardian_id,
            "payload_hash": approval_digest(operation).hex(),
            "signature": curve.sign(secret, approval_digest(operation)).hex()}


class ApprovalVerifier:
    def __init__(self, curve, public_keys, threshold, policy_version="sandbox-v1"):
        self.curve = curve
        self.public_keys = dict(public_keys)
        self.threshold = threshold
        self.policy_version = policy_version
        if type(threshold) is not int or not 1 <= threshold <= len(public_keys):
            raise ValueError("invalid institutional approval threshold")
        if len(set(public_keys.values())) != len(public_keys):
            raise ValueError("institution public keys must be distinct")

    def verify_one(self, operation, signature):
        try:
            guardian = signature["guardian_id"]
            expected = approval_digest(operation)
            return (guardian in self.public_keys
                    and signature["payload_hash"] == expected.hex()
                    and self.curve.verify_signature(bytes.fromhex(self.public_keys[guardian]), expected,
                                                    bytes.fromhex(signature["signature"])))
        except (KeyError, ValueError, TypeError):
            return False

    def certificate(self, operation, signatures, *, now=None, allow_expired=False):
        now = int(time.time()) if now is None else now
        if operation["policy_version"] != self.policy_version:
            raise ValueError("unknown approval policy")
        if not allow_expired and operation["expires_at"] <= now:
            raise ValueError("operation approval expired")
        valid = {}
        for signature in signatures:
            if not self.verify_one(operation, signature):
                raise ValueError("invalid institutional signature")
            guardian = signature["guardian_id"]
            if guardian in valid:
                raise ValueError("duplicate institutional signature")
            valid[guardian] = signature
        if len(valid) < self.threshold:
            raise ValueError("institutional approval threshold not reached")
        return {"version": 1, "payload": approval_payload(operation),
                "payload_hash": approval_digest(operation).hex(),
                "signatures": [valid[key] for key in sorted(valid)]}

    def verify_certificate(self, operation, certificate, **kwargs):
        if not isinstance(certificate, dict) or certificate.get("version") != 1 or certificate.get("payload") != approval_payload(operation):
            raise ValueError("certificate does not authorize this operation")
        checked = self.certificate(operation, certificate.get("signatures", []), **kwargs)
        if checked["payload_hash"] != certificate.get("payload_hash"):
            raise ValueError("wrong certificate payload hash")
        return checked


class ApprovalPolicies:
    """Current approval identities plus explicit immutable historic policies."""
    def __init__(self, current, history=()):
        self.current = current
        self.history = {}
        for policy in (*history, current):
            self._register(policy)

    def _register(self, policy):
        existing = self.history.get(policy.policy_version)
        if existing and (existing.public_keys != policy.public_keys or existing.threshold != policy.threshold):
            raise ValueError('historic approval policy cannot be replaced')
        self.history[policy.policy_version] = policy

    @property
    def curve(self):
        return self.current.curve

    @property
    def public_keys(self):
        return self.current.public_keys

    @property
    def threshold(self):
        return self.current.threshold

    @property
    def policy_version(self):
        return self.current.policy_version

    def activate(self, policy):
        from .policy import policy_epoch
        current, target = policy_epoch(self.current.policy_version), policy_epoch(policy.policy_version)
        if target not in (current, current + 1):
            raise ValueError('approval policy must advance exactly one epoch')
        self._register(policy)
        self.current = policy

    def _policy(self, operation):
        try:
            return self.history[operation['policy_version']]
        except KeyError as error:
            raise ValueError('unknown historic approval policy') from error

    def verify_one(self, operation, signature):
        return self._policy(operation).verify_one(operation, signature)

    def certificate(self, operation, signatures, **kwargs):
        return self._policy(operation).certificate(operation, signatures, **kwargs)

    def verify_certificate(self, operation, certificate, **kwargs):
        return self._policy(operation).verify_certificate(operation, certificate, **kwargs)
