"""Signed payout evidence from the explicitly simulated custodian.

This is an independently keyed sandbox evidence format, not a statement that a
real bank API, mandate, segregated account, or redemption obligor exists.
"""

import hashlib

from .approval import canonical


DOMAIN = b"ElementsSimulatedCustodianPayout/v1\x00"
CREDIT_DOMAIN = b"ElementsSimulatedCustodianCredit/v1\x00"


def credit_payload(operation):
    return {"id": operation["id"], "receipt_id": operation["cash_receipt_id"],
            "currency": operation["currency"], "asset_id": operation["asset_id"],
            "amount_minor": operation["amount_minor"], "genesis_hash": operation["genesis_hash"],
            "destination_hash": operation["destination_hash"],
            "source_account_hash": operation["source_account_hash"],
            "transaction_template_hash": operation.get("transaction_template_hash"),
            "status": "credited", "simulated": True}


def sign_credit_receipt(curve, secret, operation):
    payload = credit_payload(operation)
    digest = hashlib.sha256(CREDIT_DOMAIN + canonical(payload)).digest()
    return {"version": 1, "payload": payload, "signature": curve.sign(secret, digest).hex()}


def verify_credit_receipt(curve, bank_public_key, operation, receipt):
    try:
        if (not isinstance(receipt, dict) or not operation.get("cash_receipt_id") or receipt.get("version") != 1
                or receipt["payload"] != credit_payload(operation)):
            return False
        public = bytes.fromhex(bank_public_key) if isinstance(bank_public_key, str) else bank_public_key
        digest = hashlib.sha256(CREDIT_DOMAIN + canonical(receipt["payload"])).digest()
        return curve.verify_signature(public, digest, bytes.fromhex(receipt["signature"]))
    except (ValueError, KeyError, TypeError):
        return False


def payout_payload(operation, payout_id):
    return {"id": operation["id"], "currency": operation["currency"],
            "asset_id": operation["asset_id"], "amount_minor": operation["amount_minor"],
            "genesis_hash": operation["genesis_hash"],
            "bank_account_ref_hash": operation["bank_account_ref_hash"],
            "escrow_txid": operation["escrow_txid"], "payout_id": payout_id,
            "status": "settled", "simulated": True}


def sign_payout_receipt(curve, secret, operation, payout_id):
    payload = payout_payload(operation, payout_id)
    digest = hashlib.sha256(DOMAIN + canonical(payload)).digest()
    return {"version": 1, "payload": payload, "signature": curve.sign(secret, digest).hex()}


def verify_payout_receipt(curve, bank_public_key, operation, receipt):
    try:
        if not isinstance(receipt, dict):
            return False
        payload = receipt["payload"]
        if receipt.get("version") != 1 or payload != payout_payload(operation, "settlement:" + operation["id"]):
            return False
        public = bytes.fromhex(bank_public_key) if isinstance(bank_public_key, str) else bank_public_key
        digest = hashlib.sha256(DOMAIN + canonical(payload)).digest()
        return curve.verify_signature(public, digest, bytes.fromhex(receipt["signature"]))
    except (ValueError, KeyError, TypeError):
        return False


CANCELLATION_DOMAIN = b"ElementsSimulatedCustodianCancellation/v1\x00"


def cancellation_payload(operation):
    return {"id": operation["id"], "original_operation_id": operation["cash_receipt_id"],
            "currency": operation["currency"], "asset_id": operation["asset_id"],
            "amount_minor": operation["amount_minor"], "genesis_hash": operation["genesis_hash"],
            "escrow_txid": operation["escrow_txid"], "destination_hash": operation["destination_hash"],
            "payout_id": "settlement:" + operation["cash_receipt_id"],
            "status": "cancelled-no-payment", "simulated": True}


def sign_cancellation_receipt(curve, secret, operation):
    payload = cancellation_payload(operation)
    digest = hashlib.sha256(CANCELLATION_DOMAIN + canonical(payload)).digest()
    return {"version": 1, "payload": payload, "signature": curve.sign(secret, digest).hex()}


def verify_cancellation_receipt(curve, bank_public_key, operation, receipt):
    try:
        if not isinstance(receipt, dict) or receipt.get("version") != 1 or receipt["payload"] != cancellation_payload(operation):
            return False
        public = bytes.fromhex(bank_public_key) if isinstance(bank_public_key, str) else bank_public_key
        digest = hashlib.sha256(CANCELLATION_DOMAIN + canonical(receipt["payload"])).digest()
        return curve.verify_signature(public, digest, bytes.fromhex(receipt["signature"]))
    except (ValueError, KeyError, TypeError):
        return False
