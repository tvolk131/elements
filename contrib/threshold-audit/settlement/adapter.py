"""Boundary implemented by the local federation/Elements integration.

The coordinator MUST NOT hold federation spending or institution approval
private keys. Preparing a transaction does not broadcast it. Prepared raw bytes
and their actual Elements txid are committed to SQLite before broadcasting.
"""

from typing import Protocol


class ChainAdapter(Protocol):
    def network(self) -> dict:
        """Return chain, genesis_hash, height and audit configuration metadata."""

    def assets(self) -> list:
        """Return currency, asset_id, registered, registry_version for each asset."""

    def prepare(self, operation: dict, stage: str, certificate: dict) -> dict:
        """Return txid, rawtx, stage after independent federation tx signatures.

        issue spends the federation's reissuance token; transfer spends the
        bank-managed customer wallet; escrow locks redeemed tokens into the
        federation script; burn spends that exact confirmed escrow outpoint;
        refund spends escrow to the original customer only after a freshly
        authorized cancellation and signed definitive non-payment evidence.
        Signers must bind a cash receipt to exactly one issuance transaction.
        """

    def broadcast(self, prepared: dict) -> str:
        """Broadcast the same rawtx on retry, returning its real txid."""

    def inspect(self, prepared: dict) -> dict:
        """Return confirmations:int and conflicted:bool from actual chain RPC."""


class UnavailableChain:
    def network(self):
        return {"chain": "unavailable", "genesis_hash": "", "height": None,
                "connected": False, "error": "Elements adapter is not configured"}

    def assets(self):
        return []

    def prepare(self, operation, stage, certificate):
        raise RuntimeError("Elements adapter is not configured")

    def broadcast(self, prepared):
        raise RuntimeError("Elements adapter is not configured")

    def inspect(self, prepared):
        raise RuntimeError("Elements adapter is not configured")
