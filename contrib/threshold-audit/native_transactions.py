# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""External TAC2 transaction constructor for the experimental native chain.

This helper uses the functional-test transaction serializer. It is not native
wallet/PSET support and must never receive production wallet blinding keys.
Callers explicitly enable test_framework.messages.THRESHOLD_AUDIT first.
"""

from chunked import encrypt_chunked
from curve import rewind_nonce
from recovery import Opening, Statement, opening_matches
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CTransaction, CTxOutWitness, CTxWitness, hash256


def transaction_template_digest(transaction):
    """Match native copy/clear-scriptSig/GetHash; signatures and witnesses excluded."""
    unsigned = CTransaction(transaction)
    for txin in unsigned.vin:
        txin.scriptSig = b''
    unsigned.wit = CTxWitness()
    return hash256(unsigned.serialize_without_witness())


def output_statement(transaction, index, chain_id, audit_key, assets):
    output = transaction.vout[index]
    return Statement(chain_id, transaction_template_digest(transaction), index,
                     bytes(output.scriptPubKey), output.nAsset.vchCommitment,
                     output.nValue.vchCommitment, audit_key, tuple(sorted(assets)))


def rewind_wallet_output(curve, node, transaction, index):
    """Try one wallet's address-derived key; caller can try another recipient."""
    output = transaction.vout[index]
    decoded = node.decodescript(bytes(output.scriptPubKey).hex())
    address = decoded.get('address')
    if address is None:
        addresses = decoded.get('addresses', [])
        address = addresses[0] if len(addresses) == 1 else None
    if address is None:
        raise ValueError('output has no supported single address')
    private_key = int(node.dumpblindingkey(address), 16)
    witness = transaction.wit.vtxoutwit[index]
    nonce = rewind_nonce(curve, private_key, output.nNonce.vchCommitment)
    amount, value_blinder, message = curve.rewind(output.nAsset.vchCommitment,
                                                output.nValue.vchCommitment,
                                                witness.vchRangeproof, nonce,
                                                bytes(output.scriptPubKey))
    return Opening(message[:32], amount, int.from_bytes(message[32:64], 'big'), value_blinder)


def wallet_openings(curve, transaction, wallets, chain_id, audit_key, assets):
    """Recover test output openings without constructing or replacing packets."""
    openings = {}
    for index, output in enumerate(transaction.vout):
        asset_blinded = output.nAsset.vchCommitment[0] in (10, 11)
        value_blinded = output.nValue.vchCommitment[0] in (8, 9)
        if not asset_blinded and not value_blinded:
            continue
        if not asset_blinded or not value_blinded:
            raise ValueError('this native experiment requires both commitments to be blinded')
        statement = output_statement(transaction, index, chain_id, audit_key, assets)
        opening = None
        for wallet in wallets:
            try:
                candidate = rewind_wallet_output(curve, wallet, transaction, index)
                if opening_matches(curve, statement, candidate):
                    opening = candidate
                    break
            except (ValueError, JSONRPCException):
                continue
        if opening is None:
            raise ValueError(f'no supplied wallet can recover output {index}')
        openings[index] = opening
    if not openings:
        raise ValueError('transaction has no confidential outputs to audit')
    return openings


def attach_recovery(curve, transaction, wallets, chain_id, audit_key, assets):
    """External constructor retained for stale-key and adversarial test cases."""
    while len(transaction.wit.vtxoutwit) < len(transaction.vout):
        transaction.wit.vtxoutwit.append(CTxOutWitness())
    openings = wallet_openings(curve, transaction, wallets, chain_id, audit_key, assets)
    for index, witness in enumerate(transaction.wit.vtxoutwit):
        if index not in openings:
            witness.vchAuditProof = b''
            continue
        statement = output_statement(transaction, index, chain_id, audit_key, assets)
        witness.vchAuditProof = encrypt_chunked(curve, statement, openings[index]).to_bytes()
    transaction.rehash()
    return openings
