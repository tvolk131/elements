"""Federation authorization of whole transactions.

Once a chain's DynaFed policy names authorizers, the node rejects every
non-coinbase transaction that lacks an unexpired quorum of their signatures.
These helpers mirror the node's encoding exactly; `CheckAuthorization` in
`src/threshold_audit_validation.cpp` is the reference.

Authorizers see only what the chain shows: inputs, output scripts and
commitments. They are never given amounts.
"""

import hashlib

from test_framework import messages
from test_framework.messages import hash256

DOMAIN = b'Elements/tx-authorization/v1'
REGISTRATION_DOMAIN = b'Elements/address-registration/v1'
MAX_AUTHORIZERS = 16
# Blocks an authorization stays usable. Institutions refuse a longer window.
WINDOW = 20


def policy_bytes(public_keys, order, threshold):
    keys = [bytes.fromhex(public_keys[guardian]) for guardian in order]
    if (not 1 <= len(keys) <= MAX_AUTHORIZERS or type(threshold) is not int or not 1 <= threshold <= len(keys)
            or any(len(key) != 32 for key in keys) or len(set(keys)) != len(keys)):
        raise ValueError('invalid transaction authorization policy')
    return bytes([threshold]) + b''.join(keys)


def decode_policy(policy):
    if len(policy) < 33 or len(policy) > 1 + 32 * MAX_AUTHORIZERS or (len(policy) - 1) % 32:
        raise ValueError('invalid transaction authorization policy')
    keys = [policy[offset:offset + 32] for offset in range(1, len(policy), 32)]
    if not 1 <= policy[0] <= len(keys) or len(set(keys)) != len(keys):
        raise ValueError('invalid transaction authorization policy')
    return policy[0], keys


def template_hash(transaction):
    """The node's TransactionTemplateHash: every input and output, no witnesses."""
    unsigned = messages.CTransaction(transaction)
    unsigned.wit = messages.CTxWitness()
    for inp in unsigned.vin:
        inp.scriptSig = b''
    return hash256(unsigned.serialize_without_witness())


def authorization_digest(genesis_hash, policy, transaction, expiry_height):
    return hashlib.sha256(DOMAIN + bytes.fromhex(genesis_hash)[::-1] + hashlib.sha256(policy).digest()
                          + template_hash(transaction) + expiry_height.to_bytes(4, 'big')).digest()


def encode(expiry_height, signatures):
    """`signatures` maps each signer's index in the policy to its signature."""
    return expiry_height.to_bytes(4, 'little') + b''.join(bytes([index]) + signatures[index] for index in sorted(signatures))


def registration_digest(genesis_hash, script):
    """What a member bank signs to vouch that a destination is one of its customers'."""
    return hashlib.sha256(REGISTRATION_DOMAIN + bytes.fromhex(genesis_hash)[::-1] + script).digest()


def needs_registration(script):
    """Fee outputs and burns have no recipient."""
    return script not in (b'', b'\x6a')
