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
# Consensus ceiling: a transaction at height h needs h <= expiry < h + this.
# Mirrors MAX_AUTHORIZATION_LIFETIME in src/threshold_audit_validation.h.
MAX_LIFETIME = 20
# Institutions sign expiry = tip + WINDOW for inclusion from tip + 1 and refuse
# anything longer, so a signed authorization never exceeds the ceiling.
WINDOW = MAX_LIFETIME


class AuthorizationRefused(ValueError):
    """Enough institutions declined that no quorum can authorize this transaction."""


class AuthorizationUnavailable(ValueError):
    """Too few institutions answered; the same transaction can be retried."""


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


# Recovery: the same quorum moves named outputs without their owners'
# signatures, first only into quarantine or a burn, then from quarantine
# anywhere. Mirrors RECOVERY_* and QuarantineScript in the node.
RECOVERY_DOMAIN = b'Elements/tx-recovery/v1'
RECOVERY_MARKER = 0x52
RECOVERY_BITMAP_BYTES = 32
QUARANTINE_TAG = b'QUARANTINE-CASE1'


def recovery_bitmap(indexes):
    bitmap = bytearray(RECOVERY_BITMAP_BYTES)
    for index in indexes:
        if not 0 <= index < RECOVERY_BITMAP_BYTES * 8:
            raise ValueError('recovered input index out of range')
        bitmap[index // 8] |= 1 << (index % 8)
    return bytes(bitmap)


def recovery_digest(genesis_hash, policy, transaction, bitmap, expiry_height):
    return hashlib.sha256(RECOVERY_DOMAIN + bytes.fromhex(genesis_hash)[::-1] + hashlib.sha256(policy).digest()
                          + template_hash(transaction) + bitmap + expiry_height.to_bytes(4, 'big')).digest()


def encode_recovery(bitmap, expiry_height, signatures):
    return bytes([RECOVERY_MARKER]) + bitmap + encode(expiry_height, signatures)


def quarantine_script(case_reference):
    """Spendable by no key: tag, 32-byte case reference, OP_2DROP OP_FALSE."""
    if len(case_reference) != 32:
        raise ValueError('quarantine case reference must be 32 bytes')
    return bytes([len(QUARANTINE_TAG)]) + QUARANTINE_TAG + bytes([32]) + case_reference + b'\x6d\x00'


def is_quarantine_script(script):
    return (len(script) == 52 and script[:17] == bytes([16]) + QUARANTINE_TAG and script[17] == 32
            and script[50:] == b'\x6d\x00')
