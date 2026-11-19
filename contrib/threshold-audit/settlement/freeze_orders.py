"""Freeze and release orders signed by a case authority, and operator receipts.

A case authority (the regulator) signs an order naming exact outputs. Each
operator checks the signature against the case-authority keys in its own
configuration, records the order, and from then on refuses to authorize a
transaction or sign a block that spends those outputs. A release order names
the freeze it lifts. The settlement server only relays orders: it cannot
create one, and an operator does not take its word for one.
"""

import hashlib
import re
import time

from curve import ORDER
from .approval import canonical


FORMAT = 'concord-freeze-order-v1'
ORDER_DOMAIN = b'CEND/freeze-order/v1\x00'
RECEIPT_DOMAIN = b'CEND/freeze-applied/v1\x00'
# The regulator signs with a key derived from its disclosure recipient key, so
# one password-protected key file serves both roles without reusing the key.
SIGNING_TAG = b'concord-case-authority-signing-v1'
MAX_OUTPUTS = 16
BASE_FIELDS = {'format', 'kind', 'id', 'genesis_hash', 'authority', 'authority_key', 'case_reference', 'reason', 'issued_at'}
HEX32 = re.compile('[0-9a-f]{64}')
HEX16 = re.compile('[0-9a-f]{32}')
REFERENCE = re.compile('[a-z0-9._-]{1,64}@[a-z0-9._-]{1,64}')
# Fields beyond the base, by kind. A quarantine moves every output of one
# active freeze into quarantine; a restore pays one quarantine to the account
# a member bank's reference names.
KIND_FIELDS = {'freeze': {'outputs'}, 'release': {'releases'}, 'quarantine': {'freeze'},
               'restore': {'quarantine', 'destination'}}


def tagged_hash(tag, data):
    prefix = hashlib.sha256(tag).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def case_authority_secret(recipient_secret):
    """Order-signing scalar for the holder of a disclosure recipient key."""
    if type(recipient_secret) is not int or not 0 < recipient_secret < ORDER:
        raise ValueError('invalid recipient secret')
    value = int.from_bytes(tagged_hash(SIGNING_TAG, recipient_secret.to_bytes(32, 'big')), 'big') % ORDER
    if value == 0:
        raise ValueError('derived case-authority key is zero')
    return value


def outpoint(txid, vout):
    return f'{txid}:{vout}'


def validate(order, genesis_hash, *, now=None):
    """Return the order's outpoints (freeze) or the order it releases (release)."""
    if not isinstance(order, dict):
        raise ValueError('freeze order must be an object')
    kind = order.get('kind')
    if kind not in KIND_FIELDS or set(order) != BASE_FIELDS | KIND_FIELDS[kind]:
        raise ValueError('freeze order has unknown kind or fields')
    if order['format'] != FORMAT or order['genesis_hash'] != genesis_hash:
        raise ValueError('freeze order is for another format or chain')
    if not isinstance(order['id'], str) or HEX16.fullmatch(order['id']) is None:
        raise ValueError('freeze order needs a 32-character hex ID')
    if not isinstance(order['authority_key'], str) or HEX32.fullmatch(order['authority_key']) is None:
        raise ValueError('freeze order names an invalid authority key')
    for name, low, high in (('authority', 2, 160), ('case_reference', 1, 200), ('reason', 8, 1000)):
        if not isinstance(order[name], str) or not low <= len(order[name].strip()) <= high:
            raise ValueError(f'freeze order {name.replace("_", " ")} is missing or too long')
    issued = order['issued_at']
    if type(issued) is not int or issued <= 0 or issued > (now if now is not None else time.time()) + 300:
        raise ValueError('freeze order has an invalid issue time')
    if kind in ('release', 'quarantine', 'restore'):
        named = order[{'release': 'releases', 'quarantine': 'freeze', 'restore': 'quarantine'}[kind]]
        if not isinstance(named, str) or HEX16.fullmatch(named) is None:
            raise ValueError(f'{kind} order must name the order it acts on')
        if kind == 'restore' and (not isinstance(order['destination'], str)
                                  or REFERENCE.fullmatch(order['destination']) is None):
            raise ValueError('restore order needs a destination bank reference, such as acme-main@bank')
        return named
    outputs = order['outputs']
    if not isinstance(outputs, list) or not 1 <= len(outputs) <= MAX_OUTPUTS:
        raise ValueError(f'freeze order must name 1 to {MAX_OUTPUTS} outputs')
    result = []
    for item in outputs:
        if (not isinstance(item, dict) or set(item) != {'txid', 'vout'} or not isinstance(item['txid'], str)
                or HEX32.fullmatch(item['txid']) is None or type(item['vout']) is not int or not 0 <= item['vout'] <= 65535):
            raise ValueError('freeze order names an invalid output')
        result.append(outpoint(item['txid'], item['vout']))
    if len(set(result)) != len(result):
        raise ValueError('freeze order names an output twice')
    return result


def order_digest(order):
    return hashlib.sha256(ORDER_DOMAIN + canonical(order)).digest()


def verify(curve, trusted_keys, order, signature):
    """Check the order is signed by a configured case authority; return its name."""
    names = {key: name for name, key in (trusted_keys or {}).items()}
    if order['authority_key'] not in names:
        raise ValueError('freeze order is not from a trusted case authority')
    try:
        raw = bytes.fromhex(signature)
    except (TypeError, ValueError):
        raw = b''
    if not curve.verify_signature(bytes.fromhex(order['authority_key']), order_digest(order), raw):
        raise ValueError('freeze order signature is invalid')
    return names[order['authority_key']]


def receipt_digest(order, guardian_id):
    """What an operator signs to show it applied this exact order."""
    return hashlib.sha256(RECEIPT_DOMAIN + order_digest(order) + guardian_id.encode()).digest()


def sign(curve, secret, order):
    return curve.sign(secret, order_digest(order)).hex()


def quarantine_case(order_id):
    """The 32-byte case reference a quarantine order's outputs carry."""
    return hashlib.sha256(b'CEND/quarantine/' + order_id.encode()).digest()
