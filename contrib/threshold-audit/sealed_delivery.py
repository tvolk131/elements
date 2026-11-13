"""Recipient-encrypted research disclosure transport; not a new threshold scheme.

ECDH(secp256k1), HKDF-SHA256 and AES-256-GCM protect each partial independently.
The signed request binds the recipient, output and case. A relay sees ciphertext.
This does not restrict a colluding recovery quorum or revoke delivered packages.
"""

import json
import secrets
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from recovery import digest, index_bytes


INFO = b'Elements/threshold-audit/sealed-partial/v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def context(request_binding, member, recipient):
    return digest(b'sealed-partial', request_binding, index_bytes(member), recipient)


def envelope_digest(envelope):
    return digest(b'sealed-partial-envelope', canonical({k: v for k, v in envelope.items() if k != 'signature'}))


def seal(curve, identity_secret, recipient, request_binding, member, payload):
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), recipient)
    ephemeral = ec.generate_private_key(ec.SECP256K1())
    aad = context(request_binding, member, recipient)
    shared = ephemeral.exchange(ec.ECDH(), key)
    aes = HKDF(algorithm=hashes.SHA256(), length=32, salt=aad, info=INFO).derive(shared)
    nonce = secrets.token_bytes(12)
    envelope = {'scheme': 'secp256k1-hkdf-aesgcm-v1', 'member': member,
                'released_at': int(time.time()),
                'request_binding': request_binding.hex(), 'recipient_key': recipient.hex(),
                'ephemeral_key': ephemeral.public_key().public_bytes(serialization.Encoding.X962,
                    serialization.PublicFormat.CompressedPoint).hex(),
                'nonce': nonce.hex(), 'ciphertext': AESGCM(aes).encrypt(nonce, canonical(payload), aad).hex()}
    envelope['signature'] = curve.sign(identity_secret, envelope_digest(envelope)).hex()
    return envelope


def unseal(curve, secret, identity_public, envelope, request_binding, member):
    recipient = curve.mul(secret)
    if (envelope.get('scheme') != 'secp256k1-hkdf-aesgcm-v1'
            or envelope.get('recipient_key') != recipient.hex()
            or envelope.get('request_binding') != request_binding.hex()
            or envelope.get('member') != member
            or not curve.verify_signature(identity_public, envelope_digest(envelope), bytes.fromhex(envelope['signature']))):
        raise ValueError('sealed partial does not match its guardian, recipient or request')
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(envelope['ephemeral_key']))
    shared = ec.derive_private_key(secret, ec.SECP256K1()).exchange(ec.ECDH(), peer)
    aad = context(request_binding, member, recipient)
    aes = HKDF(algorithm=hashes.SHA256(), length=32, salt=aad, info=INFO).derive(shared)
    return json.loads(AESGCM(aes).decrypt(bytes.fromhex(envelope['nonce']), bytes.fromhex(envelope['ciphertext']), aad))
