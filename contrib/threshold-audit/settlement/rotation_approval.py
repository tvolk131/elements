"""Independent institutional authorization for a same-chain membership change.

The manifest contains public membership/configuration and exact migration
transaction hashes. It never contains spending keys, decryption shares or API
credentials. This domain is separate from monetary operation approvals.
"""

import hashlib
import time
from .approval import canonical

DOMAIN = b'ElementsInstitutionalFederationRotation/v1\x00'
FIELDS = ('kind', 'id', 'chain', 'genesis_hash', 'source_policy_version',
          'target_policy_version', 'expires_at', 'manifest')


def rotation_payload(operation):
    result = {key: operation[key] for key in FIELDS}
    if result['kind'] != 'federation_rotation':
        raise ValueError('not a federation rotation authorization')
    if (not isinstance(result['id'], str) or not result['id']
            or type(result['expires_at']) is not int
            or not isinstance(result['manifest'], dict)
            or result['source_policy_version'] == result['target_policy_version']):
        raise ValueError('invalid federation rotation authorization')
    if len(canonical(result)) > 120_000:
        raise ValueError('rotation manifest exceeds sandbox bound')
    return result


def rotation_digest(operation):
    return hashlib.sha256(DOMAIN + canonical(rotation_payload(operation))).digest()


def sign_rotation(curve, guardian_id, secret, operation):
    digest = rotation_digest(operation)
    return {'guardian_id': guardian_id, 'payload_hash': digest.hex(),
            'signature': curve.sign(secret, digest).hex()}


class RotationVerifier:
    def __init__(self, curve, public_keys, threshold, source_policy_version):
        self.curve, self.public_keys = curve, dict(public_keys)
        self.threshold, self.source_policy_version = threshold, source_policy_version
        if (type(threshold) is not int or not 1 <= threshold <= len(self.public_keys)
                or len(set(self.public_keys.values())) != len(self.public_keys)):
            raise ValueError('invalid source rotation quorum')

    def verify_one(self, operation, signature):
        try:
            guardian = signature['guardian_id']
            digest = rotation_digest(operation)
            return (operation['source_policy_version'] == self.source_policy_version
                    and guardian in self.public_keys
                    and signature['payload_hash'] == digest.hex()
                    and self.curve.verify_signature(bytes.fromhex(self.public_keys[guardian]), digest,
                                                    bytes.fromhex(signature['signature'])))
        except (ValueError, KeyError, TypeError):
            return False

    def certificate(self, operation, signatures, *, now=None, allow_expired=False):
        now = int(time.time()) if now is None else now
        if operation['source_policy_version'] != self.source_policy_version:
            raise ValueError('unexpected source federation approval policy')
        if not allow_expired and operation['expires_at'] <= now:
            raise ValueError('federation rotation authorization expired')
        valid = {}
        for signature in signatures:
            if not self.verify_one(operation, signature):
                raise ValueError('invalid federation rotation signature')
            guardian = signature['guardian_id']
            if guardian in valid:
                raise ValueError('duplicate federation rotation signature')
            valid[guardian] = signature
        if len(valid) < self.threshold:
            raise ValueError('source federation rotation quorum not reached')
        return {'version': 1, 'payload': rotation_payload(operation),
                'payload_hash': rotation_digest(operation).hex(),
                'signatures': [valid[key] for key in sorted(valid)]}

    def verify_certificate(self, operation, certificate, **kwargs):
        if not isinstance(certificate, dict) or certificate.get('version') != 1 or certificate.get('payload') != rotation_payload(operation):
            raise ValueError('rotation certificate does not match this manifest')
        checked = self.certificate(operation, certificate.get('signatures', []), **kwargs)
        if checked['payload_hash'] != certificate.get('payload_hash'):
            raise ValueError('rotation certificate has wrong digest')
        return checked
