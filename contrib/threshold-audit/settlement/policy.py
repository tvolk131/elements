"""Public federation policy parsing, with no service credentials or key shares.

This is the common boundary used by adapters, handover manifests and signers.
It preserves the existing canonical JSON/wire values rather than introducing a
new cryptographic encoding.
"""

from dataclasses import dataclass
import hashlib
import re

from test_framework.script import CScript, OP_CHECKMULTISIG


POLICY_FIELDS = ('policy_version', 'approval_public_keys', 'threshold', 'guardian_order',
                 'treasury_script', 'witness_script', 'treasury_address',
                 'block_signing_script', 'block_witness_script', 'block_public_keys')
BLOCK_FIELDS = ('block_signing_script', 'block_witness_script', 'block_public_keys')


def policy_epoch(version):
    match = re.fullmatch(r'sandbox-v([1-9][0-9]*)', version) if isinstance(version, str) else None
    if match is None or int(match.group(1)) > 0xffffffff:
        raise ValueError('invalid federation policy version')
    return int(match.group(1))


@dataclass(frozen=True)
class PublicFederationPolicy:
    version: str
    threshold: int
    members: tuple
    approval_keys: tuple
    witness_script: str
    treasury_script: str
    treasury_address: str
    block_keys: tuple = ()
    block_witness_script: str = ''
    block_signing_script: str = ''

    @classmethod
    def parse(cls, value):
        version = value['policy_version']
        policy_epoch(version)
        threshold, members = value['threshold'], tuple(value['guardian_order'])
        if (type(threshold) is not int or not 1 <= threshold <= len(members) <= 15
                or any(not isinstance(member, str) or not member for member in members)
                or len(set(members)) != len(members)):
            raise ValueError('invalid treasury quorum')
        witness = bytes.fromhex(value['witness_script'])
        if bytes.fromhex(value['treasury_script']) != b'\x00\x20' + hashlib.sha256(witness).digest():
            raise ValueError('treasury program does not match its witness script')
        script = list(CScript(witness))
        if (len(script) != len(members) + 3 or script[0] != threshold
                or script[-2] != len(members) or script[-1] != OP_CHECKMULTISIG
                or len(set(script[1:-2])) != len(members)
                or set(value['approval_public_keys']) != set(members)):
            raise ValueError('treasury witness does not match operator roster')
        approval = tuple((member, value['approval_public_keys'][member]) for member in members)
        encoded = [bytes.fromhex(key) for _, key in approval]
        if len(set(encoded)) != len(members) or any(len(key) != 32 for key in encoded):
            raise ValueError('operator approval keys must be distinct x-only public keys')
        if any(not isinstance(key, bytes) or len(key) != 33 or key[0] not in (2, 3) for key in script[1:-2]):
            raise ValueError('treasury members must use compressed public keys')
        address = value['treasury_address']
        if not isinstance(address, str) or not address:
            raise ValueError('treasury address is required')
        block_keys, block_witness, block_script = (), '', ''
        if any(key in value for key in BLOCK_FIELDS):
            if not all(key in value for key in BLOCK_FIELDS) or set(value['block_public_keys']) != set(members):
                raise ValueError('block policy must describe the complete operator roster')
            block_keys = tuple((member, value['block_public_keys'][member]) for member in members)
            public = [bytes.fromhex(key) for _, key in block_keys]
            if (len(set(public)) != len(members)
                    or any(len(key) != 33 or key[0] not in (2, 3) for key in public)):
                raise ValueError('block signing keys must be distinct compressed public keys')
            block_witness = value['block_witness_script']
            block_script = value['block_signing_script']
            expected = bytes(CScript([threshold, *public, len(members), OP_CHECKMULTISIG]))
            if (bytes.fromhex(block_witness) != expected
                    or bytes.fromhex(block_script) != b'\x00\x20' + hashlib.sha256(expected).digest()):
                raise ValueError('block signing program or keys differ from operator roster')
        return cls(version, threshold, members, approval, value['witness_script'],
                   value['treasury_script'], address, block_keys, block_witness, block_script)

    def to_dict(self):
        result = {'policy_version': self.version, 'threshold': self.threshold,
                  'guardian_order': list(self.members), 'approval_public_keys': dict(self.approval_keys),
                  'witness_script': self.witness_script, 'treasury_script': self.treasury_script,
                  'treasury_address': self.treasury_address}
        if self.block_keys:
            result.update(block_public_keys=dict(self.block_keys), block_witness_script=self.block_witness_script,
                          block_signing_script=self.block_signing_script)
        return result


def public_policy(config):
    result = {key: config[key] for key in POLICY_FIELDS if key in config}
    result.setdefault('policy_version', 'sandbox-v1')
    return PublicFederationPolicy.parse(result).to_dict()


def validate_policy(policy):
    PublicFederationPolicy.parse(policy)
    return policy


def validate_successor(source, target):
    validate_policy(source)
    validate_policy(target)
    if policy_epoch(target['policy_version']) != policy_epoch(source['policy_version']) + 1:
        raise ValueError('federation policy must advance exactly one epoch')
    return target
