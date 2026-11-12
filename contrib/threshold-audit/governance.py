# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Python reference model for the experimental native audit-governance rules.

Block validity/signatures, UTXOs, networking and secure key ceremonies remain
outside this model. Readiness proves participation now, not future availability,
exclusive possession, share erasure or an inability to bypass disclosure logs.
"""

from dataclasses import dataclass

from curve import G, scalar_bytes
from recovery import canonical_proof, digest, dleq_prove, dleq_verify, index_bytes
from threshold import Committee, validate_roster, validate_share

MAGIC = b'TAG1'
MAX_KEYS = 16
MAX_MEMBERS = 32
MAX_CONFIG_BYTES = 4 + 4 + 4 + 32 + 1 + 36 * MAX_MEMBERS + 1 + MAX_KEYS * (12 + 37 * MAX_MEMBERS)


def uint(value, bits, *, nonzero=False):
    if type(value) is not int or not int(nonzero) <= value < 1 << bits:
        raise ValueError('noncanonical unsigned integer')
    return value.to_bytes(bits // 8, 'big')


def hash32(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError('expected a 32-byte digest')
    return value


@dataclass(frozen=True)
class AuditKey:
    version: int
    scheme: int
    committee: Committee

    @property
    def public_key(self):
        return self.committee.public_key

    def validate(self, curve):
        uint(self.version, 32, nonzero=True)
        uint(self.scheme, 16, nonzero=True)
        self.committee.validate(curve)


@dataclass(frozen=True)
class AuditConfig:
    generation: int
    signer_policy: bytes  # Digest of the proposed block-signing authorization.
    identities: tuple  # (institution ID, independent BIP340 identity key).
    active_version: int
    keys: tuple  # Includes EVERY historical key, with its CURRENT committee.

    def _shape(self):
        uint(self.generation, 32)
        uint(self.active_version, 32, nonzero=True)
        hash32(self.signer_policy)
        if not isinstance(self.identities, tuple):
            raise ValueError('identity roster must be a tuple')
        members = tuple(i for i, _ in self.identities)
        validate_roster(members, 1)
        if any(not isinstance(key, bytes) or len(key) != 32 for _, key in self.identities):
            raise ValueError('invalid institution identity key')
        if len({key for _, key in self.identities}) != len(self.identities):
            raise ValueError('duplicate institution identity keys')
        if not isinstance(self.keys, tuple) or not 1 <= len(self.keys) <= MAX_KEYS:
            raise ValueError('invalid historical key count')
        versions = tuple(key.version for key in self.keys)
        if versions != tuple(range(1, len(self.keys) + 1)) or self.active_version not in versions:
            raise ValueError('key versions must be contiguous, unique and ordered')
        for key in self.keys:
            if not isinstance(key, AuditKey) or not isinstance(key.committee, Committee):
                raise ValueError('invalid audit key descriptor')
            uint(key.version, 32, nonzero=True)
            uint(key.scheme, 16, nonzero=True)
            uint(key.committee.epoch, 32)
            if not isinstance(key.committee.commitments, tuple):
                raise ValueError('coefficient commitments must be an immutable tuple')
            validate_roster(key.committee.members, key.committee.threshold)
            if key.committee.members != members:
                raise ValueError('every retained key must belong to the current institution roster')
            if any(not isinstance(p, bytes) or len(p) != 33 for p in key.committee.commitments):
                raise ValueError('invalid coefficient commitment length')

    def validate(self, curve):
        self._shape()
        for _, public_key in self.identities:
            curve.parse(b'\x02' + public_key, allow_infinity=False)
        for key in self.keys:
            key.validate(curve)

    def key(self, version):
        if type(version) is not int:
            raise ValueError('noncanonical key version')
        for key in self.keys:
            if key.version == version:
                return key
        raise ValueError('unknown key version')

    @property
    def active_key(self):
        return self.key(self.active_version)

    def to_bytes(self):
        self._shape()
        out = bytearray(MAGIC + uint(self.generation, 32) + uint(self.active_version, 32)
                        + self.signer_policy + uint(len(self.identities), 8))
        for member, identity in self.identities:
            out.extend(uint(member, 32, nonzero=True) + identity)
        out.extend(uint(len(self.keys), 8))
        for key in self.keys:
            committee = key.committee
            out.extend(uint(key.version, 32) + uint(key.scheme, 16) + uint(committee.epoch, 32)
                       + uint(committee.threshold, 8) + uint(len(committee.members), 8))
            out.extend(b''.join(uint(i, 32) for i in committee.members))
            out.extend(b''.join(committee.commitments))
        return bytes(out)

    @staticmethod
    def from_bytes(data, curve):
        if not isinstance(data, bytes) or not 46 <= len(data) <= MAX_CONFIG_BYTES or data[:4] != MAGIC:
            raise ValueError('invalid audit-config format or size')
        offset = 4

        def take(size):
            nonlocal offset
            if offset + size > len(data):
                raise ValueError('truncated audit config')
            value = data[offset:offset + size]
            offset += size
            return value

        def number(size):
            return int.from_bytes(take(size), 'big')

        generation, active, signer = number(4), number(4), take(32)
        count = number(1)
        if not 1 <= count <= MAX_MEMBERS:
            raise ValueError('invalid identity count')
        identities = tuple((number(4), take(32)) for _ in range(count))
        key_count = number(1)
        if not 1 <= key_count <= MAX_KEYS:
            raise ValueError('invalid historical key count')
        keys = []
        for _ in range(key_count):
            version, scheme, epoch, threshold, size = number(4), number(2), number(4), number(1), number(1)
            if not 1 <= threshold <= size <= MAX_MEMBERS:
                raise ValueError('invalid committee dimensions')
            members = tuple(number(4) for _ in range(size))
            commitments = tuple(take(33) for _ in range(threshold))
            keys.append(AuditKey(version, scheme, Committee(epoch, members, commitments)))
        if offset != len(data):
            raise ValueError('trailing audit-config bytes')
        config = AuditConfig(generation, signer, identities, active, tuple(keys))
        config.validate(curve)
        return config

    def binding(self):
        return digest(b'audit-config', self.to_bytes())


@dataclass(frozen=True)
class Transition:
    previous: bytes
    activation_height: int
    config: AuditConfig

    def binding(self, chain_id):
        return digest(b'audit-transition', hash32(chain_id), hash32(self.previous),
                      uint(self.activation_height, 32, nonzero=True), self.config.binding())


@dataclass(frozen=True)
class Readiness:
    version: int
    member: int
    possession_proof: tuple
    signature: bytes

    def to_bytes(self):
        if not canonical_proof((self.possession_proof,), 1) or not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError('invalid readiness encoding')
        return (uint(self.version, 32, nonzero=True) + uint(self.member, 32, nonzero=True)
                + b''.join(scalar_bytes(v) for v in self.possession_proof) + self.signature)


def readiness_context(chain_id, transition, version, member):
    return digest(b'audit-readiness', transition.binding(chain_id), uint(version, 32, nonzero=True),
                  uint(member, 32, nonzero=True))


def make_readiness(curve, chain_id, transition, version, share, identity_secret):
    transition.config.validate(curve)
    key = transition.config.key(version)
    validate_share(curve, key.committee, share)
    identities = dict(transition.config.identities)
    if curve.mul(identity_secret)[1:] != identities[share.member]:
        raise ValueError('identity secret does not match proposed institution')
    context = readiness_context(chain_id, transition, version, share.member)
    public_share = key.committee.verification_key(curve, share.member)
    proof = dleq_prove(curve, G, G, public_share, public_share, share.value, context)
    signature = curve.sign(identity_secret, digest(b'audit-ready-signature', context,
                                                  b''.join(scalar_bytes(v) for v in proof)))
    return Readiness(version, share.member, proof, signature)


@dataclass(frozen=True)
class PreparedTransition:
    transition: Transition
    readiness: tuple  # Canonically ordered public certificate; no private shares.

    def vote_root(self, chain_id):
        return digest(b'audit-prepared-transition', self.transition.binding(chain_id),
                      b''.join(ready.to_bytes() for ready in self.readiness))


def verify_readiness(curve, chain_id, prepared):
    config = prepared.transition.config
    config.validate(curve)
    if not isinstance(prepared.readiness, tuple) or not 1 <= len(prepared.readiness) <= MAX_KEYS * MAX_MEMBERS:
        raise ValueError('invalid readiness certificate size')
    pairs = tuple((r.version, r.member) for r in prepared.readiness)
    if tuple(sorted(set(pairs))) != pairs:
        raise ValueError('readiness entries must be ordered and distinct')
    identities = dict(config.identities)
    counts = {key.version: 0 for key in config.keys}
    for ready in prepared.readiness:
        ready.to_bytes()
        key = config.key(ready.version)
        if ready.member not in identities:
            raise ValueError('unknown readiness signer')
        context = readiness_context(chain_id, prepared.transition, ready.version, ready.member)
        public_share = key.committee.verification_key(curve, ready.member)
        if not dleq_verify(curve, G, G, public_share, public_share, ready.possession_proof, context):
            raise ValueError('invalid readiness share-possession proof')
        signature_message = digest(b'audit-ready-signature', context,
                                   b''.join(scalar_bytes(v) for v in ready.possession_proof))
        if not curve.verify_signature(identities[ready.member], signature_message, ready.signature):
            raise ValueError('invalid institution readiness signature')
        counts[ready.version] += 1
    if any(counts[key.version] < key.committee.threshold for key in config.keys):
        raise ValueError('each retained key needs a distinct ready quorum')


@dataclass(frozen=True)
class BlockRecord:
    height: int
    block_id: bytes
    config: AuditConfig
    vote: object


@dataclass(frozen=True)
class OutputReference:
    creation_block: bytes
    key_version: int
    scheme: int
    public_key: bytes


class AuditChain:
    """A bounded in-memory model of DynaFed-aligned public audit governance.

    connect() assumes its caller already checked the block-signing script. It
    does not implement a node, a P2P wire protocol, transaction checks, or finality.
    """

    def __init__(self, curve, chain_id, genesis_config, epoch_length=10, supported_schemes=(1,)):
        self.curve = curve
        self.chain_id = hash32(chain_id)
        if type(epoch_length) is not int or not 2 <= epoch_length <= 100000:
            raise ValueError('invalid epoch length')
        if not isinstance(supported_schemes, tuple) or not supported_schemes:
            raise ValueError('supported scheme IDs must be a nonempty tuple')
        for scheme in supported_schemes:
            uint(scheme, 16, nonzero=True)
        if tuple(sorted(set(supported_schemes))) != supported_schemes:
            raise ValueError('supported scheme IDs must be unique and ordered')
        self.epoch_length, self.supported_schemes = epoch_length, supported_schemes
        self._validate_config(genesis_config)
        if genesis_config.generation != 0:
            raise ValueError('genesis audit generation must be zero')
        if (len(genesis_config.keys) != 1 or genesis_config.active_version != 1
                or genesis_config.active_key.committee.epoch != 0):
            raise ValueError('genesis must initialize one active audit key at share epoch zero')
        block_id = digest(b'audit-model-genesis', self.chain_id, genesis_config.binding())
        self.blocks = [BlockRecord(0, block_id, genesis_config, None)]

    @property
    def height(self):
        return self.blocks[-1].height

    @property
    def current(self):
        return self.blocks[-1].config

    def _validate_config(self, config):
        config.validate(self.curve)
        if any(key.scheme not in self.supported_schemes for key in config.keys):
            raise ValueError('unsupported recovery scheme')

    def _validate_transition(self, prepared, previous, activation_height):
        transition, proposed = prepared.transition, prepared.transition.config
        self._validate_config(proposed)
        if transition.previous != previous.binding() or proposed.generation != previous.generation + 1:
            raise ValueError('transition does not extend current audit configuration')
        if transition.activation_height != activation_height:
            raise ValueError('incorrect activation boundary')
        if len(proposed.keys) not in (len(previous.keys), len(previous.keys) + 1):
            raise ValueError('historical audit keys cannot be deleted')
        for old_key in previous.keys:
            new_key = proposed.key(old_key.version)
            if new_key.public_key != old_key.public_key or new_key.scheme != old_key.scheme:
                raise ValueError('historical key identity or scheme changed')
            if new_key.committee != old_key.committee and new_key.committee.epoch != old_key.committee.epoch + 1:
                raise ValueError('handoff must increment the share epoch exactly once')
        if len(proposed.keys) == len(previous.keys):
            if proposed.active_version != previous.active_version:
                raise ValueError('cannot reactivate a historical-only key')
        else:
            new_key = proposed.keys[-1]
            if proposed.active_version != new_key.version or new_key.committee.epoch != 0:
                raise ValueError('new audit key must start a fresh active version and share epoch')
            if new_key.public_key in {key.public_key for key in previous.keys}:
                raise ValueError('rollover requires a fresh public audit key')
        verify_readiness(self.curve, self.chain_id, prepared)

    def _winner(self, activation_height):
        if activation_height % self.epoch_length:
            return None
        threshold = self.epoch_length - self.epoch_length // 5
        tally = {}
        for block in self.blocks[activation_height - self.epoch_length:activation_height]:
            if block.vote is not None:
                root = block.vote.vote_root(self.chain_id)
                count = tally.get(root, 0) + 1
                tally[root] = count
                if count >= threshold:
                    return block.vote
        return None

    def next_config(self):
        winner = self._winner(self.height + 1)
        if winner is None:
            return self.current
        self._validate_transition(winner, self.current, self.height + 1)
        return winner.transition.config

    def connect(self, vote=None):
        height = self.height + 1
        uint(height, 32, nonzero=True)
        current = self.next_config()
        if vote is not None:
            boundary = (height // self.epoch_length + 1) * self.epoch_length
            self._validate_transition(vote, current, boundary)
        block_id = digest(b'audit-model-block', self.blocks[-1].block_id, index_bytes(height),
                          current.binding(), b'' if vote is None else vote.vote_root(self.chain_id))
        record = BlockRecord(height, block_id, current, vote)
        self.blocks.append(record)
        return record

    def disconnect(self):
        if self.height == 0:
            raise ValueError('cannot disconnect genesis')
        return self.blocks.pop()

    def require_new_output(self, version, scheme, public_key):
        """Policy for inclusion in the NEXT block, including a pending boundary."""
        uint(version, 32, nonzero=True)
        uint(scheme, 16, nonzero=True)
        key = self.next_config().active_key
        if (version, scheme, public_key) != (key.version, key.scheme, key.public_key):
            raise ValueError('new output uses a stale or unauthorized audit key')

    def output_reference(self, creation_height):
        """Create only a policy reference, not evidence that an output exists."""
        if type(creation_height) is not int or not 0 <= creation_height <= self.height:
            raise ValueError('unknown creation height')
        block = self.blocks[creation_height]
        key = block.config.active_key
        return OutputReference(block.block_id, key.version, key.scheme, key.public_key)

    def historical_key(self, reference):
        """Validate creation policy, then select CURRENT shares for that key."""
        matching = [b for b in self.blocks if b.block_id == reference.creation_block]
        if len(matching) != 1:
            raise ValueError('creation block is not in the active chain')
        uint(reference.key_version, 32, nonzero=True)
        uint(reference.scheme, 16, nonzero=True)
        created = matching[0].config.active_key
        if (reference.key_version, reference.scheme, reference.public_key) != (
                created.version, created.scheme, created.public_key):
            raise ValueError('historical output did not use its creation policy')
        return self.current.key(reference.key_version)
