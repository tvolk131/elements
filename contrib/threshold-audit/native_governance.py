# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Public governance encodings shared with the experimental native custom chain.

Requires the functional-test serializer on sys.path. No private shares are
serialized here; readiness creation remains in governance.py/guardian services.
"""

import struct

from governance import MAX_KEYS, MAX_MEMBERS, PreparedTransition, Readiness, Transition, uint
from test_framework.messages import hash256, ser_compact_size, ser_string, ser_string_vector

PREPARED_MAGIC = b'TAP1'
MAX_PREPARED_BYTES = 4 + 32 + 4 + 2 + MAX_KEYS * MAX_MEMBERS * 136


def policy_binding(signblockscript, max_block_witness, fedpeg_program, fedpegscript, extension_space,
                   audit_assets=(), audit_assets_version=0, tx_authorization=b''):
    """Native PolicyBinding, including registered asset sets after genesis.

    Asset IDs are raw 32-byte values, not RPC display hex. Version zero is
    immutable chain configuration; omitting it avoids the default-policy-asset
    dependency on the genesis hash, which itself commits the initial TAG1.
    """
    if type(audit_assets_version) is not int or not 0 <= audit_assets_version <= 0xffffffff:
        raise ValueError('invalid audit registry version')
    encoded = (ser_string(signblockscript) + struct.pack('<I', max_block_witness)
               + ser_string(fedpeg_program) + ser_string(fedpegscript)
               + ser_string_vector(extension_space))
    if audit_assets_version:
        assets = tuple(audit_assets)
        if (not 1 <= len(assets) <= 256 or any(not isinstance(asset, bytes) or len(asset) != 32
                                             or asset == bytes(32) for asset in assets)
                or tuple(sorted(set(assets))) != assets):
            raise ValueError('audit assets must be bounded, nonzero, sorted and distinct')
        encoded += (ser_string(b'threshold-audit-assets-v1') + struct.pack('<I', audit_assets_version)
                    + ser_compact_size(len(assets)) + b''.join(assets))
    if tx_authorization:
        # Bound only once set, as in the node, so earlier bindings are unchanged.
        encoded += ser_string(b'tx-authorization-v1') + ser_string(tx_authorization)
    return hash256(encoded)


def prepared_to_bytes(prepared):
    if not isinstance(prepared, PreparedTransition):
        raise ValueError('expected a prepared audit transition')
    transition = prepared.transition
    if not isinstance(transition.previous, bytes) or len(transition.previous) != 32:
        raise ValueError('invalid predecessor configuration hash')
    if not 1 <= len(prepared.readiness) <= MAX_KEYS * MAX_MEMBERS:
        raise ValueError('invalid readiness certificate count')
    pairs = tuple((entry.version, entry.member) for entry in prepared.readiness)
    if tuple(sorted(set(pairs))) != pairs:
        raise ValueError('readiness entries must be ordered and distinct')
    return (PREPARED_MAGIC + transition.previous + uint(transition.activation_height, 32, nonzero=True)
            + uint(len(prepared.readiness), 16) + b''.join(entry.to_bytes() for entry in prepared.readiness))


def prepared_from_bytes(data, config):
    if (not isinstance(data, bytes) or not 42 <= len(data) <= MAX_PREPARED_BYTES
            or data[:4] != PREPARED_MAGIC):
        raise ValueError('invalid prepared transition format')
    count = int.from_bytes(data[40:42], 'big')
    if not 1 <= count <= MAX_KEYS * MAX_MEMBERS or len(data) != 42 + count * 136:
        raise ValueError('invalid prepared transition length')
    entries = []
    for offset in range(42, len(data), 136):
        row = data[offset:offset + 136]
        entries.append(Readiness(int.from_bytes(row[:4], 'big'), int.from_bytes(row[4:8], 'big'),
                                 (int.from_bytes(row[8:40], 'big'), int.from_bytes(row[40:72], 'big')),
                                 row[72:136]))
    result = PreparedTransition(Transition(data[4:36], int.from_bytes(data[36:40], 'big'), config), tuple(entries))
    # Re-encoding checks scalar canonicality, ordering, positive IDs and boundary.
    if prepared_to_bytes(result) != data:
        raise ValueError('noncanonical prepared transition')
    return result
