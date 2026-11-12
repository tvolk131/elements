# Copyright (c) 2026 The Elements Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Research-only ctypes adapter to this checkout's libsecp256k1-zkp.

Python secrets, arithmetic and allocations here are NOT suitable for production
key handling. Points use compressed SEC encoding; 33 zero bytes encode infinity
inside this experiment only. No opaque native struct is serialized.
"""

import ctypes as C
import hashlib
import secrets

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD = 2**256 - 2**32 - 977
INF = bytes(33)
G = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')


def scalar_bytes(value):
    if type(value) is not int or not 0 <= value < ORDER:
        raise ValueError('noncanonical scalar')
    return value.to_bytes(32, 'big')


def random_scalar():
    return secrets.randbelow(ORDER - 1) + 1


class Curve:
    def __init__(self, library):
        self.lib = C.CDLL(str(library))
        p, size = C.c_void_p, C.c_size_t
        signatures = {
            'context_create': ([C.c_uint], p),
            'context_destroy': ([p], None),
            'context_randomize': ([p, p], C.c_int),
            'ec_pubkey_parse': ([p, p, p, size], C.c_int),
            'ec_pubkey_serialize': ([p, p, p, p, C.c_uint], C.c_int),
            'ec_pubkey_create': ([p, p, p], C.c_int),
            'ec_pubkey_tweak_mul': ([p, p, p], C.c_int),
            'ec_pubkey_combine': ([p, p, p, size], C.c_int),
            'keypair_create': ([p, p, p], C.c_int),
            'xonly_pubkey_parse': ([p, p, p], C.c_int),
            'schnorrsig_sign32': ([p, p, p, p, p], C.c_int),
            'schnorrsig_verify': ([p, p, p, size, p], C.c_int),
            'generator_generate': ([p, p, p], C.c_int),
            'generator_generate_blinded': ([p, p, p, p], C.c_int),
            'generator_parse': ([p, p, p], C.c_int),
            'generator_serialize': ([p, p, p], C.c_int),
            'pedersen_commit': ([p, p, p, C.c_uint64, p], C.c_int),
            'pedersen_commitment_parse': ([p, p, p], C.c_int),
            'pedersen_commitment_serialize': ([p, p, p], C.c_int),
            'rangeproof_sign': ([p, p, p, C.c_uint64, p, p, p, C.c_int,
                                 C.c_int, C.c_uint64, p, size, p, size, p], C.c_int),
            'rangeproof_verify': ([p, p, p, p, p, size, p, size, p], C.c_int),
            'rangeproof_rewind': ([p, p, p, p, p, p, p, p, p, p, size,
                                  p, size, p], C.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, 'secp256k1_' + name)
            function.argtypes, function.restype = args, result
            setattr(self, '_' + name, function)
        self.ctx = self._context_create(1)  # SECP256K1_CONTEXT_NONE
        if not self.ctx:
            raise RuntimeError('cannot create secp256k1 context')
        if not self._context_randomize(self.ctx, secrets.token_bytes(32)):
            raise RuntimeError('cannot randomize secp256k1 context')

    def close(self):
        if self.ctx:
            self._context_destroy(self.ctx)
            self.ctx = None

    def parse(self, point, *, allow_infinity=True):
        if not isinstance(point, bytes) or len(point) != 33:
            raise ValueError('expected a 33-byte point')
        if point == INF:
            if allow_infinity:
                return None
            raise ValueError('infinity is forbidden here')
        native = C.create_string_buffer(64)
        if not self._ec_pubkey_parse(self.ctx, native, point, len(point)):
            raise ValueError('invalid curve point')
        return native

    def _serialize(self, native):
        out, length = C.create_string_buffer(33), C.c_size_t(33)
        if not self._ec_pubkey_serialize(self.ctx, out, C.byref(length), native, 258):
            raise ValueError('cannot serialize point')
        return out.raw

    def add(self, *points):
        native = [self.parse(point) for point in points if point != INF]
        if not native:
            return INF
        if len(native) == 1:
            return self._serialize(native[0])
        pointers = (C.c_void_p * len(native))(*(C.addressof(point) for point in native))
        out = C.create_string_buffer(64)
        if not self._ec_pubkey_combine(self.ctx, out, pointers, len(native)):
            return INF  # All inputs were valid: their sum is infinity.
        return self._serialize(out)

    @staticmethod
    def neg(point):
        return INF if point == INF else bytes([point[0] ^ 1]) + point[1:]

    def sub(self, left, right):
        return self.add(left, self.neg(right))

    def mul(self, scalar, point=G):
        scalar %= ORDER
        if scalar == 0 or point == INF:
            return INF
        out = C.create_string_buffer(64)
        if point == G:
            ok = self._ec_pubkey_create(self.ctx, out, scalar_bytes(scalar))
        else:
            out = self.parse(point, allow_infinity=False)
            ok = self._ec_pubkey_tweak_mul(self.ctx, out, scalar_bytes(scalar))
        if not ok:
            raise ValueError('point multiplication failed')
        return self._serialize(out)

    def linear(self, terms):
        return self.add(*(self.mul(scalar, point) for scalar, point in terms))

    def sign(self, secret, message):
        if len(message) != 32 or secret == 0:
            raise ValueError('invalid signing secret or message')
        keypair, signature = C.create_string_buffer(96), C.create_string_buffer(64)
        if not self._keypair_create(self.ctx, keypair, scalar_bytes(secret)):
            raise ValueError('invalid signing secret')
        if not self._schnorrsig_sign32(self.ctx, signature, message, keypair, secrets.token_bytes(32)):
            raise ValueError('approval signature failed')
        return signature.raw

    def verify_signature(self, public_key, message, signature):
        if len(public_key) != 32 or len(message) != 32 or len(signature) != 64:
            return False
        native = C.create_string_buffer(64)
        if not self._xonly_pubkey_parse(self.ctx, native, public_key):
            return False
        return bool(self._schnorrsig_verify(self.ctx, signature, message, 32, native))

    def confidential_point(self, encoded, kind):
        """Translate Elements' quadratic-residue encoding to SEC encoding."""
        prefix = {'asset': 10, 'value': 8}[kind]
        if not isinstance(encoded, bytes) or len(encoded) != 33 or encoded[0] not in (prefix, prefix + 1):
            raise ValueError('invalid confidential commitment encoding')
        x = int.from_bytes(encoded[1:], 'big')
        if x >= FIELD:
            raise ValueError('noncanonical coordinate')
        y = pow((x**3 + 7) % FIELD, (FIELD + 1) // 4, FIELD)
        if y**2 % FIELD != (x**3 + 7) % FIELD:
            raise ValueError('commitment is not on the curve')
        square = pow(y, (FIELD - 1) // 2, FIELD) == 1
        if square != (encoded[0] == prefix):
            y = FIELD - y
        point = bytes([2 + y % 2]) + encoded[1:]
        self.parse(point, allow_infinity=False)
        return point

    def _generator(self, asset, blinder=None):
        if not isinstance(asset, bytes) or len(asset) != 32:
            raise ValueError('asset ID must be 32 bytes in Elements internal byte order')
        out = C.create_string_buffer(64)
        if blinder is None:
            ok = self._generator_generate(self.ctx, out, asset)
        else:
            ok = self._generator_generate_blinded(self.ctx, out, asset, scalar_bytes(blinder))
        if not ok:
            raise ValueError('asset generator failed')
        return out

    def asset_commitment(self, asset, blinder):
        out = C.create_string_buffer(33)
        self._generator_serialize(self.ctx, out, self._generator(asset, blinder))
        return out.raw

    def asset_generator(self, asset):
        return self.confidential_point(self.asset_commitment(asset, 0), 'asset')

    def _native_asset(self, asset_commitment):
        self.confidential_point(asset_commitment, 'asset')
        out = C.create_string_buffer(64)
        if not self._generator_parse(self.ctx, out, asset_commitment):
            raise ValueError('invalid asset commitment')
        return out

    def _native_value(self, value_commitment):
        self.confidential_point(value_commitment, 'value')
        out = C.create_string_buffer(64)
        if not self._pedersen_commitment_parse(self.ctx, out, value_commitment):
            raise ValueError('invalid value commitment')
        return out

    def value_commitment(self, asset_commitment, amount, blinder):
        if type(amount) is not int or not 0 <= amount < 2**64:
            raise ValueError('amount is not uint64')
        native, out = C.create_string_buffer(64), C.create_string_buffer(33)
        if not self._pedersen_commit(self.ctx, native, scalar_bytes(blinder), amount,
                                     self._native_asset(asset_commitment)):
            raise ValueError('value commitment failed')
        self._pedersen_commitment_serialize(self.ctx, out, native)
        return out.raw

    def rangeproof(self, asset_commitment, value_commitment, amount, blinder,
                   nonce, message, script):
        if len(nonce) != 32 or len(message) != 64:
            raise ValueError('invalid range-proof nonce or asset message')
        proof, length = C.create_string_buffer(5134), C.c_size_t(5134)
        minimum = 0 if script[:1] == b'\x6a' else 1
        ok = self._rangeproof_sign(self.ctx, proof, C.byref(length), minimum,
                                   self._native_value(value_commitment), scalar_bytes(blinder),
                                   nonce, 0, 52, amount, message, len(message), script,
                                   len(script), self._native_asset(asset_commitment))
        if not ok:
            raise ValueError('range-proof generation failed')
        return proof.raw[:length.value]

    def verify_rangeproof(self, asset_commitment, value_commitment, proof, script):
        minimum, maximum = C.c_uint64(), C.c_uint64()
        return bool(self._rangeproof_verify(self.ctx, C.byref(minimum), C.byref(maximum),
                                            self._native_value(value_commitment), proof,
                                            len(proof), script, len(script),
                                            self._native_asset(asset_commitment)))

    def bounded_rangeproof(self, generator, amount, blinder, context, bits=16):
        """Commit to a small chunk using fixed blinding base G and NUMS generator.

        Unlike an ordinary output proof, this starts at zero and carries no
        recovery side-channel message. Never use a generator with known log_G.
        """
        if type(bits) is not int or bits not in (8, 16, 32):
            raise ValueError('unsupported research range width')
        if type(amount) is not int or not 0 <= amount < 1 << bits:
            raise ValueError('chunk is outside the specified range')
        commitment = self.value_commitment(generator, amount, blinder)
        proof, length = C.create_string_buffer(5134), C.c_size_t(5134)
        ok = self._rangeproof_sign(self.ctx, proof, C.byref(length), 0,
                                   self._native_value(commitment), scalar_bytes(blinder),
                                   secrets.token_bytes(32), 0, bits, amount, b'', 0,
                                   context, len(context), self._native_asset(generator))
        if not ok:
            raise ValueError('chunk range-proof generation failed')
        return commitment, proof.raw[:length.value]

    def rangeproof_bounds(self, generator, commitment, proof, context):
        minimum, maximum = C.c_uint64(), C.c_uint64()
        if not self._rangeproof_verify(self.ctx, C.byref(minimum), C.byref(maximum),
                                       self._native_value(commitment), proof, len(proof),
                                       context, len(context), self._native_asset(generator)):
            return None
        return minimum.value, maximum.value

    def rewind(self, asset_commitment, value_commitment, proof, nonce, script):
        if len(nonce) != 32:
            raise ValueError('invalid rewind nonce')
        blind, message = C.create_string_buffer(32), C.create_string_buffer(4096)
        amount, minimum, maximum = C.c_uint64(), C.c_uint64(), C.c_uint64()
        length = C.c_size_t(4096)
        ok = self._rangeproof_rewind(self.ctx, blind, C.byref(amount), message,
                                     C.byref(length), nonce, C.byref(minimum), C.byref(maximum),
                                     self._native_value(value_commitment), proof, len(proof),
                                     script, len(script), self._native_asset(asset_commitment))
        if not ok or length.value < 64:
            raise ValueError('range-proof rewind failed')
        return amount.value, int.from_bytes(blind.raw, 'big'), message.raw[:64]


def rewind_nonce(curve, private_key, public_key):
    """Match GenerateOutputRangeproofNonce: SHA256(native default ECDH hash)."""
    curve.parse(public_key, allow_infinity=False)
    shared = curve.mul(private_key, public_key)
    if shared == INF:
        raise ValueError('invalid ECDH secret')
    return hashlib.sha256(hashlib.sha256(shared).digest()).digest()
