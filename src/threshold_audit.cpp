// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <threshold_audit.h>

#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <random.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>
#include <support/cleanse.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace threshold_audit {
namespace {

using Bytes = std::vector<unsigned char>;
using Hash = std::array<unsigned char, 32>;
using Scalar = arith_uint256;
constexpr size_t CHUNKS{36};
constexpr size_t MAX_RANGE_BYTES{1536};
constexpr std::string_view DOMAIN{"Elements/threshold-audit/experiment/v1"};

[[noreturn]] void Fail(const char* message) { throw std::runtime_error(message); }

Bytes B(std::span<const unsigned char> bytes) { return {bytes.begin(), bytes.end()}; }

Bytes BE(uint64_t value, size_t length)
{
    Bytes result(length);
    for (size_t i = 0; i < length; ++i) {
        result[length - 1 - i] = value & 0xff;
        value >>= 8;
    }
    return result;
}

Scalar FromBig(std::span<const unsigned char> bytes)
{
    Scalar result{0};
    for (unsigned char byte : bytes) {
        result <<= 8;
        result += Scalar{byte};
    }
    return result;
}

Hash ToBig(Scalar value)
{
    Hash result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[result.size() - 1 - i] = value.GetLow64() & 0xff;
        value >>= 8;
    }
    return result;
}

Scalar HexNumber(std::string_view text)
{
    Scalar result{0};
    for (char c : text) {
        const unsigned int digit = c <= '9' ? c - '0' : c - 'a' + 10;
        result <<= 4;
        result += Scalar{digit};
    }
    return result;
}

const Scalar& Order()
{
    static const Scalar value = HexNumber("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    return value;
}

// All operands are reduced. This avoids overflowing the 256-bit accumulator.
Scalar AddMod(const Scalar& left, const Scalar& right, const Scalar& modulus)
{
    const Scalar remaining = modulus - right;
    return left >= remaining ? Scalar{left - remaining} : Scalar{left + right};
}

Scalar NegScalar(const Scalar& value) { return value == Scalar{0} ? Scalar{0} : Scalar{Order() - value}; }

const secp256k1_context* Context()
{
    struct DestroyContext {
        void operator()(secp256k1_context* context) const { secp256k1_context_destroy(context); }
    };
    static const std::unique_ptr<secp256k1_context, DestroyContext> context{
        secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    if (!context) Fail("audit verifier context unavailable");
    return context.get();
}

struct Point {
    std::array<unsigned char, 33> bytes{};
    secp256k1_pubkey native{};
    bool infinity{true};
};

Point ParsePoint(std::span<const unsigned char> bytes, bool allow_infinity)
{
    if (bytes.size() != 33) Fail("invalid audit point length");
    Point result;
    std::copy(bytes.begin(), bytes.end(), result.bytes.begin());
    if (std::all_of(bytes.begin(), bytes.end(), [](unsigned char b) { return b == 0; })) {
        if (!allow_infinity) Fail("infinite audit point forbidden");
        return result;
    }
    if ((bytes[0] != 2 && bytes[0] != 3) ||
        !secp256k1_ec_pubkey_parse(Context(), &result.native, bytes.data(), bytes.size())) {
        Fail("invalid audit curve point");
    }
    result.infinity = false;
    return result;
}

Point SerializePoint(const secp256k1_pubkey& native)
{
    Point result;
    result.native = native;
    result.infinity = false;
    size_t length = result.bytes.size();
    if (!secp256k1_ec_pubkey_serialize(Context(), result.bytes.data(), &length,
                                    &result.native, SECP256K1_EC_COMPRESSED) || length != 33) {
        Fail("audit curve serialization failed");
    }
    return result;
}

Point ConfidentialPoint(std::span<const unsigned char> bytes, unsigned char prefix)
{
    if (bytes.size() != 33 || (bytes[0] != prefix && bytes[0] != prefix + 1)) {
        Fail("invalid audit commitment encoding");
    }
    // These coordinates/commitments are public. Use exact, unbounded arithmetic
    // so products cannot truncate before reduction. No secret scalar operations
    // use Boost; those remain on the native scalar/ECDH paths below.
    using boost::multiprecision::cpp_int;
    static const cpp_int field{"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"};
    static const cpp_int sqrt_exponent = (field + 1) >> 2;
    static const cpp_int legendre_exponent = (field - 1) >> 1;
    cpp_int x{0};
    for (unsigned char byte : bytes.subspan(1)) { x <<= 8; x += byte; }
    if (x >= field) Fail("noncanonical audit commitment coordinate");
    const cpp_int rhs = ((x * x % field) * x + 7) % field;
    cpp_int y = boost::multiprecision::powm(rhs, sqrt_exponent, field);
    if (y * y % field != rhs) Fail("audit commitment is not a curve point");
    const bool square = boost::multiprecision::powm(y, legendre_exponent, field) == 1;
    if (square != (bytes[0] == prefix)) y = field - y;
    std::array<unsigned char, 33> compressed{};
    compressed[0] = 2 + static_cast<unsigned int>(y & 1);
    std::copy(bytes.begin() + 1, bytes.end(), compressed.begin() + 1);
    return ParsePoint(compressed, false);
}

const Point& Generator()
{
    static const Point point = [] {
        const auto x = ToBig(HexNumber("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
        std::array<unsigned char, 33> bytes{};
        bytes[0] = 2;
        std::copy(x.begin(), x.end(), bytes.begin() + 1);
        return ParsePoint(bytes, false);
    }();
    return point;
}

Point Add(const Point& left, const Point& right)
{
    if (left.infinity) return right;
    if (right.infinity) return left;
    const secp256k1_pubkey* inputs[2]{&left.native, &right.native};
    secp256k1_pubkey native;
    if (!secp256k1_ec_pubkey_combine(Context(), &native, inputs, 2)) return Point{};
    return SerializePoint(native);
}

Point Negate(const Point& point)
{
    if (point.infinity) return point;
    auto bytes = point.bytes;
    bytes[0] ^= 1;
    return ParsePoint(bytes, false);
}

Point Multiply(const Scalar& scalar, const Point& point)
{
    if (scalar == Scalar{0} || point.infinity) return Point{};
    const Hash encoded = ToBig(scalar);
    secp256k1_pubkey result = point.native;
    if (!secp256k1_ec_pubkey_tweak_mul(Context(), &result, encoded.data())) Fail("audit curve multiplication failed");
    return SerializePoint(result);
}

Point TwoTerms(const Scalar& first, const Point& a, const Scalar& second, const Point& b)
{
    return Add(Multiply(first, a), Multiply(second, b));
}

Hash Digest(std::string_view label, const std::vector<Bytes>& parts)
{
    CSHA256 hasher;
    auto write = [&](std::span<const unsigned char> bytes) {
        const Bytes length = BE(bytes.size(), 8);
        hasher.Write(length.data(), length.size());
        if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    };
    write({reinterpret_cast<const unsigned char*>(DOMAIN.data()), DOMAIN.size()});
    write({reinterpret_cast<const unsigned char*>(label.data()), label.size()});
    for (const Bytes& part : parts) write(part);
    Hash result;
    hasher.Finalize(result.data());
    return result;
}

Hash SchemeDigest(std::string_view label, const std::vector<Bytes>& parts)
{
    return Digest(std::string{"TAC2/"} + std::string{label}, parts);
}

Scalar Challenge(std::string_view label, const std::vector<Bytes>& parts)
{
    Scalar value = FromBig(Digest(label, parts));
    if (value >= Order()) value -= Order();
    return value;
}

Hash RangeAsset()
{
    static constexpr std::string_view label{"Elements/threshold-audit/TAC2/range-generator"};
    Hash result;
    CSHA256{}.Write(reinterpret_cast<const unsigned char*>(label.data()), label.size()).Finalize(result.data());
    return result;
}

struct AssetGenerator {
    secp256k1_generator native{};
    Point point;
};

AssetGenerator MakeAssetGenerator(const Hash& asset)
{
    AssetGenerator result;
    if (!secp256k1_generator_generate(Context(), &result.native, asset.data())) Fail("audit asset generator failed");
    std::array<unsigned char, 33> encoded{};
    if (!secp256k1_generator_serialize(Context(), encoded.data(), &result.native)) Fail("audit asset serialization failed");
    result.point = ConfidentialPoint(encoded, 10);
    return result;
}

struct Chunk {
    Point first;
    Point second;
    Point range_point;
    std::array<unsigned char, 33> commitment{};
    secp256k1_pedersen_commitment native_commitment{};
    Bytes range_proof;
    std::array<Scalar, 4> bridge;
};

using Pair = std::array<Scalar, 2>;
struct Packet {
    std::array<Chunk, CHUNKS> chunks;
    std::vector<Pair> asset_proof;
    Pair value_proof;
};

class Reader {
    std::span<const unsigned char> m_bytes;
    size_t m_offset{0};
public:
    explicit Reader(std::span<const unsigned char> bytes) : m_bytes(bytes) {}
    std::span<const unsigned char> Take(size_t size)
    {
        if (size > m_bytes.size() - m_offset) Fail("truncated audit packet");
        const auto result = m_bytes.subspan(m_offset, size);
        m_offset += size;
        return result;
    }
    Scalar TakeScalar()
    {
        const Scalar value = FromBig(Take(32));
        if (value >= Order()) Fail("noncanonical audit proof scalar");
        return value;
    }
    bool Finished() const { return m_offset == m_bytes.size(); }
};

Packet ParsePacket(std::span<const unsigned char> bytes, size_t assets)
{
    const size_t suffix = 64 * (assets + 1);
    constexpr size_t MIN_CHUNK = 99 + 2 + 1 + 128;
    constexpr size_t MAX_CHUNK = 99 + 2 + MAX_RANGE_BYTES + 128;
    if (bytes.size() < 4 + CHUNKS * MIN_CHUNK + suffix || bytes.size() > 4 + CHUNKS * MAX_CHUNK + suffix) {
        Fail("invalid audit packet size");
    }
    Reader reader{bytes};
    const auto magic = reader.Take(4);
    if (!std::equal(magic.begin(), magic.end(), "TAC2")) Fail("unsupported audit packet version");
    Packet result;
    for (Chunk& chunk : result.chunks) {
        chunk.first = ParsePoint(reader.Take(33), false);
        chunk.second = ParsePoint(reader.Take(33), true);
        const auto commitment = reader.Take(33);
        std::copy(commitment.begin(), commitment.end(), chunk.commitment.begin());
        if (!secp256k1_pedersen_commitment_parse(Context(), &chunk.native_commitment, chunk.commitment.data())) {
            Fail("invalid audit range commitment");
        }
        chunk.range_point = ConfidentialPoint(chunk.commitment, 8);
        const auto length_bytes = reader.Take(2);
        const size_t length = (size_t{length_bytes[0]} << 8) | length_bytes[1];
        if (length == 0 || length > MAX_RANGE_BYTES) Fail("invalid audit range-proof length");
        chunk.range_proof = B(reader.Take(length));
        for (Scalar& value : chunk.bridge) value = reader.TakeScalar();
    }
    result.asset_proof.resize(assets);
    for (Pair& pair : result.asset_proof) for (Scalar& value : pair) value = reader.TakeScalar();
    for (Scalar& value : result.value_proof) value = reader.TakeScalar();
    if (!reader.Finished()) Fail("trailing audit packet data");
    return result;
}

Hash StatementBinding(const Statement& statement)
{
    Bytes assets;
    assets.reserve(statement.assets.size() * 32);
    for (const auto& asset : statement.assets) assets.insert(assets.end(), asset.begin(), asset.end());
    return Digest("statement", {B(statement.chain_id), B(statement.tx_digest), BE(statement.output_index, 4),
                               statement.script, statement.asset_commitment, statement.value_commitment,
                               statement.audit_key, assets});
}

Hash Envelope(const Statement& statement, const Packet& packet)
{
    Bytes vector;
    vector.reserve(CHUNKS * 99);
    for (const Chunk& chunk : packet.chunks) {
        vector.insert(vector.end(), chunk.first.bytes.begin(), chunk.first.bytes.end());
        vector.insert(vector.end(), chunk.second.bytes.begin(), chunk.second.bytes.end());
        vector.insert(vector.end(), chunk.commitment.begin(), chunk.commitment.end());
    }
    return SchemeDigest("envelope", {B(StatementBinding(statement)), B(RangeAsset()), BE(16, 4), vector});
}

Hash ProofContext(const Hash& envelope, const Packet& packet)
{
    std::vector<Bytes> parts{B(envelope)};
    for (const Chunk& chunk : packet.chunks) parts.push_back(chunk.range_proof);
    return SchemeDigest("range-proofs", parts);
}

Hash ConsistencyContext(const Hash& proof_context, const Packet& packet)
{
    Bytes bridges;
    bridges.reserve(CHUNKS * 128);
    for (const Chunk& chunk : packet.chunks) {
        for (const Scalar& scalar : chunk.bridge) {
            const Hash bytes = ToBig(scalar);
            bridges.insert(bridges.end(), bytes.begin(), bytes.end());
        }
    }
    return SchemeDigest("consistency", {B(proof_context), bridges});
}

bool VerifyBridge(const Chunk& chunk, const Point& base, const Point& key,
                  const Point& range_generator, const Hash& context)
{
    const auto& [c, zm, zr, zu] = chunk.bridge;
    const Scalar negative = NegScalar(c);
    const Point first = TwoTerms(zr, Generator(), negative, chunk.first);
    const Point second = Add(TwoTerms(zm, base, zr, key), Multiply(negative, chunk.second));
    const Point third = Add(TwoTerms(zm, range_generator, zu, Generator()), Multiply(negative, chunk.range_point));
    return c == Challenge("TAC2/bridge", {B(context), B(Generator().bytes), B(range_generator.bytes),
                                          B(base.bytes), B(key.bytes), B(chunk.first.bytes), B(chunk.second.bytes),
                                          B(chunk.range_point.bytes), B(first.bytes), B(second.bytes), B(third.bytes)});
}

struct Ciphertext { Point first; Point second; };

std::array<Ciphertext, 3> Aggregate(const Packet& packet)
{
    std::array<Ciphertext, 3> result;
    constexpr std::array<size_t, 3> counts{4, 16, 16};
    size_t start{0};
    for (size_t field = 0; field < counts.size(); ++field) {
        for (size_t j = 0; j < counts[field]; ++j) {
            const Scalar weight = Scalar{1} << (16 * j);
            result[field].first = Add(result[field].first, Multiply(weight, packet.chunks[start + j].first));
            result[field].second = Add(result[field].second, Multiply(weight, packet.chunks[start + j].second));
        }
        start += counts[field];
    }
    return result;
}

bool VerifyAssetOR(const Point& key, const Ciphertext& abf, const Point& asset_point,
                   const Statement& statement, const Packet& packet, const Hash& context)
{
    std::vector<Point> alternatives;
    std::vector<Point> commitments;
    alternatives.reserve(statement.assets.size());
    commitments.reserve(2 * statement.assets.size());
    Scalar sum{0};
    const Point difference = Add(abf.second, Negate(asset_point));
    for (size_t i = 0; i < statement.assets.size(); ++i) {
        const Point alternative = Add(difference, MakeAssetGenerator(statement.assets[i]).point);
        alternatives.push_back(alternative);
        const auto& [c, z] = packet.asset_proof[i];
        commitments.push_back(TwoTerms(z, Generator(), NegScalar(c), abf.first));
        commitments.push_back(TwoTerms(z, key, NegScalar(c), alternative));
        sum = AddMod(sum, c, Order());
    }
    std::vector<Bytes> parts{B(context), B(Generator().bytes), B(key.bytes), B(abf.first.bytes)};
    for (const Point& alternative : alternatives) parts.push_back(B(alternative.bytes));
    for (const Point& commitment : commitments) parts.push_back(B(commitment.bytes));
    return sum == Challenge("or-dleq", parts);
}

bool VerifyValueDLEQ(const Point& key, const Ciphertext& amount, const Ciphertext& vbf,
                     const Point& value, const Pair& proof, const Hash& context)
{
    const auto& [c, z] = proof;
    const Point first = Add(amount.first, vbf.first);
    const Point second = Add(Add(amount.second, vbf.second), Negate(value));
    const Point a = TwoTerms(z, Generator(), NegScalar(c), first);
    const Point b = TwoTerms(z, key, NegScalar(c), second);
    return c == Challenge("dleq", {B(context), B(Generator().bytes), B(key.bytes), B(first.bytes),
                                   B(second.bytes), B(a.bytes), B(b.bytes)});
}

// Secret arithmetic uses the library's scalar APIs rather than arith_uint256.
// Zero handling and the surrounding prover remain research code; this does not
// claim end-to-end constant-time execution or protected wallet secret storage.
struct CleanseOnExit {
    void* data;
    size_t size;
    template <typename T> explicit CleanseOnExit(T& value) : data(&value), size(sizeof(value)) {}
    ~CleanseOnExit() { memory_cleanse(data, size); }
};

Hash RandomScalar()
{
    Hash result;
    do { GetStrongRandBytes(result); } while (!secp256k1_ec_seckey_verify(Context(), result.data()));
    return result;
}

bool IsZero(const Hash& value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) { return byte == 0; });
}

Hash AddSecret(Hash left, const Hash& right)
{
    CleanseOnExit cleanup{left};
    if (IsZero(left)) return right;
    if (!secp256k1_ec_seckey_tweak_add(Context(), left.data(), right.data())) left.fill(0);
    return left;
}

Hash MultiplySecret(Hash left, const Hash& right)
{
    CleanseOnExit cleanup{left};
    if (IsZero(left) || IsZero(right)) return Hash{};
    if (!secp256k1_ec_seckey_tweak_mul(Context(), left.data(), right.data())) Fail("invalid audit secret scalar");
    return left;
}

Hash Respond(const Hash& nonce, const Scalar& challenge, const Hash& witness)
{
    return AddSecret(nonce, MultiplySecret(ToBig(challenge), witness));
}

Point SecretMultiply(const Hash& scalar, const Point& point)
{
    if (IsZero(scalar) || point.infinity) return Point{};
    std::array<unsigned char, 33> encoded;
    const auto serialize = [](unsigned char* output, const unsigned char* x,
                              const unsigned char* y, void*) {
        output[0] = 2 + (y[31] & 1);
        std::memcpy(output + 1, x, 32);
        return 1;
    };
    // ECDH uses constant-time arbitrary-point scalar multiplication, whereas
    // the public verifier's pubkey tweak API is variable-time.
    if (!secp256k1_ecdh(Context(), encoded.data(), &point.native, scalar.data(), serialize, nullptr)) {
        Fail("audit secret curve multiplication failed");
    }
    return ParsePoint(encoded, false);
}

Bytes SerializePacket(const Packet& packet)
{
    Bytes result{'T', 'A', 'C', '2'};
    auto append = [&](std::span<const unsigned char> bytes) { result.insert(result.end(), bytes.begin(), bytes.end()); };
    for (const Chunk& chunk : packet.chunks) {
        append(chunk.first.bytes);
        append(chunk.second.bytes);
        append(chunk.commitment);
        append(BE(chunk.range_proof.size(), 2));
        append(chunk.range_proof);
        for (const Scalar& scalar : chunk.bridge) append(ToBig(scalar));
    }
    for (const Pair& pair : packet.asset_proof) for (const Scalar& scalar : pair) append(ToBig(scalar));
    for (const Scalar& scalar : packet.value_proof) append(ToBig(scalar));
    return result;
}

Pair ProveDLEQ(const Point& key, const Point& first, const Point& second,
               const Hash& witness, const Hash& context)
{
    Hash nonce = RandomScalar();
    CleanseOnExit cleanup{nonce};
    const Point a = SecretMultiply(nonce, Generator());
    const Point b = SecretMultiply(nonce, key);
    const Scalar c = Challenge("dleq", {B(context), B(Generator().bytes), B(key.bytes), B(first.bytes),
                                        B(second.bytes), B(a.bytes), B(b.bytes)});
    return {c, FromBig(Respond(nonce, c, witness))};
}

void ProveAssetOR(Packet& packet, const Statement& statement, const Point& key,
                  const Point& asset, const Ciphertext& abf, size_t branch,
                  const Hash& witness, const Hash& context)
{
    std::vector<Point> alternatives;
    std::vector<Point> commitments;
    packet.asset_proof.resize(statement.assets.size());
    Hash nonce = RandomScalar();
    CleanseOnExit cleanup{nonce};
    Scalar sum{0};
    for (size_t j = 0; j < statement.assets.size(); ++j) {
        const Point alternative = Add(Add(abf.second, Negate(asset)), MakeAssetGenerator(statement.assets[j]).point);
        alternatives.push_back(alternative);
        if (j == branch) {
            commitments.push_back(SecretMultiply(nonce, Generator()));
            commitments.push_back(SecretMultiply(nonce, key));
        } else {
            const Scalar c = FromBig(RandomScalar()), z = FromBig(RandomScalar());
            packet.asset_proof[j] = {c, z};
            sum = AddMod(sum, c, Order());
            commitments.push_back(TwoTerms(z, Generator(), NegScalar(c), abf.first));
            commitments.push_back(TwoTerms(z, key, NegScalar(c), alternative));
        }
    }
    std::vector<Bytes> parts{B(context), B(Generator().bytes), B(key.bytes), B(abf.first.bytes)};
    for (const Point& alternative : alternatives) parts.push_back(B(alternative.bytes));
    for (const Point& commitment : commitments) parts.push_back(B(commitment.bytes));
    const Scalar c = AddMod(Challenge("or-dleq", parts), NegScalar(sum), Order());
    packet.asset_proof[branch] = {c, FromBig(Respond(nonce, c, witness))};
}

Packet ProvePacket(const Statement& statement, const Opening& opening)
{
    if (statement.script.size() > 10000 || statement.assets.empty() || statement.assets.size() > 256 ||
        !std::is_sorted(statement.assets.begin(), statement.assets.end()) ||
        std::adjacent_find(statement.assets.begin(), statement.assets.end()) != statement.assets.end()) {
        Fail("invalid audit statement or registry");
    }
    const auto branch = std::find(statement.assets.begin(), statement.assets.end(), opening.asset);
    if (branch == statement.assets.end()) Fail("output asset is absent from the audit registry");
    for (const Hash* blinder : {&opening.asset_blinder, &opening.value_blinder}) {
        if (!IsZero(*blinder) && !secp256k1_ec_seckey_verify(Context(), blinder->data())) Fail("invalid audit opening blinder");
    }
    secp256k1_generator native_asset;
    std::array<unsigned char, 33> encoded_asset;
    secp256k1_pedersen_commitment native_value;
    std::array<unsigned char, 33> encoded_value;
    if (!secp256k1_generator_generate_blinded(Context(), &native_asset, opening.asset.data(), opening.asset_blinder.data()) ||
        !secp256k1_generator_serialize(Context(), encoded_asset.data(), &native_asset) ||
        !secp256k1_pedersen_commit(Context(), &native_value, opening.value_blinder.data(), opening.amount, &native_asset) ||
        !secp256k1_pedersen_commitment_serialize(Context(), encoded_value.data(), &native_value) ||
        statement.asset_commitment != B(encoded_asset) || statement.value_commitment != B(encoded_value)) {
        Fail("audit opening does not match output commitments");
    }
    const Point key = ParsePoint(statement.audit_key, false);
    const Point asset = ConfidentialPoint(statement.asset_commitment, 10);
    const Point value = ConfidentialPoint(statement.value_commitment, 8);
    const AssetGenerator range_generator = MakeAssetGenerator(RangeAsset());
    std::array<uint16_t, CHUNKS> limbs;
    CleanseOnExit cleanup_limbs{limbs};
    for (size_t j = 0; j < 4; ++j) limbs[j] = (opening.amount >> (16 * j)) & 0xffff;
    for (size_t j = 0; j < 16; ++j) {
        const size_t offset = 30 - 2 * j;
        limbs[4 + j] = (uint16_t{opening.asset_blinder[offset]} << 8) | opening.asset_blinder[offset + 1];
        limbs[20 + j] = (uint16_t{opening.value_blinder[offset]} << 8) | opening.value_blinder[offset + 1];
    }
    std::array<Hash, CHUNKS> nonces, blinds;
    CleanseOnExit cleanup_nonces{nonces}, cleanup_blinds{blinds};
    Packet packet;
    for (size_t j = 0; j < CHUNKS; ++j) {
        Chunk& chunk = packet.chunks[j];
        nonces[j] = RandomScalar();
        blinds[j] = RandomScalar();
        Hash m{};
        CleanseOnExit cleanup_m{m};
        m[30] = limbs[j] >> 8;
        m[31] = limbs[j] & 0xff;
        chunk.first = SecretMultiply(nonces[j], Generator());
        chunk.second = Add(SecretMultiply(m, j < 4 ? asset : Generator()), SecretMultiply(nonces[j], key));
        if (!secp256k1_pedersen_commit(Context(), &chunk.native_commitment, blinds[j].data(), limbs[j], &range_generator.native) ||
            !secp256k1_pedersen_commitment_serialize(Context(), chunk.commitment.data(), &chunk.native_commitment)) {
            Fail("audit chunk commitment failed");
        }
        chunk.range_point = ConfidentialPoint(chunk.commitment, 8);
    }
    const Hash envelope = Envelope(statement, packet);
    for (size_t j = 0; j < CHUNKS; ++j) {
        Chunk& chunk = packet.chunks[j];
        const Hash context = SchemeDigest("range", {B(envelope), BE(j, 4)});
        Hash nonce;
        CleanseOnExit cleanup_nonce{nonce};
        GetStrongRandBytes(nonce);
        chunk.range_proof.resize(MAX_RANGE_BYTES);
        size_t length = chunk.range_proof.size();
        if (!secp256k1_rangeproof_sign(Context(), chunk.range_proof.data(), &length, 0,
                                     &chunk.native_commitment, blinds[j].data(), nonce.data(), 0, 16, limbs[j],
                                     nullptr, 0, context.data(), context.size(), &range_generator.native)) {
            Fail("audit chunk range proof failed");
        }
        chunk.range_proof.resize(length);
    }
    const Hash proof_context = ProofContext(envelope, packet);
    for (size_t j = 0; j < CHUNKS; ++j) {
        Chunk& chunk = packet.chunks[j];
        const Point& base = j < 4 ? asset : Generator();
        Hash wm = RandomScalar(), wr = RandomScalar(), wu = RandomScalar();
        CleanseOnExit cleanup_wm{wm}, cleanup_wr{wr}, cleanup_wu{wu};
        const Point first = SecretMultiply(wr, Generator());
        const Point second = Add(SecretMultiply(wm, base), SecretMultiply(wr, key));
        const Point third = Add(SecretMultiply(wm, range_generator.point), SecretMultiply(wu, Generator()));
        const Hash context = SchemeDigest("bridge-index", {B(proof_context), BE(j, 4)});
        const Scalar c = Challenge("TAC2/bridge", {B(context), B(Generator().bytes), B(range_generator.point.bytes),
                                                   B(base.bytes), B(key.bytes), B(chunk.first.bytes), B(chunk.second.bytes),
                                                   B(chunk.range_point.bytes), B(first.bytes), B(second.bytes), B(third.bytes)});
        Hash m{};
        CleanseOnExit cleanup_m{m};
        m[30] = limbs[j] >> 8;
        m[31] = limbs[j] & 0xff;
        chunk.bridge = {c, FromBig(Respond(wm, c, m)), FromBig(Respond(wr, c, nonces[j])), FromBig(Respond(wu, c, blinds[j]))};
    }
    std::array<Hash, 3> randomness{};
    CleanseOnExit cleanup_randomness{randomness};
    constexpr std::array<size_t, 3> counts{4, 16, 16};
    size_t start{0};
    for (size_t field = 0; field < counts.size(); ++field) {
        for (size_t j = 0; j < counts[field]; ++j) {
            randomness[field] = AddSecret(randomness[field], MultiplySecret(ToBig(Scalar{1} << (16 * j)), nonces[start + j]));
        }
        start += counts[field];
    }
    const auto aggregate = Aggregate(packet);
    const Hash consistency = ConsistencyContext(proof_context, packet);
    ProveAssetOR(packet, statement, key, asset, aggregate[1], branch - statement.assets.begin(), randomness[1],
                 SchemeDigest("asset", {B(consistency)}));
    packet.value_proof = ProveDLEQ(key, Add(aggregate[0].first, aggregate[2].first),
                                  Add(Add(aggregate[0].second, aggregate[2].second), Negate(value)),
                                  AddSecret(randomness[0], randomness[2]), SchemeDigest("value", {B(consistency)}));
    return packet;
}

} // namespace

Opening::~Opening() { memory_cleanse(this, sizeof(*this)); }

size_t MaximumPacketSize(size_t assets)
{
    if (assets == 0 || assets > 256) throw std::invalid_argument("audit registry size outside limits");
    return 4 + CHUNKS * (99 + 2 + MAX_RANGE_BYTES + 128) + 64 * (assets + 1);
}

bool CreatePacket(const Statement& statement, const Opening& opening, Bytes& packet, std::string* error)
{
    try {
        packet = SerializePacket(ProvePacket(statement, opening));
        if (error) error->clear();
        return true;
    } catch (const std::exception& exception) {
        packet.clear();
        if (error) *error = exception.what();
        return false;
    }
}

bool VerifyPacket(const Statement& statement, std::span<const unsigned char> bytes, std::string* error)
{
    try {
        if (statement.script.size() > 10000) Fail("audit script exceeds limit");
        if (statement.assets.empty() || statement.assets.size() > 256) Fail("audit registry size outside limits");
        if (!std::is_sorted(statement.assets.begin(), statement.assets.end()) ||
            std::adjacent_find(statement.assets.begin(), statement.assets.end()) != statement.assets.end()) {
            Fail("audit registry must be sorted and unique");
        }
        const Point key = ParsePoint(statement.audit_key, false);
        const Point asset = ConfidentialPoint(statement.asset_commitment, 10);
        const Point value = ConfidentialPoint(statement.value_commitment, 8);
        const Packet packet = ParsePacket(bytes, statement.assets.size());
        const AssetGenerator range_generator = MakeAssetGenerator(RangeAsset());
        const Hash envelope = Envelope(statement, packet);
        const Hash proof_context = ProofContext(envelope, packet);
        for (size_t j = 0; j < CHUNKS; ++j) {
            const Chunk& chunk = packet.chunks[j];
            const Hash range_context = SchemeDigest("range", {B(envelope), BE(j, 4)});
            uint64_t minimum{0}, maximum{0};
            if (!secp256k1_rangeproof_verify(Context(), &minimum, &maximum, &chunk.native_commitment,
                                            chunk.range_proof.data(), chunk.range_proof.size(),
                                            range_context.data(), range_context.size(), &range_generator.native) ||
                minimum != 0 || maximum != 65535) {
                Fail("invalid audit chunk range proof or bounds");
            }
            const Hash bridge_context = SchemeDigest("bridge-index", {B(proof_context), BE(j, 4)});
            if (!VerifyBridge(chunk, j < 4 ? asset : Generator(), key, range_generator.point, bridge_context)) {
                Fail("invalid audit chunk representation proof");
            }
        }
        const Hash consistency = ConsistencyContext(proof_context, packet);
        const auto aggregates = Aggregate(packet);
        if (!VerifyAssetOR(key, aggregates[1], asset, statement, packet, SchemeDigest("asset", {B(consistency)}))) {
            Fail("invalid audit asset consistency proof");
        }
        if (!VerifyValueDLEQ(key, aggregates[0], aggregates[2], value, packet.value_proof,
                            SchemeDigest("value", {B(consistency)}))) {
            Fail("invalid audit value consistency proof");
        }
        if (error) error->clear();
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

} // namespace threshold_audit
