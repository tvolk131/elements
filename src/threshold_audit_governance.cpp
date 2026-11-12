// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <threshold_audit_governance.h>

#include <consensus/params.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/block.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string_view>

namespace threshold_audit::governance {
namespace {

using Bytes = std::vector<unsigned char>;
constexpr std::string_view DOMAIN{"Elements/threshold-audit/experiment/v1"};

[[noreturn]] void Fail(const char* error) { throw std::runtime_error(error); }
Bytes B(std::span<const unsigned char> bytes) { return {bytes.begin(), bytes.end()}; }
Bytes Number(uint64_t value, size_t size)
{
    Bytes bytes(size);
    for (size_t i = 0; i < size; ++i) {
        bytes[size - 1 - i] = value & 255;
        value >>= 8;
    }
    return bytes;
}

Hash Digest(std::string_view label, const std::vector<Bytes>& parts)
{
    CSHA256 sha;
    auto append = [&](std::span<const unsigned char> bytes) {
        const Bytes length = Number(bytes.size(), 8);
        sha.Write(length.data(), length.size());
        if (!bytes.empty()) sha.Write(bytes.data(), bytes.size());
    };
    append({reinterpret_cast<const unsigned char*>(DOMAIN.data()), DOMAIN.size()});
    append({reinterpret_cast<const unsigned char*>(label.data()), label.size()});
    for (const auto& part : parts) append(part);
    Hash hash;
    sha.Finalize(hash.data());
    return hash;
}

Hash RawHash(const uint256& value)
{
    Hash hash;
    std::copy(value.begin(), value.end(), hash.begin());
    return hash;
}

class Reader {
    std::span<const unsigned char> m_bytes;
    size_t m_offset{0};
public:
    explicit Reader(std::span<const unsigned char> bytes) : m_bytes(bytes) {}
    std::span<const unsigned char> Take(size_t length)
    {
        if (length > m_bytes.size() - m_offset) Fail("truncated audit governance payload");
        const auto value = m_bytes.subspan(m_offset, length);
        m_offset += length;
        return value;
    }
    uint32_t Number(size_t length)
    {
        uint32_t value{0};
        for (unsigned char byte : Take(length)) value = (value << 8) | byte;
        return value;
    }
    template <size_t Size> std::array<unsigned char, Size> Array()
    {
        std::array<unsigned char, Size> value;
        const auto bytes = Take(Size);
        std::copy(bytes.begin(), bytes.end(), value.begin());
        return value;
    }
    void End() const { if (m_offset != m_bytes.size()) Fail("trailing audit governance bytes"); }
};

struct CurvePoint {
    Point bytes{};
    secp256k1_pubkey native{};
    bool infinity{true};
};

CurvePoint Parse(const Point& bytes, bool allow_infinity = true)
{
    CurvePoint point;
    point.bytes = bytes;
    if (std::all_of(bytes.begin(), bytes.end(), [](unsigned char b) { return b == 0; })) {
        if (!allow_infinity) Fail("infinite audit governance key");
        return point;
    }
    if ((bytes[0] != 2 && bytes[0] != 3) ||
        !secp256k1_ec_pubkey_parse(secp256k1_context_static, &point.native, bytes.data(), bytes.size())) {
        Fail("invalid audit governance point");
    }
    point.infinity = false;
    return point;
}

CurvePoint Native(const secp256k1_pubkey& native)
{
    CurvePoint point;
    point.native = native;
    point.infinity = false;
    size_t length = point.bytes.size();
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, point.bytes.data(), &length,
                                    &point.native, SECP256K1_EC_COMPRESSED) || length != 33) {
        Fail("audit governance point serialization failed");
    }
    return point;
}

CurvePoint Add(const CurvePoint& left, const CurvePoint& right)
{
    if (left.infinity) return right;
    if (right.infinity) return left;
    const secp256k1_pubkey* points[]{&left.native, &right.native};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_static, &sum, points, 2)) return {};
    return Native(sum);
}

CurvePoint Multiply(const CurvePoint& point, const Hash& scalar)
{
    if (point.infinity || std::all_of(scalar.begin(), scalar.end(), [](unsigned char b) { return b == 0; })) return {};
    secp256k1_pubkey product = point.native;
    if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &product, scalar.data())) Fail("invalid audit scalar");
    return Native(product);
}

CurvePoint Multiply(const CurvePoint& point, uint32_t scalar)
{
    Hash bytes{};
    const Bytes encoded = Number(scalar, 4);
    std::copy(encoded.begin(), encoded.end(), bytes.end() - 4);
    return Multiply(point, bytes);
}

CurvePoint Negate(const CurvePoint& point)
{
    if (point.infinity) return point;
    secp256k1_pubkey negative = point.native;
    if (!secp256k1_ec_pubkey_negate(secp256k1_context_static, &negative)) Fail("audit governance negation failed");
    return Native(negative);
}

const CurvePoint& Generator()
{
    static const CurvePoint point = [] {
        const Point bytes{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                          0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
                          0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
        return Parse(bytes, false);
    }();
    return point;
}

const Hash& Order()
{
    static constexpr Hash order{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
    return order;
}

Hash Challenge(const Hash& context, const CurvePoint& share, const CurvePoint& commitment)
{
    Hash value = Digest("dleq", {B(context), B(Generator().bytes), B(Generator().bytes),
                                B(share.bytes), B(share.bytes), B(commitment.bytes), B(commitment.bytes)});
    if (value >= Order()) {
        unsigned int borrow{0};
        for (size_t i = value.size(); i-- > 0;) {
            const unsigned int sub = static_cast<unsigned int>(Order()[i]) + borrow;
            const unsigned int digit = value[i];
            value[i] = digit - sub;
            borrow = digit < sub;
        }
    }
    return value;
}

CurvePoint VerificationKey(const Key& key, uint32_t member)
{
    CurvePoint result;
    for (auto it = key.commitments.rbegin(); it != key.commitments.rend(); ++it) {
        result = Add(Multiply(result, member), Parse(*it));
    }
    return result;
}

Config ReadConfig(std::span<const unsigned char> bytes)
{
    if (bytes.size() < 46 || bytes.size() > MAX_CONFIG_BYTES) Fail("invalid audit-config size");
    Reader reader{bytes};
    const auto magic = reader.Take(4);
    if (!std::equal(magic.begin(), magic.end(), reinterpret_cast<const unsigned char*>("TAG1"))) Fail("invalid audit-config magic");
    Config config;
    config.generation = reader.Number(4);
    config.active_version = reader.Number(4);
    config.signer_policy = reader.Array<32>();
    const size_t count = reader.Number(1);
    if (count < 1 || count > MAX_MEMBERS) Fail("invalid audit identity count");
    uint32_t previous{0};
    std::vector<Hash> seen;
    for (size_t i = 0; i < count; ++i) {
        Identity identity{reader.Number(4), reader.Array<32>()};
        if (identity.member <= previous) Fail("audit identities must be ordered, distinct and nonzero");
        previous = identity.member;
        if (std::find(seen.begin(), seen.end(), identity.public_key) != seen.end()) Fail("duplicate audit identity key");
        secp256k1_xonly_pubkey public_key;
        if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &public_key, identity.public_key.data())) Fail("invalid audit identity key");
        seen.push_back(identity.public_key);
        config.identities.push_back(identity);
    }
    const size_t key_count = reader.Number(1);
    if (key_count < 1 || key_count > MAX_KEYS || config.active_version < 1 || config.active_version > key_count) Fail("invalid retained key count/version");
    for (size_t i = 0; i < key_count; ++i) {
        Key key;
        key.version = reader.Number(4);
        key.scheme = reader.Number(2);
        key.epoch = reader.Number(4);
        const size_t threshold = reader.Number(1);
        const size_t members = reader.Number(1);
        if (key.version != i + 1 || key.scheme != 2 || threshold < 1 || threshold > members || members != count) Fail("invalid audit key version/scheme/dimensions");
        for (size_t j = 0; j < members; ++j) {
            const uint32_t member = reader.Number(4);
            if (member != config.identities[j].member) Fail("historical key does not belong to proposed roster");
            key.members.push_back(member);
        }
        for (size_t j = 0; j < threshold; ++j) {
            const Point point = reader.Array<33>();
            Parse(point, j != 0 && j + 1 != threshold);
            key.commitments.push_back(point);
        }
        for (uint32_t member : key.members) {
            if (VerificationKey(key, member).infinity) Fail("audit committee contains publicly known zero share");
        }
        config.keys.push_back(std::move(key));
    }
    reader.End();
    return config;
}

bool EqualCommittee(const Key& left, const Key& right)
{
    return left.epoch == right.epoch && left.members == right.members && left.commitments == right.commitments;
}

Hash RegistryBinding(const DynaFedParamEntry& entry)
{
    return RawHash((HashWriter{} << entry.m_audit_assets_version << entry.m_audit_assets).GetHash());
}

void CheckRegistry(const DynaFedParamEntry& entry)
{
    const auto& assets = entry.m_audit_assets;
    if (assets.empty() || assets.size() > MAX_ASSETS ||
        std::any_of(assets.begin(), assets.end(), [](const CAsset& asset) { return asset.IsNull(); }) ||
        !std::is_sorted(assets.begin(), assets.end()) ||
        std::adjacent_find(assets.begin(), assets.end()) != assets.end()) Fail("audit asset registry must be bounded, nonzero, sorted and distinct");
}

void CheckEntry(const DynaFedParamEntry& entry, const Config& config)
{
    const auto& active = config.ActiveKey();
    if (entry.m_audit_version != active.version ||
        entry.m_audit_pubkey != B(active.commitments.front())) Fail("audit key/version does not match complete configuration");
    if (config.signer_policy != PolicyBinding(entry)) Fail("audit configuration does not bind proposed DynaFed policy");
}

void ReadReadiness(const Hash& chain_id, const Hash& previous, const Config& config,
                   std::span<const unsigned char> config_bytes,
                   std::span<const unsigned char> prepared, uint32_t activation_height)
{
    if (prepared.size() < 42 || prepared.size() > MAX_PREPARED_BYTES) Fail("invalid prepared audit transition size");
    Reader reader{prepared};
    const auto magic = reader.Take(4);
    if (!std::equal(magic.begin(), magic.end(), reinterpret_cast<const unsigned char*>("TAP1"))) Fail("invalid prepared audit transition magic");
    if (reader.Array<32>() != previous) Fail("audit transition does not extend previous configuration");
    if (reader.Number(4) != activation_height) Fail("audit transition targets wrong activation boundary");
    const size_t count = reader.Number(2);
    if (count < 1 || count > MAX_KEYS * MAX_MEMBERS || prepared.size() != 42 + 136 * count) Fail("invalid audit readiness count");
    const Hash transition = Digest("audit-transition", {B(chain_id), B(previous), Number(activation_height, 4), B(ConfigBinding(config_bytes))});
    std::vector<size_t> counts(config.keys.size(), 0);
    std::pair<uint32_t, uint32_t> previous_pair{0, 0};
    for (size_t i = 0; i < count; ++i) {
        const uint32_t version = reader.Number(4);
        const uint32_t member = reader.Number(4);
        const std::pair<uint32_t, uint32_t> pair{version, member};
        if (pair <= previous_pair || version < 1 || version > config.keys.size()) Fail("audit readiness entries must be ordered and distinct");
        previous_pair = pair;
        const Hash challenge = reader.Array<32>();
        const Hash response = reader.Array<32>();
        const auto signature = reader.Array<64>();
        if (challenge >= Order() || response >= Order()) Fail("noncanonical audit readiness scalar");
        const auto identity = std::find_if(config.identities.begin(), config.identities.end(), [&](const Identity& value) { return value.member == member; });
        if (identity == config.identities.end()) Fail("unknown audit readiness signer");
        const Hash context = Digest("audit-readiness", {B(transition), Number(version, 4), Number(member, 4)});
        const CurvePoint share = VerificationKey(config.keys[version - 1], member);
        const CurvePoint commitment = Add(Multiply(Generator(), response), Negate(Multiply(share, challenge)));
        if (Challenge(context, share, commitment) != challenge) Fail("invalid audit share-possession proof");
        Bytes proof = B(challenge);
        proof.insert(proof.end(), response.begin(), response.end());
        const Hash message = Digest("audit-ready-signature", {B(context), proof});
        secp256k1_xonly_pubkey public_key;
        if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &public_key, identity->public_key.data()) ||
            !secp256k1_schnorrsig_verify(secp256k1_context_static, signature.data(), message.data(), message.size(), &public_key)) {
            Fail("invalid institution readiness signature");
        }
        ++counts[version - 1];
    }
    reader.End();
    for (size_t i = 0; i < counts.size(); ++i) {
        if (counts[i] < config.keys[i].Threshold()) Fail("each retained audit key needs a distinct ready quorum");
    }
}

} // namespace

bool DecodeConfig(std::span<const unsigned char> bytes, Config& config, std::string* error)
{
    try {
        if (bytes.size() < 46 || bytes.size() > MAX_CONFIG_BYTES) Fail("invalid audit-config size");
        // Bounded successful parse cache avoids repeatedly evaluating every
        // polynomial when identical full manifests recur in voting headers.
        const Hash binding = ConfigBinding(bytes);
        static std::mutex mutex;
        static std::map<Hash, Config> cache;
        {
            std::lock_guard lock{mutex};
            if (const auto it = cache.find(binding); it != cache.end()) {
                config = it->second;
                return true;
            }
        }
        Config parsed = ReadConfig(bytes);
        {
            std::lock_guard lock{mutex};
            if (cache.size() >= 32) cache.clear();
            cache.emplace(binding, parsed);
        }
        config = std::move(parsed);
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

Hash ConfigBinding(std::span<const unsigned char> bytes) { return Digest("audit-config", {B(bytes)}); }

Hash PolicyBinding(const DynaFedParamEntry& entry)
{
    HashWriter writer;
    writer << entry.m_signblockscript << entry.m_signblock_witness_limit << entry.m_fedpeg_program
           << entry.m_fedpegscript << entry.m_extension_space;
    // Genesis policyasset is derived from the genesis hash, which also commits
    // TAG1. Version-zero registry is immutable and chain-configured; including
    // it here would create a hash cycle. Every later registration is bound.
    if (entry.m_audit_assets_version != 0) {
        writer << std::string{"threshold-audit-assets-v1"} << entry.m_audit_assets_version << entry.m_audit_assets;
    }
    return RawHash(writer.GetHash());
}

Hash InitialPolicyBinding(const Consensus::Params& params)
{
    Hash signblock;
    CSHA256().Write(params.signblockscript.data(), params.signblockscript.size()).Finalize(signblock.data());
    Hash fedpeg;
    CSHA256().Write(params.fedpegScript.data(), params.fedpegScript.size()).Finalize(fedpeg.data());
    CScript program = CScript() << OP_0 << B(fedpeg);
    if (!params.start_p2wsh_script) {
        const uint160 hash = Hash160(program);
        program = CScript() << OP_HASH160 << std::vector<unsigned char>(hash.begin(), hash.end()) << OP_EQUAL;
    }
    return PolicyBinding(DynaFedParamEntry{CScript() << OP_0 << B(signblock), params.max_block_signature_size,
                                         program, params.fedpegScript, params.first_extension_space});
}

bool ValidateGenesis(const Consensus::Params& params, std::string* error)
{
    Config config;
    if (!DecodeConfig(params.audit_config, config, error)) return false;
    if (config.generation != 0 || config.active_version != 1 || config.keys.size() != 1 ||
        config.keys.front().epoch != 0 || config.signer_policy != InitialPolicyBinding(params) ||
        params.audit_pubkey != B(config.ActiveKey().commitments.front())) {
        if (error) *error = "genesis audit configuration must initialize one key at epoch/generation zero and bind the initial DynaFed policy";
        return false;
    }
    return true;
}

bool ValidateProposal(const Hash& chain_id, const DynaFedParamEntry& current,
                      const DynaFedParamEntry& proposed, uint32_t activation_height, std::string* error)
{
    try {
        if (current.m_audit_config.size() > MAX_CONFIG_BYTES || proposed.m_audit_config.size() > MAX_CONFIG_BYTES ||
            proposed.m_audit_prepared.size() > MAX_PREPARED_BYTES) Fail("oversized audit governance payload");
        if (activation_height == 0) Fail("audit activation height must be positive");
        CheckRegistry(current);
        CheckRegistry(proposed);
        if (proposed.m_audit_assets == current.m_audit_assets) {
            if (proposed.m_audit_assets_version != current.m_audit_assets_version) Fail("unchanged audit registry must retain its version");
        } else {
            if (current.m_audit_assets_version == std::numeric_limits<uint32_t>::max() ||
                proposed.m_audit_assets_version != current.m_audit_assets_version + 1 ||
                proposed.m_audit_assets.size() <= current.m_audit_assets.size() ||
                !std::includes(proposed.m_audit_assets.begin(), proposed.m_audit_assets.end(),
                               current.m_audit_assets.begin(), current.m_audit_assets.end())) Fail("audit registry updates must append assets and increment version exactly once");
        }
        // Successful certificates recur throughout an epoch. Bind every policy,
        // certificate and context byte; never cache a failed verification.
        const Hash cache_key = Digest("audit-native-proposal-cache", {B(chain_id), Number(activation_height, 4),
            current.m_audit_config, proposed.m_audit_config, proposed.m_audit_prepared,
            B(PolicyBinding(current)), B(RegistryBinding(current)), current.m_audit_pubkey, Number(current.m_audit_version, 4),
            B(PolicyBinding(proposed)), B(RegistryBinding(proposed)), proposed.m_audit_pubkey, Number(proposed.m_audit_version, 4)});
        static std::mutex mutex;
        static std::map<Hash, bool> cache;
        {
            std::lock_guard lock{mutex};
            if (cache.contains(cache_key)) return true;
        }
        Config old_config, config;
        std::string decode_error;
        if (!DecodeConfig(current.m_audit_config, old_config, &decode_error) ||
            !DecodeConfig(proposed.m_audit_config, config, &decode_error)) throw std::runtime_error(decode_error);
        CheckEntry(current, old_config);
        CheckEntry(proposed, config);
        if (old_config.generation == std::numeric_limits<uint32_t>::max() || config.generation != old_config.generation + 1) Fail("audit configuration generation must increment exactly once");
        if (config.keys.size() < old_config.keys.size() || config.keys.size() > old_config.keys.size() + 1) Fail("historical audit keys cannot be deleted");
        for (size_t i = 0; i < old_config.keys.size(); ++i) {
            const Key& old_key = old_config.keys[i];
            const Key& key = config.keys[i];
            if (key.commitments.front() != old_key.commitments.front() || key.scheme != old_key.scheme) Fail("historical audit key identity or scheme changed");
            if (!EqualCommittee(key, old_key) && (old_key.epoch == std::numeric_limits<uint32_t>::max() || key.epoch != old_key.epoch + 1)) Fail("handoff must increment share epoch exactly once");
        }
        if (config.keys.size() == old_config.keys.size()) {
            if (config.active_version != old_config.active_version) Fail("historical-only audit key cannot be reactivated");
        } else {
            const Key& key = config.keys.back();
            if (config.active_version != key.version || key.epoch != 0) Fail("new audit key must start fresh active version/share epoch");
            for (const Key& old_key : old_config.keys) {
                if (key.commitments.front() == old_key.commitments.front()) Fail("audit rollover requires fresh public key");
            }
        }
        ReadReadiness(chain_id, ConfigBinding(current.m_audit_config), config, proposed.m_audit_config,
                      proposed.m_audit_prepared, activation_height);
        {
            std::lock_guard lock{mutex};
            if (cache.size() >= 32) cache.clear();
            cache.emplace(cache_key, true);
        }
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

} // namespace threshold_audit::governance
