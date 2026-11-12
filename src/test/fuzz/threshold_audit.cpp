// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <threshold_audit.h>
#include <threshold_audit_governance.h>

#include <algorithm>
#include <span>
#include <stdexcept>

/** Input is TAG1, or the public statement/vector encoding described in
 * contrib/threshold-audit/NATIVE-INTEGRATION.md. No private keys enter either parser. */
FUZZ_TARGET(threshold_audit)
{
    if (buffer.size() > 125000) return;
    const std::span<const unsigned char> bytes{buffer.data(), buffer.size()};
    if (bytes.size() >= 4 && std::equal(bytes.begin(), bytes.begin() + 4, "TAG1")) {
        threshold_audit::governance::Config config;
        (void)threshold_audit::governance::DecodeConfig(bytes, config);
        return;
    }
    size_t offset{0};
    auto take = [&](size_t length) {
        if (length > bytes.size() - offset) throw std::out_of_range("truncated audit fuzz input");
        const auto value = bytes.subspan(offset, length);
        offset += length;
        return value;
    };
    auto number = [&] {
        uint32_t value{0};
        for (unsigned char byte : take(4)) value = (value << 8) | byte;
        return value;
    };
    try {
        if (bytes.size() >= 4 && std::equal(bytes.begin(), bytes.begin() + 4, "TAPF")) {
            (void)take(4);
            threshold_audit::governance::Hash chain;
            auto value = take(32);
            std::copy(value.begin(), value.end(), chain.begin());
            const uint32_t boundary = number();
            const auto current_bytes = take(number());
            const auto proposed_bytes = take(number());
            const auto prepared_bytes = take(number());
            if (offset != bytes.size()) return;
            threshold_audit::governance::Config current_config, proposed_config;
            if (!threshold_audit::governance::DecodeConfig(current_bytes, current_config) ||
                !threshold_audit::governance::DecodeConfig(proposed_bytes, proposed_config)) return;
            std::array<unsigned char, 32> script_hash;
            const unsigned char script{0x51};
            CSHA256().Write(&script, 1).Finalize(script_hash.data());
            const CScript program = CScript{} << OP_0 << std::vector<unsigned char>{script_hash.begin(), script_hash.end()};
            auto entry = [&](const auto& config, auto encoded) {
                DynaFedParamEntry result{program, 108, program, CScript{} << OP_TRUE, {{}}};
                result.m_audit_config.assign(encoded.begin(), encoded.end());
                result.m_audit_version = config.active_version;
                const auto& key = config.ActiveKey().commitments.front();
                result.m_audit_pubkey.assign(key.begin(), key.end());
                return result;
            };
            const auto current = entry(current_config, current_bytes);
            auto proposed = entry(proposed_config, proposed_bytes);
            proposed.m_audit_prepared.assign(prepared_bytes.begin(), prepared_bytes.end());
            (void)threshold_audit::governance::ValidateProposal(chain, current, proposed, boundary);
            return;
        }
        threshold_audit::Statement statement;
        auto value = take(32);
        std::copy(value.begin(), value.end(), statement.chain_id.begin());
        value = take(32);
        std::copy(value.begin(), value.end(), statement.tx_digest.begin());
        statement.output_index = number();
        value = take(number());
        statement.script.assign(value.begin(), value.end());
        value = take(33);
        statement.asset_commitment.assign(value.begin(), value.end());
        value = take(33);
        statement.value_commitment.assign(value.begin(), value.end());
        value = take(33);
        statement.audit_key.assign(value.begin(), value.end());
        const uint32_t count = number();
        if (count > 256) return;
        for (uint32_t index = 0; index < count; ++index) {
            value = take(32);
            std::array<unsigned char, 32> asset;
            std::copy(value.begin(), value.end(), asset.begin());
            statement.assets.push_back(asset);
        }
        const auto packet = take(number());
        if (offset != bytes.size()) return;
        (void)threshold_audit::VerifyPacket(statement, packet);
    } catch (const std::out_of_range&) {
        // The vector envelope is intentionally permissive input to the bounded
        // cryptographic parsers; malformed envelopes are ordinary fuzz cases.
    }
}
