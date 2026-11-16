// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <threshold_audit.h>
#include <threshold_audit_governance.h>
#include <threshold_audit_validation.h>

#include <algorithm>
#include <cassert>
#include <ios>
#include <span>
#include <stdexcept>

namespace {
/** TXAU || height (BE32) || policy length (BE32) || policy || transaction with
 * witness. Exercises the authorization witness parser and quorum check that
 * every node runs on every transaction once a chain sets a policy. */
void CheckAuthorizationInput(std::span<const unsigned char> bytes)
{
    if (bytes.size() < 12) return;
    auto number = [&](size_t at) {
        return uint32_t{bytes[at]} << 24 | uint32_t{bytes[at + 1]} << 16 | uint32_t{bytes[at + 2]} << 8 | bytes[at + 3];
    };
    const uint32_t height = number(4);
    const uint32_t policy_size = number(8);
    if (policy_size > bytes.size() - 12) return;
    const std::vector<unsigned char> policy(bytes.begin() + 12, bytes.begin() + 12 + policy_size);
    unsigned threshold;
    std::vector<XOnlyPubKey> keys;
    const bool policy_valid = threshold_audit::DecodeAuthorizationPolicy(policy, threshold, keys);
    if (policy_valid) assert(threshold >= 1 && threshold <= keys.size() && keys.size() <= 16);

    // Audit chains are Elements chains; both globals select their serialization.
    const bool previous_elements = g_con_elementsmode, previous = g_threshold_audit_enabled;
    g_con_elementsmode = true;
    g_threshold_audit_enabled = true;
    try {
        DataStream stream{bytes.subspan(12 + policy_size)};
        CMutableTransaction mutable_tx;
        stream >> TX_WITH_WITNESS(mutable_tx);
        const CTransaction tx{mutable_tx};
        (void)threshold_audit::TransactionTemplateHash(tx);
        const auto expiry = threshold_audit::AuthorizationExpiry(tx);
        // Only policies that passed header validation reach this check.
        if (policy.empty() || policy_valid) {
            const Consensus::Params consensus{};
            TxValidationState state;
            if (threshold_audit::CheckAuthorization(tx, consensus, policy, height, state) && !policy.empty() && !tx.IsCoinBase()) {
                assert(expiry && *expiry >= height && *expiry - height < threshold_audit::MAX_AUTHORIZATION_LIFETIME);
            }
        }
    } catch (const std::ios_base::failure&) {
    }
    g_threshold_audit_enabled = previous;
    g_con_elementsmode = previous_elements;
}
} // namespace

/** Input is TAG1, TXAU (above), or the public statement/vector encoding described
 * in contrib/threshold-audit/NATIVE-INTEGRATION.md. No private keys enter any parser. */
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
    if (bytes.size() >= 4 && std::equal(bytes.begin(), bytes.begin() + 4, "TXAU")) {
        CheckAuthorizationInput(bytes);
        return;
    }
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
