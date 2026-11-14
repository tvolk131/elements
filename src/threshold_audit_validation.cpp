// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <threshold_audit_validation.h>

#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <threshold_audit.h>

#include <algorithm>
#include <map>
#include <mutex>

namespace threshold_audit {

uint256 TransactionTemplateHash(const CTransaction& tx)
{
    CMutableTransaction copy{tx};
    for (auto& input : copy.vin) input.scriptSig.clear();
    copy.witness.SetNull();
    return CTransaction{copy}.GetHash();
}

size_t ConfidentialOutputCount(const CTransaction& tx)
{
    return std::count_if(tx.vout.begin(), tx.vout.end(), [](const CTxOut& out) {
        return out.nAsset.IsCommitment() || out.nValue.IsCommitment();
    });
}

bool AttachTransactionProofs(CMutableTransaction& tx, const Consensus::Params& consensus,
                             const Policy& audit_policy,
                             const std::vector<std::optional<Opening>>& openings, std::string* error)
{
    if (!consensus.threshold_audit) return true;
    if (ConfidentialOutputCount(CTransaction{tx}) > MAX_OUTPUTS_PER_BLOCK) {
        if (error) *error = "audit output count exceeds the experimental block limit";
        return false;
    }
    if (openings.size() != tx.vout.size()) {
        if (error) *error = "audit output opening count mismatch";
        return false;
    }
    const uint256 template_hash = TransactionTemplateHash(CTransaction{tx});
    Statement statement;
    std::copy(consensus.hashGenesisBlock.begin(), consensus.hashGenesisBlock.end(), statement.chain_id.begin());
    std::copy(template_hash.begin(), template_hash.end(), statement.tx_digest.begin());
    statement.audit_key = audit_policy.key;
    for (const auto& asset : audit_policy.assets) {
        statement.assets.emplace_back();
        std::copy(asset.begin(), asset.end(), statement.assets.back().begin());
    }
    std::vector<std::vector<unsigned char>> packets(tx.vout.size());
    for (size_t index = 0; index < tx.vout.size(); ++index) {
        const auto& out = tx.vout[index];
        if (out.nAsset.IsExplicit() && out.nValue.IsExplicit()) continue;
        if (!out.nAsset.IsCommitment() || !out.nValue.IsCommitment()) {
            if (error) *error = "audit output requires both confidential commitments";
            return false;
        }
        statement.output_index = index;
        statement.script.assign(out.scriptPubKey.begin(), out.scriptPubKey.end());
        statement.asset_commitment = out.nAsset.vchCommitment;
        statement.value_commitment = out.nValue.vchCommitment;
        if (openings[index]) {
            if (!CreatePacket(statement, *openings[index], packets[index], error)) return false;
        } else {
            if (index >= tx.witness.vtxoutwit.size() ||
                !VerifyPacket(statement, tx.witness.vtxoutwit[index].vchAuditProof, error)) {
                if (error && error->empty()) *error = "missing audit output opening";
                return false;
            }
            packets[index] = tx.witness.vtxoutwit[index].vchAuditProof;
        }
    }
    tx.witness.vtxoutwit.resize(tx.vout.size());
    for (size_t index = 0; index < tx.vout.size(); ++index) tx.witness.vtxoutwit[index].vchAuditProof = std::move(packets[index]);
    if (error) error->clear();
    return true;
}

bool CheckTransaction(const CTransaction& tx, const Consensus::Params& consensus,
                      const Policy& audit_policy, TxValidationState& state)
{
    if (!consensus.threshold_audit) return true;
    for (const auto& input : tx.vin) {
        if (input.assetIssuance.nAmount.IsCommitment() || input.assetIssuance.nInflationKeys.IsCommitment()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-issuance",
                                 "Confidential issuance recovery is not implemented by this experiment");
        }
    }
    if (ConfidentialOutputCount(tx) > MAX_OUTPUTS_PER_BLOCK) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-output-limit");
    }

    // Cache only successful COMPLETE transactions, binding the actual serialized
    // recovery witnesses and every public-policy input. A changed proof/key may
    // never reuse ordinary CT/range-proof cache success. Bounded to 128 entries.
    HashWriter cache_hash;
    cache_hash << consensus.hashGenesisBlock << audit_policy.key << audit_policy.assets_version << audit_policy.assets << tx.GetWitnessHash();
    const uint256 cache_key = cache_hash.GetHash();
    static std::mutex cache_mutex;
    static std::map<uint256, bool> valid_cache;
    {
        std::lock_guard lock{cache_mutex};
        if (valid_cache.contains(cache_key)) return true;
    }

    const uint256 template_hash = TransactionTemplateHash(tx);
    Statement statement;
    std::copy(consensus.hashGenesisBlock.begin(), consensus.hashGenesisBlock.end(), statement.chain_id.begin());
    std::copy(template_hash.begin(), template_hash.end(), statement.tx_digest.begin());
    statement.audit_key = audit_policy.key;
    for (const auto& asset : audit_policy.assets) {
        std::array<unsigned char, 32> bytes;
        std::copy(asset.begin(), asset.end(), bytes.begin());
        statement.assets.push_back(bytes);
    }
    for (size_t index = 0; index < tx.vout.size(); ++index) {
        const auto& out = tx.vout[index];
        const auto* witness = index < tx.witness.vtxoutwit.size() ? &tx.witness.vtxoutwit[index] : nullptr;
        const bool has_packet = witness && !witness->vchAuditProof.empty();
        if (out.nAsset.IsExplicit() && out.nValue.IsExplicit()) {
            if (has_packet) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-unexpected-proof");
            }
            continue; // The complete financial information is already public.
        }
        if (tx.IsCoinBase() || !out.nAsset.IsCommitment() || !out.nValue.IsCommitment()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-output-mode");
        }
        if (!has_packet) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-missing-proof");
        }
        statement.output_index = index;
        statement.script.assign(out.scriptPubKey.begin(), out.scriptPubKey.end());
        statement.asset_commitment = out.nAsset.vchCommitment;
        statement.value_commitment = out.nValue.vchCommitment;
        std::string error;
        if (!VerifyPacket(statement, witness->vchAuditProof, &error)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-threshold-audit-proof", error);
        }
    }
    {
        std::lock_guard lock{cache_mutex};
        if (valid_cache.size() >= 128) valid_cache.clear();
        valid_cache.emplace(cache_key, true);
    }
    return true;
}

bool DecodeAuthorizationPolicy(std::span<const unsigned char> policy, unsigned& threshold,
                               std::vector<XOnlyPubKey>& keys)
{
    keys.clear();
    if (policy.size() < 33 || policy.size() > MAX_AUTHORIZATION_POLICY_BYTES || (policy.size() - 1) % 32 != 0) return false;
    const size_t count = (policy.size() - 1) / 32;
    threshold = policy[0];
    if (threshold < 1 || threshold > count) return false;
    for (size_t index = 0; index < count; ++index) {
        const XOnlyPubKey key{Span<const unsigned char>{policy.data() + 1 + 32 * index, 32}};
        if (!key.IsFullyValid() || std::find(keys.begin(), keys.end(), key) != keys.end()) return false;
        keys.push_back(key);
    }
    return true;
}

uint256 AuthorizationDigest(const uint256& genesis, std::span<const unsigned char> policy,
                            const uint256& template_hash, uint32_t expiry_height)
{
    static constexpr unsigned char domain[] = "Elements/tx-authorization/v1";
    unsigned char policy_hash[32];
    CSHA256().Write(policy.data(), policy.size()).Finalize(policy_hash);
    unsigned char expiry[4];
    WriteBE32(expiry, expiry_height);
    uint256 digest;
    CSHA256().Write(domain, sizeof(domain) - 1).Write(genesis.begin(), 32).Write(policy_hash, 32)
             .Write(template_hash.begin(), 32).Write(expiry, 4).Finalize(digest.begin());
    return digest;
}

std::optional<uint32_t> AuthorizationExpiry(const CTransaction& tx)
{
    const auto& bytes = tx.witness.vchAuthorization;
    if (bytes.size() < 4 + 65 || (bytes.size() - 4) % 65 != 0) return std::nullopt;
    return ReadLE32(bytes.data());
}

bool CheckAuthorization(const CTransaction& tx, const Consensus::Params& consensus,
                        const std::vector<unsigned char>& policy, uint32_t height,
                        TxValidationState& state)
{
    // The authorization is witness data that depends on the height and on the
    // policy in force, and anyone relaying a transaction can strip or alter it.
    // None of these failures therefore says the relaying peer misbehaved, so
    // none uses TX_CONSENSUS. A block that fails here is still invalid.
    const auto& bytes = tx.witness.vchAuthorization;
    if (policy.empty() || tx.IsCoinBase()) {
        if (bytes.empty()) return true;
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-tx-authorization-unexpected");
    }
    if (bytes.empty()) {
        return state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED, "bad-tx-authorization-missing");
    }
    unsigned threshold;
    std::vector<XOnlyPubKey> keys;
    if (!DecodeAuthorizationPolicy(policy, threshold, keys)) {
        // Unreachable for a policy accepted by header validation.
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-tx-authorization-policy");
    }
    const auto expiry = AuthorizationExpiry(tx);
    if (!expiry || bytes.size() != 4 + 65 * static_cast<size_t>(threshold)) {
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-tx-authorization-malformed");
    }
    if (*expiry < height) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-tx-authorization-expired");
    }
    const uint256 digest = AuthorizationDigest(consensus.hashGenesisBlock, policy, TransactionTemplateHash(tx), *expiry);
    int previous{-1};
    for (unsigned n = 0; n < threshold; ++n) {
        const unsigned char* entry = bytes.data() + 4 + 65 * n;
        const int index = entry[0];
        if (index <= previous || static_cast<size_t>(index) >= keys.size()) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-tx-authorization-malformed");
        }
        previous = index;
        if (!keys[index].VerifySchnorr(digest, Span<const unsigned char>{entry + 1, 64})) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-tx-authorization-signature");
        }
    }
    return true;
}

} // namespace threshold_audit
