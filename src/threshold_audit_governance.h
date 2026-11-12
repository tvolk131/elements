// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THRESHOLD_AUDIT_GOVERNANCE_H
#define BITCOIN_THRESHOLD_AUDIT_GOVERNANCE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

class DynaFedParamEntry;
namespace Consensus { struct Params; }

namespace threshold_audit::governance {

using Hash = std::array<unsigned char, 32>;
using Point = std::array<unsigned char, 33>;
inline constexpr size_t MAX_ASSETS{256};
inline constexpr size_t MAX_KEYS{16};
inline constexpr size_t MAX_MEMBERS{32};
inline constexpr size_t MAX_CONFIG_BYTES{20334};
inline constexpr size_t MAX_PREPARED_BYTES{69674};

struct Identity {
    uint32_t member;
    Hash public_key;
    bool operator==(const Identity&) const = default;
};

struct Key {
    uint32_t version;
    uint16_t scheme;
    uint32_t epoch;
    std::vector<uint32_t> members;
    std::vector<Point> commitments;
    size_t Threshold() const { return commitments.size(); }
};

struct Config {
    uint32_t generation;
    uint32_t active_version;
    Hash signer_policy;
    std::vector<Identity> identities;
    std::vector<Key> keys;
    const Key& ActiveKey() const { return keys.at(active_version - 1); }
};

/** Exact bounded TAG1 decoder, including curve/manifest validation. Native
 * recovery supports TAC2 (scheme 2) only. Success is not proof of secure DKG,
 * threshold privacy for arbitrary malicious coefficients or future availability.
 */
bool DecodeConfig(std::span<const unsigned char> bytes, Config& config, std::string* error = nullptr);
Hash ConfigBinding(std::span<const unsigned char> bytes);

/** Bind public DynaFed parameters and every post-genesis asset registration.
 * Version zero retains the genesis encoding: its registry is fixed by chain
 * configuration, avoiding a policyasset/genesis/configuration hash cycle. */
Hash PolicyBinding(const DynaFedParamEntry& entry);
Hash InitialPolicyBinding(const Consensus::Params& params);

/** Require one genesis key, generation/epoch zero and the converted initial
 * DynaFed signing policy. Initial membership is part of chain configuration.
 */
bool ValidateGenesis(const Consensus::Params& params, std::string* error = nullptr);

/** Validate complete historical-key retention and transition-bound TAP1
 * readiness. Each retained key needs its own threshold of distinct signed
 * share-possession proofs. No secret material is accepted by this API.
 */
bool ValidateProposal(const Hash& chain_id, const DynaFedParamEntry& current,
                      const DynaFedParamEntry& proposed, uint32_t activation_height,
                      std::string* error = nullptr);

} // namespace threshold_audit::governance
#endif // BITCOIN_THRESHOLD_AUDIT_GOVERNANCE_H
