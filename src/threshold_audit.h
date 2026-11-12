// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THRESHOLD_AUDIT_H
#define BITCOIN_THRESHOLD_AUDIT_H

#include <asset.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace threshold_audit {

/** One atomic next-block policy snapshot. Historical verification selects the
 * snapshot effective at the output's creation block, never today's registry. */
struct Policy {
    std::vector<unsigned char> key;
    std::vector<CAsset> assets;
    uint32_t assets_version{0};
};

/** Public inputs derived from the transaction and authenticated chain policy.
 * Byte arrays use the same raw byte order as the Python TAC2 reference, not
 * display-order uint256 hex. The caller defines the transaction-template hash.
 */
struct Statement {
    std::array<unsigned char, 32> chain_id{};
    std::array<unsigned char, 32> tx_digest{};
    uint32_t output_index{0};
    std::vector<unsigned char> script;
    std::vector<unsigned char> asset_commitment;
    std::vector<unsigned char> value_commitment;
    std::vector<unsigned char> audit_key;
    std::vector<std::array<unsigned char, 32>> assets;
};

/** Wallet-known opening. Scalar byte arrays use canonical big-endian encoding. */
struct Opening {
    std::array<unsigned char, 32> asset{};
    uint64_t amount{0};
    std::array<unsigned char, 32> asset_blinder{};
    std::array<unsigned char, 32> value_blinder{};
    ~Opening();
};

/** Create a TAC2 recovery package from a complete opening and final statement.
 * Experimental prover: callers must clear openings after use. This is not a
 * production side-channel/security-reviewed implementation.
 */
bool CreatePacket(const Statement& statement, const Opening& opening,
                  std::vector<unsigned char>& packet, std::string* error = nullptr);

/** Conservative serialized packet limit used for fee estimation. */
size_t MaximumPacketSize(size_t assets);

/** Verify the experimental TAC2 full-opening recovery package.
 * This checks public cryptographic consistency only. It does not implement
 * threshold key generation, disclosure authorization, or committee readiness.
 * Invalid/oversized input returns false and optionally a diagnostic string.
 */
bool VerifyPacket(const Statement& statement, std::span<const unsigned char> packet,
                  std::string* error = nullptr);

} // namespace threshold_audit

#endif // BITCOIN_THRESHOLD_AUDIT_H
