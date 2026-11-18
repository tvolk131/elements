// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THRESHOLD_AUDIT_VALIDATION_H
#define BITCOIN_THRESHOLD_AUDIT_VALIDATION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <optional>
#include <pubkey.h>
#include <string>
#include <threshold_audit.h>
#include <vector>

class CCoinsViewCache;
class CScript;
class CTransaction;
class CMutableTransaction;
class TxValidationState;
class uint256;
namespace Consensus { struct Params; }

namespace threshold_audit {

/** Experimental public-data CPU budget, additional to normal block weight. */
inline constexpr size_t MAX_OUTPUTS_PER_BLOCK{16};

/** Number of consecutive block heights in which one transaction authorization
 * can be used: a transaction at height h needs h <= expiry < h + this value.
 * Without a ceiling an authorizer quorum could hand out effectively permanent
 * authorizations, and refusing to sign (a freeze) would never take effect on
 * transactions it had already authorized. Matches the settlement signers'
 * WINDOW, which signs expiry = tip + 20 for inclusion from tip + 1. */
inline constexpr uint32_t MAX_AUTHORIZATION_LIFETIME{20};

/** Double-SHA256 of nonwitness transaction serialization, with every scriptSig
 * cleared. This permits signing after recovery proof construction and excludes
 * recovery witnesses, avoiding a circular hash. All outputs/nonces, prevouts,
 * issuance fields, sequences, version and locktime remain committed. */
uint256 TransactionTemplateHash(const CTransaction& tx);

/** Count outputs with at least one confidential component. */
size_t ConfidentialOutputCount(const CTransaction& tx);

/** Attach packets after every commitment/nonce is final, before input signing.
 * A missing opening is permitted only if an existing packet verifies for the
 * complete final template. No openings or audit secret shares enter the packet.
 */
bool AttachTransactionProofs(CMutableTransaction& tx, const Consensus::Params& consensus,
                             const Policy& audit_policy,
                             const std::vector<std::optional<Opening>>& openings,
                             std::string* error = nullptr);

/** Check mandatory TAC2 output recovery under the candidate block's public key.
 * Never use a wallet-supplied key or skip this based on assumevalid/script flags.
 * The first native experiment rejects confidential issuance amounts and mixed
 * explicit/confidential output pairs until their recovery modes are specified.
 */
bool CheckTransaction(const CTransaction& tx, const Consensus::Params& consensus,
                      const Policy& audit_policy, TxValidationState& state);

/** Decode a DynaFed transaction-authorization policy: one threshold byte and
 * between one and sixteen distinct, valid 32-byte BIP340 keys. */
bool DecodeAuthorizationPolicy(std::span<const unsigned char> policy, unsigned& threshold,
                               std::vector<XOnlyPubKey>& keys);

/** What each authorizer signs. Binds the chain, the exact policy in force, the
 * transaction template (every input and output, no witnesses) and the last
 * block height at which the transaction may confirm. */
uint256 AuthorizationDigest(const uint256& genesis, std::span<const unsigned char> policy,
                            const uint256& template_hash, uint32_t expiry_height);

/** Recovery: the same quorum may move named outputs without their owners'
 * signatures, first into quarantine (or a burn), and from quarantine anywhere.
 * A recovery authorization is the marker byte, a 32-byte bitmap of recovered
 * input indexes (bit i of byte i / 8), the expiry and the signatures; it is
 * signed in its own domain, so an ordinary authorization can never be replayed
 * as one. Its length is 37 mod 65, an ordinary one's 4 mod 65. */
inline constexpr unsigned char RECOVERY_MARKER{0x52};
inline constexpr size_t RECOVERY_BITMAP_BYTES{32};
using RecoveryBitmap = std::array<unsigned char, RECOVERY_BITMAP_BYTES>;

/** Signed by the quorum to recover the inputs in `bitmap`. */
uint256 RecoveryDigest(const uint256& genesis, std::span<const unsigned char> policy,
                       const uint256& template_hash, const RecoveryBitmap& bitmap, uint32_t expiry_height);

/** Last height at which the authorization allows confirmation, if it parses. */
std::optional<uint32_t> AuthorizationExpiry(const CTransaction& tx);

/** Inputs whose owner signature a well-formed recovery authorization waives;
 * empty for ordinary transactions. Parsing only: CheckAuthorization verifies
 * the quorum signature on every path that relies on this. */
std::vector<bool> RecoveredInputs(const CTransaction& tx);

/** Quarantine output: tag, 32-byte case reference, OP_2DROP OP_FALSE. No key
 * can spend it (the script always fails); only a recovery may move it. */
bool IsQuarantineScript(const CScript& script);
CScript QuarantineScript(const uint256& case_reference);

/** Require a quorum authorization on every non-coinbase transaction while the
 * candidate block's policy is set, and none while it is empty. The expiry must
 * fall within MAX_AUTHORIZATION_LIFETIME heights of `height`. The witness
 * holds a little-endian expiry height followed by exactly `threshold` pairs of
 * key index and BIP340 signature, in increasing index order, optionally after
 * a recovery marker and bitmap. Consensus-critical independently of script
 * checks and assumevalid. */
bool CheckAuthorization(const CTransaction& tx, const Consensus::Params& consensus,
                        const std::vector<unsigned char>& policy, uint32_t height,
                        TxValidationState& state);

/** Rules that need the spent coins: a quarantine output can be spent only by
 * recovering it, and a recovery that takes anything other than quarantined
 * funds may pay only into quarantine, a burn or the fee. */
bool CheckRecovery(const CTransaction& tx, const CCoinsViewCache& inputs, TxValidationState& state);

} // namespace threshold_audit
#endif // BITCOIN_THRESHOLD_AUDIT_VALIDATION_H
