// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THRESHOLD_AUDIT_VALIDATION_H
#define BITCOIN_THRESHOLD_AUDIT_VALIDATION_H

#include <cstddef>
#include <optional>
#include <string>
#include <threshold_audit.h>
#include <vector>

class CTransaction;
class CMutableTransaction;
class TxValidationState;
class uint256;
namespace Consensus { struct Params; }

namespace threshold_audit {

/** Experimental public-data CPU budget, additional to normal block weight. */
inline constexpr size_t MAX_OUTPUTS_PER_BLOCK{16};

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

} // namespace threshold_audit
#endif // BITCOIN_THRESHOLD_AUDIT_VALIDATION_H
