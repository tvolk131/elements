// Copyright (c) 2016-2019 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_PRIMITIVES_TXWITNESS_H
#define BITCOIN_PRIMITIVES_TXWITNESS_H

#include <primitives/confidential.h>
#include <script/script.h>
#include <uint256.h>

/** Chain-wide experimental serialization gate, fixed during parameter selection. */
extern bool g_threshold_audit_enabled;
static constexpr size_t MAX_THRESHOLD_AUDIT_PROOF_SIZE = 80000;
/** Expiry height plus at most sixteen indexed BIP340 signatures. */
static constexpr size_t MAX_TX_AUTHORIZATION_SIZE = 4 + 16 * 65;

/** Bound allocations before reading experimental proof/key byte vectors. */
template <size_t MaxSize>
struct ThresholdAuditBytesFormatter
{
    template <typename Stream>
    void Ser(Stream& s, const std::vector<unsigned char>& value)
    {
        if (value.size() > MaxSize) throw std::ios_base::failure("threshold audit byte vector too large");
        ::Serialize(s, value);
    }

    template <typename Stream>
    void Unser(Stream& s, std::vector<unsigned char>& value)
    {
        const uint64_t size = ReadCompactSize(s);
        if (size > MaxSize) throw std::ios_base::failure("threshold audit byte vector too large");
        value.resize(size);
        if (size != 0) s.read(MakeWritableByteSpan(value));
    }
};

class CTxInWitness
{
public:
    std::vector<unsigned char> vchIssuanceAmountRangeproof;
    std::vector<unsigned char> vchInflationKeysRangeproof;
    CScriptWitness scriptWitness;
    // Re-use script witness struct to include its own witness
    CScriptWitness m_pegin_witness;

    SERIALIZE_METHODS(CTxInWitness, obj) { READWRITE(obj.vchIssuanceAmountRangeproof, obj.vchInflationKeysRangeproof, obj.scriptWitness.stack, obj.m_pegin_witness.stack); }

    CTxInWitness() { }

    bool IsNull() const
    {
        return vchIssuanceAmountRangeproof.empty() && vchInflationKeysRangeproof.empty() && scriptWitness.IsNull() && m_pegin_witness.IsNull();
    }
    void SetNull()
    {
        vchIssuanceAmountRangeproof.clear();
        vchInflationKeysRangeproof.clear();
        scriptWitness.stack.clear();
        m_pegin_witness.stack.clear();
    }

    uint256 GetHash() const;

private:
//    CTxInWitness(const CTxInWitness&);
//    CTxInWitness(CTxInWitness&&);
//    CTxInWitness& operator=(const CTxInWitness&);
//    CTxInWitness& operator=(CTxInWitness&&);
};

class CTxOutWitness
{
public:
    std::vector<unsigned char> vchSurjectionproof;
    std::vector<unsigned char> vchRangeproof;
    std::vector<unsigned char> vchAuditProof;

    SERIALIZE_METHODS(CTxOutWitness, obj)
    {
        READWRITE(obj.vchSurjectionproof, obj.vchRangeproof);
        if (g_threshold_audit_enabled) {
            READWRITE(Using<ThresholdAuditBytesFormatter<MAX_THRESHOLD_AUDIT_PROOF_SIZE>>(obj.vchAuditProof));
        } else {
            SER_READ(obj, obj.vchAuditProof.clear());
        }
    }

    CTxOutWitness() = default;

    bool IsNull() const
    {
        return vchSurjectionproof.empty() && vchRangeproof.empty() && vchAuditProof.empty();
    }
    void SetNull()
    {
        vchSurjectionproof.clear();
        vchRangeproof.clear();
        vchAuditProof.clear();
    }

    uint256 GetHash() const;

private:
//    CTxOutWitness(const CTxOutWitness&);
//    CTxOutWitness(CTxInWitness&&);
//    CTxOutWitness& operator=(const CTxOutWitness&);
//    CTxOutWitness& operator=(CTxOutWitness&&);
};

class CTxWitness
{
public:
    /** In case vtxinwit is missing, all entries are treated as if they were empty CTxInWitnesses */
    std::vector<CTxInWitness> vtxinwit;
    std::vector<CTxOutWitness> vtxoutwit;
    /** Federation authorization of the whole transaction. Serialized only on
     * experimental audit chains; empty where the chain does not require one. */
    std::vector<unsigned char> vchAuthorization;

    CTxWitness() = default;

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        for (size_t n = 0; n < vtxinwit.size(); n++) {
            s << vtxinwit[n];
        }
        for (size_t n = 0; n < vtxoutwit.size(); n++) {
            s << vtxoutwit[n];
        }
        if (g_threshold_audit_enabled) {
            ThresholdAuditBytesFormatter<MAX_TX_AUTHORIZATION_SIZE>{}.Ser(s, vchAuthorization);
        }
        if (IsNull()) {
            /* It's illegal to encode a witness when all vtxinwit and vtxoutwit entries are empty. */
            assert(false && "Superfluous witness record");
        }
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        for (size_t n = 0; n < vtxinwit.size(); n++) {
            s >> vtxinwit[n];
        }
        for (size_t n = 0; n < vtxoutwit.size(); n++) {
            s >> vtxoutwit[n];
        }
        if (g_threshold_audit_enabled) {
            ThresholdAuditBytesFormatter<MAX_TX_AUTHORIZATION_SIZE>{}.Unser(s, vchAuthorization);
        } else {
            vchAuthorization.clear();
        }
        if (IsNull()) {
            /* It's illegal to encode a witness when all vtxinwit and vtxoutwit entries are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }

    bool IsEmpty() const
    {
        return vtxinwit.empty() && vtxoutwit.empty() && vchAuthorization.empty();
    }

    bool IsNull() const
    {
        for (size_t n = 0; n < vtxinwit.size(); n++) {
            if (!vtxinwit[n].IsNull()) {
                return false;
            }
        }
        for (size_t n = 0; n < vtxoutwit.size(); n++) {
            if (!vtxoutwit[n].IsNull()) {
                return false;
            }
        }
        return vchAuthorization.empty();
    }

    void SetNull()
    {
        vtxinwit.clear();
        vtxoutwit.clear();
        vchAuthorization.clear();
    }

private:
//    CTxWitness(const CTxWitness&);
//    CTxWitness(CTxWitness&&);
//    CTxWitness& operator=(const CTxWitness&);
//    CTxWitness& operator=(CTxWitness&&);
};


/*
 * Compute the Merkle root of the transactions in a block using mid-state only.
 * Note that the merkle root calculated with this method is not the same as the
 * one computed by ComputeMerkleRoot.
 */
uint256 ComputeFastMerkleRoot(const std::vector<uint256>& hashes);


#endif // BITCOIN_PRIMITIVES_TXWITNESS_H
