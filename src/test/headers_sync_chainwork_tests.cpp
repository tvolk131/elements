// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
    /** Synthetic headers with real audit metadata allocations. Contextual
     * governance validity is outside the low-work sync state's responsibility. */
    std::vector<CBlockHeader> GenerateAuditHeaders(size_t count, bool large_payload);
};

namespace {
struct AuditSerializationGuard {
    const bool previous{g_threshold_audit_enabled};
    AuditSerializationGuard() { g_threshold_audit_enabled = true; }
    ~AuditSerializationGuard() { g_threshold_audit_enabled = previous; }
};
} // namespace

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

std::vector<CBlockHeader> HeadersGeneratorSetup::GenerateAuditHeaders(size_t count, bool large_payload)
{
    std::vector<CBlockHeader> headers;
    headers.reserve(count);
    uint256 previous = Params().GenesisBlock().GetHash();
    uint64_t nonce{0};
    for (size_t index = 0; index < count; ++index) {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = previous;
        header.nTime = Params().GenesisBlock().nTime + index + 1;
        header.nBits = Params().GenesisBlock().nBits;
        header.block_height = index + 1;
        header.m_dynafed_params.m_current = DynaFedParamEntry(CScript() << OP_TRUE, 108, ArithToUint256(arith_uint256{1}));
        auto& proposal = header.m_dynafed_params.m_proposed;
        proposal = DynaFedParamEntry(CScript() << OP_TRUE, 108, CScript() << OP_TRUE, CScript() << OP_TRUE, {{1, 2, 3}});
        proposal.m_audit_pubkey.assign(33, 2);
        proposal.m_audit_version = 1;
        proposal.m_audit_config.assign(large_payload ? threshold_audit::governance::MAX_CONFIG_BYTES : 100, 3);
        proposal.m_audit_prepared.assign(large_payload ? threshold_audit::governance::MAX_PREPARED_BYTES : 100, 4);
        proposal.m_audit_assets_version = 1;
        for (size_t asset = 0; asset < (large_payload ? threshold_audit::governance::MAX_ASSETS : 2); ++asset) {
            proposal.m_audit_assets.emplace_back(ArithToUint256(arith_uint256{asset + 1}));
        }
        header.m_signblock_witness.stack = {{5, 6, 7}};
        // DynaFed hashes do not include nNonce; vary the merkle root instead.
        do {
            header.hashMerkleRoot = ArithToUint256(arith_uint256{++nonce});
        } while (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus()));
        previous = header.GetHash();
        headers.push_back(std::move(header));
    }
    return headers;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(audit_header_memory_limit)
{
    AuditSerializationGuard audit_serialization;
    // Less than the 14827-header commitment lookahead, but native bounded
    // governance payloads would retain over 64 MiB. A byte limit must abort;
    // returning an earlier prefix would defeat the commitment security bound.
    const auto headers = GenerateAuditHeaders(900, true);
    const CBlockIndex* start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    auto consensus = Params().GetConsensus();
    consensus.threshold_audit = true;
    const arith_uint256 target = start->nChainWork + arith_uint256{headers.size() * 2};
    HeadersSyncState sync{0, consensus, start, target};
    auto result = sync.ProcessNextHeaders(headers, true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
    // The cached final presync header is part of the byte budget too.
    BOOST_CHECK(sync.GetAuditHeaderMemoryUsage() > threshold_audit::governance::MAX_PREPARED_BYTES);
    result = sync.ProcessNextHeaders(headers, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK_EQUAL(sync.GetAuditHeaderMemoryUsage(), 0);

    // The audit-only resource policy does not change other networks' behavior,
    // even when the in-memory fixtures carry the same large metadata vectors.
    consensus.threshold_audit = false;
    HeadersSyncState ordinary{0, consensus, start, target};
    BOOST_REQUIRE(ordinary.ProcessNextHeaders(headers, true).success);
    BOOST_CHECK_EQUAL(ordinary.GetAuditHeaderMemoryUsage(), 0);
    result = ordinary.ProcessNextHeaders(headers, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), headers.size());
    BOOST_CHECK(ordinary.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(audit_header_memory_roundtrip)
{
    AuditSerializationGuard audit_serialization;
    const auto headers = GenerateAuditHeaders(16000, false);
    const CBlockIndex* start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    auto consensus = Params().GetConsensus();
    consensus.threshold_audit = true;
    const arith_uint256 target = start->nChainWork + arith_uint256{headers.size() * 2};
    HeadersSyncState sync{0, consensus, start, target};
    BOOST_REQUIRE(sync.ProcessNextHeaders(headers, true).success);
    BOOST_REQUIRE(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
    std::vector<CBlockHeader> batch{headers.begin(), headers.begin() + 15500};
    auto result = sync.ProcessNextHeaders(batch, true);
    BOOST_REQUIRE(result.success);
    BOOST_REQUIRE(result.request_more);
    BOOST_REQUIRE_EQUAL(result.pow_validated_headers.size(), 15500 - 14827);
    const size_t retained = sync.GetAuditHeaderMemoryUsage();
    BOOST_CHECK(retained > 0);
    BOOST_CHECK(retained <= HeadersSyncState::MAX_AUDIT_HEADER_MEMORY_USAGE);
    for (size_t index = 0; index < result.pow_validated_headers.size(); ++index) {
        const auto& actual = result.pow_validated_headers[index];
        BOOST_CHECK(actual.GetHash() == headers[index].GetHash());
        BOOST_CHECK(actual.m_dynafed_params.m_current == headers[index].m_dynafed_params.m_current);
        BOOST_CHECK(actual.m_dynafed_params.m_current.m_elided_root == headers[index].m_dynafed_params.m_current.m_elided_root);
        BOOST_CHECK(actual.m_dynafed_params.m_proposed == headers[index].m_dynafed_params.m_proposed);
        BOOST_CHECK(actual.m_signblock_witness.stack == headers[index].m_signblock_witness.stack);
    }
    batch.assign(headers.begin() + 15500, headers.begin() + 15600);
    result = sync.ProcessNextHeaders(batch, true);
    BOOST_REQUIRE(result.success);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), 100);
    // Equal-sized payloads replace the 100 headers popped for validation. The
    // charge must decrease on pop rather than accumulating for the whole sync.
    BOOST_CHECK_EQUAL(sync.GetAuditHeaderMemoryUsage(), retained);
    batch.assign(headers.begin() + 15600, headers.end());
    result = sync.ProcessNextHeaders(batch, true);
    BOOST_REQUIRE(result.success);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), 14827 + 400);
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK_EQUAL(sync.GetAuditHeaderMemoryUsage(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
