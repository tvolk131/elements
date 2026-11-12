// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Expected-result review checks. Unlike parser fuzz replay, success requires
// valid Python-generated packets/proposals to verify and mutations to fail.
// The input contains intentionally PUBLIC test secrets, never live key data.
#include <asset.h>
#include <primitives/block.h>
#include <threshold_audit.h>
#include <threshold_audit_governance.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{};

namespace {
using Bytes = std::vector<unsigned char>;
size_t positive_checks{0}, negative_checks{0};

void Require(bool value, std::string_view name, bool positive = true)
{
    if (!value) throw std::runtime_error(std::string{"review vector mismatch: "} + std::string{name});
    if (positive) ++positive_checks;
    else ++negative_checks;
}

Bytes Hex(const UniValue& value)
{
    const auto encoded = value.get_str();
    if (!encoded.empty() && !IsHex(encoded)) throw std::runtime_error("invalid fixture hex");
    return ParseHex(encoded);
}

template <size_t Size> std::array<unsigned char, Size> Array(const UniValue& value)
{
    const auto bytes = Hex(value);
    if (bytes.size() != Size) throw std::runtime_error("incorrect fixed vector length");
    std::array<unsigned char, Size> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

threshold_audit::Statement Statement(const UniValue& value)
{
    threshold_audit::Statement statement;
    statement.chain_id = Array<32>(value["chain_id_raw"]);
    statement.tx_digest = Array<32>(value["tx_digest_raw"]);
    statement.output_index = value["output_index"].getInt<uint32_t>();
    statement.script = Hex(value["script"]);
    statement.asset_commitment = Hex(value["asset_commitment"]);
    statement.value_commitment = Hex(value["value_commitment"]);
    statement.audit_key = Hex(value["audit_key"]);
    for (const auto& asset : value["assets_raw"].getValues()) statement.assets.push_back(Array<32>(asset));
    return statement;
}

DynaFedParamEntry Entry(const UniValue& policy, const UniValue& scenario, bool target)
{
    const auto script = Hex(policy["signblockscript"]);
    const auto program = Hex(policy["fedpeg_program"]);
    const auto fedpeg = Hex(policy["fedpegscript"]);
    std::vector<Bytes> extensions;
    for (const auto& item : policy["extension_space"].getValues()) extensions.push_back(Hex(item));
    DynaFedParamEntry entry{CScript{script.begin(), script.end()}, policy["max_block_witness"].getInt<uint32_t>(),
                            CScript{program.begin(), program.end()}, CScript{fedpeg.begin(), fedpeg.end()}, extensions};
    entry.m_audit_config = Hex(scenario[target ? "target_config" : "source_config"]);
    threshold_audit::governance::Config config;
    Require(threshold_audit::governance::DecodeConfig(entry.m_audit_config, config), target ? "target TAG1" : "source TAG1");
    Require(threshold_audit::governance::ConfigBinding(entry.m_audit_config) == Array<32>(scenario[target ? "target_config_binding" : "source_config_binding"]), "TAG1 binding");
    entry.m_audit_version = config.active_version;
    const auto& key = config.ActiveKey().commitments.front();
    entry.m_audit_pubkey.assign(key.begin(), key.end());
    entry.m_audit_assets_version = scenario[target ? "target_assets_version" : "source_assets_version"].getInt<uint32_t>();
    for (const auto& item : scenario[target ? "target_assets_raw" : "source_assets_raw"].getValues()) {
        const auto raw = Array<32>(item);
        uint256 value;
        std::copy(raw.begin(), raw.end(), value.begin());
        entry.m_audit_assets.emplace_back(value);
    }
    if (target) entry.m_audit_prepared = Hex(scenario["prepared"]);
    Require(threshold_audit::governance::PolicyBinding(entry) == Array<32>(scenario[target ? "target_policy_binding_raw" : "source_policy_binding_raw"]), "DynaFed policy binding");
    return entry;
}

void PacketChecks(const UniValue& value)
{
    const auto statement = Statement(value["statement"]);
    const auto packet = Hex(value["packet_hex"]);
    Require(packet.size() == value["packet_bytes"].getInt<size_t>(), "packet byte length");
    Require(threshold_audit::VerifyPacket(statement, packet), "valid Python TAC2 packet");
    Require(threshold_audit::VerifyPacket(statement, packet), "repeated valid Python TAC2 packet");
    auto changed = packet;
    changed.back() ^= 1;
    Require(!threshold_audit::VerifyPacket(statement, changed), "tampered consistency scalar rejected", false);
    changed = packet; changed.push_back(0);
    Require(!threshold_audit::VerifyPacket(statement, changed), "trailing packet byte rejected", false);
    changed = packet; changed[4] = 4;
    Require(!threshold_audit::VerifyPacket(statement, changed), "invalid SEC point rejected", false);
    auto context = statement; ++context.output_index;
    Require(!threshold_audit::VerifyPacket(context, packet), "different output index rejected", false);
    context = statement; context.script.push_back(0);
    Require(!threshold_audit::VerifyPacket(context, packet), "different output script rejected", false);
    context = statement; context.chain_id[0] ^= 1;
    Require(!threshold_audit::VerifyPacket(context, packet), "different chain rejected", false);
    context = statement; context.tx_digest[0] ^= 1;
    Require(!threshold_audit::VerifyPacket(context, packet), "different template rejected", false);
    context = statement; std::reverse(context.assets.begin(), context.assets.end());
    Require(!threshold_audit::VerifyPacket(context, packet), "noncanonical registry rejected", false);
    Require(threshold_audit::MaximumPacketSize(256) == 79992, "maximum 256-asset packet size");
}

void GovernanceChecks(const UniValue& policy, const UniValue& value)
{
    const auto chain = Array<32>(value["chain_id_raw"]);
    const auto height = value["activation_height"].getInt<uint32_t>();
    const auto current = Entry(policy, value, false);
    const auto proposed = Entry(policy, value, true);
    Require(threshold_audit::governance::ValidateProposal(chain, current, proposed, height), "valid Python TAG1/TAP1 transition");
    Require(threshold_audit::governance::ValidateProposal(chain, current, proposed, height), "valid warm proposal-cache transition");
    Require(!threshold_audit::governance::ValidateProposal(chain, current, proposed, height + 1), "wrong activation height rejected", false);
    auto wrong_chain = chain; wrong_chain[0] ^= 1;
    Require(!threshold_audit::governance::ValidateProposal(wrong_chain, current, proposed, height), "wrong chain transition rejected", false);
    auto changed = proposed; changed.m_audit_prepared.back() ^= 1;
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "changed readiness signature rejected", false);
    changed = proposed; changed.m_audit_prepared[4] ^= 1;
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "changed predecessor rejected", false);
    changed = proposed;
    const uint16_t count = (uint16_t(changed.m_audit_prepared[40]) << 8) | changed.m_audit_prepared[41];
    changed.m_audit_prepared.resize(changed.m_audit_prepared.size() - 136);
    changed.m_audit_prepared[40] = (count - 1) >> 8;
    changed.m_audit_prepared[41] = (count - 1) & 255;
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "below-threshold readiness rejected", false);
    changed = proposed; changed.m_audit_assets_version += 1;
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "wrong registry version rejected", false);
    changed = proposed; changed.m_audit_assets.pop_back();
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "removed or rebound registry rejected", false);
    changed = proposed; std::reverse(changed.m_audit_assets.begin(), changed.m_audit_assets.end());
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "reordered registry rejected", false);
    changed = proposed; changed.m_audit_pubkey[0] ^= 1;
    Require(!threshold_audit::governance::ValidateProposal(chain, current, changed, height), "redundant active-key mismatch rejected", false);
    threshold_audit::governance::Config decoded;
    auto encoded = proposed.m_audit_config; encoded.push_back(0);
    Require(!threshold_audit::governance::DecodeConfig(encoded, decoded), "trailing TAG1 bytes rejected", false);
}
} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc != 2) throw std::runtime_error("usage: threshold_audit_vectors PUBLIC-REVIEW-VECTORS.json");
        if (std::filesystem::file_size(argv[1]) > 1000000) throw std::runtime_error("oversized public vector file");
        std::ifstream stream{argv[1], std::ios::binary};
        const std::string bytes{std::istreambuf_iterator<char>{stream}, {}};
        if (!stream) throw std::runtime_error("unable to read vector file");
        UniValue value;
        if (!value.read(bytes) || value["format"].get_str() != "elements-threshold-audit-public-review-v1" ||
            !value["public_test_only"].get_bool()) throw std::runtime_error("expected public test-only review fixture");
        PacketChecks(value["packet"]);
        for (const auto& scenario : value["governance"].getValues()) GovernanceChecks(value["native_policy"], scenario);
        std::cout << "{\"status\":\"passed\",\"native_expected_result_checks\":" << positive_checks + negative_checks
                  << ",\"positive_checks\":" << positive_checks << ",\"negative_checks\":" << negative_checks << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
