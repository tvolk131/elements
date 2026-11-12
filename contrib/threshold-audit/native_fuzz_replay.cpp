// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Public-parser corpus replay without the full fuzz framework's unsafe-mode
// initialization. Coverage-guided fuzzing still uses BUILD_FOR_FUZZING=ON.
#include <test/fuzz/fuzz.h>
#include <util/translation.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{};

static TypeTestOneInput& Target()
{
    static TypeTestOneInput target;
    return target;
}

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target, FuzzTargetOptions)
{
    if (name != "threshold_audit" || Target()) throw std::runtime_error("unexpected replay target");
    Target() = std::move(target);
}

int main(int argc, char** argv)
{
    if (argc != 2 || !Target()) return 2;
    size_t count{0};
    for (const auto& file : std::filesystem::directory_iterator(argv[1])) {
        if (!file.is_regular_file()) continue;
        if (file.file_size() > 125000) throw std::runtime_error("oversized replay seed");
        std::ifstream stream{file.path(), std::ios::binary};
        const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>{stream}, {}};
        if (!stream || bytes.size() != file.file_size()) throw std::runtime_error("unable to read replay seed");
        Target()(bytes);
        ++count;
    }
    std::cout << "threshold_audit: replayed " << count << " public seeds successfully\n";
}
