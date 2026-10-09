#include "fuzz_contract.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {
int calls = 0;
std::string seen_path;

void require(bool cond, const char *msg) {
    if (!cond) { std::cerr << "FAILED: " << msg << "\n"; std::exit(1); }
}
} // namespace

// Test-only fake adapter. Never link this translation unit into a shipped harness.
extern "C" int sumatra_parse_pdf(const char *path) {
    ++calls;
    seen_path = path;
    std::ifstream input(path, std::ios::binary);
    std::string signature(5, '\0');
    input.read(signature.data(), 5);
    return input.gcount() == 5 && signature == "%PDF-" ? 0 : 1;
}

int main() {
    namespace fs = std::filesystem;
    const fs::path p = fs::temp_directory_path() / "SumatraFuzz A2 contract sample.pdf";
    { std::ofstream out(p, std::ios::binary); out << "%PDF-1.4\n"; }
    const auto expected = p.string();
    require(fuzz_one_file(nullptr) == 1, "null path must be rejected");
    require(fuzz_one_file("") == 1, "empty path must be rejected");
    require(fuzz_one_file("this-file-does-not-exist.pdf") == 1, "missing path must be rejected");
    require(calls == 0, "invalid paths must not call parser adapter");
    require(fuzz_one_file(expected.c_str()) == 0, "valid file should invoke test adapter");
    require(calls == 1 && seen_path == expected, "adapter must get exact file path");
    { std::ofstream out(p, std::ios::binary | std::ios::trunc); out << "INVALID"; }
    require(fuzz_one_file(expected.c_str()) == 1, "parser rejection propagates");
    require(calls == 2, "parser called once per existing input");
    std::error_code ec;
    fs::remove(p, ec);
    std::cout << "A2 contract tests: PASS (test-only parser adapter, no Sumatra integration)\n";
}
