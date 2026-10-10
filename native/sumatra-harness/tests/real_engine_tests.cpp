#include "fuzz_contract.h"
#include "sumatra_runtime.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdlib>

void require(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << "\n"; std::exit(1); }
}

int main() {
    namespace fs = std::filesystem;
    const auto path = fs::temp_directory_path() / "SumatraFuzz A3 real parser.pdf";
    // Deterministic complete one-page PDF; compute cross-reference offsets explicitly.
    std::string pdf = "%PDF-1.4\n";
    size_t offsets[5] = {};
    const char* objects[] = {
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n",
        "4 0 obj\n<< /Producer (SumatraFuzz A3) >>\nendobj\n"
    };
    for (int i=1; i<=4; ++i) { offsets[i] = pdf.size(); pdf += objects[i-1]; }
    const auto xref = pdf.size();
    pdf += "xref\n0 5\n0000000000 65535 f \n";
    char offset[32];
    for (int i=1; i<=4; ++i) {
        sprintf_s(offset, "%010llu 00000 n \n", static_cast<unsigned long long>(offsets[i]));
        pdf += offset;
    }
    pdf += "trailer\n<< /Root 1 0 R /Size 5 >>\nstartxref\n" +
           std::to_string(xref) + "\n%%EOF\n";

    { std::ofstream out(path, std::ios::binary); out << pdf; }
    const auto bytes = path.u8string();
    require(prepare_sumatra_runtime(), "pinned Sumatra runtime must initialize before fuzzing");
    DWORD handlesBefore = 0;
    require(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore) != 0, "initial handle count");
    require(fuzz_one_file(bytes.c_str()) == 0, "genuine Sumatra PDF engine should parse basic PDF");
    require(fuzz_one_file(bytes.c_str()) == 0, "repeated valid PDF should parse");
    { std::ofstream out(path, std::ios::binary | std::ios::trunc); }
    require(fuzz_one_file(bytes.c_str()) == 1, "empty PDF rejected by real engine");
    { std::ofstream out(path, std::ios::binary | std::ios::trunc); out << "%PDF-1.4\n"; }
    require(fuzz_one_file(bytes.c_str()) == 1, "truncated PDF rejected by real engine");
    // Every entry must reopen the current file bytes, including after rejection.
    for (int i = 0; i < 12; ++i) {
        { std::ofstream out(path, std::ios::binary | std::ios::trunc); out << pdf; }
        require(fuzz_one_file(bytes.c_str()) == 0, "valid PDF must parse after rewritten file");
        { std::ofstream out(path, std::ios::binary | std::ios::trunc); out << "NOT A PDF"; }
        require(fuzz_one_file(bytes.c_str()) == 1, "invalid rewrite must reject");
    }
    require(fuzz_one_file("does-not-exist-at-all.pdf") == 1, "nonexistent input is rejected");
    DWORD handlesAfter = 0;
    require(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) != 0, "final handle count");
    require(handlesAfter <= handlesBefore + 8, "reentry leaked OS handles");
    release_sumatra_runtime();
    std::error_code ec;
    require(fs::remove(path, ec) && !ec, "released engine must not hold file lock");
    require(prepare_sumatra_runtime(), "runtime must support clean reinitialization");
    release_sumatra_runtime();
    std::cout << "Real SumatraPDF parser: PASS\n";
}
