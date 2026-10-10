#include "fuzz_contract.h"
#include "sumatra_runtime.h"
#include <windows.h>
#include <string>
#include <iostream>

static std::string utf8(const wchar_t* value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                           out.data(), size, nullptr, nullptr) != size) return {};
    out.pop_back();
    return out;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 && !(argc == 3 && std::wstring(argv[1]) == L"--selftest")) {
        std::cerr << "usage: sumatrafuzz-harness [--selftest] <pdf-path>\n";
        return 2;
    }
    const auto path = utf8(argv[argc - 1]);
    if (path.empty()) return 2;
    if (!prepare_sumatra_runtime()) { std::cerr << "SumatraPDF pinned runtime initialization failed\n"; return 3; }
    const int result = fuzz_one_file(path.c_str());
    release_sumatra_runtime();
    std::cout << (result == 0 ? "PARSED" : "REJECTED") << '\n';
    return result;
}
