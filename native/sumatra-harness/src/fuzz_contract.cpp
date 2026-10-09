#include "fuzz_contract.h"

#include <filesystem>
#include <system_error>

int SUMATRAFUZZ_CALL fuzz_one_file(const char *path) {
    if (path == nullptr || path[0] == '\0') {
        return 1;
    }
    const std::filesystem::path input(path);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(input, ec) || ec) {
        return 1;
    }
    // No exception or SEH catch: access violations must be observable to WinAFL.
    return sumatra_parse_pdf(path) == 0 ? 0 : 1;
}
