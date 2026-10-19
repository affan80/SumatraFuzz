#pragma once

#include <string>
#include <vector>

namespace sumatrafuzz::supervisor {
std::wstring QuoteWindowsArgument(const std::wstring& argument);
std::wstring BuildWindowsCommandLine(const std::vector<std::wstring>& arguments);
}  // namespace sumatrafuzz::supervisor
