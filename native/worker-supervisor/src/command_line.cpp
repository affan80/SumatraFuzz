#include "command_line.h"

namespace sumatrafuzz::supervisor {

std::wstring QuoteWindowsArgument(const std::wstring& argument) {
  const bool needs_quotes = argument.empty() || argument.find_first_of(L" \t\n\v\"") != std::wstring::npos;
  if (!needs_quotes) return argument;

  std::wstring result = L"\"";
  size_t backslashes = 0;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'"') {
      result.append(backslashes * 2 + 1, L'\\');
      result.push_back(L'"');
      backslashes = 0;
      continue;
    }
    result.append(backslashes, L'\\');
    backslashes = 0;
    result.push_back(character);
  }
  result.append(backslashes * 2, L'\\');
  result.push_back(L'"');
  return result;
}

std::wstring BuildWindowsCommandLine(const std::vector<std::wstring>& arguments) {
  std::wstring result;
  for (const auto& argument : arguments) {
    if (!result.empty()) result.push_back(L' ');
    result += QuoteWindowsArgument(argument);
  }
  return result;
}

}  // namespace sumatrafuzz::supervisor
