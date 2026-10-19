#include "command_line.h"

#include <cassert>
#include <string>
#include <vector>

int main() {
  using sumatrafuzz::supervisor::BuildWindowsCommandLine;
  using sumatrafuzz::supervisor::QuoteWindowsArgument;

  assert(QuoteWindowsArgument(L"") == L"\"\"");
  assert(QuoteWindowsArgument(L"plain") == L"plain");
  assert(QuoteWindowsArgument(L"two words") == L"\"two words\"");
  assert(QuoteWindowsArgument(L"embedded\"quote") == L"\"embedded\\\"quote\"");
  assert(QuoteWindowsArgument(L"space and slash\\") == L"\"space and slash\\\\\"");
  assert(QuoteWindowsArgument(L"trailing\\") == L"trailing\\");
  assert(BuildWindowsCommandLine({L"C:\\Program Files\\afl-fuzz.exe", L"-i", L"input folder", L"@@"}) ==
         L"\"C:\\Program Files\\afl-fuzz.exe\" -i \"input folder\" @@");
  return 0;
}
