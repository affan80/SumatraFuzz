#pragma once

// WinAFL-compatible entry point. Do not inline: instrumentation needs a real symbol.
// Return 0 on successful parsing, 1 on ordinary invalid input; never swallow crashes.
#if defined(_WIN32)
#define SUMATRAFUZZ_API extern "C" __declspec(dllexport) __declspec(noinline)
#define SUMATRAFUZZ_CALL __cdecl
#else
#define SUMATRAFUZZ_API extern "C" __attribute__((noinline))
#define SUMATRAFUZZ_CALL
#endif

SUMATRAFUZZ_API int SUMATRAFUZZ_CALL fuzz_one_file(const char *path);

// Implemented by the real SumatraPDF integration in Task A3.
// Unit-test executables may link their own explicitly test-only adapter.
extern "C" int sumatra_parse_pdf(const char *path);
