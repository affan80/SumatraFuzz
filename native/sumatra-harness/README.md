# Native harness contract (Task A2)

This directory implements the exported `fuzz_one_file(const char*)` ABI contract and contract tests. The tests deliberately use a **test-only fake parser adapter**. They prove entry point and return behavior, **not** real SumatraPDF integration or WinAFL compatibility.

The production parser adapter symbol `sumatra_parse_pdf(const char*)` is intentionally unresolved in the `fuzz_contract` static library. Task A3 must provide a real SumatraPDF-linked implementation before an executable can be distributed.

To check the contract on Windows x64:

```powershell
cmake -S native/sumatra-harness -B build/a2 -A x64
cmake --build build/a2 --config Debug
ctest --test-dir build/a2 -C Debug --output-on-failure
```

Do not claim the WinAFL gate passed until a native Windows executable invoking pinned SumatraPDF code is instrumented and fuzzed.
