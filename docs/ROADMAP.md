# Delivery roadmap

## Stage A — Native engine (mandatory first)
- A1: verify pinned SumatraPDF source, Windows x64 tooling and SHA-256 fingerprints.
- A2: C++ `fuzz_one_file(const char*)` exported ABI, CLI and contract tests.
- A3: integrate real SumatraPDF parser, not mock / unrelated standalone MuPDF.
- A4: prove repeated DynamoRIO target calls and instrumented modules.
- A5: run a real WinAFL fuzzing session.
- A6: evidence, coverage semantics, reproducibility and report.

## Stage B — Desktop control
Tauri 2, React, Rust typed commands, SQLite, one active campaign, safe process management.

## Stage C — Observability and packaging
Metrics parser, crash triage, evidence-backed reporting and Windows installer.

Never ship GUI claims before native Stage A passes.
