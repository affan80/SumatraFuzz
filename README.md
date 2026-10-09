# SumatraFuzz

An offline Windows x64 desktop workbench for coverage-guided testing of **SumatraPDF** using a genuine Sumatra-integrated C++ harness, WinAFL/DynamoRIO, and later Tauri 2 + React + Rust.

**Current status:** Task A1 preparation; no functioning native fuzzing campaign or desktop GUI has been verified.

## Delivery order
1. A1: Pin source and verify Windows toolchain.
2. A2–A3: Build the harness contract and integrate actual SumatraPDF engine.
3. A4–A6: Prove DynamoRIO and WinAFL runs; preserve coverage and crash evidence.
4. B: Desktop campaign control.
5. C: Metrics, findings, reports, and Windows packaging.

Target source: SumatraPDF `3.6.1rel` commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.

Read [contribution rules](CONTRIBUTING.md), [automation rules](AGENTS.md), [development gates](docs/DEVELOPMENT.md) and [roadmap](docs/ROADMAP.md).

Use an isolated Windows x64 environment. Do not commit secrets, WinAFL binaries, crash corpora, or unsupported vulnerability claims. Work in task branches; PRs target `dev`, stable releases go `dev` to `main`.
