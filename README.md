# SumatraFuzz

An offline Windows x64 desktop workbench for coverage-guided testing of **SumatraPDF** using a genuine Sumatra-integrated C++ harness, WinAFL/DynamoRIO, and an Electron + TypeScript controller.

**Current status:** Electron pairing and secure worker communication are implemented; the campaign/run workflow is in progress. No functioning native fuzzing campaign is claimed by this desktop status.

## Delivery order
1. A1: Pin source and verify Windows toolchain.
2. A2–A3: Build the harness contract and integrate actual SumatraPDF engine.
3. A4–A6: Prove DynamoRIO and WinAFL runs; preserve coverage and crash evidence.
4. B: Electron desktop campaign control.
5. C: Metrics, findings, reports, and Windows packaging.

Target source: SumatraPDF `3.6.1rel` commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.

Read [contribution rules](CONTRIBUTING.md), [automation rules](AGENTS.md), [development gates](docs/DEVELOPMENT.md) and [roadmap](docs/ROADMAP.md).

New signed worker profiles include the controller UUID in the Ed25519-protected pairing bundle. Upgrades leave legacy encrypted profiles untouched; import a fresh signed pairing bundle to pair again.

Use an isolated Windows x64 environment. Do not commit secrets, WinAFL binaries, crash corpora, or unsupported vulnerability claims. Work in task branches; PRs target `dev`, stable releases go `dev` to `main`.
