# SumatraFuzz

An offline Windows x64 desktop workbench for coverage-guided testing of **SumatraPDF** using a genuine Sumatra-integrated C++ harness, WinAFL/DynamoRIO, and an Electron + TypeScript controller.

**Current status:** The Electron campaign workflow, signed worker pairing, bounded PDF ZIP import, active-run recovery, and Windows x64 NSIS packaging are implemented. The desktop controls the paired worker; native fuzzing acceptance remains governed by the blocking A4–A6 gates below.

## Delivery order
1. A1: Pin source and verify Windows toolchain.
2. A2–A3: Build the harness contract and integrate actual SumatraPDF engine.
3. A4–A6: Prove DynamoRIO and WinAFL runs; preserve coverage and crash evidence.
4. B: Electron desktop campaign control and secure worker pairing.
5. C: Metrics, findings, reports, and release signing.

Target source: SumatraPDF `3.6.1rel` commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.

Read [contribution rules](CONTRIBUTING.md), [automation rules](AGENTS.md), [development gates](docs/DEVELOPMENT.md) and [roadmap](docs/ROADMAP.md).

New signed worker profiles include the controller UUID in the Ed25519-protected pairing bundle. Upgrades leave legacy encrypted profiles untouched; import a fresh signed pairing bundle to pair again.

Build the unsigned Windows x64 NSIS installer with `npm run desktop:package:win`. The packaging job inspects the ASAR contents, then silently installs, launches and uninstalls the application. The package contains only the compiled desktop, its worker client/protocol runtime and required production dependencies; the Windows worker service and native fuzzing tools run on the worker host.

The desktop build uses Node.js 24.22.0 and Electron 44.9.0. CI installers are unsigned until Windows release signing is configured.

Use an isolated Windows x64 environment. Do not commit secrets, WinAFL binaries, crash corpora, or unsupported vulnerability claims. Work in task branches; PRs target `dev`, stable releases go `dev` to `main`.
