# Engineering rules for SumatraFuzz

- Scope: offline Windows x64 SumatraPDF fuzzing workbench. Follow the approved system design and native-first implementation plans.
- Branches: `main` stable, `dev` integration, `feat/*`, `fix/*`, `test/*`, `docs/*`, `chore/*` from `dev`. PRs into `dev`; release PR `dev` -> `main`.
- Use test-driven development and small Conventional Commits. Never claim tests, coverage, crashes, or successful fuzzing without observed evidence.
- Pin SumatraPDF `3.6.1rel` to commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.
- The harness must call actual Sumatra-integrated parsing code, not fake output or unrelated standalone MuPDF.
- Do not build the full UI until the real Windows x64 native fuzzing verification gate passes.
- Derive WinAFL target and coverage modules from real symbols and instrumentation logs.
- Rust executes structured argv, never concatenated shell commands. Limit to one active campaign.
- Use an isolated, nonadministrator Windows x64 test environment for untrusted PDFs.
- Never commit external binary tools, dumps, private corpus, secrets, or unreviewed exploit samples.
- No merge, release, force-push or shared branch rewrite without explicit approval.
