# Development and verification rules

- `main` is stable; `dev` collects reviewed task branches.
- Every PR should have an issue, a focused diff, appropriate regression tests and actual observed results.
- Do not push to `main`; no force pushes or shared history rewrites.
- Native Stage A is NOT PASS until a pinned real SumatraPDF engine parses PDFs inside Windows x64 under repeatable DynamoRIO instrumentation and WinAFL produces actual feedback.
- Linux source lint and fake executable Pester tests are not proof of WinAFL execution.

## GitHub branch rules to configure (not applied automatically)

In Settings > Rules > Rulesets, create a ruleset for `main` requiring a PR, successful `Target config` and `Windows Pester` checks, resolved conversations and blocking force pushes/deletions. Add a similar ruleset for `dev`. Solo maintainer: use 0 mandatory human approvals until an independent reviewer is available. Once CI checks have appeared in GitHub, select them as required checks. Review bypass permissions. CODEOWNERS does not activate branch protection.
