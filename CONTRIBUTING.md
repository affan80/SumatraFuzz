# Contributing

## Branches
- `main`: releases only; reviewed PRs from `dev`.
- `dev`: integration; reviewed PRs from feature, fix, test, docs, chore branches.
- `feat/<topic>`, `fix/<topic>`, `test/<topic>`, `docs/<topic>`, `chore/<topic>`: short-lived work.

```bash
git fetch origin
git switch dev && git pull --ff-only origin dev
git switch -c feat/a2-harness-contract
# write failing tests, implement, test, commit
git push -u origin feat/a2-harness-contract
# create PR with base dev
```

Use Conventional Commits (`feat(native): ...`, `test(native): ...`, `docs: ...`). Each issue/PR must state acceptance criteria and command outputs. Windows-only tests must not be marked passed on Linux. CI is necessary but does not replace physical WinAFL/DynamoRIO runtime evidence. Do not merge a blocked stage gate. Prefer independent reviews; never pretend self-review is independent. See [SECURITY.md](SECURITY.md).
