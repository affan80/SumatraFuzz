# Electron migration execution ledger

- Base: `0d45355f25eec2826d963223819096ddcf4dafb9` (`origin/dev` merge base).
- Task 1: workspace tests observed RED because `package.json` was absent, then passed. `npm ci`, formatting, lint, typecheck, tests, audit threshold and dependency tree inspected under Node 24.22.0.
- Task 2: protocol transition/request/sequence tests observed RED before exports existed, then passed against TypeScript parity behavior. Rust source remains until Task 11.
- Security review: `npm audit` reports 8 moderate advisories in the dev-only `electron-builder` dependency chain (`sprintf-js` via `roarr`/`global-agent`); no high/critical advisory was reported. Keep this recorded and re-evaluate the packager version before release packaging.
- Ruling: combine workspace/CI and canonical protocol in one foundation commit — the workspace's required protocol package and its tests form one runnable unit — cost if wrong: task-level commits are less granular for bisecting.
- Preserve all current Rust/Python/native acceptance jobs until parity and exact-commit acceptance are green.
