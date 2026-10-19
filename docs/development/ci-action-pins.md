# Immutable GitHub Actions references (#68)

All external `uses` references in `repository-checks.yml` are pinned to full
commit IDs rather than mutable major-version tags. This is an incremental
supply-chain change that does not depend on the worker journal or native launch
acceptance. It does not complete #68 or change repository branch protections.

The following official action `v4` refs were resolved through GitHub on
19 October 2026. Each object was a commit, GitHub reported its commit signature
verified, and `action.yml` was fetched successfully at that exact revision.
This establishes the observed upstream identity, not an audit of the action's
bundled dependencies or a guarantee against an upstream compromise.

| Action | Pinned commit | Official source |
| --- | --- | --- |
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | [commit](https://github.com/actions/checkout/commit/11d5960a326750d5838078e36cf38b85af677262) |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | [commit](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02) |
| `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | [commit](https://github.com/actions/download-artifact/commit/d3f86a106a0bac45b974a628896c90dbdf5c8093) |

The existing workflow's jobs, triggers, job dependencies, scripts, assertions,
timeouts, token permissions, checkout credential settings, artifact paths and
failure behavior are preserved. This change does not restore any native gate
removed by an earlier revert; a green workflow still proves only the checks
that actually ran on its exact commit.

## Updating and reviewing

Dependabot is configured to propose weekly GitHub Actions updates against
`dev`, with at most five open update PRs. This configuration must reach the
repository's default branch for GitHub to activate it; a feature PR or a merge
only into a non-default integration branch does not activate scheduling.
The repository currently uses `main` as its default branch. See
[GitHub's configuration requirements](https://docs.github.com/en/code-security/concepts/supply-chain-security/about-the-dependabot-yml-file).
No automatic approval or merge is configured.

For each proposed change, inspect the official upstream commit and release
notes, the precise SHA diff, action runtime compatibility and artifact contract.
Require existing CI and human review. Never replace a pin with a moving tag to
work around a resolution or execution failure. A verified commit signature
does not substitute for reviewing changed action code.

For a resolution regression, disable affected starts and propose a normal PR
back to a previously reviewed **full commit ID**. Do not remove required jobs,
weaken assertions, broaden permissions or silently ignore a failing action.
Use the established `dev`/`main` release process to deliver dependency updates.

## Validation and remaining work

Validation resolves all three upstream refs and their exact action metadata,
parses the edited YAML, checks every remote action has a 40-character hex SHA,
and compares parsed pre/post workflow structures after mapping each pinned
reference back to its former `v4` value. The comparison must show no execution
or permission changes beyond those action references. Configuration-only
validation is not a new native execution claim.

#68 still requires effective branch-protection verification, security/dependency
scanning, tool provenance and SBOM/license review, later lifecycle/API gates,
exact-commit native CI and reviewed merges. PowerShell module versions, runner
images, tool installers and upstream downloads are not all pinned by this PR.
