# SumatraFuzz Campaign and Run Workflow UI

**Status:** Design sections approved by the user on 2026-10-19; awaiting review of this written spec.
**Repository:** `affan80/SumatraFuzz`
**Target:** Electron/TypeScript desktop, Windows x64 worker and release.

## 1. Goal and scope

Give an operator a secure campaign workflow in the Electron desktop: verify the paired worker, import a bounded PDF input bundle, configure a run within worker policy, start or stop one campaign, and observe its status. The desktop must recover the controller's active run after restart without introducing a full run-history catalog. Build the Windows x64 desktop as an NSIS `.exe` installer.

This is the next migration slice, not a redesign of the fuzzing engine or evidence format. The worker's SQLite journal remains authoritative. Full historical run browsing, evidence exploration/download UI, multiple simultaneous campaigns, macOS/Linux release packaging, and installer signing are outside this slice. CI may publish an unsigned installer until release signing is configured.

## 2. Current constraints

- Pairing already imports an organization-signed `.sfpair` bundle and verifies the worker through mutual TLS. The signed profile currently has no controller UUID.
- `GET /v1/capabilities` is authenticated and returns worker identity, protocol version, target lock hash and maximum limits. The worker resolves the controller UUID from the authorized client certificate.
- `POST /v1/input-bundles` already accepts a ZIP up to 32 MiB, validates safe PDF filenames and entries, and caps expanded data at 64 MiB. It returns an input bundle ID, archive hash, file count and expanded byte count.
- Run start/get/stop routes and renderer IPC exist. The worker enforces controller ownership and one active slot. The desktop has no input-bundle upload method and forgets a run ID on restart.
- The desktop controller closes its TLS client at quit. Worker execution and durable SQLite state are independent of the renderer lifecycle.
- `electron-builder` is already a locked development dependency. The NSIS target and packaged install smoke check need to be made explicit in configuration and CI.

## 3. User workflow

The existing worker pairing screen remains the entry point. Once paired, the desktop shows one campaign page with:

1. Worker connection and verified identity, including controller identity status.
2. A main-process file picker for a PDF ZIP input bundle. The UI displays only the worker-validated file count, archive hash and expanded byte count.
3. A campaign label and resource limits. The UI displays worker-advertised ceilings; main-process validation and worker policy both reject values above those ceilings.
4. Start and stop actions, plus the current run state and safe stop reason. The renderer does not display raw archive names, arbitrary worker event payloads, local paths, certificate material or worker error bodies.

There is one active run per worker/controller. On startup or reconnect, the desktop queries the authenticated active-run endpoint and restores that run's status. If there is no active run, the campaign page is ready for a new bundle. A completed run remains in the worker journal, but this slice does not add a historical run list.

## 4. Identity and pairing contract

Add a non-nil UUID `controller_id` to the signed pairing profile. The bundle signature covers this field. The importer validates it as a UUID before constructing a profile. During pairing, the desktop obtains authenticated capabilities over the bundle's mutual TLS connection and requires both `worker_id` and `controller_id` to match the signed profile before it persists any credentials.

The worker capabilities response adds the `controller_id` resolved from the authenticated certificate fingerprint. A missing, malformed or mismatched identity fails pairing closed. The desktop continues to store private credentials only through the existing protected profile store and never returns them over IPC.

Run request identity and idempotency data are main-process owned. The renderer submits only a validated run draft. Main creates `request_id`, takes `controller_id` from the verified profile, and uses the worker-validated `input_bundle_id`. The worker independently checks authenticated ownership, request identity, target lock and policy ceilings.

## 5. Import and run data flow

The Electron main process opens the ZIP picker and reads a regular file with a strict 32 MiB maximum. The renderer receives neither a path nor archive bytes. Main uploads bytes through a new typed `WorkerClient.importInputBundle` method to the existing authenticated `POST /v1/input-bundles` endpoint with `application/zip`. The client validates the response shape and UUID/hash/count/size bounds before returning a safe summary to IPC.

The worker retains responsibility for ZIP parsing, path and entry validation, PDF acceptance, duplicate-name checks, compressed/expanded limits, staging cleanup and controller-scoped storage. The desktop does not inspect or extract archive contents.

Starting a run requires an imported bundle ID from the current verified worker and controller. The main process builds the complete `RunRequest`, including a fresh request ID, verified controller ID, target lock from capabilities, chosen limits and input bundle ID. The worker remains the final authority for limits, exclusivity, bundle ownership and idempotency. Inputs that exceed the worker's advertised limits are rejected in the desktop before sending and again by worker policy.

## 6. Active-run recovery and UI polling

Add authenticated `GET /v1/runs/active`. It returns the active run owned by the authenticated controller, or an empty result. If another controller owns the worker's global slot, the endpoint returns an empty result without disclosing that controller's run ID or data. It does not enumerate history.

The coordinator reads its durable active-run snapshot and then applies ownership filtering before returning a validated run status. The desktop calls this endpoint after profile restore and successful capability verification. It retains the active run ID in main-process state and uses the existing `GET /v1/runs/{run_id}` endpoint for polling. Poll calls never overlap; transient errors use bounded backoff, and an identity mismatch clears the displayed run and closes the client. Stop requests use the existing ownership-checked route and keep displaying `stopping` until the worker reports a terminal state.

Closing the window does not stop a run. The worker owns execution and enforces its configured time, CPU, memory and disk limits. Closing the app closes the desktop connection; on the next launch, authenticated recovery discovers the still-active run. The existing conservative worker startup reconciliation remains in force and does not relaunch a process after a crash.

## 7. IPC and renderer security

Add narrow preload methods for selecting/importing a bundle, reading current campaign capabilities/status, starting a run draft, and stopping the active run. Validate every IPC request and response at runtime. Do not expose filesystem paths, generic network requests, raw WorkerClient methods, arbitrary run IDs or credentials. Main binds imported bundle IDs to the currently verified worker/controller and rejects stale IDs after unpair/re-pair.

Render only allowlisted state, limits, file count, hash, byte counts and stop-reason enums using text nodes. Do not render worker-provided HTML, event payloads, filenames or error text. Keep the current sandbox, context isolation, disabled Node integration, exact-document IPC sender checks and restrictive CSP.

## 8. Windows installer and CI

Configure electron-builder to produce an NSIS Windows x64 `.exe` installer. Use a pinned configuration and explicit application file allowlist. The installer must not contain private signing keys, pairing credentials, test corpora, native fuzzing executables or build-only files. Release signing remains a separate configured step; CI produces an unsigned artifact.

Keep the genuine native parser and A4–A6 acceptance checks blocking. Add or extend checks for:

- pairing bundle UUID validation, signature coverage, certificate-to-controller mismatch and no-save-on-failure;
- authenticated capability response validation and wrong-controller rejection;
- malformed, oversized, traversal, duplicate, symlink-like and expanded-size ZIP cases through the API/import path;
- binary upload content type, request-size enforcement and strict response validation;
- over-limit run draft rejection, correct main-generated request identity, one-slot behavior and bundle/controller ownership;
- authenticated active-run lookup, no cross-controller disclosure, recovery after desktop restart, empty state and terminal status;
- poll serialization/backoff, stop transition and renderer handling of untrusted status/error data;
- Windows x64 NSIS build, installer content inspection, silent install/launch/uninstall smoke test and artifact upload.

Use TDD for implementation. Keep workflow action pins, least-privilege permissions, dependency caching and concurrency behavior. This UI slice must not weaken native acceptance gates or replace them with mocked parser evidence.

## 9. Rollout and acceptance

Implement in dependency order: protocol/profile identity, worker capabilities and active-run API, client upload/recovery support, main-process import and run controller, renderer campaign page, then Windows NSIS packaging and CI. Keep each boundary covered by focused tests and preserve compatibility by making the protocol version change explicit if the new required identity field cannot be safely introduced within v1.

Acceptance requires:

- A signed bundle and authenticated capabilities agree on both worker and controller identity before credentials are saved.
- A bounded PDF ZIP can be imported and only validated summary data reaches the renderer.
- A run can be started, observed, stopped and recovered after desktop restart, with one worker slot and worker-enforced resource ceilings.
- Other controllers cannot learn another controller's run ID or status through recovery.
- The NSIS x64 installer installs, launches and uninstalls in Windows CI, and its package inspection finds no forbidden secrets or corpora.
- All applicable TypeScript, security, Windows service/native, genuine parser/A4–A6 and installer checks pass on the exact PR commit.

## 10. Deferred decisions

- Historical run list, local controller catalog, evidence browsing and downloads.
- Whether future release signing uses Authenticode and how its secret is provisioned.
- macOS/Linux packages and any cross-platform worker pairing policy.
- Whether a future operator workflow accepts individual PDFs in addition to PDF ZIP bundles.
