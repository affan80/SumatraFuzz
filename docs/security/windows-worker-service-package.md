# Windows worker-service package

The worker service ships as a separate Windows x64 payload alongside the Electron installer. Its fixed layout is consumed by `SumatraFuzzWorkerHost.exe` and `install-worker-service.ps1`:

```text
SumatraFuzz/
  apps/worker-service/dist/src/service-entry.js
  config/organization-signing-public-key.pem
  native/worker-supervisor/build/Release/worker_supervisor.node
  node_modules/                         # explicit production runtime closure
  packages/                             # inspectable copies of compiled workspace packages
  provisioning/                         # install, first-run provisioning, uninstall, and this guide
  runtime/node.exe
  service/SumatraFuzzWorkerHost.exe
```

Build on Windows x64 with the repository's locked Node version and Visual Studio C++ tools. The build fails if the Node runtime, SCM host, or either native addon is not a PE x64 binary. It also smoke-imports the service entrypoint and loads both native addons from the staged tree.

```powershell
npm ci --ignore-scripts
npm run native:sqlite:build
npm run native:supervisor:build
npm run typecheck
cmake -S native/worker-supervisor -B build/worker-supervisor
cmake --build build/worker-supervisor --config Release --target sumatrafuzz_worker_service_host
$nodeRuntime = (Get-Command node).Source
node scripts/stage-worker-service.mjs `
  --node $nodeRuntime `
  --host (Resolve-Path build/worker-supervisor/Release/SumatraFuzzWorkerHost.exe).Path `
  --public-key apps/desktop/resources/worker-bundle-signing-key.pem `
  --output release/worker-service/SumatraFuzz
```

Staging uses an explicit runtime dependency allowlist and rejects symlinks/reparse points, unsupported files, non-x64 PE inputs, and private signing material. The output directory must not already exist. `package-manifest.json` records the staged file list for review. The signing key input is the public Ed25519 organization root only; no private key is used or copied.

The package contains the PowerShell install/provision/uninstall scripts and this guide. Copy the complete payload to `%ProgramFiles%\SumatraFuzz` without changing its layout. Mount the dedicated NTFS data volume at the otherwise empty `%SystemDrive%\ProgramData\SumatraFuzz\Worker` directory; this exact mounted-folder root is the only reparse point accepted by the service. The installer and native SCM host verify that the path resolves to the configured volume root and that it is separate from the Windows/install volume. Run `provisioning\install-worker-service.ps1` from an elevated Windows PowerShell 7 session with the dedicated NTFS data volume GUID, disk limit, and bind settings. An unprovisioned service is created with demand start, so a missing configuration cannot trigger a boot-time restart loop.

Create `worker-config.json` as an administrator-owned local file. Its strict JSON schema is the `WorkerServiceConfig` interface in `apps/worker-service/src/service-entry.ts`: schema version 1, worker UUID, bind policy, fixed data root and volume GUID, the configured disk limit, the packaged signing-key path, protected credential path, campaign policy paths/pins, and bounded audit policy. The provision command checks the binding, volume, disk quota, and fixed key/credential paths against the protected install marker; the worker revalidates the complete schema before it reads secrets or listens. For local mode, use only a loopback address, no peer CIDRs, and an empty adapter GUID. For remote mode, provide the exact private adapter GUID/address and private peer CIDRs selected at installation.

Keep the worker credential JSON and signed pairing bundle in separate local files protected by an ACL that grants access only to SYSTEM, Builtin Administrators, and the current administrator. The credential JSON has exactly `schema`, `workerKeyPem`, `workerCertificatePem`, and `clientCaPem`; the worker verifies the TLS 1.3 server key/certificate/CA chain, protects the key with service-identity DPAPI, imports the signed pairing bundle against the packaged Ed25519 public root, and deletes staging files before opening the listener. No private signing root belongs in the package or on the worker.

Provision initial credentials and pairing together (the script copies bytes atomically into service-readable, service-delete-only staging files, then starts the service):

```powershell
& "$env:ProgramFiles\SumatraFuzz\provisioning\provision-worker-service.ps1" `
  -ConfigurationPath 'C:\SecureAdmin\worker-config.json' `
  -WorkerCredentialsPath 'C:\SecureAdmin\worker-credentials.json' `
  -PairingBundlePath 'C:\SecureAdmin\worker.sfpair'
```

Use that same credential-plus-pairing operation for worker certificate rotation; the signed bundle must pin the new worker certificate. To revoke one controller certificate or unpair a controller, pass the organization-signed short-lived transaction file with `-TrustOperationPath`. The script stops a running service with a bounded wait and starts it only after staging. Failed startup leaves protected staging in place for administrator recovery. Store these plaintext input files in an approved secret location and remove them according to the organization’s secret-handling policy after successful activation; the service itself never logs or packages them.

For removal, run `provisioning\uninstall-worker-service.ps1`. Data, trust, and audit state remain by default. `-DeleteData` is a separate explicit destructive option; it checks volume ownership and reparse points before deletion.

The installer provisions the exact service-SID ACLs and NTFS user quota; remote mode also requires the configured adapter/address to remain owned and the Windows firewall profile/rule to match. On reinstall, the runtime directory roots are protected first and every existing descendant is checked before startup. Existing state with a reparse point or an untrusted writable ACL is rejected rather than silently adopted, because a trust database may already have been altered. The native host independently verifies the protected paths, exact data-volume mount root, NTFS format and separation from the system volume, and refuses to run elevated. `GetDiskFreeSpaceExW` is sampled under the service identity; its per-user available capacity is checked against the installed quota policy. The CI package build proves x64 payload composition and dependency loading; it does not prove installed Windows service behavior, DPAPI, real ACL enforcement, or genuine fuzzing through installed mTLS. Those acceptance results must be linked from the exact Windows workflow run before issue #91 can close.
