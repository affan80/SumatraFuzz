const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const { execFileSync } = require('node:child_process');
const os = require('node:os');
const path = require('node:path');

test('Windows supervisor bounds and tears down a child process tree', {
  skip: process.platform !== 'win32',
}, async () => {
  const addonPath = path.join(
    __dirname,
    '..',
    'native',
    'worker-supervisor',
    'build',
    'Release',
    'worker_supervisor.node',
  );
  const probePath = path.join(
    __dirname,
    '..',
    'build',
    'worker-supervisor',
    'Debug',
    'process_probe.exe',
  );
  const supervisor = require(addonPath);
  for (const method of [
    'assertWorkerServiceIdentity',
    'launchSuspended',
    'sampleJob',
    'sampleVolumeUsage',
    'assertWorkerServiceNetworkBinding',
    'stopJob',
    'protectSecret',
    'unprotectSecret',
  ])
    assert.equal(typeof supervisor[method], 'function');
  const bytes = readFileSync(probePath);
  const volumeUsage = supervisor.sampleVolumeUsage(__dirname);
  assert.ok(Number.isSafeInteger(volumeUsage.quota_bytes) && volumeUsage.quota_bytes > 0);
  assert.ok(Number.isSafeInteger(volumeUsage.available_bytes) && volumeUsage.available_bytes >= 0);
  assert.equal(volumeUsage.used_bytes + volumeUsage.available_bytes, volumeUsage.quota_bytes);
  assert.throws(
    () => supervisor.assertWorkerServiceNetworkBinding('invalid-guid', '192.168.1.2'),
    /Worker network binding verification failed/,
  );
  const proof = {
    path: probePath,
    root: path.dirname(probePath),
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
  const previousSecret = process.env.SUMATRAFUZZ_TEST_SECRET;
  process.env.SUMATRAFUZZ_TEST_SECRET = 'must-not-reach-target';
  const containmentRoot = mkdtempSync(path.join(os.tmpdir(), 'sumatrafuzz-child-scope-'));
  const toolDir = path.join(containmentRoot, 'tool');
  const evidenceDir = path.join(containmentRoot, 'evidence');
  const siblingEvidenceDir = path.join(containmentRoot, 'sibling-evidence');
  const inputDir = path.join(containmentRoot, 'input');
  const protectedDir = process.env.SUMATRAFUZZ_PROTECTED_DIR;
  assert.ok(protectedDir && path.isAbsolute(protectedDir), 'protected fixture must be provisioned');
  const containmentProbePath = path.join(toolDir, path.basename(probePath));
  const inputPath = path.join(inputDir, 'seed.pdf');
  const protectedReadPath = path.join(protectedDir, 'credential-sentinel');
  const protectedWritePath = path.join(protectedDir, 'must-not-exist');
  const eventName = `SumatraFuzz-Restricted-Probe-${process.pid}`;
  mkdirSync(toolDir);
  mkdirSync(evidenceDir);
  mkdirSync(siblingEvidenceDir);
  mkdirSync(inputDir);
  copyFileSync(probePath, containmentProbePath);
  writeFileSync(inputPath, 'pdf input sentinel');
  assert.deepEqual(readdirSync(protectedDir), ['credential-sentinel']);
  const baselineEnvironment = { ...process.env };
  delete baselineEnvironment.SUMATRAFUZZ_TEST_SECRET;
  for (const identifiers of [
    {},
    {
      SUMATRAFUZZ_NAMESPACE_ALIAS: '../invalid',
      SUMATRAFUZZ_RUN_SID: 'S-1-1-0',
    },
    {
      SUMATRAFUZZ_NAMESPACE_ALIAS: 'SFWR-00000000-0000-0000-0000-000000000000',
      SUMATRAFUZZ_RUN_SID: 'invalid',
    },
  ]) {
    const env = { ...baselineEnvironment };
    delete env.SUMATRAFUZZ_NAMESPACE_ALIAS;
    delete env.SUMATRAFUZZ_RUN_SID;
    assert.throws(
      () =>
        execFileSync(containmentProbePath, ['--validate-identifiers'], {
          env: { ...env, ...identifiers },
          stdio: 'ignore',
        }),
      (error) => error.status === 30,
      'invalid identifiers must fail closed',
    );
  }
  // Simulate installer-provisioned access narrowly: the test root gets only
  // traverse, code gets execute/read, and the exact input objects get read
  // without inheritance (the input file must not get ExecuteFile).
  execFileSync('icacls.exe', [containmentRoot, '/grant', '*S-1-5-12:(X)'], { stdio: 'ignore' });
  execFileSync('icacls.exe', [toolDir, '/grant', '*S-1-5-12:(RX)'], { stdio: 'ignore' });
  execFileSync('icacls.exe', [containmentProbePath, '/grant', '*S-1-5-12:(RX)'], {
    stdio: 'ignore',
  });
  execFileSync('icacls.exe', [inputDir, '/grant', '*S-1-5-12:(GR,GE)'], { stdio: 'ignore' });
  execFileSync('icacls.exe', [inputPath, '/grant', '*S-1-5-12:(GR)'], { stdio: 'ignore' });
  let job;
  let siblingJob;
  try {
    job = supervisor.launchSuspended({
      executable: containmentProbePath,
      argv: [
        '-D',
        toolDir,
        '-i',
        inputDir,
        '-o',
        evidenceDir,
        '--containment-probe',
        evidenceDir,
        inputPath,
        protectedReadPath,
        protectedWritePath,
        eventName,
      ],
      workingDir: containmentRoot,
      evidenceDir,
      limits: { max_memory_bytes: 67108864, max_cpu_percent: 25 },
      fileProofs: [{ ...proof, path: containmentProbePath, root: toolDir }],
    });
    let sample;
    for (let i = 0; i < 100; i++) {
      sample = supervisor.sampleJob(job);
      const evidenceNames = readdirSync(evidenceDir);
      if (
        sample.process_count >= 3 &&
        evidenceNames.filter((name) => name.startsWith('restricted-write-')).length >= 3 &&
        evidenceNames.filter((name) => /^named-event-\d+$/.test(name)).length >= 2
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    if (sample.process_count < 3) {
      const receipt = supervisor.stopJob(job, 0);
      job = undefined;
      const eventDiagnostic = readdirSync(evidenceDir)
        .filter((name) =>
          [
            'named-event-diagnostic.txt',
            'namespace-diagnostic.txt',
            'containment-diagnostic.txt',
          ].includes(name),
        )
        .map((name) => readFileSync(path.join(evidenceDir, name), 'utf8'))
        .join('\n');
      assert.fail(
        `probe process tree did not start (processes=${sample.process_count}, exit=${receipt.exitCode})${
          eventDiagnostic ? `\n${eventDiagnostic}` : ''
        }`,
      );
    }
    assert.ok(
      sample.process_count >= 3,
      'probe child must stay in the job and must not inherit secrets',
    );
    assert.ok(
      readdirSync(evidenceDir).filter((name) => name.startsWith('restricted-write-')).length >= 3,
      'restricted child process and descendant must both write evidence',
    );
    assert.ok(
      readdirSync(evidenceDir).filter((name) => /^named-event-\d+$/.test(name)).length >= 2,
      'restricted descendant must open and signal the private named event',
    );
    assert.deepEqual(
      readdirSync(protectedDir),
      ['credential-sentinel'],
      'restricted child process and its descendant must not write outside run evidence',
    );
    siblingJob = supervisor.launchSuspended({
      executable: containmentProbePath,
      argv: [
        '-D',
        toolDir,
        '-i',
        inputDir,
        '-o',
        siblingEvidenceDir,
        '--deny-open-event',
        readFileSync(path.join(evidenceDir, 'private-event-name.txt'), 'utf8'),
      ],
      workingDir: containmentRoot,
      evidenceDir: siblingEvidenceDir,
      limits: { max_memory_bytes: 67108864, max_cpu_percent: 25 },
      fileProofs: [{ ...proof, path: containmentProbePath, root: toolDir }],
    });
    let siblingSample;
    for (let i = 0; i < 100; i++) {
      siblingSample = supervisor.sampleJob(siblingJob);
      if (siblingSample.process_count === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const siblingReceipt = supervisor.stopJob(siblingJob, 0);
    siblingJob = undefined;
    assert.equal(
      siblingSample.process_count,
      0,
      'the sibling authorization probe must exit promptly',
    );
    assert.equal(
      siblingReceipt.exitCode,
      0,
      'a separate restricted run must be denied access to this run’s named event',
    );
    const privateName = readFileSync(path.join(evidenceDir, 'private-event-name.txt'), 'utf8');
    const receipt = supervisor.stopJob(job, 0);
    job = undefined;
    assert.equal(receipt.remainingProcesses, 0);
    execFileSync(containmentProbePath, ['--namespace-gone', privateName.split('\\')[0]], {
      env: baselineEnvironment,
      stdio: 'ignore',
    });
    // A verified non-PE file reaches CreateProcessAsUserW only after namespace
    // creation. Repeated failure must close every temporary namespace/job/token.
    const invalidExecutable = path.join(toolDir, 'invalid.exe');
    const invalidBytes = Buffer.from('intentionally not a Windows executable');
    writeFileSync(invalidExecutable, invalidBytes);
    execFileSync('icacls.exe', [invalidExecutable, '/grant', '*S-1-5-12:(RX)'], {
      stdio: 'ignore',
    });
    const failLaunch = (index) => {
      const failureEvidence = path.join(containmentRoot, `failure-evidence-${index}`);
      assert.throws(
        () =>
          supervisor.launchSuspended({
            executable: invalidExecutable,
            argv: ['-D', toolDir, '-i', inputDir, '-o', failureEvidence],
            workingDir: containmentRoot,
            evidenceDir: failureEvidence,
            limits: { max_memory_bytes: 67108864, max_cpu_percent: 25 },
            fileProofs: [
              {
                path: invalidExecutable,
                root: toolDir,
                sha256: createHash('sha256').update(invalidBytes).digest('hex'),
              },
            ],
          }),
        /CreateProcessAsUserW failed/,
      );
    };
    const handleCount = () =>
      Number(
        execFileSync(
          'powershell.exe',
          [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `(Get-Process -Id ${process.pid}).HandleCount`,
          ],
          { env: baselineEnvironment, encoding: 'utf8' },
        ).trim(),
      );
    failLaunch('warmup');
    const beforeFailures = handleCount();
    for (let index = 0; index < 5; index++) failLaunch(index);
    assert.ok(
      handleCount() <= beforeFailures,
      'partial launch must not leak namespace, token, job or process handles',
    );
  } finally {
    if (siblingJob) supervisor.stopJob(siblingJob, 0);
    if (job) supervisor.stopJob(job, 0);
    rmSync(containmentRoot, { recursive: true, force: true });
    if (previousSecret === undefined) delete process.env.SUMATRAFUZZ_TEST_SECRET;
    else process.env.SUMATRAFUZZ_TEST_SECRET = previousSecret;
  }
  const protectedBytes = supervisor.protectSecret(Buffer.from('service-key'));
  assert.equal(supervisor.unprotectSecret(protectedBytes).toString(), 'service-key');
  assert.throws(() => supervisor.unprotectSecret(Buffer.from('tampered')));
});

test('service identity probe rejects a non-service process without returning token data', {
  skip: process.platform !== 'win32',
}, () => {
  const addonPath = path.join(
    __dirname,
    '..',
    'native',
    'worker-supervisor',
    'build',
    'Release',
    'worker_supervisor.node',
  );
  const supervisor = require(addonPath);
  assert.equal(typeof supervisor.assertWorkerServiceIdentity, 'function');
  assert.throws(
    () => supervisor.assertWorkerServiceIdentity(),
    /worker service identity verification failed/,
  );
});

test('network binding probe reports only a generic failure for a non-owning adapter', {
  skip: process.platform !== 'win32',
}, () => {
  const addonPath = path.join(
    __dirname,
    '..',
    'native',
    'worker-supervisor',
    'build',
    'Release',
    'worker_supervisor.node',
  );
  const supervisor = require(addonPath);
  assert.throws(
    () =>
      supervisor.assertWorkerServiceNetworkBinding(
        '{00000000-0000-0000-0000-000000000001}',
        '192.168.254.253',
      ),
    /Worker network binding verification failed/,
  );
});

test('non-Windows host cannot claim the Windows supervisor is available', {
  skip: process.platform === 'win32',
}, () => {
  assert.notEqual(process.platform, 'win32');
});

test('adapter binding probe has an IP Helper dependency and exact ownership checks', () => {
  const addon = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'src', 'addon.cpp'),
    'utf8',
  );
  const binding = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'binding.gyp'),
    'utf8',
  );
  assert.match(addon, /GetIfEntry2\(&adapter\)/);
  assert.match(addon, /GetUnicastIpAddressTable\(AF_UNSPEC/);
  assert.match(addon, /row\.InterfaceLuid\.Value != adapter_luid\.Value/);
  assert.match(addon, /row\.DadState != IpDadStatePreferred/);
  assert.match(addon, /canonical_guid = canonical_guid\.substr\(1, 36\)/);
  assert.match(addon, /index == 8 \|\| index == 13 \|\| index == 18 \|\| index == 23/);
  assert.match(addon, /canonical_guid\[index\] != L'-'/);
  assert.match(addon, /"assertWorkerServiceNetworkBinding"/);
  assert.match(binding, /iphlpapi\.lib/);
});

test('WinAFL children have full restricted-token read and write boundaries', () => {
  const addon = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'src', 'addon.cpp'),
    'utf8',
  );
  assert.match(addon, /CreateRestrictedToken\(current, DISABLE_MAX_PRIVILEGE,/);
  assert.match(addon, /SID_AND_ATTRIBUTES restricting_sids/);
  assert.match(addon, /\{restricted\.sid, 0\}/);
  assert.match(addon, /CreateProcessAsUserW\(/);
  assert.match(addon, /CreatePrivateAccessAcl\(/);
  assert.match(addon, /SetPrivateRestrictedDefaultDacl/);
  assert.match(addon, /WinRestrictedCodeSid/);
  assert.match(addon, /WinAuthenticatedUserSid/);
  assert.match(addon, /WinWorldSid/);
  assert.match(addon, /SetEntriesInAclW\(1, &grant, existing_dacl/);
  assert.match(addon, /grant\.Trustee, sid/);
  assert.match(addon, /CoCreateGuid\(&run\)/);
  assert.match(addon, /evidenceDir/);
  assert.doesNotMatch(addon, /CreateProcessW\(executable\.c_str\(\)/);
  const probe = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'tests', 'process_probe.cpp'),
    'utf8',
  );
  assert.match(probe, /ProtectedReadsAndWritesDenied/);
  assert.match(probe, /ReadAllowedInput/);
  assert.match(probe, /CreateEventW\(/);
  assert.match(probe, /OpenEventW\(/);
  const config = readFileSync(
    path.join(__dirname, '..', 'scripts', 'windows', 'worker-service-config.psm1'),
    'utf8',
  );
  assert.match(config, /S-1-5-12/);
  assert.match(config, /RestrictedRead/);
  assert.match(config, /RestrictedExecute/);
  assert.match(config, /RestrictedTraverse/);
  assert.match(config, /RestrictedRead:\(\[bool\]\(\$directory -eq 'inputs'\)\)/);
  assert.match(config, /RestrictedTraverse:\(\[bool\]\(\$directory -eq 'outputs'\)\)/);
  assert.match(
    config,
    /Set-WorkerProtectedTree -Path \$layout\.Root -ServiceSid \$serviceSid -RestrictedExecute/,
  );
  assert.match(config, /RestrictedRead -and \$Directory/);
  assert.match(config, /\[Security\.AccessControl\.FileSystemRights\]::Read\s*\n\s*\} else/);
});

test('service host protects the exact worker staging and runtime ACL layout', () => {
  const host = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'src', 'service_host.cpp'),
    'utf8',
  );
  assert.match(host, /ServiceWriteAccess::CredentialFile/);
  assert.match(host, /ServiceWriteAccess::DeleteStagedFile/);
  assert.match(host, /worker-trust-operation\.sftxn/);
  assert.match(host, /L"security\\\\audit"/);
  assert.match(host, /L"inputs", L"outputs"/);
  assert.match(host, /ACCESS_ALLOWED_CALLBACK_ACE_TYPE/);
  assert.match(host, /ACCESS_ALLOWED_OBJECT_ACE_TYPE/);
  assert.match(host, /GENERIC_WRITE \| GENERIC_EXECUTE \| GENERIC_ALL/);
  assert.match(host, /sid_header->SubAuthorityCount\) \* sizeof\(DWORD\)/);
  assert.match(host, /VerifyDedicatedDataVolumeMountPoint/);
  assert.match(host, /GetVolumePathNameW\(data_path/);
  assert.match(host, /worker data volume must be separate from installed code and Windows/);
  const identity = host.slice(
    host.indexOf('void RequireServiceIdentity()'),
    host.indexOf('\n}\n\nstd::vector<wchar_t> BuildSanitizedEnvironment'),
  );
  assert.match(
    identity,
    /DuplicateTokenEx\(token\.Get\(\), TOKEN_QUERY, nullptr, SecurityImpersonation, TokenImpersonation,/,
  );
  assert.match(
    identity,
    /CheckTokenMembership\(membership_token\.Get\(\), admin_bytes\.data\(\), &is_admin\)/,
  );
  assert.match(
    identity,
    /CheckTokenMembership\(membership_token\.Get\(\), const_cast<BYTE\*>\(service_sid\.data\(\)\), &is_admin\)/,
  );
});

test('native service host exposes only a bounded local administrator trust-operation pipe', () => {
  const host = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'src', 'service_host.cpp'),
    'utf8',
  );
  const contract = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'include', 'service_host.h'),
    'utf8',
  );
  const workerControl = readFileSync(
    path.join(__dirname, '..', 'apps', 'worker-service', 'src', 'service-control.ts'),
    'utf8',
  );
  const provision = readFileSync(
    path.join(__dirname, '..', 'scripts', 'windows', 'provision-worker-service.ps1'),
    'utf8',
  );
  assert.match(host, /SumatraFuzzWorker-trust/);
  assert.match(host, /PIPE_REJECT_REMOTE_CLIENTS/);
  assert.match(host, /FILE_FLAG_FIRST_PIPE_INSTANCE/);
  assert.match(host, /D:P\(A;;GA;;;BA\)\(A;;GA;;;SY\)/);
  assert.match(host, /AuthorizeElevatedLocalAdministrator/);
  assert.match(host, /ImpersonateNamedPipeClient/);
  const trustPipeBody = host.slice(
    host.indexOf('void ServeLocalTrustPipe('),
    host.indexOf('\n}\n\nvoid ServiceMain', host.indexOf('void ServeLocalTrustPipe(')),
  );
  assert.ok(
    trustPipeBody.indexOf('ReadPipeExact(pipe.Get(), header.data()') <
      trustPipeBody.indexOf('AuthorizeElevatedLocalAdministrator(pipe.Get())'),
    'the host must read the bounded client frame header before impersonating the named-pipe client',
  );
  assert.equal(
    (trustPipeBody.match(/CreateNamedPipeW\(/g) ?? []).length,
    1,
    'keep the first-instance pipe open across requests',
  );
  assert.ok(trustPipeBody.indexOf('CreateNamedPipeW(') < trustPipeBody.indexOf('while ('));
  assert.ok(
    trustPipeBody.indexOf('DisconnectNamedPipe(pipe.Get())') > trustPipeBody.indexOf('while ('),
  );
  assert.match(trustPipeBody, /if \(!DisconnectNamedPipe\(pipe\.Get\(\)\)\) return/);
  assert.match(host, /if \(!RevertToSelf\(\)\) return PipeClientAuthorization::Fatal/);
  assert.match(host, /client_authorization == PipeClientAuthorization::Fatal/);
  assert.match(host, /kTrustPipeReadTimeoutMs/);
  assert.match(host, /kTrustOperationTimeoutMs/);
  assert.match(host, /kTrustPipeReceiptAck\s*=\s*0xa5/);
  assert.match(
    host,
    /ReadPipeExact\(pipe\.Get\(\),\s*&acknowledgement,\s*sizeof\(acknowledgement\),\s*kTrustPipeReadTimeoutMs\)/,
  );
  assert.match(
    provision,
    /Write-PipeBytesWithTimeout -Stream \$pipe -Bytes \(\[byte\[\]\]@\(0xa5\)\)/,
  );
  assert.ok(
    provision.indexOf('Read-PipeBytesExactly -Stream $pipe -Count 1') <
      provision.indexOf('Write-PipeBytesWithTimeout -Stream $pipe -Bytes ([byte[]]@(0xa5))'),
    'the provisioner must acknowledge only after reading the complete operation receipt',
  );
  assert.match(provision, /PipeOptions\]::Asynchronous/);
  const readPipeHelper = provision.slice(
    provision.indexOf('function Read-PipeBytesExactly'),
    provision.indexOf('function Write-PipeBytesWithTimeout'),
  );
  assert.match(
    readPipeHelper,
    /ReadAsync\(\$bytes,\s*\$offset,\s*\$Count\s*-\s*\$offset,\s*\$CancellationToken\)/,
  );
  assert.match(provision, /WriteAsync\(\$Bytes,\s*0,[\s\S]*\$timeout\.Token/);
  assert.match(
    provision,
    /\$receiptTimeout = \[Threading\.CancellationTokenSource\]::new\(75000\)/,
  );
  assert.match(
    provision,
    /Read-PipeBytesExactly -Stream \$pipe -Count 4 -CancellationToken \$receiptTimeout\.Token/,
  );
  assert.doesNotMatch(provision, /\$pipe\.(?:Read|Write)Timeout\s*=/);
  assert.match(host, /CreateOverlappedControlPipe\(&child\.control_read, &child\.control_write\)/);
  assert.match(
    host,
    /std::wstring pipe_name = std::wstring\(L"[^"]*"\) \+ identifier_text\.data\(\);/,
  );
  assert.match(
    host,
    /FrameRead ReadFrameUntil\(HANDLE pipe, HANDLE process, DWORD timeout_ms, ControlFrame\* frame,\s*bool observe_stop = true\)/,
  );
  const readFrameBody = host.slice(
    host.indexOf('FrameRead ReadFrameUntil('),
    host.indexOf(
      '\n}\n\nvoid CreateOverlappedControlPipe',
      host.indexOf('FrameRead ReadFrameUntil('),
    ),
  );
  assert.ok(
    readFrameBody.indexOf('PeekNamedPipe(') <
      readFrameBody.indexOf('WaitForSingleObject(process, 0)'),
    'the service host must drain a buffered final frame before reporting child exit',
  );
  assert.match(host, /bool WriteFrame\(HANDLE pipe, ControlFrame frame, DWORD timeout_ms\)/);
  const stopChildBody = host.slice(
    host.indexOf('bool StopChild('),
    host.indexOf('\n}\n\nbool WaitOverlapped', host.indexOf('bool StopChild(')),
  );
  assert.match(stopChildBody, /const ULONGLONG deadline = GetTickCount64\(\) \+ stop_timeout_ms/);
  assert.match(
    stopChildBody,
    /WriteFrame\(child\.control_write\.Get\(\), ControlFrame::Stop, static_cast<DWORD>\(deadline - now\)\)/,
  );
  assert.match(
    stopChildBody,
    /ReadFrameUntil\(child\.ready_read\.Get\(\), child\.process\.Get\(\),\s*static_cast<DWORD>\(deadline - now\), &response, false\)/,
  );
  assert.match(host, /PIPE_ACCESS_OUTBOUND\s*\|\s*FILE_FLAG_OVERLAPPED/);
  assert.match(
    host,
    /WritePipeBounded\(child\.control_write\.Get\(\), frame\.data\(\),[\s\S]*kTrustOperationTimeoutMs/,
  );
  assert.match(host, /struct VectorScrubber/);
  assert.match(host, /VectorScrubber command_scrubber\{command\}/);
  assert.match(host, /VectorScrubber frame_scrubber\{frame\}/);
  assert.match(host, /SecureZeroMemory\(bytes\.data\(\), bytes\.size\(\)\)/);
  assert.match(contract, /kMaxTrustOperationBytes = 1024 \* 1024 \+ 1/);
  assert.match(host, /length >= 2 && length <= sumatrafuzz::service_host::kMaxTrustOperationBytes/);
  assert.match(host, /command\[0\] == 0x10 \|\| command\[0\] == 0x12/);
  assert.match(host, /EncodeTrustOperationRequest\(command\)/);
  assert.match(host, /DecodeTrustOperationResponse\(response, succeeded\)/);
  assert.match(host, /trust_pipe_thread\.join\(\)/);
  assert.match(workerControl, /APPLY_SIGNED_TRUST_OPERATION = 0x10/);
  assert.match(workerControl, /APPLY_SIGNED_PAIRING_BUNDLE = 0x12/);
  assert.match(workerControl, /service\.applyTrustOperation/);
  assert.match(workerControl, /service\.applyPairingBundle/);
  assert.match(workerControl, /frame\.fill\(0\)/);
});

test('live trust provisioning authenticates the named-pipe server and prefers the running worker', () => {
  const provision = readFileSync(
    path.join(__dirname, '..', 'scripts', 'windows', 'provision-worker-service.ps1'),
    'utf8',
  );
  assert.match(provision, /GetNamedPipeServerProcessId/);
  assert.match(
    provision,
    /serverProcessId[^\n]*service\.ProcessId|service\.ProcessId[^\n]*serverProcessId/i,
  );
  assert.match(provision, /\$useLive\s*=\s*\[bool\]\$Live\s*-or/);
  assert.match(
    provision,
    /\$service\.State\s+-eq\s+'Running'\s+-and\s+-not\s+\$hasCredentials\s+-and\s+\[string\]::IsNullOrWhiteSpace\(\$ConfigurationPath\)/,
  );
  assert.match(
    provision,
    /if \(\$hasPairing\)\s*\{\s*Write-ProtectedDestination[\s\S]+worker-pairing\.sfpair/,
  );
  assert.match(
    provision,
    /\$installedConfigurationPath\s*=\s*Join-Path\s+\$dataRoot\s+'worker-config\.json'/,
  );
  assert.doesNotMatch(provision, /\$configurationPath\s*=\s*Join-Path\s+\$dataRoot/i);
  assert.match(provision, /\$service\.State\s+-eq\s+'Running'/);
  assert.match(provision, /if \(\$useLive\)/);
});

test('native quota sampling accepts only an exact mounted volume root and uses caller quota capacity', () => {
  const addon = readFileSync(
    path.join(__dirname, '..', 'native', 'worker-supervisor', 'src', 'addon.cpp'),
    'utf8',
  );
  assert.match(addon, /GetVolumePathNameW\(directory/);
  assert.match(addon, /worker data path is redirected or is not a volume mount root/);
  assert.match(addon, /user_total_available/);
  assert.match(addon, /NTFS per-user quotas may cap it below the/);
  assert.doesNotMatch(addon, /volume_free\.QuadPart\s*-\s*available\.QuadPart/);
});

test('worker payload contains admin-only first-run and certificate lifecycle provisioning', () => {
  const stage = readFileSync(
    path.join(__dirname, '..', 'scripts', 'stage-worker-service.mjs'),
    'utf8',
  );
  const install = readFileSync(
    path.join(__dirname, '..', 'scripts', 'windows', 'worker-service-config.psm1'),
    'utf8',
  );
  const provision = readFileSync(
    path.join(__dirname, '..', 'scripts', 'windows', 'provision-worker-service.ps1'),
    'utf8',
  );
  assert.match(stage, /provisioning\/provision-worker-service\.ps1/);
  assert.match(stage, /apps\/worker-service\/dist\/src\/trust-schema\.sql/);
  assert.match(stage, /new Set\(\['\.js', '\.sql'\]\)/);
  assert.match(stage, /provisioning\/worker-service-config\.psm1/);
  assert.match(install, /'start=', 'demand'/);
  assert.match(provision, /Assert-WorkerPlatform -RequireElevation/);
  assert.match(provision, /ReparsePoint/);
  assert.match(provision, /-MaximumBytes 1048576/);
  assert.match(provision, /ReadDelete/);
  assert.match(provision, /Set-Service -Name 'SumatraFuzzWorker' -StartupType Automatic/);
  assert.match(provision, /worker-trust-operation\.sftxn/);
});

test('supervisor owns a protected run-private namespace until job teardown', () => {
  const addon = readFileSync(
    path.join(__dirname, '..', 'native/worker-supervisor/src/addon.cpp'),
    'utf8',
  );
  assert.match(addon, /struct PrivateNamespace/);
  assert.match(addon, /CreateBoundaryDescriptorW/);
  assert.match(addon, /AddSIDToBoundaryDescriptor/);
  assert.match(addon, /CreatePrivateNamespaceW/);
  assert.match(addon, /SE_DACL_PROTECTED/);
  assert.match(addon, /ConvertSidToStringSidW/);
  assert.match(addon, /SUMATRAFUZZ_NAMESPACE_ALIAS/);
  assert.match(addon, /SUMATRAFUZZ_RUN_SID/);
  assert.match(addon, /ClosePrivateNamespace\(handle, PRIVATE_NAMESPACE_FLAG_DESTROY\)/);
  const probe = readFileSync(
    path.join(__dirname, '..', 'native/worker-supervisor/tests/process_probe.cpp'),
    'utf8',
  );
  assert.match(probe, /OpenPrivateNamespaceW/);
  assert.match(probe, /TokenRestrictedSids/);
  assert.match(probe, /--validate-identifiers/);
  assert.match(probe, /--grandchild/);
  assert.match(probe, /--namespace-gone/);
});

test('private namespace probe reports the exact private ACL construction failure', () => {
  const probe = readFileSync(
    path.join(__dirname, '..', 'native/worker-supervisor/tests/process_probe.cpp'),
    'utf8',
  );
  assert.match(
    probe,
    /bool Initialize\(unsigned\* failure_stage = nullptr, DWORD\* failure_error = nullptr\)/,
  );
  assert.match(probe, /CreatePrivateAccessAcl\(grants, std::size\(grants\)\)/);
  assert.match(probe, /if \(!acl\) return fail_last_error\(11\);/);
  const acl = readFileSync(
    path.join(__dirname, '..', 'native/worker-supervisor/include/private_acl.h'),
    'utf8',
  );
  assert.match(acl, /InitializeAcl\(acl, static_cast<DWORD>\(acl_size\), ACL_REVISION\)/);
  assert.match(
    acl,
    /AddAccessAllowedAceEx\(acl, ACL_REVISION, 0, grants\[index\]\.access, grants\[index\]\.sid\)/,
  );
  assert.match(
    probe,
    /InitializeSecurityDescriptor\(&descriptor, SECURITY_DESCRIPTOR_REVISION\)\) return fail_last_error\(12\)/,
  );
  assert.match(
    probe,
    /SetSecurityDescriptorDacl\(&descriptor, TRUE, acl, FALSE\)\) return fail_last_error\(13\)/,
  );
  assert.match(
    probe,
    /SetSecurityDescriptorControl\(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED\)\) return fail_last_error\(14\)/,
  );
  assert.match(probe, /ns\.Initialize\(&namespace_stage, &namespace_error\)/);
  assert.match(
    probe,
    /SetLastError\(ERROR_SUCCESS\);\s+HANDLE event = CreateEventW\(&attributes, TRUE, FALSE, event_name\.c_str\(\)\);\s+const DWORD event_error = GetLastError\(\);/,
  );
  assert.match(
    probe,
    /WriteNamespaceFailureDiagnostic\(evidence_dir, namespace_stage, namespace_error\)/,
  );
});

test('unconfirmed native teardown has a bounded fail-closed ownership quarantine', () => {
  const addon = readFileSync(
    path.join(__dirname, '..', 'native/worker-supervisor/src/addon.cpp'),
    'utf8',
  );
  assert.match(addon, /struct QuarantinedJob/);
  assert.match(addon, /g_teardown_quarantine/);
  assert.match(addon, /const ULONGLONG teardown_deadline = GetTickCount64\(\) \+ 30000/);
  assert.match(addon, /if \(!root_exited \|\| !job_empty\)/);
  assert.match(addon, /quarantine->private_namespace = std::move\(private_namespace\)/);
  assert.match(addon, /g_teardown_quarantine = quarantine.release\(\)/);
  assert.match(addon, /teardown_unconfirmed; handles quarantined/);
  assert.doesNotMatch(addon, /while\s*\(!QueryInformationJobObject/);
});
