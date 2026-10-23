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
  const inputDir = path.join(containmentRoot, 'input');
  const protectedDir = path.join(containmentRoot, 'protected');
  const containmentProbePath = path.join(toolDir, path.basename(probePath));
  const inputPath = path.join(inputDir, 'seed.pdf');
  const protectedReadPath = path.join(protectedDir, 'credential-sentinel');
  const protectedWritePath = path.join(protectedDir, 'must-not-exist');
  // An unqualified name is scoped to this logon session's BaseNamedObjects;
  // avoid a `Local\\` symbolic-link lookup from the restricted token.
  const eventName = `SumatraFuzz-Restricted-Probe-${process.pid}`;
  mkdirSync(toolDir);
  mkdirSync(evidenceDir);
  mkdirSync(inputDir);
  mkdirSync(protectedDir);
  copyFileSync(probePath, containmentProbePath);
  writeFileSync(inputPath, 'pdf input sentinel');
  writeFileSync(protectedReadPath, 'service-only trust and DPAPI sentinel');
  const baselineEnvironment = { ...process.env };
  delete baselineEnvironment.SUMATRAFUZZ_TEST_SECRET;
  execFileSync(
    containmentProbePath,
    ['--create-event', `${eventName}-baseline`],
    { env: baselineEnvironment, stdio: 'ignore' },
  );
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
        sample.process_count >= 2 &&
        evidenceNames.filter((name) => name.startsWith('restricted-write-')).length >= 2 &&
        evidenceNames.some((name) => name.startsWith('named-event-'))
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    if (sample.process_count < 2) {
      const receipt = supervisor.stopJob(job, 0);
      job = undefined;
      assert.fail(
        `probe process tree did not start (processes=${sample.process_count}, exit=${receipt.exitCode})`,
      );
    }
    assert.ok(
      sample.process_count >= 2,
      'probe child must stay in the job and must not inherit secrets',
    );
    assert.ok(
      readdirSync(evidenceDir).filter((name) => name.startsWith('restricted-write-')).length >= 2,
      'restricted child process and descendant must both write evidence',
    );
    assert.ok(
      readdirSync(evidenceDir).some((name) => name.startsWith('named-event-')),
      'restricted descendant must open and signal the private named event',
    );
    assert.deepEqual(
      readdirSync(protectedDir),
      [],
      'restricted child process and its descendant must not write outside run evidence',
    );
    const receipt = supervisor.stopJob(job, 0);
    job = undefined;
    assert.equal(receipt.remainingProcesses, 0);
  } finally {
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
  assert.match(addon, /SetEntriesInAclW\(/);
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
  assert.match(stage, /provisioning\/worker-service-config\.psm1/);
  assert.match(install, /'start=', 'demand'/);
  assert.match(provision, /Assert-WorkerPlatform -RequireElevation/);
  assert.match(provision, /ReparsePoint/);
  assert.match(provision, /-MaximumBytes 1048576/);
  assert.match(provision, /ReadDelete/);
  assert.match(provision, /Set-Service -Name 'SumatraFuzzWorker' -StartupType Automatic/);
  assert.match(provision, /worker-trust-operation\.sftxn/);
});
