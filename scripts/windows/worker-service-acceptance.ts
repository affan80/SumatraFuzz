import { createHash, createPrivateKey, randomUUID, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createWorkerClient, WorkerClientError } from '@sumatrafuzz/worker-client';
import { asControllerId, validateRunRequest } from '@sumatrafuzz/worker-protocol';
import { ZipFile } from 'yazl';

const root = process.cwd();
const fixtureRoot = process.env.WORKER_SERVICE_FIXTURE_ROOT;
const workerDataRoot = process.env.WORKER_SERVICE_DATA_ROOT;
const seedRoot = path.join(root, 'runs', 'a5', 'seeds');
const nativeRoot = path.join(root, 'runs', 'worker-native');
const summaryPath = path.join(nativeRoot, 'acceptance-summary.json');
const minimumExecutions = 1_000;
const maxWaitMs = 10 * 60_000;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type FixtureProfile = {
  workerId: string;
  controllerId: string;
  baseUrl: string;
  workerFingerprint: string;
  controllerCertificatePem: string;
  controllerPrivateKeyPem: string;
  trustedCaPem: string;
};

function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function readProfile(name: string): Promise<FixtureProfile> {
  invariant(fixtureRoot, 'worker-service fixture root is unavailable');
  const file = path.join(fixtureRoot, name);
  const metadata = await lstat(file);
  invariant(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 1024 * 1024, 'unsafe test identity file');
  return JSON.parse(await readFile(file, 'utf8')) as FixtureProfile;
}

async function zipSeeds(files: readonly string[]): Promise<Buffer> {
  const zip = new ZipFile();
  for (const file of files) zip.addBuffer(await readFile(file), path.basename(file), { compress: true });
  zip.end();
  const chunks: Buffer[] = [];
  for await (const chunk of zip.outputStream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function readExecutions(file: string): Promise<number | null> {
  try {
    const metadata = await lstat(file);
    invariant(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 1024 * 1024, 'unsafe WinAFL stats file');
    const match = /^execs_done\s*:\s*(\d+)\s*$/m.exec(await readFile(file, 'utf8'));
    if (!match) return null;
    const count = Number(match[1]);
    return Number.isSafeInteger(count) ? count : null;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

function client(profile: FixtureProfile) {
  return createWorkerClient({
    baseUrl: profile.baseUrl,
    controllerCertificate: Buffer.from(profile.controllerCertificatePem),
    controllerKey: Buffer.from(profile.controllerPrivateKeyPem),
    trustedCa: Buffer.from(profile.trustedCaPem),
    workerFingerprint: profile.workerFingerprint,
    timeoutMs: 30_000,
  });
}

async function writeFreshRevocation(profile: FixtureProfile): Promise<string> {
  invariant(fixtureRoot, 'worker-service fixture root is unavailable');
  const privateKeyBytes = await readFile(path.join(fixtureRoot, 'organization-private.pem'));
  const transactionPath = path.join(fixtureRoot, 'revoke-controller-1.sftxn');
  let payload: Buffer | undefined;
  let signature: Buffer | undefined;
  let envelope: Buffer | undefined;
  try {
    const privateKey = createPrivateKey(privateKeyBytes);
    const issuedAt = new Date();
    payload = Buffer.from(
      JSON.stringify({
        format: 'sumatrafuzz-worker-trust-operation-v1',
        workerId: profile.workerId,
        issuedAt: issuedAt.toISOString(),
        expiresAt: new Date(issuedAt.getTime() + 5 * 60_000).toISOString(),
        operation: {
          type: 'unpair_controller',
          controllerId: profile.controllerId,
          fingerprint: null,
        },
      }),
    );
    signature = sign(null, payload, privateKey);
    envelope = Buffer.from(
      JSON.stringify({
        format: 'sumatrafuzz-worker-pairing-bundle-v1',
        payload: payload.toString('base64'),
        signature: signature.toString('base64'),
      }),
    );
    await writeFile(transactionPath, envelope, { flag: 'wx', mode: 0o600 });
    return transactionPath;
  } finally {
    privateKeyBytes.fill(0);
    payload?.fill(0);
    signature?.fill(0);
    envelope?.fill(0);
  }
}

async function main(): Promise<void> {
  invariant(process.platform === 'win32' && process.arch === 'x64', 'installed-service acceptance requires Windows x64');
  invariant(process.env.GITHUB_ACTIONS === 'true', 'installed-service acceptance requires an ephemeral CI worker');
  invariant(fixtureRoot && workerDataRoot, 'installed-service acceptance paths are required');
  const workflowCommit = process.env.GITHUB_SHA ?? '';
  const sourceCommit = process.env.WORKER_ACCEPTANCE_HEAD_SHA ?? '';
  invariant(/^[0-9a-f]{40}$/i.test(workflowCommit) && /^[0-9a-f]{40}$/i.test(sourceCommit), 'acceptance requires exact workflow and source commits');
  const checkedOutCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  invariant(checkedOutCommit.toLowerCase() === workflowCommit.toLowerCase(), 'acceptance checkout does not match the exact workflow commit');
  execFileSync('git', ['merge-base', '--is-ancestor', sourceCommit, checkedOutCommit], { cwd: root, stdio: 'ignore' });
  await mkdir(nativeRoot, { recursive: true });

  const firstProfile = await readProfile('controller-1.json');
  const secondProfile = await readProfile('controller-2.json');
  const verifyRevocation = process.env.WORKER_SERVICE_VERIFY_REVOCATION === 'true';
  if (verifyRevocation) {
    const first = client(firstProfile);
    const second = client(secondProfile);
    try {
      let revokedDenied = false;
      try {
        await first.capabilities();
      } catch {
        revokedDenied = true;
      }
      invariant(revokedDenied, 'revoked controller was accepted after service restart');
      const capabilities = await second.capabilities();
      invariant(capabilities.worker_id === secondProfile.workerId, 'remaining controller trust did not survive restart');
      console.log('Verified durable controller revocation after service restart.');
      return;
    } finally {
      first.close();
      second.close();
    }
  }
  const unpairedProfile = await readProfile('controller-3.json');
  invariant(firstProfile.workerId === secondProfile.workerId, 'test controllers do not share a worker identity');
  const first = client(firstProfile);
  const second = client(secondProfile);
  const unpaired = client(unpairedProfile);
  let archive: Buffer | undefined;
  let runId: string | undefined;
  let stopped = false;
  try {
    const capabilities = await first.capabilities();
    invariant(capabilities.worker_id === firstProfile.workerId, 'mTLS returned a different worker identity');
    invariant(capabilities.controller_id === firstProfile.controllerId, 'mTLS returned a different controller identity');
    const secondCapabilities = await second.capabilities();
    invariant(secondCapabilities.controller_id === secondProfile.controllerId, 'second controller pairing was not persisted');
    let unpairedDenied = false;
    try {
      await unpaired.capabilities();
    } catch {
      unpairedDenied = true;
    }
    invariant(unpairedDenied, 'worker accepted an unpaired controller certificate');

    const seeds = (await readdir(seedRoot, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.pdf'))
      .map((entry) => path.join(seedRoot, entry.name));
    invariant(seeds.length >= 2, 'genuine A5 PDF seeds are required');
    archive = await zipSeeds(seeds);
    const imported = await first.importInputBundle(archive);
    const request = validateRunRequest({
      request_id: randomUUID(),
      controller_id: asControllerId(firstProfile.controllerId),
      input_bundle_id: imported.input_bundle_id,
      target_lock_sha256: capabilities.target_lock_sha256,
      limits: capabilities.max_limits,
      label: 'installed Windows worker acceptance',
    });
    const started = await first.startRun(request);
    invariant(started.state === 'running', 'installed service did not start a running campaign');
    runId = started.run_id;

    let crossControllerDenied = false;
    try {
      await second.getRun(started.run_id);
    } catch (error) {
      crossControllerDenied = error instanceof WorkerClientError && error.status === 404;
    }
    invariant(crossControllerDenied, 'second controller learned the first controller run');

    const serviceProcessTree = path.join(root, 'scripts', 'windows', 'assert-worker-service-process-tree.ps1');
    execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', serviceProcessTree], {
      cwd: root,
      stdio: 'pipe',
      windowsHide: true,
    });

    const statsPath = path.join(workerDataRoot, 'outputs', started.run_id, 'fuzzer_stats');
    const deadline = Date.now() + maxWaitMs;
    let executions = 0;
    while (Date.now() < deadline) {
      const observed = await readExecutions(statsPath);
      if (observed !== null) executions = Math.max(executions, observed);
      if (executions >= minimumExecutions) break;
      const status = await first.getRun(started.run_id);
      invariant(
        status.state === 'running',
        `installed worker stopped before ${minimumExecutions} genuine executions ` +
          `(state=${status.state}, stop_reason=${String(status.stop_reason ?? 'unknown')}, observed_execs=${executions})`,
      );
      await pause(1_000);
    }
    invariant(executions >= minimumExecutions, `installed worker timed out below ${minimumExecutions} genuine executions (observed_execs=${executions})`);

    const stop = await first.stopRun(started.run_id);
    stopped = true;
    invariant(stop.state === 'completed' && stop.stop_reason === 'requested', 'installed worker did not complete the requested stop');
    const finalCount = await readExecutions(statsPath);
    invariant(finalCount !== null && finalCount >= minimumExecutions, 'installed worker finalized fewer than 1,000 measured executions');
    const statsSha256 = createHash('sha256').update(await readFile(statsPath)).digest('hex');
    const events = await first.eventsAfter(started.run_id, 0n);
    const eventTypes = events.map((event) => event.event_type);
    const teardown = eventTypes.lastIndexOf('process_teardown');
    const finalized = eventTypes.lastIndexOf('evidence_finalized');
    const completed = eventTypes.lastIndexOf('state_changed');
    invariant(teardown >= 0 && finalized > teardown && completed > finalized, 'service event history does not prove ordered teardown and finalization');

    invariant(process.env.WORKER_SERVICE_PROVISIONER_PATH, 'live trust provisioner path is unavailable');
    const revocationPath = await writeFreshRevocation(firstProfile);
    execFileSync(
      'pwsh',
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        process.env.WORKER_SERVICE_PROVISIONER_PATH,
        '-TrustOperationPath',
        revocationPath,
        '-Live',
      ],
      { cwd: root, stdio: 'pipe', windowsHide: true },
    );
    let reusedSessionRevoked = false;
    try {
      await first.getRun(started.run_id);
    } catch {
      reusedSessionRevoked = true;
    }
    invariant(reusedSessionRevoked, 'live revocation did not deny the existing authenticated client session');
    invariant(
      (await second.capabilities()).controller_id === secondProfile.controllerId,
      'revoking one controller disrupted another controller trust record',
    );

    const record = {
      schema_version: 1,
      source_commit: sourceCommit.toLowerCase(),
      checked_out_commit: checkedOutCommit.toLowerCase(),
      state: stop.state,
      stop_reason: stop.stop_reason,
      worker_id: capabilities.worker_id,
      controller_id: capabilities.controller_id,
      run_id: started.run_id,
      executions_done: finalCount,
      fuzzer_stats_sha256: statsSha256,
      process_tree_verified_as_service_sid: true,
      paired_controllers: 2,
      unpaired_certificate_denied: true,
      cross_controller_run_denied: true,
      live_revocation_destroyed_existing_session: true,
      event_types: eventTypes,
    };
    await writeFile(summaryPath, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx' });
    console.log(`Verified installed mTLS service campaign: ${finalCount} genuine WinAFL executions.`);
  } finally {
    archive?.fill(0);
    if (runId && !stopped) {
      try {
        await first.stopRun(runId);
      } catch {
        // Failed shutdown is recorded by the service journal; do not fabricate a pass summary.
      }
    }
    first.close();
    second.close();
    unpaired.close();
  }
}

await main().finally(async () => {
  if (process.env.WORKER_SERVICE_ACCEPTANCE_CLEANUP === 'true') {
    await rm(nativeRoot, { recursive: true, force: true });
  }
});
