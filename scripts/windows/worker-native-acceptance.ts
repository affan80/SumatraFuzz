import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { SqliteRunStore } from '@sumatrafuzz/run-store';
import { WindowsJobSupervisor, type WorkerPolicy } from '@sumatrafuzz/worker-core';
import { asControllerId, asRunId, validateRunRequest } from '@sumatrafuzz/worker-protocol';
import { ZipFile } from 'yazl';
import { FileEvidenceRepository, importInputBundle, WorkerRunCoordinator } from '../../apps/worker-service/dist/src/index.js';

const MIN_EXECUTIONS = 1_000;
const MAX_DURATION_SECONDS = 600;
const MEMORY_LIMIT_BYTES = 4 * 1024 * 1024 * 1024;
const CPU_LIMIT_PERCENT = 75;
const POLL_INTERVAL_MS = 1_000;
const root = process.cwd();
const runsRoot = path.join(root, 'runs');
const nativeRoot = path.join(runsRoot, 'worker-native');
const acceptanceRoot = path.join(nativeRoot, randomUUID());
const inputRoot = path.join(acceptanceRoot, 'inputs');
const outputRoot = path.join(acceptanceRoot, 'output');
const databasePath = path.join(acceptanceRoot, 'worker.sqlite');
const summaryPath = path.join(nativeRoot, 'acceptance-summary.json');
const targetLockPath = path.join(root, 'external', 'native-tools', 'locks', 'target-lock.json');
const a4ManifestPath = path.join(root, 'runs', 'a4', 'debug-evidence', 'a4-confirmed.json');
const seedRoot = path.join(root, 'runs', 'a5', 'seeds');
const harnessPath = path.join(root, 'build', 'a3', 'Release', 'sumatrafuzz-harness.exe');
const binaryRoot = path.dirname(harnessPath);
const toolRoot = path.join(root, 'external', 'native-tools');
const delay = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function sha256(file: string): Promise<string> {
  return createHash('sha256').update(await readFile(file)).digest('hex');
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
    const info = await lstat(file);
    invariant(info.isFile() && !info.isSymbolicLink() && info.size <= 1024 * 1024, 'unsafe WinAFL stats file');
    const text = await readFile(file, 'utf8');
    const match = /^execs_done\s*:\s*(\d+)\s*$/m.exec(text);
    if (!match) return null;
    const executions = Number(match[1]);
    return Number.isSafeInteger(executions) ? executions : null;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

async function main(): Promise<void> {
  invariant(process.platform === 'win32' && process.arch === 'x64', 'native worker acceptance requires Windows x64');
  invariant(process.env.GITHUB_ACTIONS === 'true', 'native worker acceptance requires an ephemeral CI worker');
  invariant(/^[0-9a-f]{40}$/i.test(process.env.GITHUB_SHA ?? ''), 'native worker acceptance requires the exact CI commit SHA');

  await mkdir(nativeRoot, { recursive: true });
  await mkdir(inputRoot, { recursive: true });
  await mkdir(outputRoot, { recursive: true });
  const controllerId = asControllerId(randomUUID());
  const workerId = randomUUID();
  const controllerInputRoot = path.join(inputRoot, controllerId);
  await mkdir(controllerInputRoot, { recursive: true });

  const supervisor = new WindowsJobSupervisor();
  const volume = supervisor.sampleVolumeUsage(inputRoot);
  invariant(Number.isSafeInteger(volume.quota_bytes) && volume.quota_bytes > 0, 'worker disk quota is unavailable');
  invariant(volume.used_bytes < volume.quota_bytes, 'worker disk quota is exhausted before launch');

  const seeds = (await readdir(seedRoot, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.pdf'))
    .map((entry) => path.join(seedRoot, entry.name));
  invariant(seeds.length >= 2, 'genuine A5 PDF seeds are required');
  const imported = await importInputBundle(inputRoot, controllerId, await zipSeeds(seeds), volume.quota_bytes);
  const policy: WorkerPolicy = {
    maxLimits: {
      max_duration_s: MAX_DURATION_SECONDS,
      max_memory_bytes: MEMORY_LIMIT_BYTES,
      max_disk_bytes: volume.quota_bytes,
      max_cpu_percent: CPU_LIMIT_PERCENT,
    },
    pinnedTargetLockSha256: await sha256(targetLockPath),
    pinnedA4ManifestSha256: await sha256(a4ManifestPath),
    targetLockPath,
    a4ManifestPath,
    harnessPath,
    allowedBinaryRoot: binaryRoot,
    allowedToolRoot: toolRoot,
    allowedInputRoot: inputRoot,
    outputRoot,
  };
  const store = SqliteRunStore.open(databasePath);
  let coordinator: WorkerRunCoordinator | undefined;
  let runId: string | undefined;
  let stopped = false;
  try {
    const evidence = new FileEvidenceRepository(store, outputRoot, volume.quota_bytes);
    coordinator = new WorkerRunCoordinator({
      workerId,
      store,
      policy,
      supervisor,
      evidence,
      quotaIntervalMs: 2_000,
      measureWorkerVolumeUsedBytes: async () => supervisor.sampleVolumeUsage(inputRoot).used_bytes,
    });
    invariant((await coordinator.reconcileStartup()) === 'clean', 'native acceptance workspace must start clean');
    const request = validateRunRequest({
      request_id: randomUUID(),
      controller_id: controllerId,
      input_bundle_id: imported.input_bundle_id,
      target_lock_sha256: policy.pinnedTargetLockSha256,
      limits: policy.maxLimits,
      label: 'genuine Windows worker acceptance',
    });
    const started = (await coordinator.startRun(controllerId, request)) as { run_id?: unknown; state?: unknown };
    invariant(typeof started.run_id === 'string' && started.state === 'running', 'production coordinator did not start a running campaign');
    runId = started.run_id;
    const startedAt = Date.now();
    const statsPath = path.join(outputRoot, runId, 'fuzzer_stats');
    let executions = 0;
    while (Date.now() - startedAt < MAX_DURATION_SECONDS * 1_000 - 15_000) {
      const observed = await readExecutions(statsPath);
      if (observed !== null) executions = Math.max(executions, observed);
      if (executions >= MIN_EXECUTIONS) break;
      const status = (await coordinator.getRun(controllerId, runId)) as { state?: unknown };
      invariant(status.state === 'running', `worker stopped before ${MIN_EXECUTIONS} genuine executions`);
      await delay(POLL_INTERVAL_MS);
    }

    const stoppedStatus = (await coordinator.stopRun(controllerId, runId, 'requested')) as {
      state?: unknown;
      stop_reason?: unknown;
    };
    stopped = true;
    const finalStats = await readExecutions(statsPath);
    invariant(finalStats !== null && finalStats >= MIN_EXECUTIONS, `worker produced fewer than ${MIN_EXECUTIONS} measured executions`);
    invariant(stoppedStatus.state === 'completed' && stoppedStatus.stop_reason === 'requested', 'worker did not finalize as an explicitly stopped run');

    const run = asRunId(runId);
    const receipt = store.teardownReceipt(run);
    invariant(receipt && receipt.remainingProcesses === 0, 'native teardown receipt did not prove an empty process job');
    invariant(receipt.jobId.length > 0 && Number.isFinite(Date.parse(receipt.stoppedAtUtc)), 'native teardown receipt is malformed');

    const events = store.readEventsAfter(run, 0n, 500);
    const eventTypes = events.map((event) => event.event_type);
    const teardownIndex = eventTypes.lastIndexOf('process_teardown');
    const finalizationIndex = eventTypes.lastIndexOf('evidence_finalized');
    const completionIndex = eventTypes.lastIndexOf('state_changed');
    invariant(teardownIndex >= 0 && finalizationIndex > teardownIndex && completionIndex > finalizationIndex, 'teardown, evidence finalization and completion events are not ordered');

    const artifacts = store.finalArtifacts(run);
    const statsArtifact = artifacts.find((artifact) => artifact.relativePath === 'fuzzer_stats');
    invariant(statsArtifact, 'finalized journal does not include the measured WinAFL counters');
    invariant(statsArtifact.sha256 === (await sha256(statsPath)), 'finalized counter hash does not match the worker output');
    const reopenedStore = SqliteRunStore.open(databasePath);
    try {
      invariant(reopenedStore.runState(run) === 'completed', 'final state did not survive reopening the worker journal');
      invariant(reopenedStore.activeRunSnapshot() === null, 'worker slot remained occupied after finalization');
      invariant(reopenedStore.teardownReceipt(run)?.remainingProcesses === 0, 'reopened journal lost the teardown receipt');
      invariant(reopenedStore.finalArtifacts(run).some((artifact) => artifact.sha256 === statsArtifact.sha256), 'reopened journal lost immutable evidence');
    } finally {
      reopenedStore.close();
    }

    const summary = {
      schema_version: 1,
      source_commit: process.env.GITHUB_SHA,
      state: 'completed',
      stop_reason: 'requested',
      executions_done: finalStats,
      duration_seconds: Math.round((Date.now() - startedAt) / 1_000),
      process_count_at_teardown: receipt.remainingProcesses,
      event_types: eventTypes,
      artifact_count: artifacts.length,
      artifact_total_bytes: artifacts.reduce((total, artifact) => total + artifact.sizeBytes, 0),
      fuzzer_stats_sha256: statsArtifact.sha256,
      fuzzer_stats_size_bytes: statsArtifact.sizeBytes,
    };
    await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, { flag: 'wx' });
    console.log(`Verified production worker coordinator and Job Object: ${finalStats} genuine WinAFL executions; run ${runId}`);
  } finally {
    if (runId && !stopped) {
      try {
        await coordinator?.stopRun(controllerId, runId, 'process_failure');
      } catch {
        // A failed stop must not prevent persistent-runner workspace cleanup.
      }
    }
    store.close();
    await rm(acceptanceRoot, { recursive: true, force: true });
  }
}

await main();
