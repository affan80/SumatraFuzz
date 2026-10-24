import { createHash, randomUUID } from 'node:crypto';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface FileProof {
  readonly path: string;
  readonly root: string;
  readonly sha256: string;
}

interface LaunchSpec {
  readonly runId: string;
  readonly executable: string;
  readonly argv: readonly string[];
  readonly workingDir: string;
  readonly evidenceDir: string;
  readonly limits: { readonly max_memory_bytes: number; readonly max_cpu_percent: number };
  readonly fileProofs: readonly FileProof[];
  readonly durationSeconds: number;
}

interface JobHandle {
  readonly id: string;
  readonly processId: number;
}

interface NativeSupervisor {
  launchSuspended(spec: LaunchSpec): JobHandle;
  sampleJob(job: JobHandle): {
    readonly process_count: number;
    readonly root_exited?: boolean;
    readonly root_exit_code?: number | null;
  };
  stopJob(job: JobHandle, graceMs: number): { readonly remainingProcesses: number; readonly exitCode: number | null };
}

function fail(message: string): never {
  throw new Error(message);
}

function validateSpec(value: unknown): LaunchSpec {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid supervised WinAFL launch specification');
  const spec = value as Partial<LaunchSpec>;
  if (
    typeof spec.runId !== 'string' ||
    !/^[0-9a-f]{32}$/i.test(spec.runId) ||
    typeof spec.executable !== 'string' ||
    !path.win32.isAbsolute(spec.executable) ||
    !Array.isArray(spec.argv) ||
    spec.argv.length < 1 ||
    spec.argv.length > 256 ||
    spec.argv.some((argument) => typeof argument !== 'string' || argument.length > 32766) ||
    typeof spec.workingDir !== 'string' ||
    !path.win32.isAbsolute(spec.workingDir) ||
    typeof spec.evidenceDir !== 'string' ||
    !path.win32.isAbsolute(spec.evidenceDir) ||
    !spec.limits ||
    !Number.isSafeInteger(spec.limits.max_memory_bytes) ||
    spec.limits.max_memory_bytes < 16 * 1024 * 1024 ||
    !Number.isInteger(spec.limits.max_cpu_percent) ||
    spec.limits.max_cpu_percent < 1 ||
    spec.limits.max_cpu_percent > 100 ||
    !Array.isArray(spec.fileProofs) ||
    spec.fileProofs.length < 2 ||
    spec.fileProofs.length > 64 ||
    !Number.isInteger(spec.durationSeconds) ||
    (spec.durationSeconds ?? 0) < 15 ||
    (spec.durationSeconds ?? 0) > 1200
  ) {
    fail('invalid supervised WinAFL launch specification');
  }
  for (const proof of spec.fileProofs) {
    if (
      !proof ||
      !path.win32.isAbsolute(proof.path) ||
      !path.win32.isAbsolute(proof.root) ||
      !/^[0-9a-f]{64}$/i.test(proof.sha256)
    ) {
      fail('invalid supervised WinAFL file proof');
    }
  }
  return spec as LaunchSpec;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function snapshotStats(source: string, first: string, second: string): Promise<void> {
  try {
    await readFile(source);
  } catch {
    return;
  }
  try {
    await readFile(first);
    await copyFile(source, second);
  } catch {
    await copyFile(source, first);
  }
}

async function main(): Promise<void> {
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('Windows x64 required');
  const specPath = process.argv[2];
  if (!specPath || !path.win32.isAbsolute(specPath)) fail('absolute launch specification path required');
  const spec = validateSpec(JSON.parse(await readFile(specPath, 'utf8')) as unknown);
  const addonPath = fileURLToPath(
    new URL('../../native/worker-supervisor/build/Release/worker_supervisor.node', import.meta.url),
  );
  const require = createRequire(import.meta.url);
  const supervisor = require(addonPath) as NativeSupervisor;
  const startedAt = new Date();
  const statsPath = path.win32.join(spec.evidenceDir, 'fuzzer_stats');
  const firstStats = path.win32.join(spec.evidenceDir, 'first.stats');
  const laterStats = path.win32.join(spec.evidenceDir, 'second.stats');
  const job = supervisor.launchSuspended(spec);
  let receipt: ReturnType<NativeSupervisor['stopJob']> | undefined;
  try {
    const deadline = Date.now() + spec.durationSeconds * 1000;
    while (Date.now() < deadline) {
      const sample = supervisor.sampleJob(job);
      if (sample.root_exited || sample.process_count < 1) {
        receipt = supervisor.stopJob(job, 0);
        const exitCode = sample.root_exit_code ?? receipt.exitCode ?? 'unknown';
        fail(`supervised WinAFL exited before the bounded campaign completed (exit ${exitCode})`);
      }
      await snapshotStats(statsPath, firstStats, laterStats);
      await sleep(3000);
    }
    await snapshotStats(statsPath, firstStats, laterStats);
    receipt = supervisor.stopJob(job, 0);
    if (receipt.remainingProcesses !== 0) fail('supervised WinAFL process tree teardown was not confirmed');
    const finalStats = await readFile(statsPath);
    const first = await readFile(firstStats);
    const later = await readFile(laterStats);
    await writeFile(
      path.win32.join(spec.evidenceDir, 'campaign-metadata.json'),
      `${JSON.stringify(
        {
          start_utc: startedAt.toISOString(),
          end_utc: new Date().toISOString(),
          stop_reason: 'bounded_limit_reached',
          source_commit: '16c59fde8b824ab54c56f23aef910a6fdd874ad0',
          stats_initial_sha256: createHash('sha256').update(first).digest('hex'),
          stats_later_sha256: createHash('sha256').update(later).digest('hex'),
          stats_final_sha256: createHash('sha256').update(finalStats).digest('hex'),
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', flag: 'wx' },
    );
    process.stdout.write('Supervised bounded WinAFL campaign completed; all child processes were contained and stopped.\n');
  } finally {
    if (!receipt) {
      const stopped = supervisor.stopJob(job, 0);
      if (stopped.remainingProcesses !== 0) fail('supervised WinAFL process tree teardown was not confirmed');
    }
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'supervised WinAFL failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
