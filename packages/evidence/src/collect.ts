import { createHash } from 'node:crypto';
import type { Stats } from 'node:fs';
import { createReadStream } from 'node:fs';
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  type DebugEvidence,
  DebugLogError,
  inspectDebugLog,
} from '@sumatrafuzz/instrumentation/verify-debug';
import { parseWinAflStats, StatsError, verifyProgress, type WinAflStats } from './stats.js';

const PIN = '16c59fde8b824ab54c56f23aef910a6fdd874ad0';
const MAX_JSON_BYTES = 1024 * 1024;

export class EvidenceError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'EvidenceError';
  }
}

export interface FindingEvidence {
  path: string;
  sha256: string;
  bytes: number;
  classification: 'untriaged';
  replay_argv: string[];
}

export interface EvidenceManifest {
  schema_version: 1;
  source_commit: string;
  start_utc: string;
  end_utc: string;
  command: string[];
  stop_reason: 'bounded_limit_reached';
  toolchain_lock_sha256: string;
  a4_manifest_sha256: string;
  raw_debug_log_sha256: string;
  confirmed_coverage_modules: string[];
  metric_units: string;
  metrics: WinAflStats;
  first_snapshot: WinAflStats;
  later_snapshot: WinAflStats;
  queue: Array<{ name: string; sha256: string; bytes: number }>;
  crashes: FindingEvidence[];
  hangs: FindingEvidence[];
  finding_counts: Record<
    'crashes' | 'hangs',
    { reported_in_stats: number; saved_artifacts: number; additional_saved_artifacts: number }
  >;
  raw_stats_sha256: string;
  binary_hashes: Record<string, string>;
}

async function rejectRedirectedPath(candidate: string, trustedRoot = candidate): Promise<void> {
  const absolute = path.resolve(candidate);
  const root = path.resolve(trustedRoot);
  const relative = path.relative(root, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))
    throw new EvidenceError(`Evidence path escaped trusted root: ${candidate}`);
  let current = root;
  for (const component of ['', ...relative.split(path.sep).filter(Boolean)]) {
    if (component) current = path.join(current, component);
    try {
      if ((await lstat(current)).isSymbolicLink())
        throw new EvidenceError(`Unsafe redirected path component: ${current}`);
    } catch (error) {
      if (error instanceof EvidenceError) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
        throw new EvidenceError(`Could not inspect evidence path: ${current}`, { cause: error });
    }
  }
}

async function regularFile(file: string, trustedRoot = path.dirname(file)): Promise<void> {
  await rejectRedirectedPath(file, trustedRoot);
  const info = await lstat(file).catch((cause) => {
    throw new EvidenceError(`Missing evidence file: ${file}`, { cause });
  });
  if (!info.isFile() || info.isSymbolicLink())
    throw new EvidenceError(`Unsafe or invalid evidence file: ${file}`);
}

async function digest(file: string, trustedRoot = path.dirname(file)): Promise<string> {
  await regularFile(file, trustedRoot);
  const info = await lstat(file);
  if (info.size > 2 ** 40) throw new EvidenceError(`Evidence file exceeds maximum size: ${file}`);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

async function readJson(
  file: string,
  trustedRoot = path.dirname(file),
): Promise<Record<string, unknown>> {
  await regularFile(file, trustedRoot);
  const info = await lstat(file);
  if (info.size > MAX_JSON_BYTES)
    throw new EvidenceError(`Evidence JSON exceeds maximum size: ${file}`);
  try {
    const source = (await readFile(file, 'utf8')).replace(/^\uFEFF/, '');
    const value: unknown = JSON.parse(source);
    if (typeof value !== 'object' || value === null || Array.isArray(value))
      throw new Error('expected an object');
    return value as Record<string, unknown>;
  } catch (cause) {
    throw new EvidenceError(`Invalid JSON evidence: ${file}`, { cause });
  }
}

async function compareFile(
  file: string,
  expected: unknown,
  label: string,
  trustedRoot = path.dirname(file),
): Promise<void> {
  if (
    typeof expected !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(expected) ||
    (await digest(file, trustedRoot)).toLowerCase() !== expected.toLowerCase()
  ) {
    throw new EvidenceError(`SHA-256 mismatch for ${label}: ${file}`);
  }
}

export async function findingInventory(
  runDir: string,
  kind: 'crashes' | 'hangs',
  observedCount: number,
): Promise<FindingEvidence[]> {
  if (!Number.isSafeInteger(observedCount) || observedCount < 0)
    throw new EvidenceError('Invalid measured finding count');
  const folder = path.join(runDir, kind);
  await rejectRedirectedPath(folder, runDir);
  let info: Stats;
  try {
    info = await lstat(folder);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT' && observedCount === 0) return [];
    throw new EvidenceError(`Missing ${kind} artifacts for ${observedCount} measured findings`, {
      cause: error,
    });
  }
  if (!info.isDirectory() || info.isSymbolicLink())
    throw new EvidenceError(`Unsafe or invalid ${kind} artifact directory`);
  const names = (await readdir(folder)).filter((name) => name.startsWith('id_')).sort();
  const paths = names.map((name) => path.join(folder, name));
  for (const candidate of paths) {
    try {
      await regularFile(candidate, runDir);
    } catch (cause) {
      throw new EvidenceError(`Unsafe ${kind} sample: ${String(cause)}`, { cause });
    }
  }
  if (paths.length < observedCount)
    throw new EvidenceError(
      `${kind} artifact count ${paths.length} differs from measured unique findings ${observedCount}`,
    );
  const items: FindingEvidence[] = [];
  for (let i = 0; i < paths.length; i++) {
    const candidate = paths[i];
    const name = names[i];
    if (candidate === undefined || name === undefined)
      throw new EvidenceError('Finding inventory changed unexpectedly');
    const fileInfo = await lstat(candidate);
    items.push({
      path: `${kind}/${name}`,
      sha256: await digest(candidate, runDir),
      bytes: fileInfo.size,
      classification: 'untriaged',
      replay_argv: ['sumatrafuzz-harness.exe', `${kind}/${name}`],
    });
  }
  return items;
}

export async function collectEvidence(input: {
  runDir: string;
  toolchainLock: string;
  a4Manifest: string;
  harness: string;
  beforeStats: string;
  afterStats: string;
}): Promise<EvidenceManifest> {
  try {
    await rejectRedirectedPath(input.runDir);
    const lock = await readJson(input.toolchainLock);
    const a4 = await readJson(input.a4Manifest);
    if (lock.source_commit !== PIN || a4.target_commit !== PIN)
      throw new EvidenceError('Pinned SumatraPDF source SHA mismatch');
    await compareFile(input.toolchainLock, a4.toolchain_lock_sha256, 'A4 toolchain lock');
    if (
      a4.cycles !== 10 ||
      !Array.isArray(a4.confirmed_modules) ||
      a4.confirmed_modules.length === 0 ||
      !Number.isSafeInteger(a4.confirmed_map_nonzero_bytes) ||
      Number(a4.confirmed_map_nonzero_bytes) <= 0
    ) {
      throw new EvidenceError('A4 genuine ten-cycle coverage evidence missing');
    }
    if (typeof lock.tools !== 'object' || lock.tools === null || Array.isArray(lock.tools))
      throw new EvidenceError('Malformed locked tool inventory');
    const tools = Object.entries(lock.tools as Record<string, unknown>);
    if (tools.length < 3) throw new EvidenceError('Incomplete locked tool inventory');
    for (const [name, entry] of tools) {
      if (
        typeof entry !== 'object' ||
        entry === null ||
        typeof (entry as Record<string, unknown>).path !== 'string'
      )
        throw new EvidenceError(`Malformed tool lock: ${name}`);
      await compareFile(
        (entry as { path: string }).path,
        (entry as Record<string, unknown>).sha256,
        `${name} binary`,
      );
    }
    const binaryDir = path.dirname(input.harness);
    const parser = path.join(binaryDir, 'PdfFilter.dll');
    const mupdf = path.join(binaryDir, 'libmupdf.dll');
    await compareFile(input.harness, a4.harness_sha256, 'harness');
    await compareFile(parser, a4.pdf_filter_sha256, 'PDF parser');
    await compareFile(mupdf, a4.mupdf_sha256, 'MuPDF component');
    if (typeof a4.confirmed_log !== 'string')
      throw new EvidenceError('Missing raw instrumentation log path');
    const rawLog = a4.confirmed_log;
    await compareFile(rawLog, a4.confirmed_log_sha256, 'raw DynamoRIO log');
    const rawLogBytes = await readFile(rawLog);
    let observed: DebugEvidence;
    try {
      observed = inspectDebugLog(rawLogBytes, { expectedCycles: 10, requireNonzero: true });
    } catch (cause) {
      if (cause instanceof DebugLogError)
        throw new EvidenceError(`Invalid raw DynamoRIO instrumentation: ${cause.message}`, {
          cause,
        });
      throw cause;
    }
    if (
      observed.bitmap_nonzero_bytes !== a4.confirmed_map_nonzero_bytes ||
      JSON.stringify(observed.confirmed_coverage_modules) !== JSON.stringify(a4.confirmed_modules)
    )
      throw new EvidenceError('A4 manifest coverage does not match raw instrumentation');

    await regularFile(input.beforeStats);
    await regularFile(input.afterStats);
    await regularFile(path.join(input.runDir, 'fuzzer_stats'), input.runDir);
    const before = parseWinAflStats(await readFile(input.beforeStats, 'utf8'));
    const after = parseWinAflStats(await readFile(input.afterStats, 'utf8'));
    const final = parseWinAflStats(await readFile(path.join(input.runDir, 'fuzzer_stats'), 'utf8'));
    verifyProgress(before, after);
    if (final.execs_done < after.execs_done)
      throw new EvidenceError('Final execution counter is older than last snapshot');
    if (final.execs_done < 1000)
      throw new EvidenceError('WinAFL reference campaign has fewer than 1000 real executions');

    const metadata = await readJson(
      path.join(input.runDir, 'campaign-metadata.json'),
      input.runDir,
    );
    await compareFile(input.a4Manifest, metadata.a4_evidence_sha256, 'A4 evidence linkage');
    await compareFile(input.beforeStats, metadata.stats_initial, 'first WinAFL snapshot');
    await compareFile(input.afterStats, metadata.stats_later, 'second WinAFL snapshot');
    if (
      typeof metadata.start_utc !== 'string' ||
      typeof metadata.end_utc !== 'string' ||
      !/(?:Z|[+-]\d\d:\d\d)$/.test(metadata.start_utc) ||
      !/(?:Z|[+-]\d\d:\d\d)$/.test(metadata.end_utc)
    )
      throw new EvidenceError('Invalid campaign time range');
    const start = new Date(metadata.start_utc);
    const end = new Date(metadata.end_utc);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start)
      throw new EvidenceError('Invalid campaign time range');
    if (
      !Array.isArray(metadata.argv) ||
      metadata.argv.length < 3 ||
      !metadata.argv.every((value) => typeof value === 'string')
    )
      throw new EvidenceError('Missing executed WinAFL argument array');
    if (metadata.stop_reason !== 'bounded_limit_reached')
      throw new EvidenceError('Unrecognized or early campaign stop');

    const queueDir = path.join(input.runDir, 'queue');
    await rejectRedirectedPath(queueDir, input.runDir);
    const queueInfo = await lstat(queueDir).catch((cause) => {
      throw new EvidenceError('Queue directory missing', { cause });
    });
    if (!queueInfo.isDirectory() || queueInfo.isSymbolicLink())
      throw new EvidenceError('Unsafe queue directory');
    const queue: EvidenceManifest['queue'] = [];
    for (const name of (await readdir(queueDir)).sort()) {
      if (name.startsWith('.')) continue;
      const file = path.join(queueDir, name);
      await regularFile(file, input.runDir);
      const stat = await lstat(file);
      if (stat.isSymbolicLink() || !stat.isFile())
        throw new EvidenceError('Unsafe queued input file');
      queue.push({ name, sha256: await digest(file, input.runDir), bytes: stat.size });
    }
    if (queue.length === 0) throw new EvidenceError('No actual WinAFL queued input files');
    const crashes = await findingInventory(input.runDir, 'crashes', final.unique_crashes);
    const hangs = await findingInventory(input.runDir, 'hangs', final.unique_hangs);
    const binaryHashes: Record<string, string> = {
      harness: await digest(input.harness),
      'PdfFilter.dll': await digest(parser),
      'libmupdf.dll': await digest(mupdf),
    };
    for (const [name, entry] of tools)
      binaryHashes[name] = await digest((entry as { path: string }).path);
    const toolchainHash = await digest(input.toolchainLock);
    return {
      schema_version: 1,
      source_commit: PIN,
      start_utc: start.toISOString(),
      end_utc: end.toISOString(),
      command: metadata.argv as string[],
      stop_reason: 'bounded_limit_reached',
      toolchain_lock_sha256: toolchainHash,
      a4_manifest_sha256: await digest(input.a4Manifest),
      raw_debug_log_sha256: observed.sha256,
      confirmed_coverage_modules: a4.confirmed_modules as string[],
      metric_units: 'WinAFL execution counts and discovered paths; not source coverage percentage',
      metrics: final,
      first_snapshot: before,
      later_snapshot: after,
      queue,
      crashes,
      hangs,
      finding_counts: {
        crashes: {
          reported_in_stats: final.unique_crashes,
          saved_artifacts: crashes.length,
          additional_saved_artifacts: crashes.length - final.unique_crashes,
        },
        hangs: {
          reported_in_stats: final.unique_hangs,
          saved_artifacts: hangs.length,
          additional_saved_artifacts: hangs.length - final.unique_hangs,
        },
      },
      raw_stats_sha256: await digest(path.join(input.runDir, 'fuzzer_stats'), input.runDir),
      binary_hashes: binaryHashes,
    };
  } catch (cause) {
    if (cause instanceof EvidenceError) throw cause;
    if (cause instanceof StatsError)
      throw new EvidenceError(`Invalid WinAFL stats: ${cause.message}`, { cause });
    throw new EvidenceError('Could not verify campaign evidence', { cause });
  }
}
