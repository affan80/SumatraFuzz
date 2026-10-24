import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import {
  asRunId,
  type CampaignLimits,
  MIN_CAMPAIGN_MEMORY_BYTES,
  type RunRequest,
  validateRunRequest,
  WorkerError,
  WorkerProtocolError,
} from '@sumatrafuzz/worker-protocol';
import { toOrdinaryWindowsPath, verifyPathWithinRoot } from './path-verification.js';
import type { VerifiedFile, VerifiedRunSpec, WorkerPolicy } from './policy.js';

const PINNED_SOURCE = '16c59fde8b824ab54c56f23aef910a6fdd874ad0';
const DEFAULT_TIMEOUT_MS = '20000';
const PERSISTENT_ITERATIONS = '1000';
const MAX_JSON_BYTES = 1024 * 1024;

interface LockedTool {
  path: string;
  sha256: string;
}

interface TargetLock {
  source_commit: string;
  tools: {
    drrun: LockedTool;
    afl_fuzz: LockedTool;
    winafl_client: LockedTool;
  };
  runtime_dependencies?: LockedTool[];
}

interface A4Manifest {
  target_commit: string;
  cycles: number;
  confirmed_map_nonzero_bytes: number;
  toolchain_lock_sha256: string;
  harness_sha256: string;
  pdf_filter_sha256: string;
  mupdf_sha256: string;
  confirmed_modules: string[];
}

function fail(code: (typeof WorkerError)[keyof typeof WorkerError]): never {
  throw new WorkerProtocolError(code);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function parseTargetLock(value: unknown): TargetLock {
  if (typeof value !== 'object' || value === null) return fail(WorkerError.UnverifiedToolchain);
  const record = value as Partial<TargetLock>;
  if (record.source_commit !== PINNED_SOURCE || typeof record.tools !== 'object' || !record.tools) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  for (const name of ['drrun', 'afl_fuzz', 'winafl_client'] as const) {
    const tool = record.tools[name];
    if (
      !tool ||
      typeof tool.path !== 'string' ||
      !path.isAbsolute(tool.path) ||
      !isSha256(tool.sha256)
    ) {
      return fail(WorkerError.UnverifiedToolchain);
    }
  }
  if (record.runtime_dependencies !== undefined) {
    if (!Array.isArray(record.runtime_dependencies) || record.runtime_dependencies.length > 32) {
      return fail(WorkerError.UnverifiedToolchain);
    }
    for (const dependency of record.runtime_dependencies) {
      if (
        !dependency ||
        typeof dependency.path !== 'string' ||
        !path.isAbsolute(dependency.path) ||
        !isSha256(dependency.sha256)
      ) {
        return fail(WorkerError.UnverifiedToolchain);
      }
    }
  }
  return record as TargetLock;
}

function parseA4Manifest(value: unknown): A4Manifest {
  if (typeof value !== 'object' || value === null) return fail(WorkerError.UnverifiedToolchain);
  const record = value as Partial<A4Manifest>;
  if (
    record.target_commit !== PINNED_SOURCE ||
    !Number.isInteger(record.cycles) ||
    (record.cycles ?? 0) < 10 ||
    !Number.isSafeInteger(record.confirmed_map_nonzero_bytes) ||
    (record.confirmed_map_nonzero_bytes ?? 0) <= 0 ||
    !isSha256(record.toolchain_lock_sha256) ||
    !isSha256(record.harness_sha256) ||
    !isSha256(record.pdf_filter_sha256) ||
    !isSha256(record.mupdf_sha256) ||
    !Array.isArray(record.confirmed_modules) ||
    record.confirmed_modules.length < 1 ||
    record.confirmed_modules.length > 8
  ) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  const unique = new Set<string>();
  for (const moduleName of record.confirmed_modules) {
    if (
      typeof moduleName !== 'string' ||
      moduleName.length > 128 ||
      !/^[A-Za-z0-9_.-]+\.dll$/i.test(moduleName) ||
      unique.has(moduleName.toLowerCase())
    ) {
      return fail(WorkerError.UnverifiedToolchain);
    }
    unique.add(moduleName.toLowerCase());
  }
  return record as A4Manifest;
}

async function sha256File(filePath: string): Promise<string> {
  const metadata = await stat(filePath).catch(() => fail(WorkerError.UnverifiedToolchain));
  if (!metadata.isFile() || metadata.size > 2 ** 40) return fail(WorkerError.UnverifiedToolchain);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk as Buffer);
  }
  return hash.digest('hex');
}

async function verifyFile(
  filePath: string,
  root: string,
  expectedHash: string,
): Promise<VerifiedFile> {
  if (!isSha256(expectedHash)) return fail(WorkerError.UnverifiedToolchain);
  const verifiedPath = await verifyPathWithinRoot(filePath, root);
  if ((await sha256File(verifiedPath)).toLowerCase() !== expectedHash.toLowerCase()) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  return Object.freeze({
    path: verifiedPath,
    root: await realpath(root),
    sha256: expectedHash.toLowerCase(),
  });
}

export async function verifyFileProofs(proofs: readonly VerifiedFile[]): Promise<void> {
  for (const proof of proofs) {
    const verifiedPath = await verifyPathWithinRoot(proof.path, proof.root);
    if ((await sha256File(verifiedPath)).toLowerCase() !== proof.sha256.toLowerCase()) {
      return fail(WorkerError.UnverifiedToolchain);
    }
  }
}

async function readBoundedJson(filePath: string): Promise<unknown> {
  const metadata = await lstat(filePath).catch(() => fail(WorkerError.UnverifiedToolchain));
  if (!metadata.isFile() || metadata.size > MAX_JSON_BYTES)
    return fail(WorkerError.UnverifiedToolchain);
  try {
    return JSON.parse(await readFile(filePath, 'utf8')) as unknown;
  } catch {
    return fail(WorkerError.UnverifiedToolchain);
  }
}

function validateLimits(request: CampaignLimits, ceilings: CampaignLimits): void {
  if (request.max_memory_bytes < MIN_CAMPAIGN_MEMORY_BYTES) fail(WorkerError.InvalidConfig);
  if (request.max_disk_bytes !== ceilings.max_disk_bytes) fail(WorkerError.InvalidConfig);
  if (
    request.max_duration_s > ceilings.max_duration_s ||
    request.max_memory_bytes > ceilings.max_memory_bytes ||
    request.max_disk_bytes > ceilings.max_disk_bytes ||
    request.max_cpu_percent > ceilings.max_cpu_percent
  ) {
    fail(WorkerError.LimitExceeded);
  }
}

async function checkOutputRoot(root: string): Promise<string> {
  const resolved = path.resolve(root);
  const parent = path.dirname(resolved);
  const base = path.basename(resolved);
  const realParent = await verifyPathWithinRoot(parent, parent, { allowRoot: true });
  const finalRoot = path.join(realParent, base);
  const metadata = await lstat(finalRoot).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined;
    return fail(WorkerError.UnverifiedToolchain);
  });
  if (metadata && (metadata.isSymbolicLink() || !metadata.isDirectory())) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  return finalRoot;
}

async function verifyInputTree(root: string): Promise<void> {
  const entries = await readdir(root, { withFileTypes: true }).catch(() =>
    fail(WorkerError.InvalidConfig),
  );
  for (const entry of entries) {
    if (entry.isSymbolicLink()) return fail(WorkerError.UnverifiedToolchain);
    const child = path.join(root, entry.name);
    const metadata = await lstat(child).catch(() => fail(WorkerError.UnverifiedToolchain));
    if (metadata.isSymbolicLink()) return fail(WorkerError.UnverifiedToolchain);
    if (metadata.isDirectory()) await verifyInputTree(child);
    else if (!metadata.isFile()) return fail(WorkerError.UnverifiedToolchain);
  }
}

export async function verifyAndBuildLaunch(
  untrustedRequest: unknown,
  policy: WorkerPolicy,
): Promise<VerifiedRunSpec> {
  const request: RunRequest = validateRunRequest(untrustedRequest);
  validateLimits(request.limits, policy.maxLimits);
  if (!isSha256(policy.pinnedTargetLockSha256) || !isSha256(policy.pinnedA4ManifestSha256)) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  if (request.target_lock_sha256.toLowerCase() !== policy.pinnedTargetLockSha256.toLowerCase()) {
    return fail(WorkerError.UnverifiedToolchain);
  }

  const lockRoot = path.dirname(policy.targetLockPath);
  const a4Root = path.dirname(policy.a4ManifestPath);
  const lockProof = await verifyFile(
    policy.targetLockPath,
    lockRoot,
    policy.pinnedTargetLockSha256,
  );
  const a4Proof = await verifyFile(policy.a4ManifestPath, a4Root, policy.pinnedA4ManifestSha256);
  const lockPath = lockProof.path;
  const a4Path = a4Proof.path;
  if ((await sha256File(lockPath)).toLowerCase() !== policy.pinnedTargetLockSha256.toLowerCase()) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  if ((await sha256File(a4Path)).toLowerCase() !== policy.pinnedA4ManifestSha256.toLowerCase()) {
    return fail(WorkerError.UnverifiedToolchain);
  }
  const lock = parseTargetLock(await readBoundedJson(lockPath));
  const a4 = parseA4Manifest(await readBoundedJson(a4Path));
  if (a4.toolchain_lock_sha256.toLowerCase() !== policy.pinnedTargetLockSha256.toLowerCase()) {
    return fail(WorkerError.UnverifiedToolchain);
  }

  const harnessProof = await verifyFile(
    policy.harnessPath,
    policy.allowedBinaryRoot,
    a4.harness_sha256,
  );
  const filterProof = await verifyFile(
    path.join(path.dirname(policy.harnessPath), 'PdfFilter.dll'),
    policy.allowedBinaryRoot,
    a4.pdf_filter_sha256,
  );
  const mupdfProof = await verifyFile(
    path.join(path.dirname(policy.harnessPath), 'libmupdf.dll'),
    policy.allowedBinaryRoot,
    a4.mupdf_sha256,
  );
  const aflProof = await verifyFile(
    lock.tools.afl_fuzz.path,
    policy.allowedToolRoot,
    lock.tools.afl_fuzz.sha256,
  );
  const drrunProof = await verifyFile(
    lock.tools.drrun.path,
    policy.allowedToolRoot,
    lock.tools.drrun.sha256,
  );
  const clientProof = await verifyFile(
    lock.tools.winafl_client.path,
    policy.allowedToolRoot,
    lock.tools.winafl_client.sha256,
  );
  const runtimeProofs = await Promise.all(
    (lock.runtime_dependencies ?? []).map((dependency) =>
      verifyFile(dependency.path, policy.allowedToolRoot, dependency.sha256),
    ),
  );
  const input = await verifyPathWithinRoot(
    path.join(policy.allowedInputRoot, request.input_bundle_id),
    policy.allowedInputRoot,
  );
  if (
    !(await stat(input)
      .then((info) => info.isDirectory())
      .catch(() => false))
  ) {
    return fail(WorkerError.InvalidConfig);
  }
  await verifyInputTree(input);
  const outputRoot = await checkOutputRoot(policy.outputRoot);
  const runId = asRunId(randomUUID());
  const evidenceDir = path.join(outputRoot, runId);
  if (
    await lstat(evidenceDir)
      .then(() => true)
      .catch(() => false)
  )
    return fail(WorkerError.InvalidConfig);
  const argv = [
    '-i',
    toOrdinaryWindowsPath(input),
    '-o',
    toOrdinaryWindowsPath(evidenceDir),
    '-D',
    toOrdinaryWindowsPath(path.dirname(drrunProof.path)),
    '-w',
    toOrdinaryWindowsPath(clientProof.path),
    '-t',
    DEFAULT_TIMEOUT_MS,
    '--',
    '-covtype',
    'edge',
  ];
  for (const moduleName of a4.confirmed_modules) argv.push('-coverage_module', moduleName);
  argv.push(
    '-target_module',
    path.basename(harnessProof.path),
    '-target_method',
    'fuzz_one_file',
    '-fuzz_iterations',
    PERSISTENT_ITERATIONS,
    '-nargs',
    '1',
    '--',
    toOrdinaryWindowsPath(harnessProof.path),
    '@@',
  );

  return Object.freeze({
    runId,
    executable: toOrdinaryWindowsPath(aflProof.path),
    argv: Object.freeze(argv),
    workingDir: toOrdinaryWindowsPath(outputRoot),
    limits: Object.freeze({ ...request.limits }),
    evidenceDir: toOrdinaryWindowsPath(evidenceDir),
    fileProofs: Object.freeze([
      lockProof,
      a4Proof,
      harnessProof,
      filterProof,
      mupdfProof,
      aflProof,
      drrunProof,
      clientProof,
      ...runtimeProofs,
    ]),
  });
}
