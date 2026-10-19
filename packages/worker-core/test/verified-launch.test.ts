import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { WorkerError } from '@sumatrafuzz/worker-protocol';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ProcessError,
  rejectSpecialWindowsPath,
  verifyAndBuildLaunch,
  verifyFileProofs,
  verifyPathWithinRoot,
  WindowsJobSupervisor,
  type WorkerPolicy,
} from '../src/index.js';

const PIN = '16c59fde8b824ab54c56f23aef910a6fdd874ad0';
const dirs: string[] = [];
const digest = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');

async function writeFileWithHash(file: string, data: string): Promise<string> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, data);
  return digest(data);
}

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sumatrafuzz-core-'));
  dirs.push(root);
  const binaryRoot = path.join(root, 'binaries');
  const toolRoot = path.join(root, 'tools');
  const inputRoot = path.join(root, 'input');
  const outputRoot = path.join(root, 'output');
  const harnessPath = path.join(binaryRoot, 'sumatrafuzz-harness.exe');
  const harnessHash = await writeFileWithHash(harnessPath, 'fixture harness');
  const filterHash = await writeFileWithHash(
    path.join(binaryRoot, 'PdfFilter.dll'),
    'fixture filter',
  );
  const mupdfHash = await writeFileWithHash(path.join(binaryRoot, 'libmupdf.dll'), 'fixture mupdf');
  const drrunPath = path.join(toolRoot, 'drrun.exe');
  const aflPath = path.join(toolRoot, 'afl-fuzz.exe');
  const clientPath = path.join(toolRoot, 'winafl.dll');
  const drrunHash = await writeFileWithHash(drrunPath, 'fixture drrun');
  const aflHash = await writeFileWithHash(aflPath, 'fixture afl');
  const clientHash = await writeFileWithHash(clientPath, 'fixture client');
  await mkdir(path.join(inputRoot, 'approved-bundle'), { recursive: true });
  await writeFile(path.join(inputRoot, 'approved-bundle', 'seed.pdf'), '%PDF-1.4');
  await mkdir(outputRoot);
  const lock = JSON.stringify({
    source_commit: PIN,
    tools: {
      drrun: { path: drrunPath, sha256: drrunHash },
      afl_fuzz: { path: aflPath, sha256: aflHash },
      winafl_client: { path: clientPath, sha256: clientHash },
    },
  });
  const lockPath = path.join(root, 'target-lock.json');
  const lockHash = await writeFileWithHash(lockPath, lock);
  const a4 = JSON.stringify({
    target_commit: PIN,
    cycles: 10,
    confirmed_map_nonzero_bytes: 1,
    toolchain_lock_sha256: lockHash,
    harness_sha256: harnessHash,
    pdf_filter_sha256: filterHash,
    mupdf_sha256: mupdfHash,
    confirmed_modules: ['PdfFilter.dll', 'libmupdf.dll'],
  });
  const a4Path = path.join(root, 'a4-confirmed.json');
  const a4Hash = await writeFileWithHash(a4Path, a4);
  const limits = {
    max_duration_s: 60,
    max_memory_bytes: 268435456,
    max_disk_bytes: 536870912,
    max_cpu_percent: 75,
  };
  const policy: WorkerPolicy = {
    maxLimits: limits,
    pinnedTargetLockSha256: lockHash,
    pinnedA4ManifestSha256: a4Hash,
    targetLockPath: lockPath,
    a4ManifestPath: a4Path,
    harnessPath,
    allowedBinaryRoot: binaryRoot,
    allowedToolRoot: toolRoot,
    allowedInputRoot: inputRoot,
    outputRoot,
  };
  const request = {
    request_id: 'a11ce005-0000-4000-8000-000000000005',
    controller_id: 'a11ce006-0000-4000-8000-000000000006',
    input_bundle_id: 'approved-bundle',
    target_lock_sha256: lockHash,
    limits,
    label: 'fixture only',
  };
  return { policy, request, harnessPath, root };
}

afterEach(async () => {
  await Promise.all(
    dirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe('verified launch specification', () => {
  it('builds a frozen structured argv without spawning', async () => {
    const { policy, request, root } = await fixture();
    const spec = await verifyAndBuildLaunch(request, policy);
    const inputIndex = spec.argv.indexOf('-i');
    expect(spec.executable).toBe(await realpath(path.join(root, 'tools', 'afl-fuzz.exe')));
    expect(spec.argv.slice(inputIndex, inputIndex + 2)).toEqual([
      '-i',
      await realpath(path.join(root, 'input', 'approved-bundle')),
    ]);
    expect(spec.argv.slice(-2)).toEqual([expect.stringMatching(/sumatrafuzz-harness\.exe$/), '@@']);
    expect(Object.isFrozen(spec.argv)).toBe(true);
    expect(Object.isFrozen(spec.limits)).toBe(true);
    expect(spec.runId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('rejects a request that substitutes the administrator-pinned target lock digest', async () => {
    const { policy, request } = await fixture();
    await expect(
      verifyAndBuildLaunch({ ...request, target_lock_sha256: 'f'.repeat(64) }, policy),
    ).rejects.toMatchObject({ code: WorkerError.UnverifiedToolchain });
  });

  it('rejects a modified trusted harness', async () => {
    const { policy, request, harnessPath } = await fixture();
    await writeFile(harnessPath, 'changed harness');
    await expect(verifyAndBuildLaunch(request, policy)).rejects.toMatchObject({
      code: WorkerError.UnverifiedToolchain,
    });
  });

  it('rechecks trusted file proofs immediately before native launch', async () => {
    const { policy, request, harnessPath } = await fixture();
    const spec = await verifyAndBuildLaunch(request, policy);
    expect(spec.fileProofs.length).toBeGreaterThan(0);
    await writeFile(harnessPath, 'changed after policy verification');
    await expect(verifyFileProofs(spec.fileProofs)).rejects.toMatchObject({
      code: WorkerError.UnverifiedToolchain,
    });
  });

  it('does not call the native supervisor when a proof changes after specification creation', async () => {
    const { policy, request, harnessPath } = await fixture();
    const spec = await verifyAndBuildLaunch(request, policy);
    let launchCalled = false;
    const supervisor = new WindowsJobSupervisor({
      launchSuspended: () => {
        launchCalled = true;
        return { id: 'job', processId: 12 };
      },
      stopJob: () => ({
        jobId: 'job',
        stoppedAtUtc: new Date().toISOString(),
        remainingProcesses: 0,
        exitCode: 0,
        stopReason: 'requested',
      }),
      sampleJob: () => ({ cpu_percent: 0, memory_bytes: 0, process_count: 0 }),
      protectSecret: (value) => value,
      unprotectSecret: (value) => value,
    });
    await writeFile(harnessPath, 'changed before native launch');
    await expect(supervisor.launchSuspended(spec)).rejects.toBeInstanceOf(ProcessError);
    expect(launchCalled).toBe(false);
  });

  it('refuses to initialize the Windows native supervisor on another platform', () => {
    if (process.platform !== 'win32' || process.arch !== 'x64') {
      expect(() => new WindowsJobSupervisor()).toThrow(ProcessError);
    }
  });

  it('rejects a rewritten lock and matching forged A4 document', async () => {
    const { policy, request } = await fixture();
    const { readFile } = await import('node:fs/promises');
    const lock = JSON.parse(await readFile(policy.targetLockPath, 'utf8')) as Record<
      string,
      unknown
    >;
    lock.note = 'attacker repacked the lock';
    const lockBytes = JSON.stringify(lock);
    const newDigest = digest(lockBytes);
    await writeFile(policy.targetLockPath, lockBytes);
    const a4 = JSON.parse(await readFile(policy.a4ManifestPath, 'utf8')) as Record<string, unknown>;
    a4.toolchain_lock_sha256 = newDigest;
    await writeFile(policy.a4ManifestPath, JSON.stringify(a4));
    await expect(
      verifyAndBuildLaunch({ ...request, target_lock_sha256: newDigest }, policy),
    ).rejects.toMatchObject({ code: WorkerError.UnverifiedToolchain });
  });

  it('rejects an unadmitted bundle and policy limit overrun', async () => {
    const { policy, request } = await fixture();
    await expect(
      verifyAndBuildLaunch({ ...request, input_bundle_id: 'not-admitted' }, policy),
    ).rejects.toThrow();
    await expect(
      verifyAndBuildLaunch(
        { ...request, limits: { ...request.limits, max_cpu_percent: 76 } },
        policy,
      ),
    ).rejects.toMatchObject({ code: WorkerError.LimitExceeded });
    await expect(
      verifyAndBuildLaunch(
        {
          ...request,
          limits: { ...request.limits, max_disk_bytes: request.limits.max_disk_bytes - 1 },
        },
        policy,
      ),
    ).rejects.toMatchObject({ code: WorkerError.InvalidConfig });
  });

  it('rejects symlinked trusted paths', async () => {
    const { policy, request, root } = await fixture();
    const moved = path.join(root, 'real-binaries');
    await import('node:fs/promises').then(({ rename, symlink }) =>
      rename(policy.allowedBinaryRoot, moved).then(() =>
        symlink(moved, policy.allowedBinaryRoot, 'junction'),
      ),
    );
    await expect(verifyAndBuildLaunch(request, policy)).rejects.toMatchObject({
      code: WorkerError.UnverifiedToolchain,
    });
  });

  it('rejects an input bundle containing a symlinked seed', async () => {
    const { policy, request, root } = await fixture();
    const outside = path.join(root, 'outside.pdf');
    await writeFile(outside, '%PDF-1.4');
    await symlink(outside, path.join(policy.allowedInputRoot, 'approved-bundle', 'linked.pdf'));
    await expect(verifyAndBuildLaunch(request, policy)).rejects.toMatchObject({
      code: WorkerError.UnverifiedToolchain,
    });
  });

  it('rejects traversal and Windows device or network paths', async () => {
    const { policy } = await fixture();
    await expect(
      verifyPathWithinRoot(
        path.join(policy.allowedToolRoot, '..', 'outside.exe'),
        policy.allowedToolRoot,
      ),
    ).rejects.toMatchObject({ code: WorkerError.UnverifiedToolchain });
    expect(() => rejectSpecialWindowsPath('\\\\?\\C:\\Windows\\System32\\cmd.exe')).toThrow();
    expect(() => rejectSpecialWindowsPath('\\\\server\\share\\tool.exe')).toThrow();
  });
});
