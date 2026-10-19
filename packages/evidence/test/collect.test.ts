import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { collectEvidence, EvidenceError, findingInventory } from '../src/collect.js';

const PIN = '16c59fde8b824ab54c56f23aef910a6fdd874ad0';
const digest = (value: Buffer | string) => createHash('sha256').update(value).digest('hex');
const roots: string[] = [];

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'Sumatra Fuzz A6 spaces '));
  roots.push(root);
  const run = path.join(root, 'campaign');
  const queue = path.join(run, 'queue');
  await mkdir(queue, { recursive: true });
  await writeFile(path.join(queue, 'id_000000'), '%PDF-1.4');
  await writeFile(
    path.join(run, 'fuzzer_stats'),
    'execs_done: 2000\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n',
  );
  const before = path.join(root, 'before.stats');
  const after = path.join(root, 'after.stats');
  const stats0 = 'execs_done: 900\npaths_total: 1\nunique_crashes: 0\nunique_hangs: 0\n';
  const stats1 = 'execs_done: 2000\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n';
  await writeFile(before, stats0);
  await writeFile(after, stats1);
  const files = new Map<string, Buffer>([
    ['harness.exe', Buffer.from('harness')],
    ['PdfFilter.dll', Buffer.from('filter')],
    ['libmupdf.dll', Buffer.from('mupdf')],
    ['drrun.exe', Buffer.from('drrun')],
    ['winafl.dll', Buffer.from('client')],
    ['afl-fuzz.exe', Buffer.from('afl')],
  ]);
  const getBytes = (name: string): Buffer => {
    const bytes = files.get(name);
    if (!bytes) throw new Error(`missing fixture file: ${name}`);
    return bytes;
  };
  for (const [name, bytes] of files) await writeFile(path.join(root, name), bytes);
  const lockPath = path.join(root, 'target-lock.json');
  const lock = {
    source_commit: PIN,
    tools: Object.fromEntries(
      ['drrun.exe', 'winafl.dll', 'afl-fuzz.exe'].map((name) => [
        name,
        { path: path.join(root, name), sha256: digest(getBytes(name)) },
      ]),
    ),
  };
  await writeFile(lockPath, JSON.stringify(lock));
  const logPath = path.join(root, 'debug-proc.log');
  const prefix = Buffer.from(
    `Module loaded, PdfFilter.dll\nModule loaded, libmupdf.dll\n${'In pre_fuzz_handler\nIn post_fuzz_handler\n'.repeat(10)}Everything appears to be running normally.\nCoverage map follows:\n`,
  );
  const log = Buffer.concat([prefix, Buffer.alloc(65536, 1)]);
  await writeFile(logPath, log);
  const a4Path = path.join(root, 'a4.json');
  await writeFile(
    a4Path,
    JSON.stringify({
      target_commit: PIN,
      cycles: 10,
      confirmed_modules: ['PdfFilter.dll', 'libmupdf.dll'],
      confirmed_map_nonzero_bytes: 65536,
      harness_sha256: digest(getBytes('harness.exe')),
      pdf_filter_sha256: digest(getBytes('PdfFilter.dll')),
      mupdf_sha256: digest(getBytes('libmupdf.dll')),
      toolchain_lock_sha256: digest(
        await import('node:fs/promises').then(({ readFile }) => readFile(lockPath)),
      ),
      confirmed_log: logPath,
      confirmed_log_sha256: digest(log),
    }),
  );
  const metadata = {
    start_utc: '2026-10-10T00:00:00+00:00',
    end_utc: '2026-10-10T00:03:00+00:00',
    stop_reason: 'bounded_limit_reached',
    argv: ['afl-fuzz.exe', '-i', 'seeds', '--', '@@'],
    a4_evidence_sha256: digest(
      await import('node:fs/promises').then(({ readFile }) => readFile(a4Path)),
    ),
    stats_initial: digest(stats0),
    stats_later: digest(stats1),
  };
  await writeFile(path.join(run, 'campaign-metadata.json'), JSON.stringify(metadata));
  return {
    root,
    run,
    lockPath,
    a4Path,
    logPath,
    harness: path.join(root, 'harness.exe'),
    before,
    after,
  };
}

async function repinManifest(input: Awaited<ReturnType<typeof fixture>>) {
  const metadataPath = path.join(input.run, 'campaign-metadata.json');
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as Record<string, unknown>;
  metadata.a4_evidence_sha256 = digest(await readFile(input.a4Path));
  await writeFile(metadataPath, JSON.stringify(metadata));
}

afterEach(async () =>
  Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))),
);

describe('A6 evidence collection', () => {
  it('validates provenance, measured stats, and actual queued input', async () => {
    const input = await fixture();
    const evidence = await collectEvidence({
      runDir: input.run,
      toolchainLock: input.lockPath,
      a4Manifest: input.a4Path,
      harness: input.harness,
      beforeStats: input.before,
      afterStats: input.after,
    });
    expect(evidence.metrics.execs_done).toBe(2000);
    expect(evidence.queue).toHaveLength(1);
    expect(evidence.command[0]).toBe('afl-fuzz.exe');
    expect(evidence.crashes).toEqual([]);
  });
  it('rejects a modified trusted binary', async () => {
    const input = await fixture();
    await writeFile(input.harness, 'modified');
    await expect(
      collectEvidence({
        runDir: input.run,
        toolchainLock: input.lockPath,
        a4Manifest: input.a4Path,
        harness: input.harness,
        beforeStats: input.before,
        afterStats: input.after,
      }),
    ).rejects.toBeInstanceOf(EvidenceError);
  });
  it('rejects a self-hashed narrative-only debug log and A4 map mismatch', async () => {
    const input = await fixture();
    await writeFile(input.logPath, 'claimed ten cycles without actual WinAFL records');
    const a4 = JSON.parse(await readFile(input.a4Path, 'utf8')) as Record<string, unknown>;
    a4.confirmed_log_sha256 = digest(await readFile(input.logPath));
    await writeFile(input.a4Path, JSON.stringify(a4));
    await repinManifest(input);
    const args = {
      runDir: input.run,
      toolchainLock: input.lockPath,
      a4Manifest: input.a4Path,
      harness: input.harness,
      beforeStats: input.before,
      afterStats: input.after,
    };
    await expect(collectEvidence(args)).rejects.toThrow(/instrumentation/);

    const fresh = await fixture();
    const mismatch = JSON.parse(await readFile(fresh.a4Path, 'utf8')) as Record<string, unknown>;
    mismatch.confirmed_map_nonzero_bytes = 1;
    await writeFile(fresh.a4Path, JSON.stringify(mismatch));
    await repinManifest(fresh);
    await expect(
      collectEvidence({
        runDir: fresh.run,
        toolchainLock: fresh.lockPath,
        a4Manifest: fresh.a4Path,
        harness: fresh.harness,
        beforeStats: fresh.before,
        afterStats: fresh.after,
      }),
    ).rejects.toThrow(/coverage/);
  });
  it('retains saved findings beyond periodic counters as untriaged evidence', async () => {
    const input = await fixture();
    const newer = 'execs_done: 2000\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 1\n';
    await writeFile(input.after, newer);
    await writeFile(path.join(input.run, 'fuzzer_stats'), newer);
    const metadataPath = path.join(input.run, 'campaign-metadata.json');
    const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as Record<string, unknown>;
    metadata.stats_later = digest(newer);
    await writeFile(metadataPath, JSON.stringify(metadata));
    const hangs = path.join(input.run, 'hangs');
    await mkdir(hangs);
    await writeFile(path.join(hangs, 'id_000001'), 'observed hang sample');
    await writeFile(path.join(hangs, 'id_000002'), 'additional flushed sample');
    const evidence = await collectEvidence({
      runDir: input.run,
      toolchainLock: input.lockPath,
      a4Manifest: input.a4Path,
      harness: input.harness,
      beforeStats: input.before,
      afterStats: input.after,
    });
    expect(evidence.hangs).toHaveLength(2);
    expect(evidence.hangs[0]?.classification).toBe('untriaged');
    expect(evidence.finding_counts.hangs).toEqual({
      reported_in_stats: 1,
      saved_artifacts: 2,
      additional_saved_artifacts: 1,
    });
  });
  it('inventories only genuine id_ finding files and refuses symlink samples', async () => {
    const input = await fixture();
    const hangs = path.join(input.run, 'hangs');
    await mkdir(hangs);
    await writeFile(path.join(hangs, 'README.txt'), 'not a finding');
    await writeFile(path.join(hangs, 'id_000001'), 'hang sample');
    const values = await findingInventory(input.run, 'hangs', 0);
    expect(values.map((value) => value.path)).toEqual(['hangs/id_000001']);
    await rm(path.join(hangs, 'id_000001'));
    await symlink(input.harness, path.join(hangs, 'id_000001'));
    await expect(findingInventory(input.run, 'hangs', 0)).rejects.toBeInstanceOf(EvidenceError);
  });
});
