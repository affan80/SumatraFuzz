import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SqliteRunStore } from '@sumatrafuzz/run-store';
import { asControllerId, asRunId } from '@sumatrafuzz/worker-protocol';
import { afterEach, describe, expect, it } from 'vitest';
import { FileEvidenceRepository } from '../src/artifacts.js';

const roots: string[] = [];
const runId = asRunId('33333333-3333-4333-8333-333333333333');

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-artifacts-'));
  roots.push(root);
  const output = path.join(root, 'runs');
  await mkdir(output);
  const run = path.join(output, runId);
  await mkdir(run);
  const store = SqliteRunStore.open(path.join(root, 'worker.db'));
  store.claimWorkerSlot(
    asControllerId('11111111-1111-4111-8111-111111111111'),
    '44444444-4444-4444-8444-444444444444',
    'a'.repeat(64),
    runId,
  );
  store.transitionState(runId, 'created', 'preparing', 'state_changed');
  store.transitionState(runId, 'preparing', 'running', 'state_changed');
  store.transitionState(runId, 'running', 'stopping', 'state_changed');
  return { root, run, store, evidence: new FileEvidenceRepository(store, output, 1024 * 1024) };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('finalized worker evidence', () => {
  it('indexes verified files and refuses changed bytes during resumable download', async () => {
    const { run, store, evidence } = await setup();
    await writeFile(path.join(run, 'fuzzer_stats'), 'execs_done : 2\n');
    const artifacts = await evidence.finalize(runId, run);
    const receipt = {
      jobId: 'job-1',
      stoppedAtUtc: new Date().toISOString(),
      remainingProcesses: 0,
      exitCode: 0,
      stopReason: 'requested' as const,
    };
    store.recordTeardownReceipt(runId, receipt);
    store.finalizeAfterTeardown(runId, 'completed', artifacts, receipt);
    const manifest = (await evidence.manifest(runId)) as {
      revision: string;
      artifacts: Array<{ artifact_id: string; sha256: string; size_bytes: number }>;
    };
    expect(manifest.revision).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.artifacts).toHaveLength(1);
    const artifact = manifest.artifacts[0];
    if (!artifact) throw new Error('fixture artifact missing');
    const artifactId = artifact.artifact_id;
    expect(await evidence.artifactMetadata(runId, artifactId)).toEqual({
      etag: artifact.sha256,
      totalBytes: artifact.size_bytes,
    });
    expect(
      (await evidence.artifact(runId, artifactId, { start: 0, end: 4 })).bytes.toString(),
    ).toBe('execs');
    await writeFile(path.join(run, 'fuzzer_stats'), 'execs_done : 3\n');
    await expect(evidence.artifact(runId, artifactId, { start: 0, end: 4 })).rejects.toThrow(
      /hash/i,
    );
    store.close();
  });

  it('rejects a symlink in the evidence tree before publishing any artifact', async () => {
    const { root, run, store, evidence } = await setup();
    await writeFile(path.join(run, 'fuzzer_stats'), 'execs_done : 2\n');
    await symlink(path.join(root, 'worker.db'), path.join(run, 'leak'));
    await expect(evidence.finalize(runId, run)).rejects.toThrow(/redirected|untrusted/i);
    expect(store.finalArtifacts(runId)).toEqual([]);
    store.close();
  });
});
