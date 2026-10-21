import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SqliteRunStore } from '@sumatrafuzz/run-store';
import { asControllerId, asRunId } from '@sumatrafuzz/worker-protocol';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WorkerQuotaMonitor } from '../src/quota-monitor.js';

const roots: string[] = [];
const runId = asRunId('33333333-3333-4333-8333-333333333333');
const controllerId = '11111111-1111-4111-8111-111111111111';

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-quota-'));
  roots.push(root);
  const store = SqliteRunStore.open(path.join(root, 'worker.db'));
  store.claimWorkerSlot(
    asControllerId(controllerId),
    '44444444-4444-4444-8444-444444444444',
    'a'.repeat(64),
    runId,
  );
  store.transitionState(runId, 'created', 'preparing', 'state_changed');
  store.transitionState(runId, 'preparing', 'running', 'state_changed');
  return store;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('worker quota monitor', () => {
  it('journals measured usage and stops at the provisioned disk quota', async () => {
    const store = await setup();
    const stopRun = vi.fn(async () => {});
    const monitor = new WorkerQuotaMonitor({
      store,
      sampleJob: async () => ({ cpu_percent: 12, memory_bytes: 32, process_count: 1 }),
      measureWorkerVolumeUsedBytes: async () => 100,
      stopRun,
      intervalMs: 60_000,
      now: () => Date.parse('2026-10-19T12:00:00.000Z'),
    });
    monitor.start(
      runId,
      controllerId,
      { id: 'job-1', processId: 1234 },
      {
        runId,
        executable: 'unused',
        argv: [],
        workingDir: 'unused',
        evidenceDir: 'unused',
        fileProofs: [],
        limits: {
          max_duration_s: 60,
          max_memory_bytes: 1024,
          max_disk_bytes: 100,
          max_cpu_percent: 80,
        },
      },
    );

    await expect(monitor.sampleOnce(runId)).resolves.toBe('disk_limit');
    expect(stopRun).toHaveBeenCalledWith(controllerId, runId, 'disk_limit');
    expect(store.readEventsAfter(runId, 2n, 2)).toEqual([
      expect.objectContaining({
        seq: 3n,
        event_type: 'metric_sample',
        payload: expect.objectContaining({ disk_bytes: 100, process_count: 1 }),
      }),
    ]);
    await monitor.sampleOnce(runId);
    expect(stopRun).toHaveBeenCalledOnce();
    monitor.stop(runId);
    store.close();
  });

  it('fails closed when the provisioned quota source cannot be read', async () => {
    const store = await setup();
    const stopRun = vi.fn(async () => {});
    const monitor = new WorkerQuotaMonitor({
      store,
      sampleJob: async () => ({ cpu_percent: 1, memory_bytes: 1, process_count: 1 }),
      measureWorkerVolumeUsedBytes: async () => {
        throw new Error('quota source unavailable');
      },
      stopRun,
      intervalMs: 60_000,
    });
    monitor.start(
      runId,
      controllerId,
      { id: 'job-1', processId: 1234 },
      {
        runId,
        executable: 'unused',
        argv: [],
        workingDir: 'unused',
        evidenceDir: 'unused',
        fileProofs: [],
        limits: {
          max_duration_s: 60,
          max_memory_bytes: 1024,
          max_disk_bytes: 1024,
          max_cpu_percent: 80,
        },
      },
    );
    await expect(monitor.sampleOnce(runId)).rejects.toThrow(/quota source/i);
    expect(stopRun).toHaveBeenCalledWith(controllerId, runId, 'process_failure');
    monitor.stop(runId);
    store.close();
  });

  it('retries threshold stop after a transient journal or teardown failure', async () => {
    const store = await setup();
    const stopRun = vi.fn().mockRejectedValueOnce(new Error('temporary journal failure'));
    stopRun.mockResolvedValue(undefined);
    const monitor = new WorkerQuotaMonitor({
      store,
      sampleJob: async () => ({ cpu_percent: 1, memory_bytes: 1024, process_count: 1 }),
      measureWorkerVolumeUsedBytes: async () => 1,
      stopRun,
      intervalMs: 60_000,
      now: () => Date.parse('2026-10-19T12:00:00.000Z'),
    });
    monitor.start(
      runId,
      controllerId,
      { id: 'job-1', processId: 1234 },
      {
        runId,
        executable: 'unused',
        argv: [],
        workingDir: 'unused',
        evidenceDir: 'unused',
        fileProofs: [],
        limits: {
          max_duration_s: 60,
          max_memory_bytes: 1024,
          max_disk_bytes: 100,
          max_cpu_percent: 80,
        },
      },
    );

    await expect(monitor.sampleOnce(runId)).rejects.toThrow(/journal failure/i);
    await expect(monitor.sampleOnce(runId)).resolves.toBe('memory_limit');
    expect(stopRun).toHaveBeenCalledTimes(2);
    monitor.stop(runId);
    store.close();
  });
});
