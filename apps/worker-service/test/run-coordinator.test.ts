import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SqliteRunStore } from '@sumatrafuzz/run-store';
import type { VerifiedRunSpec, WorkerPolicy } from '@sumatrafuzz/worker-core';
import { asControllerId, validateRunRequest } from '@sumatrafuzz/worker-protocol';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WorkerRunCoordinator } from '../src/run-coordinator.js';

const controllerId = '11111111-1111-4111-8111-111111111111';
const otherController = '22222222-2222-4222-8222-222222222222';
const runId = '33333333-3333-4333-8333-333333333333';
const roots: string[] = [];

function request(requestId = '44444444-4444-4444-8444-444444444444') {
  return validateRunRequest({
    request_id: requestId,
    controller_id: controllerId,
    input_bundle_id: '55555555-5555-4555-8555-555555555555',
    target_lock_sha256: 'a'.repeat(64),
    limits: {
      max_duration_s: 60,
      max_memory_bytes: 1024 * 1024 * 1024,
      max_disk_bytes: 1024 * 1024 * 1024,
      max_cpu_percent: 50,
    },
    label: 'first run',
  });
}

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-coordinator-'));
  roots.push(root);
  const store = SqliteRunStore.open(path.join(root, 'worker.db'));
  const policy = {
    pinnedTargetLockSha256: 'a'.repeat(64),
    allowedInputRoot: path.join(root, 'inputs'),
    outputRoot: path.join(root, 'output'),
    maxLimits: request().limits,
  } as WorkerPolicy;
  const spec = { runId, evidenceDir: path.join(root, 'output', runId) } as VerifiedRunSpec;
  const verifyLaunch = vi.fn(async (_request: unknown, suppliedPolicy: WorkerPolicy) => {
    expect(suppliedPolicy.allowedInputRoot).toBe(path.join(root, 'inputs', controllerId));
    return spec;
  });
  const supervisor = {
    launchSuspended: vi.fn(async () => ({ id: 'job-1', processId: 1234 })),
    stopJob: vi.fn(async () => ({
      jobId: 'job-1',
      stoppedAtUtc: new Date().toISOString(),
      remainingProcesses: 0,
      exitCode: 0,
      stopReason: 'requested' as const,
    })),
    sampleJob: vi.fn(async () => ({ cpu_percent: 0, memory_bytes: 0, process_count: 1 })),
    sampleVolumeUsage: vi.fn(() => ({
      quota_bytes: 1024 * 1024 * 1024,
      available_bytes: 1024 * 1024 * 1024,
      used_bytes: 0,
      volume_id: '\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\',
    })),
  };
  const evidence = {
    finalize: vi.fn(async () => [
      {
        artifactId: 'artifact-1',
        sha256: 'b'.repeat(64),
        relativePath: 'fuzzer_stats',
        sizeBytes: 1,
      },
    ]),
    manifest: vi.fn(async () => ({ artifacts: [] })),
    artifactMetadata: vi.fn(async () => ({ etag: 'a'.repeat(64), totalBytes: 1 })),
    artifact: vi.fn(async () => ({
      etag: 'a'.repeat(64),
      totalBytes: 1,
      start: 0,
      end: 0,
      bytes: Buffer.from('x'),
    })),
  };
  const coordinatorConfig = {
    workerId: '66666666-6666-4666-8666-666666666666',
    store,
    policy,
    supervisor,
    evidence,
    measureWorkerVolumeUsedBytes: async () => 0,
    verifyLaunch,
  };
  const coordinator = new WorkerRunCoordinator(coordinatorConfig);
  return {
    coordinator,
    makeCoordinator: () => new WorkerRunCoordinator(coordinatorConfig),
    store,
    supervisor,
    evidence,
    verifyLaunch,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('worker run coordinator', () => {
  it('returns authenticated capabilities and only the caller-owned active run', async () => {
    const { coordinator, store } = await setup();

    await expect(coordinator.capabilities(controllerId)).resolves.toMatchObject({
      controller_id: controllerId,
      worker_id: '66666666-6666-4666-8666-666666666666',
    });
    await expect(coordinator.activeRun(controllerId)).resolves.toBeNull();

    await coordinator.startRun(controllerId, request());
    await expect(coordinator.activeRun(controllerId)).resolves.toMatchObject({
      run_id: runId,
      worker_id: '66666666-6666-4666-8666-666666666666',
      state: 'running',
    });
    await expect(coordinator.activeRun(otherController)).resolves.toBeNull();
    store.close();
  });

  it('claims one durable slot, replays the same command, and rejects a competing run', async () => {
    const { coordinator, store, supervisor, verifyLaunch } = await setup();
    const start = request();
    expect(await coordinator.startRun(controllerId, start)).toMatchObject({
      run_id: runId,
      state: 'running',
    });
    expect(await coordinator.startRun(controllerId, start)).toMatchObject({
      run_id: runId,
      state: 'running',
    });
    expect(verifyLaunch).toHaveBeenCalledTimes(1);
    expect(supervisor.launchSuspended).toHaveBeenCalledTimes(1);
    await expect(
      coordinator.startRun(controllerId, request('77777777-7777-4777-8777-777777777777')),
    ).rejects.toMatchObject({ status: 409 });
    expect(store.ownsRun(asControllerId(controllerId), runId as never)).toBe(true);
    store.close();
  });

  it('denies other controllers and releases the slot only after teardown and evidence finalization', async () => {
    const { coordinator, store, supervisor, evidence } = await setup();
    await coordinator.startRun(controllerId, request());
    await expect(coordinator.getRun(otherController, runId)).rejects.toMatchObject({ status: 404 });
    await expect(coordinator.eventsAfter(otherController, runId, '0', 10)).rejects.toMatchObject({
      status: 404,
    });
    await expect(coordinator.manifest(otherController, runId)).rejects.toMatchObject({
      status: 404,
    });
    const stopped = await coordinator.stopRun(controllerId, runId);
    expect(stopped).toMatchObject({ state: 'completed' });
    expect(supervisor.stopJob).toHaveBeenCalledOnce();
    expect(evidence.finalize).toHaveBeenCalledOnce();
    expect(store.readEventsAfter(runId as never, 0n, 10).map((event) => event.event_type)).toEqual([
      'state_changed',
      'state_changed',
      'state_changed',
      'process_teardown',
      'evidence_finalized',
      'state_changed',
    ]);
    expect(await coordinator.stopRun(controllerId, runId)).toEqual(stopped);
    store.close();
  });

  it('keeps the lease on teardown failure and retries from the stopping state', async () => {
    const { coordinator, store, supervisor } = await setup();
    await coordinator.startRun(controllerId, request());
    vi.mocked(supervisor.stopJob).mockRejectedValueOnce(new Error('temporary native failure'));
    await expect(coordinator.stopRun(controllerId, runId)).rejects.toThrow(/native failure/i);
    expect(store.runState(runId as never)).toBe('stopping');
    expect(store.readEventsAfter(runId as never, 0n, 10)).toHaveLength(3);

    expect(await coordinator.stopRun(controllerId, runId)).toMatchObject({ state: 'completed' });
    expect(supervisor.stopJob).toHaveBeenCalledTimes(2);
    expect(store.runState(runId as never)).toBe('completed');
    store.close();
  });

  it('rejects a memory limit below native bounds before claiming the worker slot', async () => {
    const { coordinator, store, verifyLaunch } = await setup();
    const invalid = {
      ...request(),
      limits: { ...request().limits, max_memory_bytes: 1024 },
    } as ReturnType<typeof request>;

    await expect(coordinator.startRun(controllerId, invalid)).rejects.toThrow(/invalid_config/i);
    await expect(
      coordinator.startRun(controllerId, {
        ...request(),
        limits: { ...request().limits, max_disk_bytes: request().limits.max_disk_bytes - 1 },
      }),
    ).rejects.toThrow(/invalid_config/i);
    expect(verifyLaunch).not.toHaveBeenCalled();
    expect(store.activeRunSnapshot()).toBeNull();
    store.close();
  });

  it('attempts native teardown when the first stopping-state journal write fails', async () => {
    const { coordinator, store, supervisor } = await setup();
    await coordinator.startRun(controllerId, request());
    const transition = vi.spyOn(store, 'transitionState').mockImplementationOnce(() => {
      throw new Error('temporary journal failure');
    });

    await expect(coordinator.stopRun(controllerId, runId)).resolves.toMatchObject({
      state: 'completed',
    });
    expect(supervisor.stopJob).toHaveBeenCalledOnce();
    expect(store.activeRunSnapshot()).toBeNull();
    expect(transition).toHaveBeenCalledTimes(2);
    transition.mockRestore();
    store.close();
  });

  it('finishes journaled teardown after a service restart without relaunching the run', async () => {
    const { coordinator, makeCoordinator, store, supervisor } = await setup();
    await coordinator.startRun(controllerId, request());
    store.transitionState(runId as never, 'running', 'stopping', 'state_changed');
    store.recordTeardownReceipt(runId as never, {
      jobId: 'job-1',
      stoppedAtUtc: new Date().toISOString(),
      remainingProcesses: 0,
      exitCode: 0,
      stopReason: 'time_limit',
    });

    const restarted = makeCoordinator();
    await expect(restarted.reconcileStartup()).resolves.toBe('finalized_after_restart');
    expect(await restarted.getRun(controllerId, runId)).toMatchObject({
      state: 'completed',
      stop_reason: 'time_limit',
    });
    expect(supervisor.stopJob).not.toHaveBeenCalled();
    store.close();
  });

  it('holds an active lease after restart when no durable teardown receipt exists', async () => {
    const { coordinator, makeCoordinator, store } = await setup();
    await coordinator.startRun(controllerId, request());
    await expect(makeCoordinator().reconcileStartup()).resolves.toBe('lease_held_for_operator');
    expect(store.runState(runId as never)).toBe('running');
    expect(
      store.claimWorkerSlot(
        asControllerId(otherController),
        '88888888-8888-4888-8888-888888888888',
        'd'.repeat(64),
        '99999999-9999-4999-8999-999999999999' as never,
      ),
    ).toEqual({ kind: 'worker_busy' });
    store.close();
  });

  it('records unexpected process exit as a failed run while retaining its evidence', async () => {
    const { coordinator, store } = await setup();
    await coordinator.startRun(controllerId, request());
    expect(await coordinator.stopRun(controllerId, runId, 'native_exit')).toMatchObject({
      state: 'failed',
      stop_reason: 'native_exit',
    });
    expect(store.finalArtifacts(runId as never)).toHaveLength(1);
    store.close();
  });
});
