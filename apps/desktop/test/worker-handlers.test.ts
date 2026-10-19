import type { WorkerClient } from '@sumatrafuzz/worker-client';
import type { RunStatus } from '@sumatrafuzz/worker-protocol';
import { describe, expect, it, vi } from 'vitest';
import { createWorkerDesktopHandlers } from '../src/main/worker-handlers.js';

const runId = '11111111-1111-4111-8111-111111111111';
const workerId = '22222222-2222-4222-8222-222222222222';

describe('desktop worker handlers', () => {
  it('forwards only validated IPC operations to the paired worker client', async () => {
    const client: WorkerClient = {
      capabilities: vi.fn<WorkerClient['capabilities']>(async () => ({
        worker_id: workerId,
        protocol_version: 1 as const,
        target_lock_sha256: 'a'.repeat(64),
        max_limits: {
          max_duration_s: 600,
          max_memory_bytes: 1024,
          max_disk_bytes: 2048,
          max_cpu_percent: 80,
        },
      })),
      startRun: vi.fn<WorkerClient['startRun']>(async () => ({
        run_id: runId,
        worker_id: workerId,
        state: 'running' as const,
        last_event_seq: 1n,
        stop_reason: null,
      })),
      getRun: vi.fn<WorkerClient['getRun']>(
        async (): Promise<RunStatus> => ({
          run_id: runId,
          worker_id: workerId,
          state: 'running',
          last_event_seq: 1n,
          stop_reason: null,
        }),
      ),
      stopRun: vi.fn<WorkerClient['stopRun']>(
        async (): Promise<RunStatus> => ({
          run_id: runId,
          worker_id: workerId,
          state: 'completed',
          last_event_seq: 2n,
          stop_reason: 'requested',
        }),
      ),
      eventsAfter: vi.fn(async () => []),
      close: vi.fn(),
    };
    const handlers = createWorkerDesktopHandlers(client);

    await expect(handlers.listWorkers()).resolves.toMatchObject([{ worker_id: workerId }]);
    await expect(
      handlers.startRun({
        request_id: '33333333-3333-4333-8333-333333333333' as never,
        controller_id: '44444444-4444-4444-8444-444444444444' as never,
        input_bundle_id: 'seed-set-1',
        target_lock_sha256: 'a'.repeat(64),
        limits: {
          max_duration_s: 60,
          max_memory_bytes: 1024,
          max_disk_bytes: 2048,
          max_cpu_percent: 50,
        },
        label: 'test',
      }),
    ).resolves.toMatchObject({ run_id: runId, state: 'running' });
    await expect(handlers.getRun(runId)).resolves.toMatchObject({ run_id: runId });
    await expect(handlers.stopRun(runId)).resolves.toMatchObject({ state: 'completed' });
    expect(client.capabilities).toHaveBeenCalledOnce();
    expect(client.startRun).toHaveBeenCalledOnce();
    expect(client.getRun).toHaveBeenCalledWith(runId);
    expect(client.stopRun).toHaveBeenCalledWith(runId);
  });
});
