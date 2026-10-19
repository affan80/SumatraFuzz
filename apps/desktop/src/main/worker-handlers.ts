import type { WorkerClient } from '@sumatrafuzz/worker-client';
import type { DesktopIpcHandlers } from './ipc.js';

export interface DesktopWorkerHandlers extends DesktopIpcHandlers {
  close(): void;
}

/** Adapt the authenticated worker API to the fixed Electron IPC surface. */
export function createWorkerDesktopHandlers(client: WorkerClient): DesktopWorkerHandlers {
  return {
    async listWorkers() {
      const capabilities = await client.capabilities();
      return [{ ...capabilities, connection_state: 'connected' }];
    },
    startRun: (request) => client.startRun(request),
    getRun: (runId) => client.getRun(runId),
    stopRun: (runId) => client.stopRun(runId),
    close: () => client.close(),
  };
}
