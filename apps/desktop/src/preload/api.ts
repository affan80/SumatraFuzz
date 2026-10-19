import type { RunRequest } from '@sumatrafuzz/worker-protocol';

export interface DesktopIpcTransport {
  invoke(channel: string, ...args: unknown[]): Promise<unknown>;
}

export interface SumatraFuzzApi {
  listWorkers(): Promise<readonly unknown[]>;
  startRun(request: RunRequest): Promise<unknown>;
  getRun(runId: string): Promise<unknown>;
  stopRun(runId: string): Promise<unknown>;
}

export function createSumatraFuzzApi(transport: DesktopIpcTransport): SumatraFuzzApi {
  return Object.freeze({
    listWorkers: async () => (await transport.invoke('sf:workers:list')) as readonly unknown[],
    startRun: async (request: RunRequest) => transport.invoke('sf:runs:start', request),
    getRun: async (runId: string) => transport.invoke('sf:runs:get', runId),
    stopRun: async (runId: string) => transport.invoke('sf:runs:stop', runId),
  });
}
