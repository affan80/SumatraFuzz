import type { CampaignLimits } from '@sumatrafuzz/worker-protocol';

export interface RunDraft {
  readonly label: string;
  readonly limits: CampaignLimits;
}

export interface DesktopIpcTransport {
  invoke(channel: string, ...args: unknown[]): Promise<unknown>;
}

export interface SumatraFuzzApi {
  listWorkers(): Promise<readonly unknown[]>;
  pairWorker(): Promise<unknown>;
  unpairWorker(): Promise<void>;
  importInputBundle(): Promise<unknown>;
  getCampaignStatus(): Promise<unknown>;
  startCampaign(draft: RunDraft): Promise<unknown>;
  stopActiveRun(): Promise<unknown>;
}

export function createSumatraFuzzApi(transport: DesktopIpcTransport): SumatraFuzzApi {
  return Object.freeze({
    listWorkers: async () => (await transport.invoke('sf:workers:list')) as readonly unknown[],
    pairWorker: async () => transport.invoke('sf:workers:pair'),
    unpairWorker: async () => {
      await transport.invoke('sf:workers:unpair');
    },
    importInputBundle: async () => transport.invoke('sf:campaigns:import'),
    getCampaignStatus: async () => transport.invoke('sf:campaigns:status'),
    startCampaign: async (draft: RunDraft) => transport.invoke('sf:campaigns:start', draft),
    stopActiveRun: async () => transport.invoke('sf:campaigns:stop'),
  });
}
