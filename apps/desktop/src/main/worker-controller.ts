import { randomUUID } from 'node:crypto';
import type {
  ImportedInputBundle,
  WorkerCapabilities,
  WorkerClient,
} from '@sumatrafuzz/worker-client';
import {
  MIN_CAMPAIGN_MEMORY_BYTES,
  type RunRequest,
  type RunStatus,
  validateRunRequest,
} from '@sumatrafuzz/worker-protocol';
import type { DesktopIpcHandlers, RunDraft } from './ipc.js';
import { verifyWorkerPairingBundle } from './worker-bundle.js';
import type { WorkerProfile, WorkerProfileStore } from './worker-profile-store.js';

export type WorkerPairingResult =
  | { readonly cancelled: true }
  | {
      readonly cancelled: false;
      readonly workerId: string;
      readonly baseUrl: string;
      readonly workerFingerprint: string;
    };

export interface DesktopWorkerController extends DesktopIpcHandlers {
  restore(): Promise<void>;
  close(): void;
}

export interface DesktopWorkerControllerOptions {
  readonly profileStore: Pick<WorkerProfileStore, 'load' | 'save' | 'clear'>;
  readonly loadTrustedSigningPublicKey: () => Promise<string>;
  readonly selectBundle: () => Promise<Buffer | null>;
  readonly selectInputBundle: () => Promise<Buffer | null>;
  readonly createClient: (profile: WorkerProfile) => WorkerClient;
  readonly now?: () => Date;
}

export type CampaignImportSummary = Pick<
  ImportedInputBundle,
  'archive_sha256' | 'file_count' | 'expanded_bytes'
>;

export interface CampaignStatus {
  readonly connection_state: 'connected' | 'disconnected';
  readonly worker_id: string | null;
  readonly max_limits: WorkerCapabilities['max_limits'] | null;
  readonly imported_bundle: CampaignImportSummary | null;
  readonly campaign_label: string | null;
  readonly active_run: RunStatus | null;
}

export function createDesktopWorkerController({
  profileStore,
  loadTrustedSigningPublicKey,
  selectBundle,
  selectInputBundle,
  createClient,
  now = () => new Date(),
}: DesktopWorkerControllerOptions): DesktopWorkerController {
  let activeProfile: WorkerProfile | null = null;
  let activeClient: WorkerClient | null = null;
  let importedBundle: (ImportedInputBundle & { workerId: string; controllerId: string }) | null =
    null;
  let activeRunId: string | null = null;
  let campaignLabel: string | null = null;
  let closed = false;
  let mutationQueue: Promise<void> = Promise.resolve();
  const pendingClients = new Set<WorkerClient>();
  const closedClients = new WeakSet<WorkerClient>();

  const closeClient = (client: WorkerClient): void => {
    if (closedClients.has(client)) return;
    closedClients.add(client);
    client.close();
  };

  const serializeMutation = <T>(operation: () => Promise<T>): Promise<T> => {
    const current = mutationQueue.then(operation, operation);
    mutationQueue = current.then(
      () => undefined,
      () => undefined,
    );
    return current;
  };

  const clearCampaignState = (): void => {
    importedBundle = null;
    activeRunId = null;
    campaignLabel = null;
  };

  const identityMismatch = (error: unknown): boolean =>
    error instanceof Error &&
    /identity mismatch|identity is invalid|does not match/i.test(error.message);

  const closeActiveOnIdentityMismatch = async (client: WorkerClient): Promise<void> => {
    if (activeClient !== client) return;
    closeClient(client);
    activeClient = null;
    activeProfile = null;
    clearCampaignState();
    await profileStore.clear();
  };

  const guardedClientCall = async <T>(
    client: WorkerClient,
    operation: () => Promise<T>,
  ): Promise<T> => {
    try {
      return await operation();
    } catch (error) {
      if (identityMismatch(error)) await closeActiveOnIdentityMismatch(client);
      throw error;
    }
  };

  const requireClient = async (): Promise<{ client: WorkerClient; profile: WorkerProfile }> => {
    if (!activeClient || !activeProfile) throw new Error('no worker is paired');
    const capabilities = await activeClient.capabilities();
    if (
      capabilities.worker_id !== activeProfile.workerId ||
      capabilities.controller_id !== activeProfile.controllerId
    ) {
      await closeActiveOnIdentityMismatch(activeClient);
      throw new Error('authenticated worker identity does not match the paired worker identity');
    }
    return { client: activeClient, profile: activeProfile };
  };

  return {
    async restore() {
      if (closed) throw new Error('worker controller is closed');
      if (activeProfile || activeClient) return;
      const profile = await profileStore.load();
      if (profile) {
        activeProfile = profile;
        activeClient = createClient(profile);
        try {
          const { client } = await requireClient();
          const run = await client.activeRun();
          activeRunId = run?.run_id ?? null;
        } catch (error) {
          if (identityMismatch(error) && activeClient) {
            await closeActiveOnIdentityMismatch(activeClient);
          }
        }
      }
    },
    pairWorker(): Promise<WorkerPairingResult> {
      return serializeMutation(async () => {
        if (closed) throw new Error('worker controller is closed');
        const bundleBytes = await selectBundle();
        if (!bundleBytes) return { cancelled: true };
        if (closed) throw new Error('worker controller is closed');

        const trustedKey = await loadTrustedSigningPublicKey();
        const verified = verifyWorkerPairingBundle(bundleBytes, trustedKey, now());
        const candidate = createClient(verified.profile);
        pendingClients.add(candidate);
        let capabilities: WorkerCapabilities;
        try {
          capabilities = await candidate.capabilities();
          if (
            capabilities.worker_id !== verified.profile.workerId ||
            capabilities.controller_id !== verified.profile.controllerId
          ) {
            throw new Error('authenticated worker identity does not match the signed bundle');
          }
          if (closed) throw new Error('worker controller is closed');
          await profileStore.save(verified.profile);
          if (closed) {
            await profileStore.clear();
            throw new Error('worker controller is closed');
          }
        } catch (error) {
          closeClient(candidate);
          throw error;
        } finally {
          pendingClients.delete(candidate);
        }

        if (activeClient) closeClient(activeClient);
        activeProfile = verified.profile;
        activeClient = candidate;
        clearCampaignState();
        return {
          cancelled: false,
          workerId: capabilities.worker_id,
          baseUrl: verified.profile.baseUrl,
          workerFingerprint: verified.profile.workerFingerprint,
        };
      });
    },
    unpairWorker() {
      return serializeMutation(async () => {
        if (closed) throw new Error('worker controller is closed');
        await profileStore.clear();
        if (activeClient) closeClient(activeClient);
        activeClient = null;
        activeProfile = null;
        clearCampaignState();
      });
    },
    async listWorkers() {
      const { client, profile } = await requireClient();
      const capabilities = await client.capabilities();
      return [
        {
          worker_id: capabilities.worker_id,
          baseUrl: profile.baseUrl,
          connection_state: 'connected',
        },
      ];
    },
    importInputBundle() {
      return serializeMutation(async () => {
        const { client, profile } = await requireClient();
        const archive = await selectInputBundle();
        if (!archive) return null;
        const imported = await client.importInputBundle(archive);
        importedBundle = {
          ...imported,
          workerId: profile.workerId,
          controllerId: profile.controllerId,
        };
        return {
          archive_sha256: imported.archive_sha256,
          file_count: imported.file_count,
          expanded_bytes: imported.expanded_bytes,
        } satisfies CampaignImportSummary;
      });
    },
    async getCampaignStatus(): Promise<CampaignStatus> {
      if (!activeClient || !activeProfile) {
        return {
          connection_state: 'disconnected',
          worker_id: null,
          max_limits: null,
          imported_bundle: null,
          campaign_label: null,
          active_run: null,
        };
      }
      const { client, profile } = await requireClient();
      const capabilities = await client.capabilities();
      const run = await guardedClientCall(client, () =>
        activeRunId ? client.getRun(activeRunId) : client.activeRun(),
      );
      if (!activeRunId && run) activeRunId = run.run_id;
      if (!run) {
        activeRunId = null;
        campaignLabel = null;
      }
      const currentImport =
        importedBundle?.workerId === profile.workerId &&
        importedBundle.controllerId === profile.controllerId
          ? {
              archive_sha256: importedBundle.archive_sha256,
              file_count: importedBundle.file_count,
              expanded_bytes: importedBundle.expanded_bytes,
            }
          : null;
      return {
        connection_state: 'connected',
        worker_id: capabilities.worker_id,
        max_limits: capabilities.max_limits,
        imported_bundle: currentImport,
        campaign_label: campaignLabel,
        active_run: run,
      };
    },
    startCampaign(draft: RunDraft) {
      return serializeMutation(async () => {
        const { client, profile } = await requireClient();
        const capabilities = await client.capabilities();
        if (
          !importedBundle ||
          importedBundle.workerId !== profile.workerId ||
          importedBundle.controllerId !== profile.controllerId
        ) {
          throw new Error('import a PDF bundle for the currently paired worker first');
        }
        const active = await guardedClientCall(client, () => client.activeRun());
        if (active) throw new Error('a campaign is already active');
        if (draft.limits.max_memory_bytes < MIN_CAMPAIGN_MEMORY_BYTES) {
          throw new RangeError('campaign memory limit is below the native minimum');
        }
        if (draft.limits.max_disk_bytes !== capabilities.max_limits.max_disk_bytes) {
          throw new RangeError('campaign disk limit must match the worker volume quota');
        }
        for (const key of [
          'max_duration_s',
          'max_memory_bytes',
          'max_disk_bytes',
          'max_cpu_percent',
        ] as const) {
          if (draft.limits[key] > capabilities.max_limits[key]) {
            throw new RangeError(`campaign ${key} exceeds the worker policy ceiling`);
          }
        }
        const request: RunRequest = validateRunRequest({
          request_id: randomUUID(),
          controller_id: profile.controllerId,
          input_bundle_id: importedBundle.input_bundle_id,
          target_lock_sha256: capabilities.target_lock_sha256,
          limits: draft.limits,
          label: draft.label,
        });
        const status = await guardedClientCall(client, () => client.startRun(request));
        activeRunId = status.run_id;
        campaignLabel = draft.label;
        return status;
      });
    },
    stopActiveRun() {
      return serializeMutation(async () => {
        const { client } = await requireClient();
        const runId = activeRunId;
        if (!runId) return null;
        const status = await guardedClientCall(client, () => client.stopRun(runId));
        return status;
      });
    },
    close() {
      closed = true;
      for (const client of pendingClients) closeClient(client);
      pendingClients.clear();
      if (activeClient) closeClient(activeClient);
      activeClient = null;
      activeProfile = null;
      clearCampaignState();
    },
  };
}
