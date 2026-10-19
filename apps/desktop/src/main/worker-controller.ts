import type { WorkerCapabilities, WorkerClient } from '@sumatrafuzz/worker-client';
import type { RunRequest } from '@sumatrafuzz/worker-protocol';
import type { DesktopIpcHandlers } from './ipc.js';
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
  readonly createClient: (profile: WorkerProfile) => WorkerClient;
  readonly now?: () => Date;
}

export function createDesktopWorkerController({
  profileStore,
  loadTrustedSigningPublicKey,
  selectBundle,
  createClient,
  now = () => new Date(),
}: DesktopWorkerControllerOptions): DesktopWorkerController {
  let activeProfile: WorkerProfile | null = null;
  let activeClient: WorkerClient | null = null;
  let closed = false;
  let mutationQueue: Promise<void> = Promise.resolve();

  const serializeMutation = <T>(operation: () => Promise<T>): Promise<T> => {
    const current = mutationQueue.then(operation, operation);
    mutationQueue = current.then(
      () => undefined,
      () => undefined,
    );
    return current;
  };

  const requireClient = async (): Promise<{ client: WorkerClient; profile: WorkerProfile }> => {
    if (!activeClient || !activeProfile) throw new Error('no worker is paired');
    const capabilities = await activeClient.capabilities();
    if (capabilities.worker_id !== activeProfile.workerId) {
      activeClient.close();
      activeClient = null;
      activeProfile = null;
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
        let capabilities: WorkerCapabilities;
        try {
          capabilities = await candidate.capabilities();
          if (capabilities.worker_id !== verified.profile.workerId) {
            throw new Error('authenticated worker identity does not match the signed bundle');
          }
          if (closed) throw new Error('worker controller is closed');
          await profileStore.save(verified.profile);
        } catch (error) {
          candidate.close();
          throw error;
        }

        activeClient?.close();
        activeProfile = verified.profile;
        activeClient = candidate;
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
        activeClient?.close();
        activeClient = null;
        activeProfile = null;
      });
    },
    async listWorkers() {
      const { client, profile } = await requireClient();
      const capabilities = await client.capabilities();
      return [{ ...capabilities, baseUrl: profile.baseUrl, connection_state: 'connected' }];
    },
    async startRun(request: RunRequest) {
      const { client } = await requireClient();
      return client.startRun(request);
    },
    async getRun(runId: string) {
      const { client } = await requireClient();
      return client.getRun(runId);
    },
    async stopRun(runId: string) {
      const { client } = await requireClient();
      return client.stopRun(runId);
    },
    close() {
      closed = true;
      activeClient?.close();
      activeClient = null;
      activeProfile = null;
    },
  };
}
