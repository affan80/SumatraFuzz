import { generateKeyPairSync, sign } from 'node:crypto';
import type { WorkerClient } from '@sumatrafuzz/worker-client';
import { describe, expect, it, vi } from 'vitest';
import { createDesktopWorkerController } from '../src/main/worker-controller.js';
import type { WorkerProfile } from '../src/main/worker-profile-store.js';

const workerId = '11111111-1111-4111-8111-111111111111';
const controllerId = '22222222-2222-4222-8222-222222222222';
const runId = '33333333-3333-4333-8333-333333333333';
const importedBundle = {
  input_bundle_id: '44444444-4444-4444-8444-444444444444',
  archive_sha256: 'c'.repeat(64),
  file_count: 2,
  expanded_bytes: 4096,
};
const profile: WorkerProfile = {
  workerId,
  controllerId,
  baseUrl: 'https://worker.example.test',
  workerFingerprint: 'a'.repeat(64),
  controllerCertificatePem: '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----',
  controllerPrivateKeyPem: '-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----',
  trustedCaPem: '-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----',
};
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function signedBundle(): Buffer {
  const payload = Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-payload-v1',
      issuedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      profile,
    }),
  );
  return Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-bundle-v1',
      payload: payload.toString('base64'),
      signature: sign(null, payload, privateKey).toString('base64'),
    }),
  );
}

function workerClient(id = workerId, authenticatedControllerId = controllerId): WorkerClient {
  return {
    capabilities: vi.fn(async () => ({
      worker_id: id,
      controller_id: authenticatedControllerId,
      protocol_version: 1 as const,
      target_lock_sha256: 'b'.repeat(64),
      max_limits: {
        max_duration_s: 10,
        max_memory_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 200,
        max_cpu_percent: 20,
      },
    })),
    importInputBundle: vi.fn(async () => importedBundle),
    activeRun: vi.fn(async () => null),
    startRun: vi.fn(async () => ({}) as never),
    getRun: vi.fn(async () => ({}) as never),
    stopRun: vi.fn(async () => ({}) as never),
    eventsAfter: vi.fn(async () => []),
    close: vi.fn(),
  };
}

function setup(
  options: {
    readonly selected?: Buffer | null;
    readonly clientId?: string;
    readonly authenticatedControllerId?: string;
    readonly storedProfile?: WorkerProfile | null;
  } = {},
) {
  const save = vi.fn(async () => undefined);
  const clear = vi.fn(async () => undefined);
  const client = workerClient(options.clientId, options.authenticatedControllerId);
  const createClient = vi.fn(() => client);
  const controller = createDesktopWorkerController({
    profileStore: {
      load: vi.fn(async () => options.storedProfile ?? null),
      save,
      clear,
    },
    loadTrustedSigningPublicKey: async () => publicKeyPem,
    selectBundle: async () => options.selected ?? null,
    selectInputBundle: async () => Buffer.from('zip archive'),
    createClient,
  });
  return { controller, save, clear, client, createClient };
}

describe('desktop worker controller pairing', () => {
  it('authenticates the worker identity before persisting its credentials', async () => {
    const { controller, save, client } = setup({ selected: signedBundle() });
    const paired = await controller.pairWorker();

    expect(client.capabilities).toHaveBeenCalledOnce();
    expect(save).toHaveBeenCalledWith(profile);
    expect(paired).toMatchObject({ workerId, baseUrl: profile.baseUrl });
    expect(JSON.stringify(paired)).not.toContain('-----BEGIN PRIVATE KEY-----');
  });

  it('refuses a certificate bundle that authenticates as a different worker', async () => {
    const { controller, save, client } = setup({
      selected: signedBundle(),
      clientId: '22222222-2222-4222-8222-222222222222',
    });

    await expect(controller.pairWorker()).rejects.toThrow(/worker identity/);
    expect(save).not.toHaveBeenCalled();
    expect(client.close).toHaveBeenCalledOnce();
  });

  it('refuses a pairing bundle when authenticated controller identity differs', async () => {
    const { controller, save, client } = setup({
      selected: signedBundle(),
      authenticatedControllerId: '33333333-3333-4333-8333-333333333333',
    });

    await expect(controller.pairWorker()).rejects.toThrow(/worker identity/);
    expect(save).not.toHaveBeenCalled();
    expect(client.close).toHaveBeenCalledOnce();
  });

  it('closes the paired client and clears credentials if its authenticated identity later changes', async () => {
    const { controller, clear, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    vi.mocked(client.capabilities).mockResolvedValue({
      worker_id: workerId,
      controller_id: '33333333-3333-4333-8333-333333333333',
      protocol_version: 1,
      target_lock_sha256: 'b'.repeat(64),
      max_limits: {
        max_duration_s: 10,
        max_memory_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 200,
        max_cpu_percent: 20,
      },
    });

    await expect(controller.getCampaignStatus()).rejects.toThrow(/worker identity/i);
    expect(client.close).toHaveBeenCalledOnce();
    expect(clear).toHaveBeenCalledOnce();
    await expect(controller.getCampaignStatus()).resolves.toMatchObject({
      connection_state: 'disconnected',
    });
  });

  it('keeps the slot unchanged when the operator cancels bundle selection', async () => {
    const { controller, save, createClient } = setup({ selected: null });

    await expect(controller.pairWorker()).resolves.toEqual({ cancelled: true });
    expect(save).not.toHaveBeenCalled();
    expect(createClient).not.toHaveBeenCalled();
  });

  it('returns only public identity and capability data for the paired worker', async () => {
    const { controller } = setup({ selected: signedBundle() });
    await controller.pairWorker();

    await expect(controller.listWorkers()).resolves.toMatchObject([
      { worker_id: workerId, baseUrl: profile.baseUrl, connection_state: 'connected' },
    ]);
    await expect(controller.listWorkers()).resolves.not.toMatchObject([
      { controllerPrivateKeyPem: expect.anything() },
    ]);
    await expect(controller.listWorkers()).resolves.not.toMatchObject([
      { controller_id: expect.any(String), target_lock_sha256: expect.any(String) },
    ]);
  });

  it('closes the active client and removes stored credentials when unpairing', async () => {
    const { controller, clear, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await controller.unpairWorker();

    expect(clear).toHaveBeenCalledOnce();
    expect(client.close).toHaveBeenCalledOnce();
    await expect(controller.listWorkers()).rejects.toThrow(/no worker is paired/);
  });

  it('imports only a safe summary and constructs run identity in the main process', async () => {
    const { controller, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await expect(controller.importInputBundle()).resolves.toEqual({
      archive_sha256: importedBundle.archive_sha256,
      file_count: importedBundle.file_count,
      expanded_bytes: importedBundle.expanded_bytes,
    });
    expect(client.importInputBundle).toHaveBeenCalledWith(Buffer.from('zip archive'));

    vi.mocked(client.startRun).mockResolvedValue({
      run_id: runId,
      worker_id: workerId,
      state: 'running',
      last_event_seq: 0n,
      stop_reason: null,
    });
    const status = await controller.startCampaign({
      label: 'nightly',
      limits: {
        max_duration_s: 10,
        max_memory_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 200,
        max_cpu_percent: 20,
      },
    });
    expect(status.run_id).toBe(runId);
    const request = vi.mocked(client.startRun).mock.calls[0]?.[0];
    expect(request).toMatchObject({
      controller_id: controllerId,
      input_bundle_id: importedBundle.input_bundle_id,
      target_lock_sha256: 'b'.repeat(64),
      label: 'nightly',
    });
    expect(request?.request_id).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('rejects worker policy excesses and refuses starts after unpairing', async () => {
    const { controller, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await controller.importInputBundle();
    await expect(
      controller.startCampaign({
        label: 'too large',
        limits: {
          max_duration_s: 11,
          max_memory_bytes: 64 * 1024 * 1024,
          max_disk_bytes: 200,
          max_cpu_percent: 20,
        },
      }),
    ).rejects.toThrow(/policy ceiling/i);
    expect(client.startRun).not.toHaveBeenCalled();

    await controller.unpairWorker();
    await expect(
      controller.startCampaign({
        label: 'stale',
        limits: {
          max_duration_s: 10,
          max_memory_bytes: 64 * 1024 * 1024,
          max_disk_bytes: 200,
          max_cpu_percent: 20,
        },
      }),
    ).rejects.toThrow(/no worker is paired/i);
  });

  it('rejects native memory below its minimum and disk limits below the provisioned quota', async () => {
    const { controller, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await controller.importInputBundle();
    const limits = {
      max_duration_s: 10,
      max_memory_bytes: 64 * 1024 * 1024,
      max_disk_bytes: 200,
      max_cpu_percent: 20,
    };

    await expect(
      controller.startCampaign({
        label: 'too little memory',
        limits: { ...limits, max_memory_bytes: 1024 },
      }),
    ).rejects.toThrow(/native minimum/i);
    await expect(
      controller.startCampaign({
        label: 'unprovisioned disk limit',
        limits: { ...limits, max_disk_bytes: 199 },
      }),
    ).rejects.toThrow(/worker volume quota/i);
    expect(client.startRun).not.toHaveBeenCalled();
  });

  it('recovers the active run after restoring the profile and stops only that run', async () => {
    const { controller, client } = setup({ storedProfile: profile });
    vi.mocked(client.activeRun).mockResolvedValue({
      run_id: runId,
      worker_id: workerId,
      state: 'running',
      last_event_seq: 3n,
      stop_reason: null,
    });
    vi.mocked(client.stopRun).mockResolvedValue({
      run_id: runId,
      worker_id: workerId,
      state: 'stopping',
      last_event_seq: 4n,
      stop_reason: 'requested',
    });
    await controller.restore();
    expect(client.activeRun).toHaveBeenCalledOnce();
    await controller.stopActiveRun();
    expect(client.stopRun).toHaveBeenCalledWith(runId);
  });

  it('keeps the last run outcome visible after the worker clears its active slot', async () => {
    const { controller, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await controller.importInputBundle();
    vi.mocked(client.startRun).mockResolvedValue({
      run_id: runId,
      worker_id: workerId,
      state: 'running',
      last_event_seq: 1n,
      stop_reason: null,
    });
    await controller.startCampaign({
      label: 'nightly',
      limits: {
        max_duration_s: 10,
        max_memory_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 200,
        max_cpu_percent: 20,
      },
    });

    vi.mocked(client.activeRun).mockResolvedValue(null);
    vi.mocked(client.getRun).mockResolvedValue({
      run_id: runId,
      worker_id: workerId,
      state: 'completed',
      last_event_seq: 4n,
      stop_reason: 'time_limit',
    });

    await expect(controller.getCampaignStatus()).resolves.toMatchObject({
      campaign_label: 'nightly',
      active_run: { run_id: runId, state: 'completed', stop_reason: 'time_limit' },
    });
    expect(client.getRun).toHaveBeenCalledWith(runId);
  });

  it('closes a pairing client and clears its profile when shutdown races with persistence', async () => {
    let finishSave!: () => void;
    const save = vi.fn(() => new Promise<void>((resolve) => (finishSave = resolve)));
    const clear = vi.fn(async () => undefined);
    const client = workerClient();
    const controller = createDesktopWorkerController({
      profileStore: {
        load: vi.fn(async () => null),
        save,
        clear,
      },
      loadTrustedSigningPublicKey: async () => publicKeyPem,
      selectBundle: async () => signedBundle(),
      selectInputBundle: async () => Buffer.from('zip archive'),
      createClient: () => client,
    });

    const pairing = controller.pairWorker();
    await vi.waitFor(() => expect(save).toHaveBeenCalledOnce());
    controller.close();
    finishSave();

    await expect(pairing).rejects.toThrow(/controller is closed/);
    expect(clear).toHaveBeenCalledOnce();
    expect(client.close).toHaveBeenCalledOnce();
    await expect(controller.listWorkers()).rejects.toThrow(/no worker is paired/);
  });
});
