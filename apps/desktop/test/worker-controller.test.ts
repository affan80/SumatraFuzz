import { generateKeyPairSync, sign } from 'node:crypto';
import type { WorkerClient } from '@sumatrafuzz/worker-client';
import { describe, expect, it, vi } from 'vitest';
import { createDesktopWorkerController } from '../src/main/worker-controller.js';
import type { WorkerProfile } from '../src/main/worker-profile-store.js';

const workerId = '11111111-1111-4111-8111-111111111111';
const controllerId = '22222222-2222-4222-8222-222222222222';
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
        max_memory_bytes: 100,
        max_disk_bytes: 200,
        max_cpu_percent: 20,
      },
    })),
    importInputBundle: vi.fn(async () => ({}) as never),
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
  } = {},
) {
  const save = vi.fn(async () => undefined);
  const clear = vi.fn(async () => undefined);
  const client = workerClient(options.clientId, options.authenticatedControllerId);
  const createClient = vi.fn(() => client);
  const controller = createDesktopWorkerController({
    profileStore: {
      load: vi.fn(async () => null),
      save,
      clear,
    },
    loadTrustedSigningPublicKey: async () => publicKeyPem,
    selectBundle: async () => options.selected ?? null,
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
  });

  it('closes the active client and removes stored credentials when unpairing', async () => {
    const { controller, clear, client } = setup({ selected: signedBundle() });
    await controller.pairWorker();
    await controller.unpairWorker();

    expect(clear).toHaveBeenCalledOnce();
    expect(client.close).toHaveBeenCalledOnce();
    await expect(controller.listWorkers()).rejects.toThrow(/no worker is paired/);
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
