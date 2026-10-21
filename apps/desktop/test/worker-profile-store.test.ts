import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createWorkerProfileStore,
  type SafeStorageAdapter,
  validateWorkerProfile,
  type WorkerProfile,
} from '../src/main/worker-profile-store.js';

const profile: WorkerProfile = {
  workerId: '11111111-1111-4111-8111-111111111111',
  controllerId: '22222222-2222-4222-8222-222222222222',
  baseUrl: 'https://worker.example.test',
  workerFingerprint: 'a'.repeat(64),
  controllerCertificatePem: '-----BEGIN CERTIFICATE-----\npublic-cert\n-----END CERTIFICATE-----',
  controllerPrivateKeyPem: '-----BEGIN PRIVATE KEY-----\nprivate-key\n-----END PRIVATE KEY-----',
  trustedCaPem: '-----BEGIN CERTIFICATE-----\ntrusted-ca\n-----END CERTIFICATE-----',
};

const directories: string[] = [];

async function temporaryFile(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'sumatrafuzz-profile-'));
  directories.push(directory);
  return path.join(directory, 'worker-profile.v2.enc');
}

function testSafeStorage(): SafeStorageAdapter {
  return {
    isAsyncEncryptionAvailable: vi.fn(async () => true),
    encryptStringAsync: vi.fn(async (value: string) => Buffer.from(`sealed:${value}`)),
    decryptStringAsync: vi.fn(async (value: Buffer) => ({
      result: value.toString().slice('sealed:'.length),
      shouldReEncrypt: false,
    })),
  };
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
});

describe('encrypted worker profile store', () => {
  it('stores credentials encrypted and loads the one paired worker profile', async () => {
    const filePath = await temporaryFile();
    const safeStorage = testSafeStorage();
    const store = createWorkerProfileStore({ filePath, safeStorage, platform: 'win32' });

    await store.save(profile);
    const onDisk = await readFile(filePath, 'utf8');
    expect(onDisk).not.toContain('private-key');
    await expect(store.load()).resolves.toEqual(profile);
    expect(safeStorage.encryptStringAsync).toHaveBeenCalledOnce();
    expect(safeStorage.decryptStringAsync).toHaveBeenCalledOnce();
  });

  it('refuses to save when OS encryption is unavailable', async () => {
    const safeStorage = testSafeStorage();
    vi.mocked(safeStorage.isAsyncEncryptionAvailable).mockResolvedValue(false);
    const store = createWorkerProfileStore({
      filePath: await temporaryFile(),
      safeStorage,
      platform: 'win32',
    });

    await expect(store.save(profile)).rejects.toThrow(/OS-backed encryption is unavailable/);
    expect(safeStorage.encryptStringAsync).not.toHaveBeenCalled();
  });

  it('does not enable credential storage outside Windows x64-target platforms', async () => {
    const safeStorage = testSafeStorage();
    const store = createWorkerProfileStore({
      filePath: await temporaryFile(),
      safeStorage,
      platform: 'darwin',
    });

    await expect(store.save(profile)).rejects.toThrow(/Windows DPAPI/);
    expect(safeStorage.encryptStringAsync).not.toHaveBeenCalled();
  });

  it('validates worker identity and TLS endpoint before persisting', async () => {
    const safeStorage = testSafeStorage();
    const store = createWorkerProfileStore({
      filePath: await temporaryFile(),
      safeStorage,
      platform: 'win32',
    });

    await expect(store.save({ ...profile, baseUrl: 'http://worker.example.test' })).rejects.toThrow(
      /HTTPS origin/,
    );
    await expect(store.save({ ...profile, workerFingerprint: 'wrong' })).rejects.toThrow(
      /SHA-256 fingerprint/,
    );
    expect(safeStorage.encryptStringAsync).not.toHaveBeenCalled();
  });

  it.each([
    ['missing', undefined],
    ['nil', '00000000-0000-0000-0000-000000000000'],
    ['malformed', 'controller-one'],
  ])('rejects a %s controller UUID before persistence', async (_name, controllerId) => {
    expect(() => validateWorkerProfile({ ...profile, controllerId })).toThrow(
      /worker profile is invalid/,
    );
  });

  it('fails closed on a malformed or oversized encrypted profile file', async () => {
    const filePath = await temporaryFile();
    const safeStorage = testSafeStorage();
    const store = createWorkerProfileStore({ filePath, safeStorage, platform: 'win32' });
    await store.save(profile);
    await writeFile(filePath, '{"version":2}');

    await expect(store.load()).rejects.toThrow(/profile file is invalid/);
    expect(safeStorage.decryptStringAsync).not.toHaveBeenCalled();
  });

  it('removes the paired profile and reports an empty slot', async () => {
    const store = createWorkerProfileStore({
      filePath: await temporaryFile(),
      safeStorage: testSafeStorage(),
      platform: 'win32',
    });

    await store.save(profile);
    await store.clear();
    await expect(store.load()).resolves.toBeNull();
  });

  it('leaves a legacy profile untouched and requires signed re-pairing', async () => {
    const filePath = await temporaryFile();
    const legacyFilePath = path.join(path.dirname(filePath), 'worker-profile.v1.enc');
    const legacyBytes = Buffer.from('{"format":"sumatrafuzz-worker-profile-v1","data":"c2VhbGVk"}');
    await writeFile(legacyFilePath, legacyBytes);
    const safeStorage = testSafeStorage();
    const store = createWorkerProfileStore({
      filePath,
      legacyFilePath,
      safeStorage,
      platform: 'win32',
    });

    await expect(store.load()).resolves.toBeNull();
    expect(await readFile(legacyFilePath)).toEqual(legacyBytes);
    expect(safeStorage.decryptStringAsync).not.toHaveBeenCalled();

    await store.save(profile);
    expect(await readFile(legacyFilePath)).toEqual(legacyBytes);
    expect((await readFile(filePath)).toString('utf8')).toContain('sumatrafuzz-worker-profile-v2');
  });
});
