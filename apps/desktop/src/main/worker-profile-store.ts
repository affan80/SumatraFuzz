import { randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { normalizeCertificateFingerprint, validateWorkerUrl } from '@sumatrafuzz/worker-client';
import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';

const FORMAT = 'sumatrafuzz-worker-profile-v2';
const MAX_PROFILE_BYTES = 512 * 1024;
const MAX_ENVELOPE_BYTES = MAX_PROFILE_BYTES + 4096;
const MAX_ROTATION_RETRIES = 3;

export interface WorkerProfile {
  readonly workerId: string;
  readonly controllerId: string;
  readonly baseUrl: string;
  readonly workerFingerprint: string;
  readonly controllerCertificatePem: string;
  readonly controllerPrivateKeyPem: string;
  readonly trustedCaPem: string;
}

export interface SafeStorageAdapter {
  isAsyncEncryptionAvailable(): Promise<boolean>;
  encryptStringAsync(plainText: string): Promise<Buffer>;
  decryptStringAsync(encrypted: Buffer): Promise<{
    readonly result: string;
    readonly shouldReEncrypt: boolean;
  }>;
}

export interface WorkerProfileStore {
  load(): Promise<WorkerProfile | null>;
  save(profile: WorkerProfile): Promise<void>;
  clear(): Promise<void>;
}

export interface WorkerProfileStoreOptions {
  readonly filePath: string;
  readonly legacyFilePath?: string;
  readonly safeStorage: SafeStorageAdapter;
  readonly platform?: NodeJS.Platform;
}

export function validateWorkerProfile(value: unknown): WorkerProfile {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('worker profile is invalid');
  }
  const candidate = value as Record<string, unknown>;
  const expectedKeys = [
    'workerId',
    'controllerId',
    'baseUrl',
    'workerFingerprint',
    'controllerCertificatePem',
    'controllerPrivateKeyPem',
    'trustedCaPem',
  ].sort();
  const keys = Object.keys(candidate).sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    typeof candidate.workerId !== 'string' ||
    !isNonNilUuid(candidate.workerId) ||
    typeof candidate.controllerId !== 'string' ||
    !isNonNilUuid(candidate.controllerId) ||
    typeof candidate.baseUrl !== 'string' ||
    typeof candidate.workerFingerprint !== 'string' ||
    typeof candidate.controllerCertificatePem !== 'string' ||
    typeof candidate.controllerPrivateKeyPem !== 'string' ||
    typeof candidate.trustedCaPem !== 'string'
  ) {
    throw new TypeError('worker profile is invalid');
  }

  validateWorkerUrl(candidate.baseUrl);
  const workerFingerprint = normalizeCertificateFingerprint(candidate.workerFingerprint);
  const pemFields = [
    candidate.controllerCertificatePem,
    candidate.controllerPrivateKeyPem,
    candidate.trustedCaPem,
  ];
  if (
    pemFields.some(
      (pem) =>
        pem.length === 0 ||
        pem.length > MAX_PROFILE_BYTES / 2 ||
        !pem.startsWith('-----BEGIN ') ||
        !pem.includes('\n-----END '),
    )
  ) {
    throw new TypeError('worker profile certificate material is invalid');
  }

  const profile: WorkerProfile = {
    workerId: candidate.workerId,
    controllerId: candidate.controllerId,
    baseUrl: candidate.baseUrl,
    workerFingerprint,
    controllerCertificatePem: candidate.controllerCertificatePem,
    controllerPrivateKeyPem: candidate.controllerPrivateKeyPem,
    trustedCaPem: candidate.trustedCaPem,
  };
  if (Buffer.byteLength(JSON.stringify(profile), 'utf8') > MAX_PROFILE_BYTES) {
    throw new TypeError('worker profile exceeds the maximum supported size');
  }
  return profile;
}

function decodeEnvelope(contents: Buffer): Buffer {
  if (contents.length > MAX_ENVELOPE_BYTES) throw new Error('worker profile file is invalid');
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents.toString('utf8')) as unknown;
  } catch {
    throw new Error('worker profile file is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(',') !== 'data,format' ||
    (parsed as { format?: unknown }).format !== FORMAT ||
    typeof (parsed as { data?: unknown }).data !== 'string' ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      (parsed as { data: string }).data,
    )
  ) {
    throw new Error('worker profile file is invalid');
  }
  const encrypted = Buffer.from((parsed as { data: string }).data, 'base64');
  if (encrypted.length === 0) throw new Error('worker profile file is invalid');
  return encrypted;
}

export function createWorkerProfileStore({
  filePath,
  legacyFilePath,
  safeStorage,
  platform = process.platform,
}: WorkerProfileStoreOptions): WorkerProfileStore {
  const requireDpapi = async (): Promise<void> => {
    if (platform !== 'win32') {
      throw new Error('worker credentials require Windows DPAPI protected storage');
    }
    if (!(await safeStorage.isAsyncEncryptionAvailable())) {
      throw new Error('OS-backed encryption is unavailable');
    }
  };

  const writeEncrypted = async (plainText: string): Promise<void> => {
    const encrypted = await safeStorage.encryptStringAsync(plainText);
    if (encrypted.length === 0 || encrypted.length > MAX_ENVELOPE_BYTES) {
      throw new Error('OS encryption returned an invalid worker profile');
    }
    const envelope = Buffer.from(
      JSON.stringify({ format: FORMAT, data: encrypted.toString('base64') }),
      'utf8',
    );
    const directory = path.dirname(filePath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporaryPath = path.join(directory, `.worker-profile-${randomUUID()}.tmp`);
    try {
      const handle = await open(temporaryPath, 'wx', 0o600);
      try {
        await handle.writeFile(envelope);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temporaryPath, filePath);
    } finally {
      await rm(temporaryPath, { force: true });
    }
  };

  return {
    async load() {
      let contents: Buffer;
      try {
        const metadata = await stat(filePath);
        if (metadata.size <= 0 || metadata.size > MAX_ENVELOPE_BYTES) {
          throw new Error('worker profile file is invalid');
        }
        contents = await readFile(filePath);
      } catch (error) {
        if (
          typeof error === 'object' &&
          error !== null &&
          'code' in error &&
          error.code === 'ENOENT'
        ) {
          if (legacyFilePath) {
            try {
              await lstat(legacyFilePath);
              // A legacy profile lacks a signed controller identity. Leave it intact and require re-pairing.
              return null;
            } catch (legacyError) {
              if (
                typeof legacyError !== 'object' ||
                legacyError === null ||
                !('code' in legacyError) ||
                legacyError.code !== 'ENOENT'
              ) {
                throw legacyError;
              }
            }
          }
          return null;
        }
        throw error;
      }
      await requireDpapi();
      const encrypted = decodeEnvelope(contents);
      let decrypted = await safeStorage.decryptStringAsync(encrypted);
      for (
        let retries = 0;
        decrypted.shouldReEncrypt && retries < MAX_ROTATION_RETRIES;
        retries += 1
      ) {
        decrypted = await safeStorage.decryptStringAsync(encrypted);
      }
      if (decrypted.shouldReEncrypt)
        throw new Error('worker profile encryption key rotation failed');
      let value: unknown;
      try {
        value = JSON.parse(decrypted.result) as unknown;
      } catch {
        throw new Error('decrypted worker profile is invalid');
      }
      return validateWorkerProfile(value);
    },
    async save(input) {
      await requireDpapi();
      const profile = validateWorkerProfile(input);
      await writeEncrypted(JSON.stringify(profile));
    },
    async clear() {
      await Promise.all(
        [filePath, legacyFilePath]
          .filter((candidate): candidate is string => Boolean(candidate))
          .map((candidate) => rm(candidate, { force: true })),
      );
    },
  };
}
