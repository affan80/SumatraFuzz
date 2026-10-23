import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { lstat, mkdir, open, unlink } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { createSecureContext } from 'node:tls';
import { fileURLToPath } from 'node:url';
import type { WorkerPolicy } from '@sumatrafuzz/worker-core';
import { WindowsJobSupervisor } from '@sumatrafuzz/worker-core';
import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';
import { validateEndpointCertificate } from '@sumatrafuzz/worker-security';
import { createWorkerApplication } from './application.js';
import { AuditedTrustAdministration } from './audited-trust-administration.js';
import { monitorNetworkBinding } from './network-binding-monitor.js';
import { type BindMode, validateBindAddress } from './network-policy.js';
import {
  createDpapiCredentialProtector,
  verifyAndApplySignedTrustOperation,
  verifyAndProvisionPairingBundle,
} from './pairing-provision.js';
import { FileSecurityAudit } from './security-audit.js';
import { runWorkerServiceControl } from './service-control.js';
import { SqliteWorkerTrustStore } from './trust-store.js';

const CONFIG_MAX_BYTES = 64 * 1024;
const SIGNING_KEY_MAX_BYTES = 16 * 1024;
const CREDENTIAL_MAX_BYTES = 1024 * 1024;
const PAIRING_MAX_BYTES = 1024 * 1024;
const MAX_DISK_BYTES = 2 ** 40;
const GUID =
  /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const VOLUME_ID = /^volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i;
const PEM_CERT =
  /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/;
const PEM_PRIVATE_KEY =
  /^-----BEGIN (?:EC |RSA )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END (?:EC |RSA )?PRIVATE KEY-----\s*$/;

export interface WorkerServiceConfig {
  readonly schema: 1;
  readonly workerId: string;
  readonly bind: {
    readonly mode: BindMode;
    readonly address: string;
    readonly port: number;
    readonly adapterGuid: string;
    readonly peerCidrs: readonly string[];
  };
  readonly storage: {
    readonly root: string;
    readonly volumeId: string;
    readonly diskLimitBytes: number;
  };
  readonly trust: { readonly organizationSigningPublicKeyPath: string };
  readonly credentials: { readonly protectedBundlePath: string };
  readonly policy: WorkerPolicy;
  readonly audit: {
    readonly maxBytes: number;
    readonly maxSegmentBytes: number;
    readonly maxSegments: number;
  };
}

function invalid(): never {
  throw new Error('invalid worker service configuration');
}

function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalid();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function boundedString(value: unknown, max: number, pattern?: RegExp): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return !pattern || pattern.test(value);
}

function integer(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function validCidr(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 64) return false;
  const [address, prefix, extra] = value.split('/');
  if (!address || prefix === undefined || extra !== undefined || !/^\d{1,3}$/.test(prefix))
    return false;
  const family = isIP(address);
  const bits = family === 4 ? 32 : family === 6 ? 128 : 0;
  return bits > 0 && Number(prefix) >= 0 && Number(prefix) <= bits;
}

function absoluteOrdinaryPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 1024 &&
    path.win32.isAbsolute(value) &&
    !value.startsWith('\\\\') &&
    !value.split(/[\\/]/).some((part) => part === '..' || part === '.')
  );
}

function within(parent: string, child: string): boolean {
  const base = path.win32.resolve(parent).toLowerCase();
  const target = path.win32.resolve(child).toLowerCase();
  return target === base || target.startsWith(`${base}\\`);
}

/** Validate the complete JSON contract before any paths or secrets are opened. */
export function parseWorkerServiceConfig(value: unknown): WorkerServiceConfig {
  exact(value, [
    'schema',
    'workerId',
    'bind',
    'storage',
    'trust',
    'credentials',
    'policy',
    'audit',
  ]);
  if (
    value.schema !== 1 ||
    !boundedString(value.workerId, 36) ||
    !isNonNilUuid(value.workerId) ||
    value.workerId !== value.workerId.toLowerCase()
  )
    invalid();

  exact(value.bind, ['mode', 'address', 'port', 'adapterGuid', 'peerCidrs']);
  if (
    (value.bind.mode !== 'local' && value.bind.mode !== 'remote') ||
    !boundedString(value.bind.address, 64) ||
    !integer(value.bind.port, 1024, 65535) ||
    !boundedString(value.bind.adapterGuid, 64, GUID)
  )
    invalid();
  if (
    !Array.isArray(value.bind.peerCidrs) ||
    value.bind.peerCidrs.length > 64 ||
    !value.bind.peerCidrs.every(validCidr)
  )
    invalid();
  try {
    validateBindAddress(value.bind.address, value.bind.mode);
  } catch {
    invalid();
  }

  exact(value.storage, ['root', 'volumeId', 'diskLimitBytes']);
  if (
    !absoluteOrdinaryPath(value.storage.root) ||
    !boundedString(value.storage.volumeId, 128, VOLUME_ID) ||
    !integer(value.storage.diskLimitBytes, 64 * 1024 * 1024, MAX_DISK_BYTES)
  )
    invalid();
  exact(value.trust, ['organizationSigningPublicKeyPath']);
  if (!absoluteOrdinaryPath(value.trust.organizationSigningPublicKeyPath)) invalid();
  exact(value.credentials, ['protectedBundlePath']);
  if (!absoluteOrdinaryPath(value.credentials.protectedBundlePath)) invalid();

  exact(value.policy, [
    'maxLimits',
    'pinnedTargetLockSha256',
    'pinnedA4ManifestSha256',
    'targetLockPath',
    'a4ManifestPath',
    'harnessPath',
    'allowedBinaryRoot',
    'allowedToolRoot',
    'allowedInputRoot',
    'outputRoot',
  ]);
  exact(value.policy.maxLimits, [
    'max_duration_s',
    'max_memory_bytes',
    'max_disk_bytes',
    'max_cpu_percent',
  ]);
  if (
    !integer(value.policy.maxLimits.max_duration_s, 1, 7 * 24 * 60 * 60) ||
    !integer(value.policy.maxLimits.max_memory_bytes, 16 * 1024 * 1024, MAX_DISK_BYTES) ||
    !integer(value.policy.maxLimits.max_disk_bytes, 64 * 1024 * 1024, MAX_DISK_BYTES) ||
    !integer(value.policy.maxLimits.max_cpu_percent, 1, 100) ||
    !SHA256.test(String(value.policy.pinnedTargetLockSha256)) ||
    !SHA256.test(String(value.policy.pinnedA4ManifestSha256))
  )
    invalid();
  for (const key of [
    'targetLockPath',
    'a4ManifestPath',
    'harnessPath',
    'allowedBinaryRoot',
    'allowedToolRoot',
    'allowedInputRoot',
    'outputRoot',
  ] as const) {
    if (!absoluteOrdinaryPath(value.policy[key])) invalid();
  }
  if (value.policy.maxLimits.max_disk_bytes !== value.storage.diskLimitBytes) invalid();
  if (
    !within(value.storage.root, value.policy.allowedInputRoot as string) ||
    !within(value.storage.root, value.policy.outputRoot as string)
  )
    invalid();

  exact(value.audit, ['maxBytes', 'maxSegmentBytes', 'maxSegments']);
  if (
    !integer(value.audit.maxBytes, 4096, Math.min(MAX_DISK_BYTES, value.storage.diskLimitBytes)) ||
    !integer(value.audit.maxSegmentBytes, 1024, value.audit.maxBytes) ||
    !integer(value.audit.maxSegments, 1, 4096) ||
    value.audit.maxSegmentBytes * value.audit.maxSegments > value.audit.maxBytes
  )
    invalid();

  return value as unknown as WorkerServiceConfig;
}

async function assertNoReparsePath(filePath: string, includeLeaf = true): Promise<void> {
  const resolved = path.win32.resolve(filePath);
  const parsed = path.win32.parse(resolved);
  const parts = resolved.slice(parsed.root.length).split(path.win32.sep).filter(Boolean);
  const systemRoot = process.env.SystemRoot ?? '';
  const fixedDataRoot = path.win32.join(
    path.win32.parse(systemRoot).root,
    'ProgramData',
    'SumatraFuzz',
    'Worker',
  );
  let current = parsed.root;
  for (const [index, part] of parts.entries()) {
    current = path.win32.join(current, part);
    if (!includeLeaf && index === parts.length - 1) break;
    const metadata = await lstat(current);
    // The fixed worker data directory is a dedicated NTFS volume mount point.
    // The native SCM host validates that this exact path resolves to a volume
    // root before it launches Node; no other reparse point is accepted here.
    const verifiedDataVolumeRoot =
      current.toLowerCase() === fixedDataRoot.toLowerCase() && metadata.isDirectory();
    if (
      (metadata.isSymbolicLink() && !verifiedDataVolumeRoot) ||
      (metadata.isDirectory() && (metadata.mode & 0o170000) !== 0o040000)
    )
      invalid();
    if (index < parts.length - 1 && !metadata.isDirectory()) invalid();
  }
}

async function readBoundedRegularFile(filePath: string, maxBytes: number): Promise<Buffer> {
  await assertNoReparsePath(filePath);
  const pathMetadata = await lstat(filePath);
  if (!pathMetadata.isFile() || pathMetadata.isSymbolicLink()) invalid();
  const handle = await open(filePath, 'r');
  try {
    const metadata = await handle.stat();
    const finalPathMetadata = await lstat(filePath);
    if (
      !metadata.isFile() ||
      metadata.size < 1 ||
      metadata.size > maxBytes ||
      !finalPathMetadata.isFile() ||
      finalPathMetadata.isSymbolicLink() ||
      (pathMetadata.ino !== 0 && metadata.ino !== pathMetadata.ino) ||
      (finalPathMetadata.ino !== 0 && metadata.ino !== finalPathMetadata.ino) ||
      pathMetadata.size !== metadata.size ||
      finalPathMetadata.size !== metadata.size
    )
      invalid();
    const bytes = await handle.readFile();
    if (bytes.length !== metadata.size || bytes.length > maxBytes) {
      bytes.fill(0);
      invalid();
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readOptionalBoundedRegularFile(
  filePath: string,
  maxBytes: number,
): Promise<Buffer | null> {
  try {
    await assertNoReparsePath(filePath);
    const metadata = await lstat(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maxBytes) invalid();
    if (metadata.size === 0) return Buffer.alloc(0);
    return await readBoundedRegularFile(filePath, maxBytes);
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      (error as Error & { code?: unknown }).code === 'ENOENT'
    )
      return null;
    throw error;
  }
}

async function replaceProtectedEnvelope(filePath: string, envelope: Buffer): Promise<void> {
  if (!Buffer.isBuffer(envelope) || envelope.length < 1 || envelope.length > CREDENTIAL_MAX_BYTES)
    invalid();
  await assertNoReparsePath(filePath);
  const before = await lstat(filePath);
  if (!before.isFile() || before.isSymbolicLink()) invalid();
  const handle = await open(filePath, 'r+');
  try {
    const opened = await handle.stat();
    const current = await lstat(filePath);
    if (
      !opened.isFile() ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      (before.ino !== 0 && opened.ino !== before.ino) ||
      (current.ino !== 0 && opened.ino !== current.ino)
    )
      invalid();
    await handle.truncate(0);
    let offset = 0;
    while (offset < envelope.length) {
      const written = await handle.write(envelope, offset, envelope.length - offset, offset);
      if (written.bytesWritten < 1) invalid();
      offset += written.bytesWritten;
    }
    await handle.sync();
    if ((await handle.stat()).size !== envelope.length) invalid();
  } finally {
    await handle.close();
  }
}

function parseJsonBytes(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
}

export interface WorkerServicePaths {
  readonly installRoot: string;
  readonly programDataRoot: string;
  readonly configPath: string;
  readonly signingKeyPath: string;
  readonly stagingRoot: string;
  readonly credentialStagePath: string;
  readonly pairingStagePath: string;
  readonly trustOperationStagePath: string;
}

/** All bootstrap paths are derived from the fixed packaged entrypoint and Windows system root. */
export function deriveWorkerServicePaths(
  entryFile: string,
  systemRoot: string,
): WorkerServicePaths {
  if (!path.win32.isAbsolute(entryFile) || !path.win32.isAbsolute(systemRoot)) invalid();
  const installRoot = path.win32.resolve(entryFile, '..', '..', '..', '..', '..');
  const drive = path.win32.parse(systemRoot).root;
  if (!drive) invalid();
  const programDataRoot = path.win32.join(drive, 'ProgramData', 'SumatraFuzz', 'Worker');
  return Object.freeze({
    installRoot,
    programDataRoot,
    configPath: path.win32.join(programDataRoot, 'worker-config.json'),
    signingKeyPath: path.win32.join(installRoot, 'config', 'organization-signing-public-key.pem'),
    stagingRoot: path.win32.join(programDataRoot, 'staging'),
    credentialStagePath: path.win32.join(programDataRoot, 'staging', 'worker-credentials.json'),
    pairingStagePath: path.win32.join(programDataRoot, 'staging', 'worker-pairing.sfpair'),
    trustOperationStagePath: path.win32.join(
      programDataRoot,
      'staging',
      'worker-trust-operation.sftxn',
    ),
  });
}

async function loadConfig(paths: WorkerServicePaths): Promise<WorkerServiceConfig> {
  const bytes = await readBoundedRegularFile(paths.configPath, CONFIG_MAX_BYTES);
  try {
    return parseWorkerServiceConfig(parseJsonBytes(bytes));
  } finally {
    bytes.fill(0);
  }
}

function requireEqualPath(configured: string, expected: string): void {
  if (path.win32.resolve(configured).toLowerCase() !== path.win32.resolve(expected).toLowerCase())
    invalid();
}

export function assertServiceBindReady(
  mode: BindMode,
  verifyRemoteBinding?: (adapterGuid: string, address: string) => void,
  adapterGuid?: string,
  address?: string,
): void {
  if (mode === 'remote') {
    if (!verifyRemoteBinding || !adapterGuid || !address)
      throw new Error('remote adapter ownership verification is unavailable');
    verifyRemoteBinding(adapterGuid, address);
  }
}

function requireConfigPaths(config: WorkerServiceConfig, paths: WorkerServicePaths): void {
  requireEqualPath(config.trust.organizationSigningPublicKeyPath, paths.signingKeyPath);
  requireEqualPath(
    config.credentials.protectedBundlePath,
    path.win32.join(paths.programDataRoot, 'credentials.dpapi'),
  );
  requireEqualPath(config.storage.root, paths.programDataRoot);
  if (
    !within(paths.installRoot, config.policy.targetLockPath) ||
    !within(paths.installRoot, config.policy.a4ManifestPath) ||
    !within(paths.installRoot, config.policy.harnessPath) ||
    !within(paths.installRoot, config.policy.allowedBinaryRoot) ||
    !within(paths.installRoot, config.policy.allowedToolRoot)
  )
    invalid();
  if (
    !within(config.storage.root, config.policy.allowedInputRoot) ||
    !within(config.storage.root, config.policy.outputRoot)
  )
    invalid();
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  const parent = path.win32.dirname(directory);
  await assertNoReparsePath(parent);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await assertNoReparsePath(directory);
}

async function removeStagingFile(filePath: string): Promise<void> {
  const bytes = await readOptionalBoundedRegularFile(filePath, PAIRING_MAX_BYTES);
  if (bytes === null) return;
  bytes.fill(0);
  await unlink(filePath);
}

function sameCredentials(
  left: { key: Buffer; certificate: Buffer; ca: Buffer },
  right: { key: Buffer; certificate: Buffer; ca: Buffer },
): boolean {
  return (
    left.key.equals(right.key) &&
    left.certificate.equals(right.certificate) &&
    left.ca.equals(right.ca)
  );
}

function parseCredentialDocument(bytes: Buffer): { key: Buffer; certificate: Buffer; ca: Buffer } {
  let value: unknown;
  try {
    value = parseJsonBytes(bytes);
    exact(value, ['schema', 'workerKeyPem', 'workerCertificatePem', 'clientCaPem']);
    if (
      value.schema !== 1 ||
      !boundedString(value.workerKeyPem, 256 * 1024) ||
      !PEM_PRIVATE_KEY.test(value.workerKeyPem) ||
      !boundedString(value.workerCertificatePem, 256 * 1024) ||
      !PEM_CERT.test(value.workerCertificatePem) ||
      !boundedString(value.clientCaPem, 256 * 1024) ||
      !PEM_CERT.test(value.clientCaPem)
    )
      invalid();
    return {
      key: Buffer.from(value.workerKeyPem, 'utf8'),
      certificate: Buffer.from(value.workerCertificatePem, 'utf8'),
      ca: Buffer.from(value.clientCaPem, 'utf8'),
    };
  } catch {
    throw new Error('invalid protected worker credentials');
  } finally {
    // The input buffer is owned by this loader; JS strings from JSON cannot be reliably zeroized.
    bytes.fill(0);
    if (isRecord(value)) {
      for (const property of ['workerKeyPem', 'workerCertificatePem', 'clientCaPem']) {
        if (typeof value[property] === 'string') value[property] = '';
      }
    }
  }
}

function validateCredentials(key: Buffer, certificate: Buffer, ca: Buffer): void {
  try {
    const privateKey = createPrivateKey(key);
    const leaf = validateEndpointCertificate(certificate, 'server');
    const root = new X509Certificate(ca);
    const privatePublicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    const certificatePublicDer = leaf.publicKey.export({ format: 'der', type: 'spki' });
    const now = Date.now();
    if (
      privateKey.type !== 'private' ||
      privateKey.asymmetricKeyType !== leaf.publicKey.asymmetricKeyType ||
      !Buffer.from(privatePublicDer).equals(Buffer.from(certificatePublicDer)) ||
      !root.ca ||
      !root.checkIssued(root) ||
      !root.verify(root.publicKey) ||
      now < Date.parse(root.validFrom) ||
      now >= Date.parse(root.validTo) ||
      !leaf.checkIssued(root) ||
      !leaf.verify(root.publicKey)
    )
      invalid();
    createSecureContext({ cert: certificate, key, minVersion: 'TLSv1.3' });
  } catch {
    throw new Error('worker endpoint credential validation failed');
  }
}

async function startWorkerService(): Promise<{ close(): Promise<void> }> {
  if (process.platform !== 'win32' || process.arch !== 'x64')
    throw new Error('unsupported worker service platform');
  const paths = deriveWorkerServicePaths(
    fileURLToPath(import.meta.url),
    process.env.SystemRoot ?? '',
  );
  const config = await loadConfig(paths);
  requireConfigPaths(config, paths);
  const supervisor = new WindowsJobSupervisor();
  supervisor.assertWorkerServiceIdentity();
  assertServiceBindReady(
    config.bind.mode,
    (adapterGuid, address) => supervisor.assertWorkerServiceNetworkBinding(adapterGuid, address),
    config.bind.adapterGuid,
    config.bind.address,
  );

  await assertNoReparsePath(config.storage.root);
  await ensurePrivateDirectory(path.win32.join(config.storage.root, 'state'));
  await ensurePrivateDirectory(path.win32.join(config.storage.root, 'security'));
  await ensurePrivateDirectory(path.win32.join(config.storage.root, 'security', 'audit'));
  await ensurePrivateDirectory(config.policy.allowedInputRoot);
  await ensurePrivateDirectory(config.policy.outputRoot);
  const protector = createDpapiCredentialProtector();
  let ciphertext: Buffer | undefined;
  let plaintext: Buffer | undefined;
  let stagedCredentialDocument: Buffer | undefined;
  let stagedPairingBundle: Buffer | null = null;
  let stagedTrustOperation: Buffer | null = null;
  let credentials: { key: Buffer; certificate: Buffer; ca: Buffer } | undefined;
  let stagedCredentials: { key: Buffer; certificate: Buffer; ca: Buffer } | undefined;
  let trust: SqliteWorkerTrustStore | undefined;
  let audit: FileSecurityAudit | undefined;
  try {
    const signingKey = await readBoundedRegularFile(paths.signingKeyPath, SIGNING_KEY_MAX_BYTES);
    let signingKeyPem: string;
    try {
      const key = createPublicKey(signingKey);
      if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') invalid();
      signingKeyPem = signingKey.toString('utf8');
    } finally {
      signingKey.fill(0);
    }
    const protectedExisting = await readOptionalBoundedRegularFile(
      config.credentials.protectedBundlePath,
      CREDENTIAL_MAX_BYTES,
    );
    stagedPairingBundle = await readOptionalBoundedRegularFile(
      paths.pairingStagePath,
      PAIRING_MAX_BYTES,
    );
    stagedTrustOperation = await readOptionalBoundedRegularFile(
      paths.trustOperationStagePath,
      PAIRING_MAX_BYTES,
    );
    if (stagedPairingBundle?.length && stagedTrustOperation?.length) invalid();
    if (protectedExisting?.length) {
      try {
        ciphertext = protectedExisting;
        plaintext = await protector.unprotect(ciphertext);
        if (
          !Buffer.isBuffer(plaintext) ||
          plaintext.length < 1 ||
          plaintext.length > CREDENTIAL_MAX_BYTES
        )
          invalid();
        credentials = parseCredentialDocument(plaintext);
        validateCredentials(credentials.key, credentials.certificate, credentials.ca);
      } catch {
        credentials?.key.fill(0);
        credentials?.certificate.fill(0);
        credentials?.ca.fill(0);
        credentials = undefined;
        plaintext?.fill(0);
        plaintext = undefined;
      }
    }
    if (protectedExisting && protectedExisting !== ciphertext) protectedExisting.fill(0);

    stagedCredentialDocument =
      (await readOptionalBoundedRegularFile(paths.credentialStagePath, CREDENTIAL_MAX_BYTES)) ??
      undefined;
    if (stagedCredentialDocument?.length) {
      stagedCredentials = parseCredentialDocument(Buffer.from(stagedCredentialDocument));
      validateCredentials(
        stagedCredentials.key,
        stagedCredentials.certificate,
        stagedCredentials.ca,
      );
      if (credentials && !sameCredentials(credentials, stagedCredentials)) {
        if (!stagedPairingBundle?.length) invalid();
        credentials.key.fill(0);
        credentials.certificate.fill(0);
        credentials.ca.fill(0);
        credentials = undefined;
      }
      if (!credentials) {
        const protectedEnvelope = await protector.protect(stagedCredentialDocument);
        try {
          await replaceProtectedEnvelope(config.credentials.protectedBundlePath, protectedEnvelope);
        } finally {
          protectedEnvelope.fill(0);
        }
        ciphertext?.fill(0);
        ciphertext = await readBoundedRegularFile(
          config.credentials.protectedBundlePath,
          CREDENTIAL_MAX_BYTES,
        );
        plaintext = await protector.unprotect(ciphertext);
        credentials = parseCredentialDocument(plaintext);
        validateCredentials(credentials.key, credentials.certificate, credentials.ca);
      }
    }
    if (!credentials) throw new Error('worker service activation is not provisioned');

    trust = SqliteWorkerTrustStore.open(
      path.win32.join(config.storage.root, 'security', 'trust.sqlite'),
    );
    audit = await FileSecurityAudit.open({
      directory: path.win32.join(config.storage.root, 'security', 'audit'),
      protector,
      ...config.audit,
    });
    const auditHealth = await audit.verifyAndRecover();
    if (auditHealth.state !== 'healthy') throw new Error('worker service audit is unavailable');
    if (stagedPairingBundle?.length) {
      await verifyAndProvisionPairingBundle(stagedPairingBundle, {
        expectedWorkerId: config.workerId,
        workerCertificatePem: credentials.certificate.toString('utf8'),
        trustedCaPem: credentials.ca.toString('utf8'),
        trustedOrgPublicKeys: [signingKeyPem],
        permissions: [
          'capabilities:read',
          'input-bundles:write',
          'runs:start',
          'runs:read',
          'runs:stop',
          'events:read',
          'artifacts:read',
        ],
        trust: new AuditedTrustAdministration(trust, audit),
      });
    }
    if (stagedTrustOperation?.length) {
      await verifyAndApplySignedTrustOperation(stagedTrustOperation, {
        expectedWorkerId: config.workerId,
        trustedOrgPublicKeys: [signingKeyPem],
        trust: new AuditedTrustAdministration(trust, audit),
      });
    }
    const now = new Date();
    const hasValidPairing = trust
      .listActive()
      .some((record) => trust?.resolveFingerprint(record.fingerprint, now) !== null);
    if (!hasValidPairing) throw new Error('worker service activation is not paired');
    // Staging is admin-owned and read/delete-only for this service SID. Delete before listen.
    await removeStagingFile(paths.credentialStagePath);
    await removeStagingFile(paths.pairingStagePath);
    await removeStagingFile(paths.trustOperationStagePath);
    const app = await createWorkerApplication({
      host: config.bind.address,
      mode: config.bind.mode,
      port: config.bind.port,
      workerId: config.workerId,
      expectedWorkerVolumeId: `\\\\?\\Volume${config.storage.volumeId.slice('volume'.length)}\\`,
      key: credentials.key,
      cert: credentials.certificate,
      ca: credentials.ca,
      trust,
      audit,
      policy: config.policy,
      inputRoot: config.policy.allowedInputRoot,
      databasePath: path.win32.join(config.storage.root, 'state', 'runs.sqlite'),
      supervisor,
      readWorkerVolumeUsage: async () => supervisor.sampleVolumeUsage(config.storage.root),
    });
    trust = undefined;
    audit = undefined;
    if (config.bind.mode === 'local') return app;
    const monitor = monitorNetworkBinding(
      () =>
        supervisor.assertWorkerServiceNetworkBinding(config.bind.adapterGuid, config.bind.address),
      () => app.server.close(),
    );
    return {
      async close() {
        const results = await Promise.allSettled([monitor.stop(), app.close()]);
        if (results.some((result) => result.status === 'rejected'))
          throw new Error('worker service shutdown failed');
      },
    };
  } catch (error) {
    trust?.close();
    await audit?.close().catch(() => {});
    throw error;
  } finally {
    ciphertext?.fill(0);
    plaintext?.fill(0);
    stagedCredentialDocument?.fill(0);
    stagedPairingBundle?.fill(0);
    stagedTrustOperation?.fill(0);
    credentials?.key.fill(0);
    credentials?.certificate.fill(0);
    credentials?.ca.fill(0);
    stagedCredentials?.key.fill(0);
    stagedCredentials?.certificate.fill(0);
    stagedCredentials?.ca.fill(0);
  }
}

export async function runWorkerServiceEntry(): Promise<void> {
  await runWorkerServiceControl(
    { input: process.stdin, output: process.stdout },
    startWorkerService,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void runWorkerServiceEntry().catch(() => {
    process.stderr.write('Worker service startup or shutdown failed\n');
    process.exitCode = 1;
  });
}
