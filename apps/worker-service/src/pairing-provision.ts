import {
  createPrivateKey,
  createPublicKey,
  type KeyObject,
  verify,
  X509Certificate,
} from 'node:crypto';
import { WindowsJobSupervisor } from '@sumatrafuzz/worker-core';
import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';
import { validateEndpointCertificate } from '@sumatrafuzz/worker-security';
import type { AuditedTrustAdministration } from './audited-trust-administration.js';
import type { TrustPermission, TrustRecord } from './trust-store.js';

/** All expected values are supplied by protected service configuration, never HTTP/renderer input. */
export interface PairingProvisionContext {
  readonly expectedWorkerId: string;
  readonly workerCertificatePem: string;
  readonly trustedCaPem: string;
  readonly trustedOrgPublicKeys: readonly string[];
  readonly permissions: readonly TrustPermission[];
  readonly trust: AuditedTrustAdministration;
}
export interface CredentialProtector {
  protect(plaintext: Buffer): Promise<Buffer>;
  unprotect(ciphertext: Buffer): Promise<Buffer>;
}
const MAX_BUNDLE_BYTES = 1024 * 1024;
const MAX_PROFILE_BYTES = 512 * 1024;
const MAX_SECRET_BYTES = 256 * 1024;
const MAX_LIFETIME_MS = 7 * 86400_000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const allowedPermissions: ReadonlySet<string> = new Set<TrustPermission>([
  'capabilities:read',
  'input-bundles:write',
  'runs:start',
  'runs:read',
  'runs:stop',
  'events:read',
  'artifacts:read',
]);
const profileKeys = [
  'workerId',
  'controllerId',
  'baseUrl',
  'workerFingerprint',
  'controllerCertificatePem',
  'controllerPrivateKeyPem',
  'trustedCaPem',
];

function requireCondition(value: unknown): asserts value {
  if (!value) throw new Error('invalid pairing evidence');
}
function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  requireCondition(value && typeof value === 'object' && !Array.isArray(value));
  const actual = Object.keys(value);
  requireCondition(actual.length === keys.length && actual.every((key) => keys.includes(key)));
}
function parse(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
}
function decode(value: unknown, max: number): Buffer {
  requireCondition(typeof value === 'string' && value.length > 0 && BASE64.test(value));
  const bytes = Buffer.from(value, 'base64');
  if (!bytes.length || bytes.length > max || bytes.toString('base64') !== value) {
    bytes.fill(0);
    throw new Error('invalid pairing encoding');
  }
  return bytes;
}
function time(value: unknown): number {
  requireCondition(typeof value === 'string');
  const result = Date.parse(value);
  requireCondition(Number.isFinite(result) && new Date(result).toISOString() === value);
  return result;
}
function validUuid(value: unknown): value is string {
  return typeof value === 'string' && isNonNilUuid(value) && value.toLowerCase() === value;
}
function oneCertificate(value: unknown): X509Certificate {
  requireCondition(
    typeof value === 'string' &&
      value.length <= MAX_SECRET_BYTES &&
      /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(
        value,
      ),
  );
  return new X509Certificate(value);
}
function fingerprint(value: X509Certificate): string {
  return value.fingerprint256.replaceAll(':', '').toLowerCase();
}
function roots(value: readonly string[]): readonly KeyObject[] {
  requireCondition(Array.isArray(value) && value.length >= 1 && value.length <= 16);
  return value.map((pem) => {
    requireCondition(
      typeof pem === 'string' &&
        pem.length <= 16 * 1024 &&
        /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$/.test(pem),
    );
    const key = createPublicKey(pem);
    requireCondition(key.type === 'public' && key.asymmetricKeyType === 'ed25519');
    return key;
  });
}
function assertIssuedBy(leaf: X509Certificate, ca: X509Certificate): void {
  requireCondition(leaf.checkIssued(ca) && leaf.verify(ca.publicKey));
}

/**
 * Consumes and clears bundle bytes on success/failure. The v1 controller private key is
 * ignored, never imported or returned. JSON/crypto string copies cannot be securely erased.
 * This operator helper has no listener or network enrollment side effects.
 */
export async function verifyAndProvisionPairingBundle(
  bundle: Buffer,
  context: PairingProvisionContext,
  now = new Date(),
): Promise<TrustRecord> {
  let payloadBytes: Buffer | undefined;
  let signature: Buffer | undefined;
  try {
    requireCondition(
      Buffer.isBuffer(bundle) && bundle.length > 0 && bundle.length <= MAX_BUNDLE_BYTES,
    );
    exact(context, [
      'expectedWorkerId',
      'workerCertificatePem',
      'trustedCaPem',
      'trustedOrgPublicKeys',
      'permissions',
      'trust',
    ]);
    requireCondition(
      validUuid(context.expectedWorkerId) && now instanceof Date && Number.isFinite(now.getTime()),
    );
    requireCondition(
      Array.isArray(context.permissions) &&
        context.permissions.length <= allowedPermissions.size &&
        new Set(context.permissions).size === context.permissions.length &&
        context.permissions.every(
          (permission) => typeof permission === 'string' && allowedPermissions.has(permission),
        ),
    );
    requireCondition(context.trust && typeof context.trust.provision === 'function');
    const trustedRoots = roots(context.trustedOrgPublicKeys);
    const worker = oneCertificate(context.workerCertificatePem);
    validateEndpointCertificate(worker.raw, 'server', now);
    const ca = oneCertificate(context.trustedCaPem);
    requireCondition(
      ca.ca &&
        ca.checkIssued(ca) &&
        ca.verify(ca.publicKey) &&
        Date.parse(ca.validFrom) <= now.getTime() &&
        now.getTime() < Date.parse(ca.validTo),
    );
    assertIssuedBy(worker, ca);

    const envelope = parse(bundle);
    exact(envelope, ['format', 'payload', 'signature']);
    requireCondition(envelope.format === 'sumatrafuzz-worker-pairing-bundle-v1');
    payloadBytes = decode(envelope.payload, MAX_BUNDLE_BYTES);
    signature = decode(envelope.signature, 64);
    requireCondition(
      signature.length === 64 &&
        trustedRoots.some((key) => verify(null, payloadBytes as Buffer, key, signature as Buffer)),
    );
    const payload = parse(payloadBytes);
    exact(payload, ['format', 'issuedAt', 'expiresAt', 'profile']);
    requireCondition(payload.format === 'sumatrafuzz-worker-pairing-payload-v1');
    const issuedAt = time(payload.issuedAt);
    const expiresAt = time(payload.expiresAt);
    requireCondition(
      issuedAt <= now.getTime() + CLOCK_SKEW_MS &&
        now.getTime() < expiresAt &&
        expiresAt > issuedAt &&
        expiresAt - issuedAt <= MAX_LIFETIME_MS,
    );
    const profile = payload.profile;
    exact(profile, profileKeys);
    requireCondition(Buffer.byteLength(JSON.stringify(profile), 'utf8') <= MAX_PROFILE_BYTES);
    requireCondition(
      validUuid(profile.workerId) &&
        profile.workerId === context.expectedWorkerId &&
        validUuid(profile.controllerId),
    );
    requireCondition(typeof profile.baseUrl === 'string' && profile.baseUrl.length <= 2048);
    const url = new URL(profile.baseUrl);
    requireCondition(
      url.protocol === 'https:' &&
        !url.username &&
        !url.password &&
        url.pathname === '/' &&
        !url.search &&
        !url.hash,
    );
    requireCondition(
      typeof profile.workerFingerprint === 'string' &&
        /^(?:[0-9a-f]{64}|(?:[0-9a-f]{2}:){31}[0-9a-f]{2})$/i.test(profile.workerFingerprint),
    );
    requireCondition(
      profile.workerFingerprint.replaceAll(':', '').toLowerCase() === fingerprint(worker),
    );
    const signedCa = oneCertificate(profile.trustedCaPem);
    requireCondition(signedCa.raw.equals(ca.raw));
    // Only shape-check the ignored desktop credential. Never turn it into a KeyObject.
    requireCondition(
      typeof profile.controllerPrivateKeyPem === 'string' &&
        profile.controllerPrivateKeyPem.length <= MAX_SECRET_BYTES &&
        /^-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s*$/.test(
          profile.controllerPrivateKeyPem,
        ),
    );
    delete profile.controllerPrivateKeyPem;
    const client = oneCertificate(profile.controllerCertificatePem);
    validateEndpointCertificate(client.raw, 'client', now);
    assertIssuedBy(client, ca);
    // The verified payload binds the certificate bytes to the signed controller UUID.
    const trustInput = {
      fingerprint: fingerprint(client),
      controllerId: profile.controllerId,
      permissions: [...context.permissions],
      notBefore: new Date(client.validFrom).toISOString(),
      notAfter: new Date(client.validTo).toISOString(),
    };
    const current = context.trust
      .listActive()
      .find((record) => record.controllerId === profile.controllerId);
    if (current && current.fingerprint !== trustInput.fingerprint) {
      const overlapUntil = new Date(
        Math.min(now.getTime() + 60 * 60 * 1000, Date.parse(current.notAfter)),
      );
      if (overlapUntil.getTime() <= now.getTime())
        throw new Error('pairing rotation overlap is unavailable');
      return await context.trust.rotate(trustInput, overlapUntil, now);
    }
    return await context.trust.provision(trustInput);
  } catch {
    // Never attach input, certificate bodies, private keys or underlying exception causes.
    throw new Error('Worker pairing provisioning failed');
  } finally {
    payloadBytes?.fill(0);
    signature?.fill(0);
    if (Buffer.isBuffer(bundle)) bundle.fill(0);
  }
}

/** Protect only the actual worker key. Consumes plaintext; persistence/staging ACLs are caller-owned. */
export async function protectWorkerPrivateKey(
  plaintext: Buffer,
  workerCertificate: Buffer | string,
  protector: CredentialProtector,
  now = new Date(),
): Promise<Buffer> {
  try {
    requireCondition(
      Buffer.isBuffer(plaintext) && plaintext.length > 0 && plaintext.length <= MAX_SECRET_BYTES,
    );
    const worker = validateEndpointCertificate(workerCertificate, 'server', now);
    const key = createPrivateKey(plaintext);
    requireCondition(worker.checkPrivateKey(key));
    const ciphertext = await protector.protect(plaintext);
    requireCondition(
      Buffer.isBuffer(ciphertext) &&
        ciphertext.length > 0 &&
        ciphertext.length <= MAX_BUNDLE_BYTES &&
        !ciphertext.equals(plaintext),
    );
    return Buffer.from(ciphertext);
  } catch {
    throw new Error('Worker credential protection failed');
  } finally {
    if (Buffer.isBuffer(plaintext)) plaintext.fill(0);
  }
}

export interface SignedTrustOperationContext {
  readonly expectedWorkerId: string;
  readonly trustedOrgPublicKeys: readonly string[];
  readonly trust: AuditedTrustAdministration;
}

/** Apply an organization-signed, short-lived administrator transaction from protected staging. */
export async function verifyAndApplySignedTrustOperation(
  bundle: Buffer,
  context: SignedTrustOperationContext,
  now = new Date(),
): Promise<void> {
  let payloadBytes: Buffer | undefined;
  let signature: Buffer | undefined;
  try {
    requireCondition(
      Buffer.isBuffer(bundle) && bundle.length > 0 && bundle.length <= MAX_BUNDLE_BYTES,
    );
    exact(context, ['expectedWorkerId', 'trustedOrgPublicKeys', 'trust']);
    requireCondition(
      validUuid(context.expectedWorkerId) && now instanceof Date && Number.isFinite(now.getTime()),
    );
    requireCondition(
      context.trust &&
        typeof context.trust.revoke === 'function' &&
        typeof context.trust.unpair === 'function',
    );
    const trustedRoots = roots(context.trustedOrgPublicKeys);
    const envelope = parse(bundle);
    exact(envelope, ['format', 'payload', 'signature']);
    requireCondition(envelope.format === 'sumatrafuzz-worker-pairing-bundle-v1');
    payloadBytes = decode(envelope.payload, MAX_BUNDLE_BYTES);
    signature = decode(envelope.signature, 64);
    requireCondition(
      signature.length === 64 &&
        trustedRoots.some((key) => verify(null, payloadBytes as Buffer, key, signature as Buffer)),
    );
    const payload = parse(payloadBytes);
    exact(payload, ['format', 'workerId', 'issuedAt', 'expiresAt', 'operation']);
    requireCondition(payload.format === 'sumatrafuzz-worker-trust-operation-v1');
    requireCondition(payload.workerId === context.expectedWorkerId);
    const issuedAt = time(payload.issuedAt);
    const expiresAt = time(payload.expiresAt);
    requireCondition(
      issuedAt <= now.getTime() + CLOCK_SKEW_MS &&
        now.getTime() < expiresAt &&
        expiresAt > issuedAt &&
        expiresAt - issuedAt <= 60 * 60 * 1000,
    );
    const operation = payload.operation;
    exact(operation, ['type', 'controllerId', 'fingerprint']);
    requireCondition(validUuid(operation.controllerId));
    const active = context.trust
      .listActive()
      .filter((record) => record.controllerId === operation.controllerId);
    if (operation.type === 'revoke_certificate') {
      requireCondition(
        typeof operation.fingerprint === 'string' &&
          /^[0-9a-f]{64}$/.test(operation.fingerprint) &&
          active.some((record) => record.fingerprint === operation.fingerprint),
      );
      await context.trust.revoke(operation.fingerprint as string);
    } else if (operation.type === 'unpair_controller') {
      requireCondition(operation.fingerprint === null && active.length > 0);
      await context.trust.unpair(operation.controllerId as string);
    } else {
      requireCondition(false);
    }
  } catch {
    throw new Error('Worker trust operation failed');
  } finally {
    payloadBytes?.fill(0);
    signature?.fill(0);
    bundle.fill(0);
  }
}

/** Current-user DPAPI: the service must invoke this under its configured service identity. */
export function createDpapiCredentialProtector(): CredentialProtector {
  const run = async (
    input: Buffer,
    operation: 'protectSecret' | 'unprotectSecret',
  ): Promise<Buffer> => {
    try {
      requireCondition(
        Buffer.isBuffer(input) && input.length > 0 && input.length <= MAX_BUNDLE_BYTES,
      );
      const supervisor = new WindowsJobSupervisor();
      const output = supervisor[operation](input);
      requireCondition(
        Buffer.isBuffer(output) &&
          output.length > 0 &&
          output.length <= MAX_BUNDLE_BYTES &&
          !output.equals(input),
      );
      return output;
    } catch {
      throw new Error('Worker DPAPI operation failed');
    }
  };
  return {
    protect: (plaintext) => run(plaintext, 'protectSecret'),
    unprotect: (ciphertext) => run(ciphertext, 'unprotectSecret'),
  };
}
