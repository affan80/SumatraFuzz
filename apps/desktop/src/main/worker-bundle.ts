import { createPublicKey, type KeyObject, verify } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { validateWorkerProfile, type WorkerProfile } from './worker-profile-store.js';

const BUNDLE_FORMAT = 'sumatrafuzz-worker-pairing-bundle-v1';
const PAYLOAD_FORMAT = 'sumatrafuzz-worker-pairing-payload-v1';
export const MAX_BUNDLE_BYTES = 1024 * 1024;
const MAX_SIGNING_KEY_FILE_BYTES = 16 * 1024;
const MAX_BUNDLE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export interface VerifiedWorkerBundle {
  readonly profile: WorkerProfile;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

function parseJson(value: Buffer, errorMessage: string): unknown {
  try {
    return JSON.parse(value.toString('utf8')) as unknown;
  } catch {
    throw new TypeError(errorMessage);
  }
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function decodeBase64(value: unknown, field: string, maxBytes: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || !BASE64.test(value)) {
    throw new TypeError(`worker pairing bundle ${field} is invalid`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new TypeError(`worker pairing bundle ${field} is invalid`);
  }
  return bytes;
}

function parseTimestamp(value: unknown, field: string): Date {
  if (typeof value !== 'string') throw new TypeError(`worker pairing bundle ${field} is invalid`);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    throw new TypeError(`worker pairing bundle ${field} is invalid`);
  }
  return date;
}

/** Load the packaged public trust root; never fall back to an unsigned or development key. */
export async function loadTrustedWorkerBundleSigningKey(filePath: string): Promise<string> {
  const metadata = await lstat(filePath).catch(() => {
    throw new Error('trusted worker bundle signing key is not configured');
  });
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > MAX_SIGNING_KEY_FILE_BYTES
  ) {
    throw new Error('trusted worker bundle signing key file is invalid');
  }
  const contents = await readFile(filePath);
  if (contents.length !== metadata.size || contents.includes(0)) {
    throw new Error('trusted worker bundle signing key file is invalid');
  }
  const pem = contents.toString('utf8');
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('trusted worker bundle signing key must be Ed25519');
    }
    return key.export({ type: 'spki', format: 'pem' }).toString();
  } catch (error) {
    if (error instanceof Error && error.message.includes('must be Ed25519')) throw error;
    throw new Error('trusted worker bundle signing key file is invalid');
  }
}

/** Verify the exact signed payload bytes before parsing or using credential material. */
export function verifyWorkerPairingBundle(
  bundleBytes: Buffer,
  trustedSigningPublicKeyPem: string,
  now = new Date(),
): VerifiedWorkerBundle {
  if (bundleBytes.length === 0 || bundleBytes.length > MAX_BUNDLE_BYTES) {
    throw new TypeError('worker pairing bundle size is invalid');
  }
  const envelope = parseJson(bundleBytes, 'worker pairing bundle is invalid');
  if (
    !exactObject(envelope, ['format', 'payload', 'signature']) ||
    envelope.format !== BUNDLE_FORMAT
  ) {
    throw new TypeError('worker pairing bundle is invalid');
  }
  const payloadBytes = decodeBase64(envelope.payload, 'payload', MAX_BUNDLE_BYTES);
  const signature = decodeBase64(envelope.signature, 'signature', 128);
  if (signature.length !== 64) throw new TypeError('worker pairing bundle signature is invalid');

  let trustedKey: KeyObject;
  try {
    trustedKey = createPublicKey(trustedSigningPublicKeyPem);
  } catch {
    throw new Error('trusted worker bundle signing key is unavailable or invalid');
  }
  if (trustedKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('trusted worker bundle signing key must be Ed25519');
  }
  let signatureValid = false;
  try {
    signatureValid = verify(null, payloadBytes, trustedKey, signature);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) throw new Error('worker pairing bundle signature verification failed');

  const payload = parseJson(payloadBytes, 'signed worker pairing payload is invalid');
  if (
    !exactObject(payload, ['format', 'issuedAt', 'expiresAt', 'profile']) ||
    payload.format !== PAYLOAD_FORMAT
  ) {
    throw new TypeError('signed worker pairing payload is invalid');
  }
  const issuedAt = parseTimestamp(payload.issuedAt, 'issuedAt');
  const expiresAt = parseTimestamp(payload.expiresAt, 'expiresAt');
  const currentTime = now.getTime();
  if (
    issuedAt.getTime() > currentTime + CLOCK_SKEW_MS ||
    expiresAt.getTime() <= currentTime ||
    expiresAt.getTime() <= issuedAt.getTime() ||
    expiresAt.getTime() - issuedAt.getTime() > MAX_BUNDLE_LIFETIME_MS
  ) {
    throw new Error('worker pairing bundle is expired or outside its validity window');
  }

  return { profile: validateWorkerProfile(payload.profile), issuedAt, expiresAt };
}
