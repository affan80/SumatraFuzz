import { isNonNilUuid } from '@sumatrafuzz/worker-protocol';
import type { TrustRecord, WorkerTrustRepository } from './trust-store.js';

export interface PeerCertificateIdentity {
  readonly fingerprint256: string;
  readonly validFrom: string;
  readonly validTo: string;
  readonly authorized: boolean;
}

function normalizeFingerprint(value: string): string {
  const normalized = value.replaceAll(':', '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error('invalid client certificate fingerprint');
  return normalized;
}

export function authorizePairedCertificate(
  peer: PeerCertificateIdentity | null,
  trust: Pick<WorkerTrustRepository, 'resolveFingerprint'>,
  now = Date.now(),
): TrustRecord {
  if (!peer?.authorized) throw new Error('client certificate is missing or not CA-authorized');
  const fingerprint = normalizeFingerprint(peer.fingerprint256);
  const validFrom = Date.parse(peer.validFrom);
  const validTo = Date.parse(peer.validTo);
  if (
    !Number.isFinite(now) ||
    !Number.isFinite(validFrom) ||
    !Number.isFinite(validTo) ||
    now < validFrom ||
    now >= validTo
  ) {
    throw new Error('client certificate is expired or outside its validity period');
  }
  const record = trust.resolveFingerprint(fingerprint, new Date(now));
  if (
    !record ||
    record.fingerprint !== fingerprint ||
    record.status !== 'active' ||
    !isNonNilUuid(record.controllerId)
  ) {
    throw new Error('client certificate is unpaired or revoked');
  }
  return record;
}
