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
  pairedFingerprints: ReadonlySet<string>,
  revokedFingerprints: ReadonlySet<string>,
  now = Date.now(),
): string {
  if (!peer?.authorized) throw new Error('client certificate is missing or not CA-authorized');
  const fingerprint = normalizeFingerprint(peer.fingerprint256);
  const validFrom = Date.parse(peer.validFrom);
  const validTo = Date.parse(peer.validTo);
  if (
    !Number.isFinite(validFrom) ||
    !Number.isFinite(validTo) ||
    now < validFrom ||
    now >= validTo
  ) {
    throw new Error('client certificate is expired or outside its validity period');
  }
  const revoked = new Set([...revokedFingerprints].map(normalizeFingerprint));
  if (revoked.has(fingerprint)) throw new Error('client certificate is revoked');
  const paired = new Set([...pairedFingerprints].map(normalizeFingerprint));
  if (!paired.has(fingerprint)) throw new Error('client certificate is unpaired');
  return fingerprint;
}
