import { describe, expect, it } from 'vitest';
import { authorizePairedCertificate, type PeerCertificateIdentity } from '../src/auth.js';

const now = Date.parse('2026-10-19T00:00:00.000Z');
const peer: PeerCertificateIdentity = {
  fingerprint256:
    '11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00',
  validFrom: 'Oct 18 00:00:00 2026 GMT',
  validTo: 'Oct 20 00:00:00 2026 GMT',
  authorized: true,
};

describe('explicit worker certificate pairing', () => {
  it('accepts only an unexpired, TLS-authorized, explicitly paired client fingerprint', () => {
    const fingerprint = peer.fingerprint256.replaceAll(':', '').toLowerCase();
    expect(() =>
      authorizePairedCertificate(peer, new Set([fingerprint]), new Set(), now),
    ).not.toThrow();
    expect(() => authorizePairedCertificate(peer, new Set(), new Set(), now)).toThrow(/unpaired/i);
    expect(() =>
      authorizePairedCertificate(
        { ...peer, authorized: false },
        new Set([fingerprint]),
        new Set(),
        now,
      ),
    ).toThrow(/certificate/i);
    expect(() =>
      authorizePairedCertificate(peer, new Set([fingerprint]), new Set([fingerprint]), now),
    ).toThrow(/revoked/i);
  });

  it('rejects expired certificates with a fail-closed time check', () => {
    const fingerprint = peer.fingerprint256.replaceAll(':', '').toLowerCase();
    expect(() =>
      authorizePairedCertificate(
        { ...peer, validTo: 'Oct 18 00:00:00 2026 GMT' },
        new Set([fingerprint]),
        new Set(),
        now,
      ),
    ).toThrow(/expired/i);
  });
});
