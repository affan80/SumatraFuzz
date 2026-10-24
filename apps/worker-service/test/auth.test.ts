import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { authorizePairedCertificate, type PeerCertificateIdentity } from '../src/auth.js';
import { SqliteWorkerTrustStore } from '../src/trust-store.js';

const now = Date.parse('2026-10-19T00:00:00.000Z');
const peer: PeerCertificateIdentity = {
  fingerprint256:
    '11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00',
  validFrom: 'Oct 18 00:00:00 2026 GMT',
  validTo: 'Oct 20 00:00:00 2026 GMT',
  authorized: true,
};
const fingerprint = peer.fingerprint256.replaceAll(':', '').toLowerCase();
const controllerId = '22222222-2222-4222-8222-222222222222';
const fixtures: { root: string; trust: SqliteWorkerTrustStore }[] = [];
async function trustFixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-live-auth-'));
  const trust = SqliteWorkerTrustStore.open(path.join(root, 'trust.db'));
  fixtures.push({ root, trust });
  trust.provision({
    fingerprint,
    controllerId,
    permissions: ['runs:read'],
    notBefore: '2026-10-18T00:00:00.000Z',
    notAfter: '2026-10-20T00:00:00.000Z',
  });
  return trust;
}
afterEach(async () => {
  for (const { root, trust } of fixtures.splice(0)) {
    trust.close();
    await rm(root, { recursive: true, force: true });
  }
});

describe('current persistent worker certificate authorization', () => {
  it('returns only the current certificate binding and explicit permissions', async () => {
    const trust = await trustFixture();
    expect(authorizePairedCertificate(peer, trust, now)).toMatchObject({
      fingerprint,
      controllerId,
      permissions: ['runs:read'],
      revision: 1,
    });
    trust.revoke(fingerprint);
    expect(() => authorizePairedCertificate(peer, trust, now)).toThrow();
  });
  it('rejects absent, unpaired and non-CA-authorized peer identities', async () => {
    const trust = await trustFixture();
    expect(() => authorizePairedCertificate(null, trust, now)).toThrow();
    expect(() => authorizePairedCertificate({ ...peer, authorized: false }, trust, now)).toThrow();
    expect(() =>
      authorizePairedCertificate({ ...peer, fingerprint256: 'a'.repeat(64) }, trust, now),
    ).toThrow();
  });
  it('rejects invalid time and expired TLS/trust records with exclusive not-after', async () => {
    const trust = await trustFixture();
    expect(() => authorizePairedCertificate(peer, trust, Number.NaN)).toThrow();
    expect(() =>
      authorizePairedCertificate(peer, trust, Date.parse('2026-10-20T00:00:00.000Z')),
    ).toThrow();
    expect(() =>
      authorizePairedCertificate({ ...peer, validTo: 'Oct 18 00:00:00 2026 GMT' }, trust, now),
    ).toThrow();
    expect(() => authorizePairedCertificate({ ...peer, validFrom: 'bad' }, trust, now)).toThrow();
  });
});
