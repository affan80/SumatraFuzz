import { generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createTlsFixture, issueCertificate } from '@sumatrafuzz/worker-security/test-fixtures';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuditedTrustAdministration } from '../src/audited-trust-administration.js';
import {
  createDpapiCredentialProtector,
  type PairingProvisionContext,
  protectWorkerPrivateKey,
  verifyAndApplySignedTrustOperation,
  verifyAndProvisionPairingBundle,
} from '../src/pairing-provision.js';
import type { AuditRecord, SecurityAudit } from '../src/security-audit.js';
import { SqliteWorkerTrustStore } from '../src/trust-store.js';

const workerId = '11111111-1111-4111-8111-111111111111';
const controllerId = '22222222-2222-4222-8222-222222222222';
const signer = generateKeyPairSync('ed25519');
const rotatedSigner = generateKeyPairSync('ed25519');
const publicPem = (key = signer.publicKey) =>
  key.export({ type: 'spki', format: 'pem' }).toString();
let root: string;
let tls: Awaited<ReturnType<typeof createTlsFixture>>;
let otherTls: typeof tls;
let now: Date;
let weak: Buffer;
let wrongUsage: Buffer;
let expired: Buffer;
const stores: SqliteWorkerTrustStore[] = [];
const dbPaths: string[] = [];
let serial = 0;
const pin = (cert: Buffer) =>
  new X509Certificate(cert).fingerprint256.replaceAll(':', '').toLowerCase();

function memoryAudit(): SecurityAudit {
  let sequence = 0;
  let state: 'healthy' | 'closed' = 'healthy';
  const audit: SecurityAudit = {
    get health() {
      return { state, reason: 'none' as const, sequence };
    },
    async append(_record: AuditRecord) {
      if (state !== 'healthy') throw new Error('audit closed');
      return ++sequence;
    },
    async verifyAndRecover() {
      return audit.health;
    },
    async close() {
      state = 'closed';
    },
  };
  return audit;
}

function profile(overrides: Record<string, unknown> = {}) {
  return {
    workerId,
    controllerId,
    baseUrl: 'https://127.0.0.1:9443',
    workerFingerprint: pin(tls.workerCert),
    controllerCertificatePem: tls.clientCert.toString(),
    controllerPrivateKeyPem: tls.clientKey.toString(),
    trustedCaPem: tls.ca.toString(),
    ...overrides,
  };
}
function bundle(
  overrides: Record<string, unknown> = {},
  payloadOverrides: Record<string, unknown> = {},
  key = signer.privateKey,
) {
  const payload = Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-payload-v1',
      issuedAt: new Date(now.getTime() - 1000).toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      profile: profile(overrides),
      ...payloadOverrides,
    }),
  );
  return Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-bundle-v1',
      payload: payload.toString('base64'),
      signature: sign(null, payload, key).toString('base64'),
    }),
  );
}
function trustOperation(type: 'revoke_certificate' | 'unpair_controller', fingerprint?: string) {
  const payload = Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-trust-operation-v1',
      workerId,
      issuedAt: new Date(now.getTime() - 1000).toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      operation: {
        type,
        controllerId,
        fingerprint: fingerprint ?? null,
      },
    }),
  );
  return Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-bundle-v1',
      payload: payload.toString('base64'),
      signature: sign(null, payload, signer.privateKey).toString('base64'),
    }),
  );
}
function context(
  overrides: Omit<Partial<PairingProvisionContext>, 'trust'> = {},
): PairingProvisionContext & { store: SqliteWorkerTrustStore } {
  const name = path.join(root, `trust-${serial++}.db`);
  dbPaths.push(name);
  const trust = SqliteWorkerTrustStore.open(name);
  stores.push(trust);
  const value: PairingProvisionContext = {
    expectedWorkerId: workerId,
    workerCertificatePem: tls.workerCert.toString(),
    trustedCaPem: tls.ca.toString(),
    trustedOrgPublicKeys: [publicPem()],
    permissions: ['runs:read'],
    trust: new AuditedTrustAdministration(trust, memoryAudit()),
    ...overrides,
  };
  Object.defineProperty(value, 'store', { value: trust });
  return value as PairingProvisionContext & { store: SqliteWorkerTrustStore };
}
beforeAll(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'sf-worker-provision-'));
  tls = await createTlsFixture(root);
  const otherRoot = await mkdtemp(path.join(root, 'other-'));
  otherTls = await createTlsFixture(otherRoot);
  now = new Date();
  weak = (
    await issueCertificate(
      root,
      'weak-client',
      'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n',
      ['-newkey', 'rsa:1024'],
    )
  ).cert;
  wrongUsage = (
    await issueCertificate(
      root,
      'bad-usage',
      'basicConstraints=CA:FALSE\nkeyUsage=keyEncipherment\nextendedKeyUsage=clientAuth\n',
    )
  ).cert;
  expired = (
    await issueCertificate(
      root,
      'expired-client',
      'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n',
      ['-newkey', 'rsa:2048'],
      '-1',
    )
  ).cert;
});
afterEach(() => {
  for (const store of stores.splice(0)) store.close();
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

async function rejectsUnchanged(bytes: Buffer, ctx = context()) {
  const before = ctx.store.listActive();
  const revision = ctx.store.revision;
  await expect(verifyAndProvisionPairingBundle(bytes, ctx, now)).rejects.toThrow();
  expect(ctx.store.revision).toBe(revision);
  expect(ctx.store.listActive()).toEqual(before);
  expect(bytes.every((byte) => byte === 0)).toBe(true);
}

describe('worker independently verifies signed pairing evidence', () => {
  it('provisions only the signed certificate/controller binding and explicit service permissions', async () => {
    const ctx = context();
    const bytes = bundle();
    const record = await verifyAndProvisionPairingBundle(bytes, ctx, now);
    expect(record).toMatchObject({
      controllerId,
      fingerprint: tls.fingerprint,
      permissions: ['runs:read'],
      generation: 1,
      revision: 1,
    });
    expect(record.notBefore).toBe(
      new Date(new X509Certificate(tls.clientCert).validFrom).toISOString(),
    );
    expect(record.notAfter).toBe(
      new Date(new X509Certificate(tls.clientCert).validTo).toISOString(),
    );
    expect(ctx.store.resolveFingerprint(tls.fingerprint, now)).toEqual(record);
    expect(bytes.every((byte) => byte === 0)).toBe(true);
    expect(JSON.stringify(record)).not.toContain('PRIVATE KEY');
    const name = dbPaths.at(-1) as string;
    ctx.store.unpair(controllerId);
    stores.at(-1)?.close();
    const persisted = await readFile(name);
    expect(persisted.includes(tls.clientKey)).toBe(false);
    expect(persisted.includes(Buffer.from('PRIVATE KEY'))).toBe(false);
  });

  it('applies signed certificate revocation and controller unpair transactions through audit', async () => {
    const value = context();
    await verifyAndProvisionPairingBundle(bundle(), value, now);
    const fingerprint = pin(tls.clientCert);
    await verifyAndApplySignedTrustOperation(
      trustOperation('revoke_certificate', fingerprint),
      {
        expectedWorkerId: workerId,
        trustedOrgPublicKeys: [publicPem()],
        trust: value.trust as AuditedTrustAdministration,
      },
      now,
    );
    expect(value.store.resolveFingerprint(fingerprint, now)).toBeNull();

    const second = context();
    await verifyAndProvisionPairingBundle(bundle(), second, now);
    await verifyAndApplySignedTrustOperation(
      trustOperation('unpair_controller'),
      {
        expectedWorkerId: workerId,
        trustedOrgPublicKeys: [publicPem()],
        trust: second.trust as AuditedTrustAdministration,
      },
      now,
    );
    expect(second.store.resolveFingerprint(fingerprint, now)).toBeNull();
  });

  it('rejects an unsigned or wrong-worker trust transaction and consumes the bytes', async () => {
    const value = context();
    await verifyAndProvisionPairingBundle(bundle(), value, now);
    const transaction = trustOperation('revoke_certificate', pin(tls.clientCert));
    const signatureByte = transaction.length - 4;
    transaction[signatureByte] = (transaction[signatureByte] ?? 0) ^ 1;
    await expect(
      verifyAndApplySignedTrustOperation(
        transaction,
        {
          expectedWorkerId: workerId,
          trustedOrgPublicKeys: [publicPem()],
          trust: value.trust as AuditedTrustAdministration,
        },
        now,
      ),
    ).rejects.toThrow('Worker trust operation failed');
    expect(transaction.every((byte) => byte === 0)).toBe(true);
    expect(value.store.resolveFingerprint(pin(tls.clientCert), now)).not.toBeNull();
  });

  it('supports explicit reviewed root overlap and rejects a retired signer without fallback', async () => {
    const ctx = context({
      trustedOrgPublicKeys: [publicPem(), publicPem(rotatedSigner.publicKey)],
    });
    await expect(
      verifyAndProvisionPairingBundle(bundle({}, {}, rotatedSigner.privateKey), ctx, now),
    ).resolves.toMatchObject({ fingerprint: tls.fingerprint });
    await rejectsUnchanged(
      bundle(),
      context({ trustedOrgPublicKeys: [publicPem(rotatedSigner.publicKey)] }),
    );
  });

  it.each([
    ['nil controller', { controllerId: '00000000-0000-0000-0000-000000000000' }],
    ['malformed controller', { controllerId: 'controller' }],
    ['wrong worker', { workerId: '33333333-3333-4333-8333-333333333333' }],
    ['wrong worker pin', { workerFingerprint: 'a'.repeat(64) }],
    ['unsafe URL', { baseUrl: 'http://127.0.0.1' }],
    ['extra profile authority', { permissions: ['runs:start'] }],
    ['malformed controller material', { controllerPrivateKeyPem: 'invalid' }],
  ])('rejects signed %s without mutation', async (_name, changes) =>
    rejectsUnchanged(bundle(changes)),
  );

  it('rejects a controller UUID altered after signing', async () => {
    const bytes = JSON.parse(bundle().toString()) as {
      format: string;
      payload: string;
      signature: string;
    };
    const payload = JSON.parse(Buffer.from(bytes.payload, 'base64').toString()) as {
      profile: { controllerId: string };
    };
    payload.profile.controllerId = '33333333-3333-4333-8333-333333333333';
    bytes.payload = Buffer.from(JSON.stringify(payload)).toString('base64');
    await rejectsUnchanged(Buffer.from(JSON.stringify(bytes)));
  });

  it('rejects an invalid signature and an unknown signer', async () => {
    const value = JSON.parse(bundle().toString()) as { signature: string };
    value.signature = Buffer.alloc(64).toString('base64');
    await rejectsUnchanged(Buffer.from(JSON.stringify(value)));
    await rejectsUnchanged(bundle({}, {}, rotatedSigner.privateKey));
  });

  it.each([299_999, 300_000])(
    'accepts issuedAt at the approved clock-skew boundary %d ms',
    async (skew) => {
      await expect(
        verifyAndProvisionPairingBundle(
          bundle(
            {},
            {
              issuedAt: new Date(now.getTime() + skew).toISOString(),
              expiresAt: new Date(now.getTime() + 600_000).toISOString(),
            },
          ),
          context(),
          now,
        ),
      ).resolves.toMatchObject({ fingerprint: tls.fingerprint });
    },
  );

  it.each([
    [
      'future beyond skew',
      {
        issuedAt: (): string => new Date(now.getTime() + 300_001).toISOString(),
        expiresAt: (): string => new Date(now.getTime() + 600_000).toISOString(),
      },
    ],
    ['expired', { expiresAt: (): string => now.toISOString() }],
    [
      'excess lifetime',
      { expiresAt: (): string => new Date(now.getTime() + 8 * 86400_000).toISOString() },
    ],
    ['bad timestamp', { issuedAt: (): string => '2026-10-22' }],
    ['wrong version', { format: (): string => 'v2' }],
  ])('rejects signed %s payload', async (_name, changes) => {
    const overrides = Object.fromEntries(
      Object.entries(changes).map(([key, make]) => [key, make()]),
    );
    await rejectsUnchanged(bundle({}, overrides));
  });

  it.each([
    'wrong purpose',
    'weak key',
    'wrong key usage',
    'CA leaf',
    'expired leaf',
    'wrong CA',
    'foreign controller',
  ])('rejects %s before trust mutation', async (kind) => {
    const overrides =
      kind === 'wrong purpose'
        ? { controllerCertificatePem: tls.workerCert.toString() }
        : kind === 'weak key'
          ? { controllerCertificatePem: weak.toString() }
          : kind === 'wrong key usage'
            ? { controllerCertificatePem: wrongUsage.toString() }
            : kind === 'CA leaf'
              ? { controllerCertificatePem: tls.ca.toString() }
              : kind === 'expired leaf'
                ? { controllerCertificatePem: expired.toString() }
                : kind === 'wrong CA'
                  ? { trustedCaPem: otherTls.ca.toString() }
                  : { controllerCertificatePem: otherTls.clientCert.toString() };
    await rejectsUnchanged(bundle(overrides));
  });

  it('rejects not-yet-valid leaves even when the bundle window is otherwise valid', async () => {
    const clock = new Date(Date.parse(new X509Certificate(tls.clientCert).validFrom) - 1000);
    const bytes = bundle(
      {},
      {
        issuedAt: new Date(clock.getTime() - 1000).toISOString(),
        expiresAt: new Date(clock.getTime() + 60_000).toISOString(),
      },
    );
    const ctx = context();
    await expect(verifyAndProvisionPairingBundle(bytes, ctx, clock)).rejects.toThrow();
    expect(ctx.store.revision).toBe(0);
  });

  it('refuses cross-controller fingerprint rebinding and rotates a controller certificate with bounded overlap', async () => {
    const ctx = context();
    await verifyAndProvisionPairingBundle(bundle(), ctx, now);
    await rejectsUnchanged(bundle({ controllerId: '33333333-3333-4333-8333-333333333333' }), ctx);
    const next = await issueCertificate(
      root,
      'collision',
      'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n',
    );
    // The certificate is minted after the fixture clock; advance just beyond its notBefore.
    const rotationTime = new Date(
      Math.max(now.getTime(), Date.parse(new X509Certificate(next.cert).validFrom)),
    );
    const rotated = await verifyAndProvisionPairingBundle(
      bundle(
        { controllerCertificatePem: next.cert.toString() },
        {
          issuedAt: new Date(rotationTime.getTime() - 1000).toISOString(),
          expiresAt: new Date(rotationTime.getTime() + 60_000).toISOString(),
        },
      ),
      ctx,
      rotationTime,
    );
    expect(rotated).toMatchObject({ controllerId, fingerprint: pin(next.cert), generation: 2 });
    expect(ctx.store.listActive()).toHaveLength(2);
    expect(ctx.store.resolveFingerprint(tls.fingerprint, now)?.notAfter).toBe(
      new Date(
        Math.min(
          rotationTime.getTime() + 60 * 60 * 1000,
          Date.parse(new X509Certificate(tls.clientCert).validTo),
        ),
      ).toISOString(),
    );
  });

  it.each([Buffer.alloc(0), Buffer.from('{}'), Buffer.from('{'), Buffer.alloc(1024 * 1024 + 1)])(
    'rejects malformed or oversized envelopes',
    async (bytes) => rejectsUnchanged(Buffer.from(bytes)),
  );

  it('rejects noncanonical base64 and envelope extras', async () => {
    const envelope = JSON.parse(bundle().toString()) as { payload: string };
    await rejectsUnchanged(
      Buffer.from(JSON.stringify({ ...envelope, payload: `${envelope.payload}\n` })),
    );
    await rejectsUnchanged(
      Buffer.from(JSON.stringify({ ...envelope, signer: publicPem(rotatedSigner.publicKey) })),
    );
  });

  it('requires explicit valid trusted roots, permissions and protected worker identity', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    for (const changes of [
      { trustedOrgPublicKeys: [] },
      { trustedOrgPublicKeys: ['invalid'] },
      { trustedOrgPublicKeys: [publicPem(rsa.publicKey)] },
      { trustedOrgPublicKeys: [publicPem(), 'invalid'] },
      { permissions: ['admin'] },
      { permissions: ['runs:read', 'runs:read'] },
      { expectedWorkerId: 'worker' },
      { workerCertificatePem: tls.clientCert.toString() },
    ])
      await rejectsUnchanged(bundle(), context(changes as Partial<PairingProvisionContext>));
    const ctx = context();
    await expect(
      verifyAndProvisionPairingBundle(bundle(), ctx, new Date(Number.NaN)),
    ).rejects.toThrow();
    expect(ctx.store.revision).toBe(0);
  });
});

async function rejectsCredentialSafely(operation: Promise<Buffer>): Promise<void> {
  // Assertions deliberately avoid printing a resolved secret Buffer or an unsafe error body.
  const outcome = await operation.then(
    () => ({ rejected: false, safe: false }),
    (error: unknown) => ({
      rejected: true,
      safe: error instanceof Error && error.message === 'Worker credential protection failed',
    }),
  );
  expect(outcome.rejected).toBe(true);
  expect(outcome.safe).toBe(true);
}

describe('worker private credentials are separate from controller trust', () => {
  it('protects only a matching worker key and clears its owned plaintext buffer', async () => {
    const key = Buffer.from(tls.workerKey);
    const encrypted = Buffer.from('opaque-native-ciphertext');
    const result = await protectWorkerPrivateKey(
      key,
      tls.workerCert,
      {
        protect: async () => encrypted,
        unprotect: async () => {
          throw new Error('unused');
        },
      },
      now,
    );
    expect(result.equals(encrypted)).toBe(true);
    expect(key.every((byte) => byte === 0)).toBe(true);
  });
  it('rejects a controller key and clears plaintext before returning failure', async () => {
    const key = Buffer.from(tls.clientKey);
    await rejectsCredentialSafely(
      protectWorkerPrivateKey(
        key,
        tls.workerCert,
        {
          protect: async () => {
            throw new Error('must not be reached');
          },
          unprotect: async () => Buffer.alloc(0),
        },
        now,
      ),
    );
    expect(key.every((byte) => byte === 0)).toBe(true);
  });
  it('fails closed on DPAPI failure or invalid native output and clears plaintext', async () => {
    for (const protect of [
      async () => {
        throw new Error(tls.workerKey.toString());
      },
      async () => Buffer.alloc(0),
    ]) {
      const key = Buffer.from(tls.workerKey);
      const result = protectWorkerPrivateKey(
        key,
        tls.workerCert,
        { protect, unprotect: async () => Buffer.alloc(0) },
        now,
      );
      await rejectsCredentialSafely(result);
      expect(key.every((byte) => byte === 0)).toBe(true);
    }
  });
  it.skipIf(process.platform !== 'win32' || process.arch !== 'x64')(
    'uses actual current-user DPAPI and rejects tampered ciphertext on Windows x64',
    async () => {
      const protector = createDpapiCredentialProtector();
      const plaintext = Buffer.from('ephemeral-worker-credential-probe');
      const ciphertext = await protector.protect(plaintext);
      const restored = await protector.unprotect(ciphertext);
      try {
        expect(ciphertext.equals(plaintext)).toBe(false);
        expect(restored.equals(plaintext)).toBe(true);
        const tampered = Buffer.from(ciphertext);
        tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1;
        await expect(protector.unprotect(tampered)).rejects.toThrow(
          'Worker DPAPI operation failed',
        );
      } finally {
        plaintext.fill(0);
        restored.fill(0);
      }
    },
  );
  it.skipIf(process.platform === 'win32')(
    'has no software encryption fallback on a non-Windows host',
    async () => {
      const protector = createDpapiCredentialProtector();
      await expect(protector.protect(Buffer.from('secret'))).rejects.toThrow();
      await expect(protector.unprotect(Buffer.from('ciphertext'))).rejects.toThrow();
    },
  );
});
