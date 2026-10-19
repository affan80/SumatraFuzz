import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  createWorkerPairingBundle,
  loadTrustedWorkerBundleSigningKey,
  verifyWorkerPairingBundle,
} from '../src/main/worker-bundle.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const profile = {
  workerId: '11111111-1111-4111-8111-111111111111',
  controllerId: '22222222-2222-4222-8222-222222222222',
  baseUrl: 'https://worker.example.test',
  workerFingerprint: `${'AA:'.repeat(31)}AA`,
  controllerCertificatePem: '-----BEGIN CERTIFICATE-----\nclient-cert\n-----END CERTIFICATE-----',
  controllerPrivateKeyPem: '-----BEGIN PRIVATE KEY-----\nclient-key\n-----END PRIVATE KEY-----',
  trustedCaPem: '-----BEGIN CERTIFICATE-----\nworker-ca\n-----END CERTIFICATE-----',
};

function makeBundle(
  options: {
    readonly profileOverrides?: Record<string, unknown>;
    readonly issuedAt?: Date;
    readonly expiresAt?: Date;
  } = {},
): Buffer {
  const payload = Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-payload-v1',
      issuedAt: (options.issuedAt ?? new Date(Date.now() - 1000)).toISOString(),
      expiresAt: (options.expiresAt ?? new Date(Date.now() + 60_000)).toISOString(),
      profile: { ...profile, ...options.profileOverrides },
    }),
  );
  return Buffer.from(
    JSON.stringify({
      format: 'sumatrafuzz-worker-pairing-bundle-v1',
      payload: payload.toString('base64'),
      signature: sign(null, payload, privateKey).toString('base64'),
    }),
  );
}

describe('signed worker pairing bundles', () => {
  it('verifies the embedded signer and returns normalized worker credentials', () => {
    const result = verifyWorkerPairingBundle(
      makeBundle(),
      publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    );
    expect(result.profile).toEqual({ ...profile, workerFingerprint: 'a'.repeat(64) });
    expect(result.expiresAt).toBeInstanceOf(Date);
  });

  it('creates a signed, bounded bundle that the importer verifies', () => {
    const bundle = createWorkerPairingBundle(profile, privateKey);
    const verified = verifyWorkerPairingBundle(
      bundle,
      publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    );
    expect(verified.profile).toEqual({ ...profile, workerFingerprint: 'a'.repeat(64) });
    expect(() => createWorkerPairingBundle(profile, publicKey)).toThrow(/private key/);
    expect(() =>
      createWorkerPairingBundle(
        profile,
        privateKey,
        new Date(0),
        new Date(8 * 24 * 60 * 60 * 1000),
      ),
    ).toThrow(/validity window/);
  });

  it.each([
    ['missing', undefined],
    ['nil', '00000000-0000-0000-0000-000000000000'],
    ['malformed', 'controller-one'],
  ])('rejects a %s signed controller UUID', (_name, controllerId) => {
    const overrides = { controllerId };
    const bundle = makeBundle({ profileOverrides: overrides });

    expect(() =>
      verifyWorkerPairingBundle(
        bundle,
        publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ),
    ).toThrow(/worker profile is invalid/);
  });

  it('rejects a controller UUID changed after the signed bundle was created', () => {
    const valid = JSON.parse(makeBundle().toString()) as {
      payload: string;
      signature: string;
      format: string;
    };
    const payload = JSON.parse(Buffer.from(valid.payload, 'base64').toString('utf8')) as {
      profile: Record<string, unknown>;
    };
    payload.profile.controllerId = '33333333-3333-4333-8333-333333333333';
    const tampered = Buffer.from(
      JSON.stringify({
        ...valid,
        payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
      }),
    );

    expect(() =>
      verifyWorkerPairingBundle(
        tampered,
        publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ),
    ).toThrow(/signature/);
  });

  it('rejects unsigned, modified, and incorrectly signed bundle contents', () => {
    const valid = JSON.parse(makeBundle().toString()) as {
      payload: string;
      signature: string;
      format: string;
    };
    const tampered = Buffer.from(
      JSON.stringify({ ...valid, payload: Buffer.from('{"admin":true}').toString('base64') }),
    );

    expect(() =>
      verifyWorkerPairingBundle(
        tampered,
        publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ),
    ).toThrow(/signature/);
    expect(() =>
      verifyWorkerPairingBundle(
        Buffer.from('{"format":"sumatrafuzz-worker-pairing-bundle-v1"}'),
        publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ),
    ).toThrow(/bundle/);
  });

  it('rejects expired bundles and bundles with unsafe worker endpoints', () => {
    const key = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const expired = makeBundle({ expiresAt: new Date(Date.now() - 60_000) });
    const unsafe = makeBundle({ profileOverrides: { baseUrl: 'http://worker.example.test' } });

    expect(() => verifyWorkerPairingBundle(expired, key)).toThrow(/validity window/);
    expect(() => verifyWorkerPairingBundle(unsafe, key)).toThrow(/HTTPS origin/);
  });

  it('loads only a valid Ed25519 public key from the build-time trust file', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'sumatrafuzz-trust-key-'));
    const filePath = path.join(directory, 'worker-bundle-signing-key.pem');
    const key = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    try {
      await expect(loadTrustedWorkerBundleSigningKey(filePath)).rejects.toThrow(/not configured/);
      await writeFile(filePath, key, { mode: 0o600 });
      await expect(loadTrustedWorkerBundleSigningKey(filePath)).resolves.toBe(key);
      await writeFile(filePath, 'invalid key');
      await expect(loadTrustedWorkerBundleSigningKey(filePath)).rejects.toThrow(/invalid/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
