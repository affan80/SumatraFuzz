import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as policy from '../src/index.js';
import { createTlsFixture, issueCertificate } from './tls-fixture.js';

const extensions = (usage = 'digitalSignature', purpose = 'clientAuth', ca = false) =>
  `basicConstraints=CA:${ca ? 'TRUE' : 'FALSE'}\n${usage ? `keyUsage=critical,${usage}\n` : ''}${purpose ? `extendedKeyUsage=${purpose}\n` : ''}`;
let root: string;
let tls: Awaited<ReturnType<typeof createTlsFixture>>;
beforeAll(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'sf-certificate-policy-'));
  tls = await createTlsFixture(root);
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('endpoint certificate policy', () => {
  it('accepts RSA client and server leaves for their explicit purposes', () => {
    expect(policy.validateEndpointCertificate(tls.clientCert, 'client')).toBeInstanceOf(
      X509Certificate,
    );
    expect(policy.validateEndpointCertificate(tls.workerCert, 'server')).toBeInstanceOf(
      X509Certificate,
    );
  });
  it.each(['prime256v1', 'secp384r1'])('accepts ECDSA %s', async (curve) => {
    const leaf = await issueCertificate(root, curve, extensions(), [
      '-newkey',
      'ec',
      '-pkeyopt',
      `ec_paramgen_curve:${curve}`,
    ]);
    expect(Date.parse(new X509Certificate(leaf.cert).validFrom)).toBeLessThan(Date.now() - 60_000);
    expect(policy.validateEndpointCertificate(leaf.cert, 'client')).toBeInstanceOf(X509Certificate);
  });
  it.each([
    ['wrong-eku', extensions('digitalSignature', 'serverAuth')],
    ['missing-eku', extensions('digitalSignature', '')],
    ['missing-key-usage', extensions('')],
    ['wrong-key-usage', extensions('keyEncipherment')],
    ['ca-leaf', extensions('digitalSignature,keyCertSign', 'clientAuth', true)],
    ['ca-without-keycertsign', extensions('digitalSignature', 'clientAuth', true)],
  ])('rejects %s', async (name, ext) => {
    const leaf = await issueCertificate(root, name, ext);
    expect(() => policy.validateEndpointCertificate(leaf.cert, 'client')).toThrow();
  });
  it.each([
    ['weak-rsa', ['-newkey', 'rsa:1024']],
    ['unsupported-curve', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp521r1']],
    ['unsupported-key', ['-newkey', 'ed25519']],
  ])('rejects %s keys', async (name, spec) => {
    const leaf = await issueCertificate(root, name, extensions(), spec);
    expect(() => policy.validateEndpointCertificate(leaf.cert, 'client')).toThrow();
  });
  it('rejects the exact notAfter instant', () => {
    const cert = new X509Certificate(tls.clientCert);
    expect(() =>
      policy.validateEndpointCertificate(tls.clientCert, 'client', new Date(cert.validTo)),
    ).toThrow();
  });
  it('rejects expired and not-yet-valid leaves using the supplied clock', () => {
    const cert = new X509Certificate(tls.clientCert);
    expect(() =>
      policy.validateEndpointCertificate(
        tls.clientCert,
        'client',
        new Date(Date.parse(cert.validTo) + 1000),
      ),
    ).toThrow();
    expect(() =>
      policy.validateEndpointCertificate(
        tls.clientCert,
        'client',
        new Date(Date.parse(cert.validFrom) - 1000),
      ),
    ).toThrow();
    expect(() =>
      policy.validateEndpointCertificate(tls.clientCert, 'client', new Date(Number.NaN)),
    ).toThrow();
  });
});
