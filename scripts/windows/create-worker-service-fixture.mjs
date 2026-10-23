import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createWorkerPairingBundle } from '../../apps/desktop/dist/src/main/worker-bundle.js';
import {
  createTlsFixture,
  issueCertificate,
} from '../../packages/worker-security/dist/test/tls-fixture.js';

const outputArgument = process.argv[2];
if (!outputArgument) throw new Error('fixture output directory is required');
const output = path.resolve(outputArgument);
await mkdir(output, { recursive: true });
const tlsRoot = path.join(output, 'tls');
await mkdir(tlsRoot, { recursive: true });
const tls = await createTlsFixture(tlsRoot);
const second = await issueCertificate(
  tlsRoot,
  'controller-b',
  'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
);
const third = await issueCertificate(
  tlsRoot,
  'controller-unpaired',
  'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
);
const signing = generateKeyPairSync('ed25519');
const workerId = '7b12c658-80e1-4f02-a3a9-91a1e50321e0';
const controllers = [
  { id: '3e91a502-d54a-45af-9a73-69f5429be6b1', cert: tls.clientCert, key: tls.clientKey },
  { id: '0e84ca36-9316-44ea-8baf-41638978125c', cert: second.cert, key: second.key },
  { id: '40dfc128-c311-4a83-900c-a5e0a171b95a', cert: third.cert, key: third.key },
];
const signingPublicKey = signing.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const signingPrivateKey = signing.privateKey;
const workerCertificatePem = tls.workerCert.toString();
const trustedCaPem = tls.ca.toString();
const fingerprint = (certificate) =>
  new X509Certificate(certificate).fingerprint256.replaceAll(':', '').toLowerCase();

await writeFile(path.join(output, 'organization-public.pem'), signingPublicKey, { mode: 0o600 });
await writeFile(
  path.join(output, 'worker-credentials.json'),
  `${JSON.stringify({
    schema: 1,
    workerKeyPem: tls.workerKey.toString(),
    workerCertificatePem,
    clientCaPem: trustedCaPem,
  })}\n`,
  { mode: 0o600 },
);

for (let index = 0; index < controllers.length; index++) {
  const controller = controllers[index];
  const profile = {
    workerId,
    controllerId: controller.id,
    baseUrl: 'https://127.0.0.1:18443',
    workerFingerprint: fingerprint(tls.workerCert),
    controllerCertificatePem: controller.cert.toString(),
    controllerPrivateKeyPem: controller.key.toString(),
    trustedCaPem,
  };
  await writeFile(
    path.join(output, `controller-${index + 1}.json`),
    `${JSON.stringify(profile)}\n`,
    {
      mode: 0o600,
    },
  );
  if (index < 2) {
    const bundle = createWorkerPairingBundle(profile, signingPrivateKey);
    await writeFile(path.join(output, `controller-${index + 1}.sfpair`), bundle, { mode: 0o600 });
  }
}

const revokePayload = Buffer.from(
  JSON.stringify({
    format: 'sumatrafuzz-worker-trust-operation-v1',
    workerId,
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    operation: {
      type: 'unpair_controller',
      controllerId: controllers[0].id,
      fingerprint: null,
    },
  }),
);
const { sign } = await import('node:crypto');
const revokeBundle = Buffer.from(
  JSON.stringify({
    format: 'sumatrafuzz-worker-pairing-bundle-v1',
    payload: revokePayload.toString('base64'),
    signature: sign(null, revokePayload, signingPrivateKey).toString('base64'),
  }),
);
await writeFile(path.join(output, 'revoke-controller-1.sftxn'), revokeBundle, { mode: 0o600 });
await writeFile(
  path.join(output, 'fixture-summary.json'),
  `${JSON.stringify({ workerId, controllerIds: controllers.map(({ id }) => id) })}\n`,
  { mode: 0o600 },
);
console.log('Generated ephemeral worker-service acceptance fixtures.');
