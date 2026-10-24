const assert = require('node:assert/strict');
const test = require('node:test');

test('desktop package policy rejects private signing material and pairing credentials', async () => {
  const { containsPrivateSigningKey, findForbiddenPackageEntries, validatePackagedTrustKey } =
    await import('../scripts/check-desktop-package.mjs');
  const findings = findForbiddenPackageEntries([
    'dist/resources/controller-private-key.pem',
    'worker-profile.v2.enc',
    'worker.sfpair',
  ]);
  assert.equal(findings.length, 3);
  assert.equal(validatePackagedTrustKey(Buffer.from('-----BEGIN PRIVATE KEY-----\nsecret')), false);
  assert.equal(validatePackagedTrustKey(Buffer.from('-----BEGIN PUBLIC KEY-----\npublic')), true);
  assert.equal(
    containsPrivateSigningKey(Buffer.from('-----BEGIN EC PRIVATE KEY-----\nsecret')),
    true,
  );
});

test('desktop package policy rejects corpora and native fuzzing tools', async () => {
  const { findForbiddenPackageEntries } = await import('../scripts/check-desktop-package.mjs');
  const findings = findForbiddenPackageEntries([
    'test/fixtures/minimal.pdf',
    'runs/a5/campaign/crashes/id:000001',
    'tools/winafl.dll',
    'tools/drrun.exe',
    'native/sumatrafuzz-harness.exe',
    'native/PdfFilter.dll',
  ]);
  assert.equal(findings.length, 6);
});

test('desktop package policy rejects build-only and unallowlisted files', async () => {
  const { findForbiddenPackageEntries } = await import('../scripts/check-desktop-package.mjs');
  const findings = findForbiddenPackageEntries([
    'apps/desktop/src/main/index.ts',
    'dist/src/main/index.js.map',
    'node_modules/unapproved-package/index.js',
    'node_modules/@sinclair/typebox/build/esm/index.d.mts',
    '../secrets.pem',
  ]);
  assert.equal(findings.length, 5);
});

test('desktop package policy accepts only the worker runtime and required app assets', async () => {
  const { findForbiddenPackageEntries } = await import('../scripts/check-desktop-package.mjs');
  const findings = findForbiddenPackageEntries([
    'package.json',
    'dist/src/main/index.js',
    'dist/preload.cjs',
    'dist/renderer/app.js',
    'dist/resources/worker-bundle-signing-key.pem',
    'node_modules/@sumatrafuzz/worker-client/package.json',
    'node_modules/@sumatrafuzz/worker-client/dist/src/index.js',
    'node_modules/@sumatrafuzz/worker-security/package.json',
    'node_modules/@sumatrafuzz/worker-security/dist/src/index.js',
    'node_modules/@sumatrafuzz/worker-security/dist/src/certificate-policy.js',
    'node_modules/@sumatrafuzz/worker-protocol/package.json',
    'node_modules/@sumatrafuzz/worker-protocol/dist/index.js',
    'node_modules/ajv/package.json',
    'node_modules/ajv/dist/ajv.js',
    'node_modules/@sinclair/typebox/package.json',
    'node_modules/@sinclair/typebox/build/esm/index.mjs',
  ]);
  assert.deepEqual(findings, []);
});

test('desktop package policy rejects unbundled preload source and allows its CommonJS bundle', async () => {
  const { findForbiddenPackageEntries } = await import('../scripts/check-desktop-package.mjs');
  const findings = findForbiddenPackageEntries(['dist/preload.cjs', 'dist/src/preload/index.js']);
  assert.equal(findings.length, 1);
  assert.match(findings[0], /preload source/i);
});

test('desktop package policy converts normalized ASAR paths to Windows separators', async () => {
  const { toArchivePath } = await import('../scripts/check-desktop-package.mjs');
  assert.equal(
    toArchivePath?.('node_modules/@sinclair/typebox/package.json', '\\'),
    'node_modules\\@sinclair\\typebox\\package.json',
  );
});

test('desktop package policy excludes worker-security fixtures and build-only files', async () => {
  const { findForbiddenPackageEntries } = await import('../scripts/check-desktop-package.mjs');
  for (const entry of [
    'node_modules/@sumatrafuzz/worker-security/dist/test/tls-fixture.js',
    'node_modules/@sumatrafuzz/worker-security/src/certificate-policy.ts',
    'node_modules/@sumatrafuzz/worker-security/dist/src/index.d.ts',
    'node_modules/@sumatrafuzz/worker-security/dist/src/index.js.map',
  ])
    assert.equal(findForbiddenPackageEntries([entry]).length, 1, entry);
});
