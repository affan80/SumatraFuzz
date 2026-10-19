const assert = require('node:assert/strict');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..');
const desktopRoot = path.join(repositoryRoot, 'apps', 'desktop');
const desktopPackage = JSON.parse(readFileSync(path.join(desktopRoot, 'package.json'), 'utf8'));

test('desktop package main, preload and renderer resolve to built files', () => {
  assert.equal(existsSync(path.join(desktopRoot, desktopPackage.main)), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'src', 'preload', 'index.js')), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'renderer', 'index.html')), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'renderer', 'app.js')), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'renderer', 'campaign-poller.js')), true);
  assert.equal(
    existsSync(path.join(desktopRoot, 'dist', 'renderer', 'campaign-view-model.js')),
    true,
  );
  assert.equal(
    existsSync(path.join(desktopRoot, 'dist', 'resources', 'worker-bundle-signing-key.pem')),
    true,
  );
});

test('desktop runtime imports compiled workspace JavaScript instead of TypeScript sources', async () => {
  await import('@sumatrafuzz/worker-protocol');
  const workerClient = await import('@sumatrafuzz/worker-client');
  assert.equal(typeof workerClient.createWorkerClient, 'function');
  await import('@sumatrafuzz/worker-core');
  await import('@sumatrafuzz/run-store');
  await import('@sumatrafuzz/evidence/collect');
  await import('@sumatrafuzz/evidence/stats');
  await import('@sumatrafuzz/instrumentation/fixtures');
  await import('@sumatrafuzz/instrumentation/verify-debug');
  await import('@sumatrafuzz/instrumentation/seed');
  await import('@sumatrafuzz/worker-service');
  assert.equal(
    existsSync(
      path.join(repositoryRoot, 'packages', 'run-store', 'dist', 'migrations', '0001_worker.sql'),
    ),
    true,
  );
  await import(
    pathToFileURL(path.join(desktopRoot, 'dist', 'src', 'main', 'worker-profile-store.js'))
  );
  await import(pathToFileURL(path.join(desktopRoot, 'dist', 'src', 'main', 'worker-bundle.js')));
});
