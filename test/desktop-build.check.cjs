const assert = require('node:assert/strict');
const { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { execFileSync } = require('node:child_process');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..');
const desktopRoot = path.join(repositoryRoot, 'apps', 'desktop');
const desktopPackage = JSON.parse(readFileSync(path.join(desktopRoot, 'package.json'), 'utf8'));

test('desktop package main, preload and renderer resolve to built files', () => {
  assert.equal(existsSync(path.join(desktopRoot, desktopPackage.main)), true);
  const preloadPath = path.join(desktopRoot, 'dist', 'preload.cjs');
  assert.equal(existsSync(preloadPath), true, 'sandboxed preload must be bundled as CommonJS');
  const preload = readFileSync(preloadPath, 'utf8');
  assert.match(preload, /require\(["']electron["']\)/);
  assert.doesNotMatch(preload, /^\s*(?:import|export)\s/m);
  const main = readFileSync(path.join(desktopRoot, 'dist', 'src', 'main', 'index.js'), 'utf8');
  assert.match(main, /dist', 'preload\.cjs/);
  const html = readFileSync(path.join(desktopRoot, 'dist', 'renderer', 'index.html'), 'utf8');
  assert.match(html, /id="limit-memory"[^>]*min="16777216"/);
  assert.match(html, /id="limit-disk"[^>]*readonly/);
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

test('staged desktop worker client imports without repository workspace resolution', () => {
  execFileSync(process.execPath, [path.join(repositoryRoot, 'scripts/stage-desktop-package.mjs')], {
    cwd: repositoryRoot,
    stdio: 'pipe',
  });
  const isolatedRoot = mkdtempSync(path.join(os.tmpdir(), 'sf-packaged-runtime-'));
  try {
    cpSync(
      path.join(desktopRoot, '.package-stage', 'node_modules'),
      path.join(isolatedRoot, 'node_modules'),
      {
        recursive: true,
        dereference: true,
      },
    );
    writeFileSync(
      path.join(isolatedRoot, 'check.mjs'),
      `
      import assert from 'node:assert/strict';
      import { createWorkerClient, validateWorkerUrl } from '@sumatrafuzz/worker-client';
      assert.equal(typeof createWorkerClient, 'function');
      assert.equal(validateWorkerUrl('https://127.0.0.1:4242').origin, 'https://127.0.0.1:4242');
    `,
    );
    const { NODE_PATH, NODE_OPTIONS, ...isolatedEnv } = process.env;
    execFileSync(process.execPath, [path.join(isolatedRoot, 'check.mjs')], {
      cwd: isolatedRoot,
      env: isolatedEnv,
      stdio: 'pipe',
    });
    const securityRoot = path.join(isolatedRoot, 'node_modules', '@sumatrafuzz', 'worker-security');
    assert.equal(existsSync(path.join(securityRoot, 'dist', 'test')), false);
    assert.equal(existsSync(path.join(securityRoot, 'dist', 'src', 'index.js.map')), false);
    assert.equal(existsSync(path.join(securityRoot, 'dist', 'src', 'index.d.ts')), false);
  } finally {
    rmSync(isolatedRoot, { recursive: true, force: true });
  }
});
