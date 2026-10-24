const { readFileSync, existsSync, readdirSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const applicationWorkflow = () => {
  const path = '.github/workflows/electron-typescript.yml';
  assert.ok(existsSync(path), 'dedicated Electron/TypeScript workflow is required');
  return readFileSync(path, 'utf8');
};

test('root manifest pins Node and defines TypeScript workspace commands', () => {
  const manifest = readJson('package.json');
  assert.equal(manifest.engines.node, '24.22.0');
  assert.deepEqual(manifest.workspaces, ['packages/*', 'apps/*']);
  for (const script of ['format:check', 'lint', 'typecheck', 'test', 'verify']) {
    assert.ok(manifest.scripts[script], `missing root script ${script}`);
  }
  assert.ok(existsSync('package-lock.json'));
  assert.match(readFileSync('.gitattributes', 'utf8'), /text=auto eol=lf/);
  assert.equal(readFileSync('.node-version', 'utf8').trim(), '24.22.0');
});

test('direct runtime dependencies use exact versions', () => {
  const manifest = readJson('package.json');
  for (const section of ['dependencies', 'devDependencies']) {
    for (const [name, version] of Object.entries(manifest[section] ?? {})) {
      assert.match(version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, `${name} must be exact`);
    }
  }
});

test('Node CI runs in both operating systems and keeps the lockfile cache scoped', () => {
  const workflow = applicationWorkflow();
  assert.match(workflow, /name: TypeScript \(\$\{\{ matrix\.os \}\}\)/);
  assert.match(workflow, /os: \[ubuntu-latest, windows-2022\]/);
  assert.match(workflow, /node-version-file: \.node-version/);
  const setupNodeRefs = [...workflow.matchAll(/^\s*- uses: actions\/setup-node@(\S+)/gm)].map(
    (match) => match[1],
  );
  assert.ok(setupNodeRefs.length > 0, 'Node CI must use setup-node');
  for (const ref of setupNodeRefs) {
    assert.equal(ref, '949feb2413d6458794dcd2491c4babbbce0c15c1', 'setup-node v7.1.0 pin');
  }
  assert.match(workflow, /cache: npm/);
  assert.match(workflow, /cache-dependency-path: package-lock\.json/);
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm run verify/);
  assert.match(workflow, /cyclonedx-npm --package-lock-only/);
  assert.match(workflow, /npm run native:sqlite:build/);
  assert.match(workflow, /npm run native:supervisor:build/);
  assert.match(workflow, /npm run native:supervisor:contract/);
  assert.match(workflow, /scripts\/windows\/ci-supervisor-check\.ps1/);
  assert.match(workflow, /npm run test:worker-api-security/);
  assert.ok(
    readJson('package.json').scripts['test:worker-api-security'],
    'focused API security suite must be available to both CI operating systems',
  );
  assert.ok(existsSync('scripts/windows/ci-supervisor-check.ps1'));
  const { verify } = readJson('package.json').scripts;
  for (const command of [
    'npm run format:check',
    'npm run lint',
    'npm run typecheck',
    'npm run desktop:build',
    'npm test',
    'npm run audit:production',
    'npm audit --audit-level=high',
  ])
    assert.ok(verify.includes(command), `verify must retain ${command}`);
});

test('every workflow action is pinned and setup-node uses the verified v7.1.0 commit', () => {
  for (const name of readdirSync('.github/workflows').filter((name) => /\.ya?ml$/.test(name))) {
    const workflow = readFileSync(join('.github/workflows', name), 'utf8');
    assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
    const references = [...workflow.matchAll(/^\s*(?:-\s+)?uses: (\S+)/gm)].map(
      (match) => match[1],
    );
    assert.ok(references.length > 0, `${name}: action references are required`);
    for (const ref of references) {
      assert.match(ref, /^[\w.-]+\/[\w./-]+@[a-f0-9]{40}$/, `${name}: immutable action reference`);
      if (ref.startsWith('actions/setup-node@')) {
        assert.equal(ref, 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1');
      }
    }
  }
});

test('Electron installer CI checks the archive and installed app before publishing its artifact', () => {
  const workflow = applicationWorkflow();
  const job = workflow.split('  desktop-installer:\n')[1]?.split(/\n {2}[a-z][a-z-]*:\n/)[0];
  assert.ok(job, 'Windows installer job is required');
  assert.match(job, /runs-on: windows-2022/);
  assert.match(job, /npm ci --ignore-scripts/);
  assert.match(job, /node node_modules\/electron\/install\.js/);
  assert.match(job, /npm run desktop:package:win/);
  assert.match(
    job,
    /check-desktop-package\.mjs release\/windows\/win-unpacked\/resources\/app\.asar/,
  );
  assert.match(job, /\$install\.ExitCode -ne 0/);
  assert.match(job, /\$process\.HasExited/);
  assert.match(job, /\$uninstall\.ExitCode -ne 0/);
  assert.match(job, /if-no-files-found: error/);
  assert.match(job, /cyclonedx-npm --package-lock-only --output-file sumatrafuzz\.cdx\.json/);
  assert.match(job, /name: sumatrafuzz-cyclonedx-sbom/);
});

test('Electron packager uses the version pinned in the dependency manifest', () => {
  const version = readFileSync('electron-builder.yml', 'utf8').match(
    /^electronVersion: (\S+)$/m,
  )?.[1];
  assert.equal(version, readJson('package.json').devDependencies.electron);
});

test('real DynamoRIO job builds workspace imports before running the native gate', () => {
  const workflow = readFileSync('.github/workflows/repository-checks.yml', 'utf8');
  const job = workflow.split('  real-dynamorio:\n')[1]?.split('\n  [a-z][a-z-]*:\n')[0];
  assert.ok(job, 'real-dynamorio job must exist');
  const install = job.indexOf('run: npm ci --ignore-scripts');
  const build = job.indexOf('run: npm run typecheck');
  const gate = job.indexOf('scripts/windows/ci-native-gate.ps1');
  assert.ok(install >= 0 && build > install && gate > build);
});

test('TypeScript compiler fixture reports the expected type diagnostic', () => {
  const compiler = join('node_modules', 'typescript', 'bin', 'tsc');
  const fixture = join('test', 'fixtures', 'expected-diagnostic.ts');
  const result = spawnSync(
    process.execPath,
    [compiler, '--ignoreConfig', '--pretty', 'false', '--noEmit', fixture],
    { encoding: 'utf8' },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /TS2322/);
});
