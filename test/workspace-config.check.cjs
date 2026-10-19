const { readFileSync, existsSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

test('root manifest pins Node and defines TypeScript workspace commands', () => {
  const manifest = readJson('package.json');
  assert.equal(manifest.engines.node, '24.22.0');
  assert.deepEqual(manifest.workspaces, ['packages/*', 'apps/*']);
  for (const script of ['format:check', 'lint', 'typecheck', 'test', 'verify']) {
    assert.ok(manifest.scripts[script], `missing root script ${script}`);
  }
  assert.ok(existsSync('package-lock.json'));
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
  const workflow = readFileSync('.github/workflows/repository-checks.yml', 'utf8');
  assert.match(workflow, /name: TypeScript \(\$\{\{ matrix\.os \}\}\)/);
  assert.match(workflow, /os: \[ubuntu-latest, windows-2022\]/);
  assert.match(workflow, /actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020/);
  assert.match(workflow, /cache: npm/);
  assert.match(workflow, /npm run typecheck/);
  assert.match(workflow, /npm audit --audit-level=high/);
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
