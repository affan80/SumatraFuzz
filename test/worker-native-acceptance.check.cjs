const { readFileSync, existsSync } = require('node:fs');
const { test } = require('node:test');
const assert = require('node:assert/strict');

const read = (file) => readFileSync(file, 'utf8');

test('Windows native gate reserves campaign proof for the installed SCM host', () => {
  const packageJson = JSON.parse(read('package.json'));
  assert.match(
    packageJson.scripts['native:sqlite:build'],
    /--force_build=1/,
    'service packaging requires a real SQLite addon build even when a prebuild exists',
  );

  const workflow = read('.github/workflows/repository-checks.yml');
  const job = workflow.split('  real-dynamorio:\n')[1]?.split(/\n {2}[a-z][a-z-]*:\n/)[0];
  assert.ok(job, 'DynamoRIO native acceptance job is required');
  assert.match(job, /fetch-depth: 0/);
  assert.match(job, /npm run native:supervisor:build/);
  assert.match(job, /npm run native:sqlite:build/);
  assert.match(job, /Verify A4–A6 as a standard Windows user/);
  assert.match(job, /timeout-minutes: 35/);
  assert.match(job, /scripts\/windows\/worker-service-acceptance\.ps1/);
  assert.match(
    job,
    /WORKER_ACCEPTANCE_HEAD_SHA:\s*\$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/,
  );
  assert.match(
    job,
    /name: worker-native-acceptance-\$\{\{ github\.run_id \}\}[\s\S]*?if-no-files-found: error/,
  );

  const gate = read('scripts/windows/verify-native-gate.ps1');
  assert.doesNotMatch(gate, /worker-native-acceptance\.ts/);

  const ciGate = read('scripts/windows/ci-native-gate.ps1');
  assert.match(ciGate, /WaitForExit\(1920000\)/);

  const acceptancePath = 'scripts/windows/worker-service-acceptance.ts';
  assert.ok(existsSync(acceptancePath), 'installed-service mTLS acceptance runner is required');
  const acceptance = read(acceptancePath);
  assert.match(acceptance, /createWorkerClient/);
  assert.match(acceptance, /importInputBundle/);
  assert.match(acceptance, /startRun/);
  assert.match(acceptance, /stopRun/);
  assert.match(acceptance, /execs_done/);
  assert.match(acceptance, /minimumExecutions = 1_000/);
  assert.match(acceptance, /live_revocation_destroyed_existing_session/);
  assert.match(acceptance, /evidence_finalized/);
  assert.doesNotMatch(acceptance, /new WorkerRunCoordinator/);
});
