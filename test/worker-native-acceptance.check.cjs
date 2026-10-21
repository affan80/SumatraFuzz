const { readFileSync, existsSync } = require('node:fs');
const { test } = require('node:test');
const assert = require('node:assert/strict');

const read = (file) => readFileSync(file, 'utf8');

test('Windows native gate launches through the real worker coordinator and supervisor', () => {
  const workflow = read('.github/workflows/repository-checks.yml');
  const job = workflow.split('  real-dynamorio:\n')[1]?.split(/\n {2}[a-z][a-z-]*:\n/)[0];
  assert.ok(job, 'DynamoRIO native acceptance job is required');
  assert.match(job, /npm run native:supervisor:build/);
  assert.match(job, /npm run native:sqlite:build/);
  assert.match(job, /Verify A4–A6 as a standard Windows user/);
  assert.match(job, /timeout-minutes: 35/);

  const gate = read('scripts/windows/verify-native-gate.ps1');
  assert.match(gate, /worker-native-acceptance\.ts/);

  const ciGate = read('scripts/windows/ci-native-gate.ps1');
  assert.match(ciGate, /WaitForExit\(1920000\)/);

  const acceptancePath = 'scripts/windows/worker-native-acceptance.ts';
  assert.ok(existsSync(acceptancePath), 'integrated worker-native acceptance runner is required');
  const acceptance = read(acceptancePath);
  assert.match(acceptance, /new WindowsJobSupervisor/);
  assert.match(acceptance, /new WorkerRunCoordinator/);
  assert.match(acceptance, /execs_done/);
  assert.match(acceptance, /1_000/);
  assert.match(acceptance, /remainingProcesses/);
  assert.match(acceptance, /evidence_finalized/);
});
