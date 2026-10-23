const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync } = require('node:fs');

const read = (file) => readFileSync(file, 'utf8');

test('required Windows workflow exercises the installed service over authenticated mTLS', () => {
  const workflow = read('.github/workflows/repository-checks.yml');
  const job = workflow.split('  real-dynamorio:\n')[1]?.split(/\n {2}[a-z][a-z-]*:\n/)[0];
  assert.ok(job, 'real Windows native acceptance job is required');
  assert.match(job, /scripts\/windows\/worker-service-acceptance\.ps1/);
  assert.match(job, /if-no-files-found: error/);

  const acceptancePath = 'scripts/windows/worker-service-acceptance.ts';
  assert.ok(existsSync(acceptancePath), 'installed-service mTLS acceptance runner is required');
  const acceptance = read(acceptancePath);
  assert.match(acceptance, /createWorkerClient/);
  assert.match(acceptance, /importInputBundle/);
  assert.match(acceptance, /startRun/);
  assert.match(acceptance, /stopRun/);
  assert.doesNotMatch(acceptance, /new WorkerRunCoordinator/);

  const setupPath = 'scripts/windows/worker-service-acceptance.ps1';
  assert.ok(existsSync(setupPath), 'Windows service setup and teardown runner is required');
  const setup = read(setupPath);
  for (const operation of [
    'install-worker-service.ps1',
    'provision-worker-service.ps1',
    'Start-Service',
    'Stop-Service',
    'uninstall-worker-service.ps1',
  ]) {
    assert.ok(setup.includes(operation), `service acceptance must cover ${operation}`);
  }
  assert.match(setup, /NT SERVICE\\SumatraFuzzWorker/);
  assert.match(setup, /Assert-OrdinaryUserDenials/);
  assert.match(setup, /Assert-WorkerQuota -VolumeId/);
  assert.match(setup, /Get-NetTCPConnection -State Listen/);
  assert.match(setup, /finally/);
  const denialProbe = read('scripts/windows/assert-worker-files-denied.ps1');
  assert.match(denialProbe, /Worker trust pipe was unavailable instead of denying/);
  assert.match(denialProbe, /Ordinary user read a protected worker file/);
  assert.match(denialProbe, /unprotectSecret/);
});
