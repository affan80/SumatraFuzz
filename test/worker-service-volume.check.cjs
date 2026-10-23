const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const assert = require('node:assert/strict');

test('install and provisioning share the exact dedicated-volume mount validation', () => {
  const module = readFileSync('scripts/windows/worker-service-config.psm1', 'utf8');
  const provision = readFileSync('scripts/windows/provision-worker-service.ps1', 'utf8');
  assert.match(module, /function Assert-WorkerDataMountPoint/);
  assert.match(module, /Get-Partition -Volume \$volume/);
  assert.match(module, /\.AccessPaths/);
  assert.match(module, /Assert-WorkerDataMountPoint -DataRoot \$DataRoot/);
  assert.match(provision, /Assert-WorkerDataMountPoint -DataRoot \$dataRoot/);
  assert.doesNotMatch(provision, /foreach \(\$directory in @\(\$dataRoot, \$stagingRoot\)\)/);
  assert.match(provision, /\$stagingItem\.Attributes -band \[IO\.FileAttributes\]::ReparsePoint/);
});
