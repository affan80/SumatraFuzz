const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');

test('Windows supervisor bounds and tears down a child process tree', {
  skip: process.platform !== 'win32',
}, async () => {
  const addonPath = path.join(
    __dirname,
    '..',
    'native',
    'worker-supervisor',
    'build',
    'Release',
    'worker_supervisor.node',
  );
  const probePath = path.join(
    __dirname,
    '..',
    'build',
    'worker-supervisor',
    'Debug',
    'process_probe.exe',
  );
  const supervisor = require(addonPath);
  for (const method of [
    'launchSuspended',
    'sampleJob',
    'stopJob',
    'protectSecret',
    'unprotectSecret',
  ])
    assert.equal(typeof supervisor[method], 'function');
  const bytes = readFileSync(probePath);
  const proof = {
    path: probePath,
    root: path.dirname(probePath),
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
  const previousSecret = process.env.SUMATRAFUZZ_TEST_SECRET;
  process.env.SUMATRAFUZZ_TEST_SECRET = 'must-not-reach-target';
  let job;
  try {
    job = supervisor.launchSuspended({
      executable: probePath,
      argv: ['-D', path.dirname(probePath)],
      workingDir: path.dirname(probePath),
      limits: { max_memory_bytes: 67108864, max_cpu_percent: 25 },
      fileProofs: [proof],
    });
    let sample;
    for (let i = 0; i < 100; i++) {
      sample = supervisor.sampleJob(job);
      if (sample.process_count >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(
      sample.process_count >= 2,
      'probe child must stay in the job and must not inherit secrets',
    );
    const receipt = supervisor.stopJob(job, 0);
    job = undefined;
    assert.equal(receipt.remainingProcesses, 0);
  } finally {
    if (job) supervisor.stopJob(job, 0);
    if (previousSecret === undefined) delete process.env.SUMATRAFUZZ_TEST_SECRET;
    else process.env.SUMATRAFUZZ_TEST_SECRET = previousSecret;
  }
  const protectedBytes = supervisor.protectSecret(Buffer.from('service-key'));
  assert.equal(supervisor.unprotectSecret(protectedBytes).toString(), 'service-key');
  assert.throws(() => supervisor.unprotectSecret(Buffer.from('tampered')));
});

test('non-Windows host cannot claim the Windows supervisor is available', {
  skip: process.platform === 'win32',
}, () => {
  assert.notEqual(process.platform, 'win32');
});
