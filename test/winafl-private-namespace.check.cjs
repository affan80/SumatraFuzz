const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = (p) =>
  fs.existsSync(path.join(root, p)) ? fs.readFileSync(path.join(root, p), 'utf8') : '';
const patch = () => read('scripts/windows/patches/winafl-private-namespace.patch');
test('pinned patch protects mapping create/open names and authenticates client namespace options', () => {
  const p = patch();
  assert.match(p, /sf_private_namespace\.h/);
  assert.match(p, /alloc_printf\("%s\\\\sample_afl_shm_%s", sf_namespace\.alias/);
  assert.match(p, /alloc_printf\("%s\\\\afl_shm_%s", sf_namespace\.alias/);
  assert.match(p, /sf_namespace_name\(&sf_namespace, options\.shm_name/);
  assert.match(p, /-namespace_alias %s -run_sid %s/);
  assert.match(p, /TokenRestrictedSids/);
  assert.match(p, /OpenPrivateNamespaceA/);
  assert.match(p, /SE_DACL_PROTECTED/);
  assert.match(p, /sf_security\(&sf_namespace, &sa, FILE_GENERIC_READ \| FILE_GENERIC_WRITE/);
  assert.equal((p.match(/^\+.*SetSecurityDescriptorDacl\([^\n]*NULL/gm) || []).length, 0);
});
test('acquisition checks clean exact source, patch applicability and immutable digest before build', () => {
  const p = read('scripts/windows/provision-winafl.ps1');
  assert.match(p, /winafl_patch_sha256/);
  assert.match(p, /apply --check/);
  assert.match(p, /status --porcelain/);
  assert.match(p, /expectedPatchHash/);
  assert.match(p, /fd85f38548b14352f4b70ad414f364ea6dc1a769/);
  for (const file of [
    'scripts/windows/verify-toolchain.ps1',
    'scripts/windows/run-dynamorio-debug.ps1',
  ]) {
    assert.match(read(file), /winafl_patch_sha256|WinAflPatchSha256/);
  }
});

test('all lock consumers require the exact reviewed patch bytes', () => {
  const digest = require('node:crypto').createHash('sha256').update(patch()).digest('hex');
  for (const file of ['provision-winafl.ps1', 'verify-toolchain.ps1', 'run-dynamorio-debug.ps1']) {
    assert.ok(read(`scripts/windows/${file}`).includes(`$expectedPatchHash = '${digest}'`), file);
  }
});

test('patch applies once to the pinned upstream and rejects source drift', {
  skip:
    !process.env.SUMATRAFUZZ_WINAFL_SOURCE &&
    'set SUMATRAFUZZ_WINAFL_SOURCE to an upstream checkout',
}, () => {
  const { spawnSync } = require('node:child_process');
  const source = process.env.SUMATRAFUZZ_WINAFL_SOURCE;
  const git = (args, cwd) =>
    spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  assert.equal(
    git(['rev-parse', 'HEAD'], source).stdout.trim(),
    'fd85f38548b14352f4b70ad414f364ea6dc1a769',
  );
  const temp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'sf-winafl-patch-'));
  const trackedPatch = path.join(root, 'scripts/windows/patches/winafl-private-namespace.patch');
  const restore = () => {
    for (const f of ['CMakeLists.txt', 'afl-fuzz.c', 'winafl.c']) {
      const result = git(['show', `HEAD:${f}`], source);
      assert.equal(result.status, 0, result.stderr);
      fs.writeFileSync(path.join(temp, f), result.stdout);
    }
    fs.rmSync(path.join(temp, 'sf_private_namespace.h'), { force: true });
  };
  try {
    restore();
    assert.equal(git(['apply', '--check', trackedPatch], temp).status, 0);
    assert.equal(git(['apply', trackedPatch], temp).status, 0);
    assert.notEqual(git(['apply', '--check', trackedPatch], temp).status, 0);
    const fuzzer = fs.readFileSync(path.join(temp, 'afl-fuzz.c'), 'utf8');
    assert.equal((fuzzer.match(/SetSecurityDescriptorDacl\([^\n]*NULL/g) || []).length, 0);
    assert.equal((fuzzer.match(/sf_security\(&sf_namespace, &sa,/g) || []).length, 3);
    restore();
    fs.writeFileSync(path.join(temp, 'afl-fuzz.c'), 'source drift');
    assert.notEqual(git(['apply', '--check', trackedPatch], temp).status, 0);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
