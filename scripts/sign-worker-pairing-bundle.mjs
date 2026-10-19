import { execFileSync } from 'node:child_process';
import { createPrivateKey, randomUUID } from 'node:crypto';
import { link, lstat, open, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { createWorkerPairingBundle } from '../apps/desktop/dist/src/main/worker-bundle.js';

const MAX_INPUT_BYTES = 1024 * 1024;
const KEYCHAIN_SERVICE = 'com.sumatrafuzz.worker-bundle-signing-passphrase';

function outputPathFromArgs(args) {
  if (args.length !== 2 || args[0] !== '--out' || !args[1]) {
    throw new Error('usage: node scripts/sign-worker-pairing-bundle.mjs --out <bundle.sfpair>');
  }
  return path.resolve(args[1]);
}

async function readStandardInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > MAX_INPUT_BYTES) throw new Error('profile input exceeds the size limit');
    chunks.push(bytes);
  }
  if (size === 0) throw new Error('profile input is empty');
  return Buffer.concat(chunks, size);
}

async function signingPassphrase() {
  if (process.env.SUMATRAFUZZ_WORKER_BUNDLE_SIGNING_KEY_PASSPHRASE) {
    return process.env.SUMATRAFUZZ_WORKER_BUNDLE_SIGNING_KEY_PASSPHRASE;
  }
  if (process.platform === 'darwin') {
    return execFileSync(
      '/usr/bin/security',
      ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
  }
  throw new Error('configure the signing passphrase through an OS secret store');
}

async function main() {
  const destination = outputPathFromArgs(process.argv.slice(2));
  const privateKeyPath = process.env.SUMATRAFUZZ_WORKER_BUNDLE_SIGNING_PRIVATE_KEY_FILE;
  if (!privateKeyPath) throw new Error('signing private key file is not configured');
  const keyMetadata = await lstat(privateKeyPath);
  if (
    !keyMetadata.isFile() ||
    keyMetadata.isSymbolicLink() ||
    keyMetadata.size === 0 ||
    keyMetadata.size > 16 * 1024 ||
    (process.platform !== 'win32' && (keyMetadata.mode & 0o077) !== 0)
  ) {
    throw new Error('signing private key file is invalid');
  }
  const privateKeyPem = await readFile(privateKeyPath, 'utf8');
  const privateKey = createPrivateKey({
    key: privateKeyPem,
    passphrase: await signingPassphrase(),
  });
  const input = await readStandardInput();
  let profile;
  try {
    profile = JSON.parse(input.toString('utf8'));
  } catch {
    throw new Error('profile input must be valid JSON');
  }
  const bundle = createWorkerPairingBundle(profile, privateKey);
  const temporaryPath = `${destination}.${randomUUID()}.tmp`;
  let temporaryCreated = false;
  try {
    const handle = await open(temporaryPath, 'wx', 0o600);
    temporaryCreated = true;
    try {
      await handle.writeFile(bundle);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await link(temporaryPath, destination);
  } finally {
    if (temporaryCreated) await rm(temporaryPath, { force: true });
  }
  process.stdout.write(`Signed pairing bundle written: ${destination}\n`);
}

main().catch(() => {
  process.stderr.write(
    'Could not sign worker pairing bundle; check configuration and profile data.\n',
  );
  process.exitCode = 1;
});
