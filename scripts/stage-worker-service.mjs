import { spawnSync } from 'node:child_process';
import { createPublicKey } from 'node:crypto';
import { cp, lstat, mkdir, open, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultOutput = path.join(repositoryRoot, 'release', 'worker-service', 'SumatraFuzz');
const defaultPublicKey = path.join(
  repositoryRoot,
  'apps',
  'desktop',
  'resources',
  'worker-bundle-signing-key.pem',
);
const expectedLayout = [
  'apps/worker-service/dist/src/service-entry.js',
  'config/organization-signing-public-key.pem',
  'native/worker-supervisor/build/Release/worker_supervisor.node',
  'packages/run-store/dist/index.js',
  'packages/worker-core/dist/index.js',
  'packages/worker-protocol/dist/index.js',
  'packages/worker-security/dist/src/index.js',
  'provisioning/install-worker-service.ps1',
  'provisioning/provision-worker-service.ps1',
  'provisioning/uninstall-worker-service.ps1',
  'provisioning/worker-service-config.psm1',
  'provisioning/README.md',
  'runtime/node.exe',
  'service/SumatraFuzzWorkerHost.exe',
];

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (!['--node', '--host', '--output', '--public-key'].includes(option)) {
      throw new Error(`Unknown option: ${option}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith('--') || values.has(option)) {
      throw new Error(`Expected one value for ${option}`);
    }
    values.set(option, path.resolve(value));
    index += 1;
  }
  for (const required of ['--node', '--host']) {
    if (!values.has(required)) throw new Error(`Missing required option ${required}`);
  }
  return {
    node: values.get('--node'),
    host: values.get('--host'),
    output: values.get('--output') ?? defaultOutput,
    publicKey: values.get('--public-key') ?? defaultPublicKey,
  };
}

async function assertOrdinaryPath(filePath, { directory = false } = {}) {
  const metadata = await lstat(filePath);
  if (metadata.isSymbolicLink() || (directory ? !metadata.isDirectory() : !metadata.isFile())) {
    throw new Error(`Expected an ordinary ${directory ? 'directory' : 'file'}: ${filePath}`);
  }
  const parsed = path.parse(path.resolve(filePath));
  let current = parsed.root;
  for (const part of path
    .resolve(filePath)
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, part);
    const entry = await lstat(current);
    if (entry.isSymbolicLink()) throw new Error(`Reparse/symlink source is forbidden: ${current}`);
  }
  return metadata;
}

async function assertNoReparseTree(root) {
  await assertOrdinaryPath(root, { directory: true });
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const child = path.join(root, entry.name);
    const metadata = await lstat(child);
    if (metadata.isSymbolicLink() || entry.isSymbolicLink()) {
      throw new Error(`Reparse/symlink source is forbidden: ${child}`);
    }
    if (entry.isDirectory()) await assertNoReparseTree(child);
    else if (!entry.isFile()) throw new Error(`Unexpected filesystem object: ${child}`);
  }
}

async function ensureOrdinaryDirectoryChain(directory) {
  const absolute = path.resolve(directory);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const metadata = await lstat(current);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error(`Output path contains a reparse point or non-directory: ${current}`);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await mkdir(current);
    }
  }
}

async function verifyX64Pe(filePath) {
  await assertOrdinaryPath(filePath);
  const handle = await open(filePath, 'r');
  try {
    const header = Buffer.alloc(64);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    if (bytesRead !== header.length || header.toString('ascii', 0, 2) !== 'MZ') {
      throw new Error(`Expected a Windows PE x64 binary: ${filePath}`);
    }
    const peOffset = header.readUInt32LE(0x3c);
    const peHeader = Buffer.alloc(6);
    const result = await handle.read(peHeader, 0, peHeader.length, peOffset);
    if (
      result.bytesRead !== peHeader.length ||
      peHeader.toString('binary', 0, 4) !== 'PE\0\0' ||
      peHeader.readUInt16LE(4) !== 0x8664
    ) {
      throw new Error(`Expected a Windows x64 PE binary: ${filePath}`);
    }
  } finally {
    await handle.close();
  }
}

async function copyFile(source, destination) {
  await assertOrdinaryPath(source);
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { errorOnExist: true, force: false });
}

async function copyRuntimeTree(sourceRoot, destinationRoot, extensions) {
  await assertNoReparseTree(sourceRoot);
  const copy = async (source, destination) => {
    for (const entry of await readdir(source, { withFileTypes: true })) {
      const sourcePath = path.join(source, entry.name);
      const destinationPath = path.join(destination, entry.name);
      if (entry.isDirectory()) await copy(sourcePath, destinationPath);
      else if (entry.isFile() && extensions.has(path.extname(entry.name).toLowerCase())) {
        await copyFile(sourcePath, destinationPath);
      } else if (
        entry.isFile() &&
        ['.d.mts', '.d.ts', '.map', '.md', '.ts'].some((extension) =>
          sourcePath.endsWith(extension),
        )
      ) {
        // Build metadata and documentation are known non-runtime files and are omitted.
      } else if (!entry.isFile()) {
        throw new Error(`Unexpected filesystem object: ${sourcePath}`);
      } else {
        throw new Error(`Unexpected file in runtime source tree: ${sourcePath}`);
      }
    }
  };
  await mkdir(destinationRoot, { recursive: true });
  await copy(sourceRoot, destinationRoot);
}

async function copyNodePackage(
  packagePath,
  packageName,
  destinationRoot,
  runtimeFiles,
  runtimeDirectories,
) {
  const sourceRoot = path.join(repositoryRoot, 'node_modules', ...packagePath.split('/'));
  await assertOrdinaryPath(sourceRoot, { directory: true });
  const destination = path.join(destinationRoot, 'node_modules', ...packageName.split('/'));
  await copyFile(path.join(sourceRoot, 'package.json'), path.join(destination, 'package.json'));
  for (const relativeFile of runtimeFiles) {
    await copyFile(path.join(sourceRoot, relativeFile), path.join(destination, relativeFile));
  }
  for (const relativeDirectory of runtimeDirectories) {
    await copyRuntimeTree(
      path.join(sourceRoot, relativeDirectory),
      path.join(destination, relativeDirectory),
      new Set(['.js', '.json', '.mjs']),
    );
  }
}

async function checkStagedPackage(root) {
  const files = [];
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) {
        throw new Error(`Package contains a reparse/unexpected filesystem object: ${relative}`);
      }
      if (entry.isDirectory()) await visit(absolute);
      else files.push(relative);
    }
  };
  await visit(root);
  for (const expected of expectedLayout) {
    if (!files.includes(expected)) throw new Error(`Package is missing required file: ${expected}`);
  }
  const allowedExtensions = new Set([
    '.exe',
    '.js',
    '.json',
    '.md',
    '.mjs',
    '.node',
    '.pem',
    '.ps1',
    '.psm1',
    '.sql',
  ]);
  for (const relative of files) {
    if (!allowedExtensions.has(path.extname(relative).toLowerCase())) {
      throw new Error(`Package contains an unexpected file type: ${relative}`);
    }
    if (/private[-_ ]?key|\.p12$|\.pfx$|\.key$/i.test(relative)) {
      throw new Error(`Private-key material is forbidden in the worker package: ${relative}`);
    }
  }
  const publicKey = await readFile(
    path.join(root, 'config', 'organization-signing-public-key.pem'),
    'utf8',
  );
  if (publicKey.includes('PRIVATE KEY'))
    throw new Error('Private-key material found in signing key input');
  const parsedKey = createPublicKey(publicKey);
  if (parsedKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('Organization signing root must be an Ed25519 public key');
  }
  for (const binary of files.filter((item) => ['.exe', '.node'].includes(path.extname(item)))) {
    await verifyX64Pe(path.join(root, ...binary.split('/')));
  }
  const runtimeSmoke = spawnSync(
    path.join(root, 'runtime', 'node.exe'),
    [
      '--input-type=module',
      '-e',
      "await import('./apps/worker-service/dist/src/service-entry.js'); const { createRequire } = await import('node:module'); const require = createRequire(import.meta.url); require('better-sqlite3'); require('./native/worker-supervisor/build/Release/worker_supervisor.node');",
    ],
    { cwd: root, encoding: 'utf8', windowsHide: true },
  );
  if (runtimeSmoke.error || runtimeSmoke.status !== 0) {
    throw new Error('Staged worker runtime dependency smoke check failed');
  }
  return files;
}

async function main() {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    throw new Error('Worker service packages must be staged on Windows x64');
  }
  const args = parseArguments(process.argv.slice(2));
  const stage = args.output;
  const releaseRoot = path.join(repositoryRoot, 'release', 'worker-service');
  if (
    path.dirname(stage).toLowerCase() !== releaseRoot.toLowerCase() ||
    path.basename(stage).toLowerCase() !== 'sumatrafuzz'
  ) {
    throw new Error(`Output must be the fixed package directory ${defaultOutput}`);
  }
  await verifyX64Pe(args.node);
  await verifyX64Pe(args.host);
  await assertOrdinaryPath(args.publicKey);
  const pem = await readFile(args.publicKey, 'utf8');
  if (pem.includes('PRIVATE KEY')) throw new Error('Signing input must not contain a private key');
  const signingKey = createPublicKey(pem);
  if (signingKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('Signing input must be an Ed25519 public key');
  }

  const serviceDist = path.join(repositoryRoot, 'apps', 'worker-service', 'dist', 'src');
  const packageDefinitions = [
    ['worker-core', ['dist']],
    ['worker-protocol', ['dist']],
    ['worker-security', ['dist/src']],
    ['run-store', ['dist']],
  ];
  const nodeRuntimePackages = [
    ['@sinclair/typebox', [], ['build/cjs', 'build/esm']],
    ['ajv', [], ['dist']],
    ['ajv-formats', [], ['dist']],
    ['fast-deep-equal', ['index.js'], []],
    ['fast-uri', ['index.js'], ['lib']],
    ['json-schema-traverse', ['index.js'], []],
    ['node-addon-api', ['index.js'], []],
    ['pend', ['index.js'], []],
    ['require-from-string', ['index.js'], []],
    ['yauzl', ['index.js', 'fd-slicer.js', 'crc32.js'], []],
  ];
  const workspaceRoot = path.join(stage, 'packages');
  const nodeModulesRoot = stage;

  await stat(serviceDist);
  const releaseParent = path.dirname(stage);
  await ensureOrdinaryDirectoryChain(releaseParent);
  try {
    await lstat(stage);
    throw new Error(`Refusing to replace an existing worker package: ${stage}`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await mkdir(stage, { recursive: true });
  await copyFile(args.node, path.join(stage, 'runtime', 'node.exe'));
  await copyFile(args.host, path.join(stage, 'service', 'SumatraFuzzWorkerHost.exe'));
  await copyFile(args.publicKey, path.join(stage, 'config', 'organization-signing-public-key.pem'));
  await copyRuntimeTree(
    serviceDist,
    path.join(stage, 'apps', 'worker-service', 'dist', 'src'),
    new Set(['.js']),
  );
  await copyFile(
    path.join(repositoryRoot, 'apps', 'worker-service', 'package.json'),
    path.join(stage, 'apps', 'worker-service', 'package.json'),
  );
  const provisioningRoot = path.join(stage, 'provisioning');
  for (const name of [
    'install-worker-service.ps1',
    'provision-worker-service.ps1',
    'uninstall-worker-service.ps1',
    'worker-service-config.psm1',
  ]) {
    await copyFile(
      path.join(repositoryRoot, 'scripts', 'windows', name),
      path.join(provisioningRoot, name),
    );
  }
  await copyFile(
    path.join(repositoryRoot, 'docs', 'security', 'windows-worker-service-package.md'),
    path.join(provisioningRoot, 'README.md'),
  );

  for (const [name, runtimeDirectories] of packageDefinitions) {
    const source = path.join(repositoryRoot, 'packages', name);
    const destinations = [
      path.join(workspaceRoot, name),
      path.join(stage, 'node_modules', '@sumatrafuzz', name),
    ];
    for (const destination of destinations) {
      await copyFile(path.join(source, 'package.json'), path.join(destination, 'package.json'));
      for (const relativeDirectory of runtimeDirectories) {
        const extensions = new Set(['.js', '.sql']);
        await copyRuntimeTree(
          path.join(source, relativeDirectory),
          path.join(destination, relativeDirectory),
          extensions,
        );
      }
    }
  }

  for (const [name, runtimeFiles, runtimeDirectories] of nodeRuntimePackages) {
    await copyNodePackage(name, name, nodeModulesRoot, runtimeFiles, runtimeDirectories);
  }
  await copyFile(
    path.join(repositoryRoot, 'node_modules', 'better-sqlite3', 'package.json'),
    path.join(stage, 'node_modules', 'better-sqlite3', 'package.json'),
  );
  await copyRuntimeTree(
    path.join(repositoryRoot, 'node_modules', 'better-sqlite3', 'lib'),
    path.join(stage, 'node_modules', 'better-sqlite3', 'lib'),
    new Set(['.js']),
  );
  await copyFile(
    path.join(
      repositoryRoot,
      'node_modules',
      'better-sqlite3',
      'build',
      'Release',
      'better_sqlite3.node',
    ),
    path.join(stage, 'node_modules', 'better-sqlite3', 'build', 'Release', 'better_sqlite3.node'),
  );
  await copyFile(
    path.join(
      repositoryRoot,
      'native',
      'worker-supervisor',
      'build',
      'Release',
      'worker_supervisor.node',
    ),
    path.join(stage, 'native', 'worker-supervisor', 'build', 'Release', 'worker_supervisor.node'),
  );

  const stagedFiles = await checkStagedPackage(stage);
  await writeFile(
    path.join(stage, 'package-manifest.json'),
    `${JSON.stringify({ schema: 1, target: 'win32-x64', files: stagedFiles.sort() }, null, 2)}\n`,
    { flag: 'wx' },
  );
  console.log(
    `Staged Windows x64 worker-service payload (${stagedFiles.length} files) at ${stage}`,
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : 'Worker package staging failed');
  process.exitCode = 1;
});
