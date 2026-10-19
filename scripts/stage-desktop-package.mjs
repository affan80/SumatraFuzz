import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appRoot = path.join(repositoryRoot, 'apps', 'desktop');
const stageRoot = path.join(appRoot, '.package-stage');
const workspacePackages = [
  ['@sumatrafuzz/worker-client', 'packages/worker-client', ['package.json', 'dist']],
  ['@sumatrafuzz/worker-protocol', 'packages/worker-protocol', ['package.json', 'dist']],
];
const runtimeDependencies = [
  ['ajv', ['package.json', 'dist']],
  ['ajv-formats', ['package.json', 'dist']],
  ['fast-deep-equal', ['package.json', 'index.js']],
  ['fast-uri', ['package.json', 'index.js', 'lib']],
  ['json-schema-traverse', ['package.json', 'index.js']],
  ['require-from-string', ['package.json', 'index.js']],
];

async function copySelected(sourceRoot, destinationRoot, paths) {
  for (const selected of paths) {
    const source = path.join(sourceRoot, selected);
    const destination = path.join(destinationRoot, selected);
    await mkdir(path.dirname(destination), { recursive: true });
    await cp(source, destination, { recursive: true, force: true });
  }
}

async function copyRuntimeFiles(sourceRoot, destinationRoot, extensions) {
  for (const entry of await readdir(sourceRoot, { withFileTypes: true })) {
    const source = path.join(sourceRoot, entry.name);
    const destination = path.join(destinationRoot, entry.name);
    if (entry.isDirectory()) {
      await copyRuntimeFiles(source, destination, extensions);
    } else if (entry.isFile() && extensions.has(path.extname(entry.name).toLowerCase())) {
      await mkdir(path.dirname(destination), { recursive: true });
      await cp(source, destination);
    }
  }
}

await rm(stageRoot, { recursive: true, force: true });
await mkdir(path.join(stageRoot, 'dist'), { recursive: true });
await copyRuntimeFiles(
  path.join(appRoot, 'dist', 'renderer'),
  path.join(stageRoot, 'dist', 'renderer'),
  new Set(['.js', '.html']),
);
for (const output of ['src/main', 'src/preload']) {
  await copyRuntimeFiles(
    path.join(appRoot, 'dist', output),
    path.join(stageRoot, 'dist', output),
    new Set(['.js']),
  );
}
await copySelected(path.join(appRoot, 'dist'), path.join(stageRoot, 'dist'), [
  'resources/worker-bundle-signing-key.pem',
]);
await writeFile(
  path.join(stageRoot, 'package.json'),
  `${JSON.stringify(JSON.parse(await readFile(path.join(appRoot, 'package.json'), 'utf8')), null, 2)}\n`,
);

for (const [packageName, repositoryPath, selected] of workspacePackages) {
  const sourceRoot = path.join(repositoryRoot, repositoryPath);
  const destinationRoot = path.join(stageRoot, 'node_modules', ...packageName.split('/'));
  await copySelected(sourceRoot, destinationRoot, selected);
}
for (const [packageName, selected] of runtimeDependencies) {
  const sourceRoot = path.join(repositoryRoot, 'node_modules', ...packageName.split('/'));
  const destinationRoot = path.join(stageRoot, 'node_modules', ...packageName.split('/'));
  await copySelected(sourceRoot, destinationRoot, selected);
}
const typeboxSource = path.join(repositoryRoot, 'node_modules', '@sinclair', 'typebox');
const typeboxDestination = path.join(stageRoot, 'node_modules', '@sinclair', 'typebox');
await copySelected(typeboxSource, typeboxDestination, ['package.json']);
await copyRuntimeFiles(
  path.join(typeboxSource, 'build', 'esm'),
  path.join(typeboxDestination, 'build', 'esm'),
  new Set(['.mjs']),
);

console.log('Staged the compiled desktop and its explicit runtime dependency closure.');
