import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rendererOutput = path.join(repositoryRoot, 'apps', 'desktop', 'dist', 'renderer');
await mkdir(rendererOutput, { recursive: true });
await cp(
  path.join(repositoryRoot, 'apps', 'desktop', 'src', 'renderer', 'index.html'),
  path.join(rendererOutput, 'index.html'),
);
