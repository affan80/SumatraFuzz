import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const migrationOutput = path.join(repositoryRoot, 'packages', 'run-store', 'dist', 'migrations');
await mkdir(migrationOutput, { recursive: true });
await cp(
  path.join(repositoryRoot, 'packages', 'run-store', 'src', 'migrations', '0001_worker.sql'),
  path.join(migrationOutput, '0001_worker.sql'),
);
