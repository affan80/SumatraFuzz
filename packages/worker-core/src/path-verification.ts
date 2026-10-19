import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { WorkerError, WorkerProtocolError } from '@sumatrafuzz/worker-protocol';

const untrustedPath = () =>
  new WorkerProtocolError(WorkerError.UnverifiedToolchain, 'untrusted filesystem path');

export function rejectSpecialWindowsPath(value: string): void {
  if (/^(?:\\\\[?.]\\|\\\\[^\\]+\\[^\\]+)/.test(value)) throw untrustedPath();
}

async function rejectSymlinkFromRoot(absolute: string): Promise<void> {
  const metadata = await lstat(absolute).catch(() => {
    throw untrustedPath();
  });
  if (metadata.isSymbolicLink()) throw untrustedPath();
}

async function rejectSymlinkDescendants(root: string, target: string): Promise<void> {
  const relative = path.relative(root, target);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const metadata = await lstat(current).catch(() => {
      throw untrustedPath();
    });
    if (metadata.isSymbolicLink()) throw untrustedPath();
  }
}

export async function verifyPathWithinRoot(
  candidate: string,
  root: string,
  options: { allowRoot?: boolean } = {},
): Promise<string> {
  rejectSpecialWindowsPath(candidate);
  rejectSpecialWindowsPath(root);
  if (!path.isAbsolute(candidate) || !path.isAbsolute(root)) throw untrustedPath();

  const candidateAbsolute = path.resolve(candidate);
  const rootAbsolute = path.resolve(root);
  const lexicalRelative = path.relative(rootAbsolute, candidateAbsolute);
  if (
    lexicalRelative === '..' ||
    lexicalRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(lexicalRelative)
  ) {
    throw untrustedPath();
  }
  await rejectSymlinkFromRoot(rootAbsolute);
  await rejectSymlinkDescendants(rootAbsolute, candidateAbsolute);

  const [candidateReal, rootReal] = await Promise.all([
    realpath(candidateAbsolute),
    realpath(rootAbsolute),
  ]);
  const relative = path.relative(rootReal, candidateReal);
  if (relative === '') {
    if (options.allowRoot) return candidateReal;
    throw untrustedPath();
  }
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw untrustedPath();
  }
  return candidateReal;
}

export function toOrdinaryWindowsPath(value: string): string {
  if (process.platform !== 'win32') return value;
  if (value.startsWith('\\\\?\\UNC\\')) return `\\\\${value.slice('\\\\?\\UNC\\'.length)}`;
  if (value.startsWith('\\\\?\\')) return value.slice('\\\\?\\'.length);
  return value;
}
