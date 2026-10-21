import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readWorkerBundleFile } from '../src/main/worker-bundle-file.js';

const directories: string[] = [];
async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'sumatrafuzz-bundle-file-'));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
});

describe('selected worker bundle file reader', () => {
  it('reads a bounded regular file as bytes', async () => {
    const filePath = path.join(await temporaryDirectory(), 'pairing.sfpair');
    await writeFile(filePath, Buffer.from([0, 1, 2, 255]));
    await expect(readWorkerBundleFile(filePath)).resolves.toEqual(Buffer.from([0, 1, 2, 255]));
  });

  it('rejects empty, oversized, and symbolic-link bundle files', async () => {
    const directory = await temporaryDirectory();
    const emptyPath = path.join(directory, 'empty.sfpair');
    const largePath = path.join(directory, 'large.sfpair');
    const targetPath = path.join(directory, 'target.sfpair');
    const linkPath = path.join(directory, 'link.sfpair');
    await writeFile(emptyPath, '');
    await writeFile(largePath, Buffer.alloc(1024 * 1024 + 1));
    await writeFile(targetPath, 'data');
    await symlink(targetPath, linkPath);

    await expect(readWorkerBundleFile(emptyPath)).rejects.toThrow(/invalid or too large/);
    await expect(readWorkerBundleFile(largePath)).rejects.toThrow(/invalid or too large/);
    await expect(readWorkerBundleFile(linkPath)).rejects.toThrow(/invalid or too large/);
  });
});
