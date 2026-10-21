import { open, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MAX_INPUT_BUNDLE_BYTES, readInputBundleFile } from '../src/main/input-bundle-file.js';

const directories: string[] = [];
async function temporaryDirectory(): Promise<string> {
  const { mkdtemp } = await import('node:fs/promises');
  const directory = await mkdtemp(path.join(tmpdir(), 'sumatrafuzz-input-bundle-'));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
});

describe('selected campaign archive reader', () => {
  it('reads only bounded bytes and returns no path metadata', async () => {
    const filePath = path.join(await temporaryDirectory(), 'campaign.zip');
    const bytes = Buffer.from([0, 1, 2, 255]);
    await writeFile(filePath, bytes);
    await expect(readInputBundleFile(filePath)).resolves.toEqual(bytes);
  });

  it('rejects empty, oversized, and symbolic-link files', async () => {
    const directory = await temporaryDirectory();
    const emptyPath = path.join(directory, 'empty.zip');
    const largePath = path.join(directory, 'large.zip');
    const targetPath = path.join(directory, 'target.zip');
    const linkPath = path.join(directory, 'link.zip');
    await writeFile(emptyPath, '');
    await writeFile(largePath, Buffer.alloc(MAX_INPUT_BUNDLE_BYTES + 1));
    await writeFile(targetPath, 'data');
    await symlink(targetPath, linkPath);

    await expect(readInputBundleFile(emptyPath)).rejects.toThrow(/invalid or too large/i);
    await expect(readInputBundleFile(largePath)).rejects.toThrow(/invalid or too large/i);
    await expect(readInputBundleFile(linkPath)).rejects.toThrow(/invalid or too large/i);
  });

  it('rejects a replacement between metadata check and open', async () => {
    const filePath = path.join(await temporaryDirectory(), 'replace.zip');
    await writeFile(filePath, 'first');
    let replaced = false;
    await expect(
      readInputBundleFile(filePath, async (selectedPath, flags) => {
        if (!replaced) {
          replaced = true;
          await rm(selectedPath);
          await writeFile(selectedPath, 'second');
        }
        return open(selectedPath, flags);
      }),
    ).rejects.toThrow(/changed while opening/i);
  });

  it('rejects a file that grows after it is opened', async () => {
    const filePath = path.join(await temporaryDirectory(), 'growing.zip');
    await writeFile(filePath, 'first');
    let grown = false;
    await expect(
      readInputBundleFile(filePath, async (selectedPath, flags) => {
        const handle = await open(selectedPath, flags);
        if (!grown) {
          grown = true;
          await writeFile(selectedPath, 'second and larger');
        }
        return handle;
      }),
    ).rejects.toThrow(/changed while opening|changed while reading/i);
  });
});
