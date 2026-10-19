import { mkdir, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ZipFile } from 'yazl';
import { importInputBundle } from '../src/input-bundles.js';

const controllerId = '11111111-1111-4111-8111-111111111111';
const roots: string[] = [];

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sf-input-'));
  roots.push(root);
  await mkdir(path.join(root, 'bundles'));
  return path.join(root, 'bundles');
}

async function makeZip(
  entries: readonly { name: string; bytes: Buffer; mode?: number; compress?: boolean }[],
): Promise<Buffer> {
  const zip = new ZipFile();
  for (const entry of entries)
    zip.addBuffer(entry.bytes, entry.name, {
      compress: entry.compress ?? true,
      ...(entry.mode === undefined ? {} : { mode: entry.mode }),
    });
  zip.end();
  const parts: Buffer[] = [];
  for await (const chunk of zip.outputStream) parts.push(Buffer.from(chunk));
  return Buffer.concat(parts);
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('input bundle staging', () => {
  it('promotes only validated PDF seeds into the authenticated controller namespace', async () => {
    const root = await makeRoot();
    const pdf = Buffer.from('%PDF-1.4\nvalid seed\n%%EOF\n');
    const archive = await makeZip([{ name: 'seed.pdf', bytes: pdf }]);
    const result = await importInputBundle(root, controllerId, archive);
    expect(result.file_count).toBe(1);
    expect(result.expanded_bytes).toBe(pdf.length);
    expect(result.archive_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(
      await readFile(path.join(root, controllerId, result.input_bundle_id, 'seed.pdf')),
    ).toEqual(pdf);
    expect(await readdir(path.join(root, controllerId))).toEqual([result.input_bundle_id]);
  });

  it('rejects traversal names and removes the incomplete staging directory', async () => {
    const root = await makeRoot();
    const archive = await makeZip([{ name: 'good.pdf', bytes: Buffer.from('%PDF-1.4\n') }]);
    const corruptedName = Buffer.from(archive);
    let replacements = 0;
    for (let offset = 0; offset < corruptedName.length - 8; offset += 1) {
      if (corruptedName.toString('ascii', offset, offset + 8) === 'good.pdf') {
        corruptedName.write('../x.pdf', offset, 'ascii');
        replacements += 1;
      }
    }
    expect(replacements).toBe(2);
    await expect(importInputBundle(root, controllerId, corruptedName)).rejects.toThrow();
    expect(await readdir(path.join(root, controllerId))).toEqual([]);
  });

  it('rejects duplicate Windows names, links, and expansion beyond the configured policy', async () => {
    const root = await makeRoot();
    const duplicates = await makeZip([
      { name: 'Seed.pdf', bytes: Buffer.from('%PDF-1.4\n') },
      { name: 'seed.pdf', bytes: Buffer.from('%PDF-1.4\n') },
    ]);
    await expect(importInputBundle(root, controllerId, duplicates)).rejects.toThrow(/duplicate/i);
    const link = await makeZip([
      { name: 'link.pdf', bytes: Buffer.from('target'), mode: 0o120777 },
    ]);
    await expect(importInputBundle(root, controllerId, link)).rejects.toThrow(/non-file/i);
    const bomb = await makeZip([{ name: 'bomb.pdf', bytes: Buffer.alloc(1024 * 1024, 65) }]);
    await expect(importInputBundle(root, controllerId, bomb)).rejects.toThrow(/expansion/i);
    expect(await readdir(path.join(root, controllerId))).toEqual([]);
  });

  it('checks each extracted entry against its ZIP CRC before promoting the bundle', async () => {
    const root = await makeRoot();
    const bytes = Buffer.from('%PDF-1.4\nCRC protected input\n%%EOF\n');
    const archive = await makeZip([{ name: 'seed.pdf', bytes, compress: false }]);
    const damaged = Buffer.from(archive);
    const offset = damaged.indexOf(bytes);
    expect(offset).toBeGreaterThanOrEqual(0);
    damaged[offset + 8] = (damaged[offset + 8] ?? 0) ^ 0xff;
    await expect(importInputBundle(root, controllerId, damaged)).rejects.toThrow(/CRC/i);
    expect(await readdir(path.join(root, controllerId))).toEqual([]);
  });
});
