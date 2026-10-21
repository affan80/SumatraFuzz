import { mkdir, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ZipFile } from 'yazl';
import { importInputBundle, importInputBundleFrom } from '../src/input-bundles.js';

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
    const result = await importInputBundle(root, controllerId, archive, 64 * 1024 * 1024);
    expect(result.file_count).toBe(1);
    expect(result.expanded_bytes).toBe(pdf.length);
    expect(result.archive_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(
      await readFile(path.join(root, controllerId, result.input_bundle_id, 'seed.pdf')),
    ).toEqual(pdf);
    expect(await readdir(path.join(root, controllerId))).toEqual([result.input_bundle_id]);
  });

  it('rejects a bundle that would exceed the aggregate worker disk limit', async () => {
    const root = await makeRoot();
    const pdf = Buffer.from('%PDF-1.4\nfirst retained seed\n%%EOF\n');
    const archive = await makeZip([{ name: 'seed.pdf', bytes: pdf }]);
    const workerDiskLimit = pdf.length;
    let usedBytes = 0;
    const ensureCapacity = async (bytesToWrite: number): Promise<void> => {
      if (usedBytes + bytesToWrite > workerDiskLimit) {
        throw Object.assign(new Error('worker disk limit would be exceeded'), { status: 507 });
      }
    };

    const first = await importInputBundle(root, controllerId, archive, workerDiskLimit, {
      ensureCapacity,
    });
    usedBytes += first.expanded_bytes;
    await expect(
      importInputBundle(root, controllerId, archive, 64 * 1024 * 1024, { ensureCapacity }),
    ).rejects.toThrow(/worker disk limit/i);
    expect(await readdir(path.join(root, controllerId))).toEqual([first.input_bundle_id]);
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
    await expect(
      importInputBundle(root, controllerId, corruptedName, 64 * 1024 * 1024),
    ).rejects.toThrow();
    expect(await readdir(path.join(root, controllerId))).toEqual([]);
  });

  it('rejects duplicate Windows names, links, and expansion beyond the configured policy', async () => {
    const root = await makeRoot();
    const duplicates = await makeZip([
      { name: 'Seed.pdf', bytes: Buffer.from('%PDF-1.4\n') },
      { name: 'seed.pdf', bytes: Buffer.from('%PDF-1.4\n') },
    ]);
    await expect(
      importInputBundle(root, controllerId, duplicates, 64 * 1024 * 1024),
    ).rejects.toThrow(/duplicate/i);
    const link = await makeZip([
      { name: 'link.pdf', bytes: Buffer.from('target'), mode: 0o120777 },
    ]);
    await expect(importInputBundle(root, controllerId, link, 64 * 1024 * 1024)).rejects.toThrow(
      /non-file/i,
    );
    const bomb = await makeZip([{ name: 'bomb.pdf', bytes: Buffer.alloc(1024 * 1024, 65) }]);
    await expect(importInputBundle(root, controllerId, bomb, 64 * 1024 * 1024)).rejects.toThrow(
      /expansion/i,
    );
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
    await expect(importInputBundle(root, controllerId, damaged, 64 * 1024 * 1024)).rejects.toThrow(
      /CRC/i,
    );
    expect(await readdir(path.join(root, controllerId))).toEqual([]);
  });

  it('serializes imports against one aggregate worker disk budget across controllers', async () => {
    const root = await makeRoot();
    const firstController = controllerId;
    const secondController = '22222222-2222-4222-8222-222222222222';
    const pdf = Buffer.from('%PDF-1.4\naggregate budget\n%%EOF\n');
    const archive = await makeZip([{ name: 'seed.pdf', bytes: pdf }]);
    const budget = pdf.length + 1;

    const results = await Promise.allSettled([
      importInputBundle(root, firstController, archive, budget),
      importInputBundle(root, secondController, archive, budget),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toMatchObject({ status: 'rejected' });
    if (rejected?.status === 'rejected') expect(rejected.reason).toMatchObject({ status: 413 });

    let storedBytes = 0;
    for (const controller of [firstController, secondController]) {
      try {
        const bundles = await readdir(path.join(root, controller));
        for (const bundle of bundles) {
          const content = await readFile(path.join(root, controller, bundle, 'seed.pdf'));
          storedBytes += content.length;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    expect(storedBytes).toBe(pdf.length);
    expect(storedBytes).toBeLessThanOrEqual(budget);
  });

  it('serializes archive body reads before buffering concurrent uploads', async () => {
    const root = await makeRoot();
    const pdf = Buffer.from('%PDF-1.4\nserialized request\n%%EOF\n');
    const archive = await makeZip([{ name: 'seed.pdf', bytes: pdf }]);
    let activeReads = 0;
    let peakReads = 0;
    const readArchive = async () => {
      activeReads += 1;
      peakReads = Math.max(peakReads, activeReads);
      await new Promise((resolve) => setTimeout(resolve, 10));
      activeReads -= 1;
      return archive;
    };

    await Promise.all([
      importInputBundleFrom(root, controllerId, readArchive, 64 * 1024 * 1024),
      importInputBundleFrom(
        root,
        '22222222-2222-4222-8222-222222222222',
        readArchive,
        64 * 1024 * 1024,
      ),
    ]);

    expect(peakReads).toBe(1);
  });
});
