import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { generateDeterministicSeed, generateGateFixtures } from '../src/seed.js';

const temporary: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporary.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe('deterministic debug seed', () => {
  it('produces a valid deterministic PDF with a correct xref offset', () => {
    const first = generateDeterministicSeed();
    expect(first).toEqual(generateDeterministicSeed());
    expect(first.toString('ascii')).toMatch(/^%PDF-1\.4[\s\S]*%%EOF\n$/);
    const offset = Number(first.toString('ascii').split('startxref\n')[1]?.split('\n')[0]);
    expect(first.subarray(offset, offset + 5).toString()).toBe('xref\n');
  });
});

describe('Windows acceptance gate fixture parity', () => {
  it('writes the exact deterministic three-page fixture set and refuses changed seeds', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'sumatrafuzz-seeds-'));
    temporary.push(directory);
    const files = await generateGateFixtures(directory);
    expect(files.map((file) => path.basename(file))).toEqual([
      'page-100.pdf',
      'page-180.pdf',
      'page-300.pdf',
    ]);
    const hashes = await Promise.all(
      files.map(async (file) =>
        (await import('node:crypto'))
          .createHash('sha256')
          .update(await readFile(file))
          .digest('hex'),
      ),
    );
    expect(hashes).toEqual([
      '1608478b971ed5190557ca977aeeea08b44fabdae1646252b5f4f6d21642335b',
      '60311c3ddfc699f9d684248f229687f33597356567129573632ce262aab71417',
      '01036098485253afdb76da2494d006ef93d9b11c38f30df761c0972b394bd1d6',
    ]);
    await expect(generateGateFixtures(directory)).resolves.toEqual(files);
    const firstFile = files[0];
    if (!firstFile) throw new Error('expected a generated seed file');
    await writeFile(firstFile, 'modified');
    await expect(generateGateFixtures(directory)).rejects.toThrow(
      'Refusing to overwrite modified seed',
    );
  });
});
