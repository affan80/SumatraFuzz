import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { generateFixtures } from '../src/fixtures.js';

const dirs: string[] = [];
afterEach(async () =>
  Promise.all(dirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))),
);

describe('deterministic fixture generation', () => {
  it('creates stable valid seeds and refuses unknown files', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'sumatra seeds '));
    dirs.push(directory);
    const first = await generateFixtures(directory);
    const bytes = await Promise.all(first.map((file) => readFile(file)));
    expect(await generateFixtures(directory)).toEqual(first);
    expect(await Promise.all(first.map((file) => readFile(file)))).toEqual(bytes);
    expect(new Set(bytes.map((value) => value.toString('hex'))).size).toBe(3);
    for (const data of bytes) expect(data.toString('ascii')).toMatch(/^%PDF-1\.4[\s\S]*%%EOF\n$/);
    await writeFile(path.join(directory, 'user.pdf'), 'private');
    await expect(generateFixtures(directory)).rejects.toThrow(/unrecognized/);
  });
});
