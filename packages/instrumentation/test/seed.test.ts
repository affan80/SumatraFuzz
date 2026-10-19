import { describe, expect, it } from 'vitest';
import { generateDeterministicSeed } from '../src/seed.js';

describe('deterministic debug seed', () => {
  it('produces a valid deterministic PDF with a correct xref offset', () => {
    const first = generateDeterministicSeed();
    expect(first).toEqual(generateDeterministicSeed());
    expect(first.toString('ascii')).toMatch(/^%PDF-1\.4[\s\S]*%%EOF\n$/);
    const offset = Number(first.toString('ascii').split('startxref\n')[1]?.split('\n')[0]);
    expect(first.subarray(offset, offset + 5).toString()).toBe('xref\n');
  });
});
