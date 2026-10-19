import { describe, expect, it } from 'vitest';
import { DebugLogError, inspectDebugLog } from '../src/verify-debug.js';

function sample(cycles = 10, nonzero = true): Buffer {
  const lines = [
    'Module loaded, sumatrafuzz-harness.exe',
    'Module loaded, PdfFilter.dll',
    'Module loaded, libmupdf.dll',
  ];
  for (let i = 0; i < cycles; i++) lines.push('In pre_fuzz_handler', 'In post_fuzz_handler');
  lines.push('Everything appears to be running normally.', 'Coverage map follows:');
  const bitmap = Buffer.alloc(65536);
  if (nonzero) bitmap[42] = 1;
  return Buffer.concat([Buffer.from(`${lines.join('\n')}\n`), bitmap]);
}

describe('raw instrumentation evidence', () => {
  it('confirms exact cycles and parser modules', () => {
    const result = inspectDebugLog(sample(), { expectedCycles: 10, requireNonzero: true });
    expect(result.pre_count).toBe(10);
    expect(result.confirmed_coverage_modules).toEqual(['PdfFilter.dll', 'libmupdf.dll']);
    expect(result.bitmap_nonzero_bytes).toBeGreaterThan(0);
  });
  it('rejects missing modules, incomplete cycles, warnings, and malformed bitmaps', () => {
    for (const bytes of [sample(9), sample().subarray(0, -1), Buffer.from('normal')]) {
      expect(() => inspectDebugLog(bytes, { expectedCycles: 10, requireNonzero: true })).toThrow(
        DebugLogError,
      );
    }
    expect(() =>
      inspectDebugLog(sample(10, false), { expectedCycles: 10, requireNonzero: true }),
    ).toThrow(DebugLogError);
  });
});
