import { createHash } from 'node:crypto';

export class DebugLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DebugLogError';
  }
}

export interface DebugEvidence {
  sha256: string;
  pre_count: number;
  post_count: number;
  loaded_modules: string[];
  confirmed_coverage_modules: string[];
  bitmap_nonzero_bytes: number;
  bitmap_units: string;
  discovery_only: boolean;
}

export function inspectDebugLog(
  raw: Buffer,
  options: { expectedCycles: number; requireNonzero: boolean },
): DebugEvidence {
  const { expectedCycles, requireNonzero } = options;
  if (!Number.isInteger(expectedCycles) || expectedCycles < 1 || expectedCycles > 100000)
    throw new DebugLogError('expected_cycles out of range');
  const marker = /Coverage map follows:\r?\n/.exec(raw.toString('latin1'));
  if (!marker) throw new DebugLogError('WinAFL debug coverage map marker missing');
  const start = marker.index + marker[0].length;
  const bitmap = raw.subarray(start);
  if (bitmap.length !== 65536)
    throw new DebugLogError(`Raw coverage bitmap length ${bitmap.length} != 65536`);
  const prefix = raw.subarray(0, marker.index).toString('utf8');
  const pre = [...prefix.matchAll(/^In pre_fuzz_handler\r?$/gm)].length;
  const post = [...prefix.matchAll(/^In post_fuzz_handler\r?$/gm)].length;
  if (pre !== expectedCycles || post !== expectedCycles)
    throw new DebugLogError(
      `Handler mismatch: pre=${pre}, post=${post}, expected=${expectedCycles}`,
    );
  if (!prefix.includes('Everything appears to be running normally.'))
    throw new DebugLogError('WinAFL debug did not confirm normal loop exit');
  if (/^(?:WARNING:|Exception caught:|crashed\b)/im.test(prefix))
    throw new DebugLogError('Exception or warning reported by WinAFL');
  const loaded = [...prefix.matchAll(/^Module loaded, ([^\r\n]+)\r?$/gim)].map((match) => match[1]);
  const byName = new Map(loaded.map((name) => [name.toLowerCase(), name]));
  const parserModules = ['PdfFilter.dll', 'libmupdf.dll'];
  const missing = parserModules.filter((name) => !byName.has(name.toLowerCase()));
  if (missing.length)
    throw new DebugLogError(`Genuine parser modules not observed: ${missing.join(', ')}`);
  let nonzero = 0;
  for (const byte of bitmap) if (byte) nonzero++;
  if (requireNonzero && nonzero === 0)
    throw new DebugLogError('Confirmed parser coverage bitmap has zero nonzero bytes');
  return {
    sha256: createHash('sha256').update(raw).digest('hex'),
    pre_count: pre,
    post_count: post,
    loaded_modules: loaded,
    confirmed_coverage_modules: parserModules.map((name) => {
      const found = byName.get(name.toLowerCase());
      if (found === undefined)
        throw new DebugLogError(`Genuine parser module not observed: ${name}`);
      return found;
    }),
    bitmap_nonzero_bytes: nonzero,
    bitmap_units: 'WinAFL edge bitmap bytes (not source coverage percentage)',
    discovery_only: !requireNonzero,
  };
}
