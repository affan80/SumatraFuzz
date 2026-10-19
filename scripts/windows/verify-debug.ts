import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { inspectDebugLog } from '@sumatrafuzz/instrumentation/verify-debug';

function option(name: string, fallback?: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? fallback : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

const logPath = path.resolve(option('--log'));
const output = path.resolve(option('--out'));
const expectedCycles = Number(option('--expected-cycles', '10'));
const discoveryOnly = process.argv.includes('--discovery-only');
const evidence = inspectDebugLog(await readFile(logPath), { expectedCycles, requireNonzero: !discoveryOnly });
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
process.stdout.write(`Verified raw WinAFL log: ${logPath} nonzero map bytes: ${evidence.bitmap_nonzero_bytes}\n`);
