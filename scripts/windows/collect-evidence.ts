import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { collectEvidence } from '@sumatrafuzz/evidence/collect';

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

const evidence = await collectEvidence({
  runDir: option('--run-dir'),
  toolchainLock: option('--toolchain-lock'),
  a4Manifest: option('--a4-manifest'),
  harness: option('--harness'),
  beforeStats: option('--before-stats'),
  afterStats: option('--after-stats'),
});
const output = path.resolve(option('--output'));
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
process.stdout.write(`Verified actual WinAFL evidence: ${output}\n`);
