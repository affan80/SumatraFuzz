import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { generateDeterministicSeed } from '@sumatrafuzz/instrumentation/seed';

const outIndex = process.argv.indexOf('--out');
if (outIndex < 0 || !process.argv[outIndex + 1]) throw new Error('usage: generate-debug-seed.ts --out <path>');
const outputArg = process.argv[outIndex + 1];
if (!outputArg) throw new Error('usage: generate-debug-seed.ts --out <path>');
const output = path.resolve(outputArg);
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, generateDeterministicSeed(), { flag: 'wx' });
process.stdout.write(`Wrote deterministic PDF seed: ${output}\n`);
