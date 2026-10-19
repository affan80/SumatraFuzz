import { readFile } from 'node:fs/promises';
import { parseWinAflStats, StatsError, verifyProgress } from '@sumatrafuzz/evidence/stats';

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

const minimumIndex = process.argv.indexOf('--min-execs');
const minimum = Number(minimumIndex < 0 ? '1000' : process.argv[minimumIndex + 1]);
if (!Number.isSafeInteger(minimum) || minimum < 1) throw new StatsError('min-execs must be positive');
const before = parseWinAflStats(await readFile(option('--before'), 'utf8'));
const after = parseWinAflStats(await readFile(option('--after'), 'utf8'));
const final = parseWinAflStats(await readFile(option('--final'), 'utf8'));
verifyProgress(before, after);
if (final.execs_done < after.execs_done) throw new StatsError('Final WinAFL snapshot is older than progress snapshot');
if (final.execs_done < minimum) throw new StatsError(`Actual WinAFL execs_done=${final.execs_done} below reference target ${minimum}`);
process.stdout.write(`Actual WinAFL campaign counters: ${JSON.stringify(final)}\n`);
