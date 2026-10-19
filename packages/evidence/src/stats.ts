export const REQUIRED_STATS = [
  'execs_done',
  'paths_total',
  'unique_crashes',
  'unique_hangs',
] as const;
export type WinAflStats = Record<(typeof REQUIRED_STATS)[number], number>;

export class StatsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StatsError';
  }
}

export function parseWinAflStats(text: string): WinAflStats {
  const fields = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const match = /^\s*([A-Za-z_][A-Za-z_0-9]*)\s*:\s*(.*?)\s*$/.exec(line);
    if (!match) throw new StatsError('Malformed fuzzer_stats line');
    const key = match[1];
    const value = match[2];
    if (key === undefined || value === undefined)
      throw new StatsError('Malformed fuzzer_stats line');
    if (fields.has(key)) throw new StatsError(`Duplicate fuzzer_stats field: ${key}`);
    fields.set(key, value);
  }
  for (const key of REQUIRED_STATS)
    if (!fields.has(key)) throw new StatsError(`Missing fuzzer_stats field: ${key}`);
  const counters = Object.fromEntries(
    REQUIRED_STATS.map((key) => {
      const value = fields.get(key);
      if (value === undefined) throw new StatsError(`Missing fuzzer_stats field: ${key}`);
      if (!/^[0-9]+$/.test(value)) throw new StatsError(`Invalid integer counter: ${key}`);
      const number = Number(value);
      if (!Number.isSafeInteger(number)) throw new StatsError(`Unsafe integer counter: ${key}`);
      return [key, number];
    }),
  ) as WinAflStats;
  return counters;
}

export function verifyProgress(before: WinAflStats, after: WinAflStats): void {
  if (after.execs_done <= before.execs_done)
    throw new StatsError('WinAFL execs_done did not advance between actual snapshots');
  if (after.paths_total < 1) throw new StatsError('WinAFL did not discover any paths');
  for (const key of REQUIRED_STATS)
    if (after[key] < before[key])
      throw new StatsError(`Monotonic WinAFL counter decreased: ${key}`);
}
