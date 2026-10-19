import { describe, expect, it } from 'vitest';
import { parseWinAflStats, StatsError, verifyProgress } from '../src/stats.js';

const raw = 'execs_done : 45\npaths_total : 2\nunique_crashes : 0\nunique_hangs : 0\n';
describe('WinAFL statistics', () => {
  it('parses required counters and checks measured progress', () => {
    const before = parseWinAflStats(raw);
    const after = parseWinAflStats(raw.replace('45', '50'));
    expect(before.execs_done).toBe(45);
    expect(() => verifyProgress(before, after)).not.toThrow();
  });
  it('rejects missing, duplicate, malformed, unchanged, and decreasing counters', () => {
    for (const invalid of ['execs_done: NA', `${raw}execs_done: 46`, 'execs_done: 2']) {
      expect(() => parseWinAflStats(invalid)).toThrow(StatsError);
    }
    const before = parseWinAflStats(raw);
    expect(() => verifyProgress(before, before)).toThrow(StatsError);
    expect(() => verifyProgress(parseWinAflStats(raw.replace('45', '55')), before)).toThrow(
      StatsError,
    );
  });
});
