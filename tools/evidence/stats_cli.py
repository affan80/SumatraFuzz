"""Validate that real WinAFL counters advance between raw snapshots."""
from __future__ import annotations
import argparse
from pathlib import Path
from stats import parse_stats, verify_progress, StatsError

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--before',required=True,type=Path)
    p.add_argument('--after',required=True,type=Path)
    p.add_argument('--final',required=True,type=Path)
    p.add_argument('--min-execs',type=int,default=1000)
    a=p.parse_args()
    try:
        if a.min_execs < 1:
            raise StatsError('min-execs must be positive')
        before=parse_stats(a.before.read_text(encoding='utf-8'))
        after=parse_stats(a.after.read_text(encoding='utf-8'))
        final=parse_stats(a.final.read_text(encoding='utf-8'))
        verify_progress(before,after)
        if final['execs_done'] < after['execs_done']:
            raise StatsError('Final WinAFL snapshot is older than progress snapshot')
        if final['execs_done'] < a.min_execs:
            raise StatsError(f"Actual WinAFL execs_done={final['execs_done']} below reference target {a.min_execs}")
    except (OSError,StatsError) as error:
        p.exit(1,f'FAILED: {error}\n')
    print('Actual WinAFL campaign counters: ',final)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
