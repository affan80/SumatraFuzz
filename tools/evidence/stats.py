"""Strict, fail-closed parsing of genuine WinAFL fuzzer_stats snapshots."""
from __future__ import annotations
import re

REQUIRED = ('execs_done', 'paths_total', 'unique_crashes', 'unique_hangs')
FIELD = re.compile(r'^\s*([A-Za-z_][A-Za-z_0-9]*)\s*:\s*(.*?)\s*$')
NUM = re.compile(r'^[0-9]+$')

class StatsError(ValueError):
    pass

def parse_stats(text: str) -> dict[str, int]:
    fields: dict[str,str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = FIELD.fullmatch(line)
        if m is None:
            raise StatsError('Malformed fuzzer_stats line')
        key,value = m.groups()
        if key in fields:
            raise StatsError(f'Duplicate fuzzer_stats field: {key}')
        fields[key] = value
    missing = [key for key in REQUIRED if key not in fields]
    if missing:
        raise StatsError(f'Missing fuzzer_stats fields: {missing}')
    counters: dict[str,int] = {}
    for key in REQUIRED:
        if NUM.fullmatch(fields[key]) is None:
            raise StatsError(f'Invalid integer counter: {key}')
        counters[key] = int(fields[key])
    return counters

def verify_progress(before: dict[str,int], after: dict[str,int]) -> None:
    if after['execs_done'] <= before['execs_done']:
        raise StatsError('WinAFL execs_done did not advance between actual snapshots')
    if after['paths_total'] < 1:
        raise StatsError('WinAFL did not discover any paths')
    for key in REQUIRED:
        if after[key] < before[key]:
            raise StatsError(f'Monotonic WinAFL counter decreased: {key}')
