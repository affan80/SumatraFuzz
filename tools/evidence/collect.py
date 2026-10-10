"""Collect verifiable, non-sensitive metadata from an actual WinAFL run.

Does not generate artificial stats, example evidence, or publish raw crash PDFs.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from stats import parse_stats, verify_progress, StatsError
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'instrumentation'))
from verify_debug import inspect_debug_log, DebugLogError

PIN='16c59fde8b824ab54c56f23aef910a6fdd874ad0'

class EvidenceError(ValueError):
    pass

def digest(p:Path) -> str:
    if not p.is_file(): raise EvidenceError(f'Missing evidence file: {p}')
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read_json(p:Path)->dict:
    try:return json.loads(p.read_text(encoding='utf-8-sig'))
    except (OSError,ValueError) as e:raise EvidenceError(f'Invalid JSON file {p}: {e}') from e

def compare_file(p:Path,expected:str,label:str):
    if digest(p).lower()!=str(expected).lower():raise EvidenceError(f'SHA-256 mismatch for {label}: {p}')

def finding_inventory(run_dir: Path, kind: str, observed_count: int) -> list[dict]:
    """Inspect actual WinAFL crash/hang files, never synthesize findings.

    Only WinAFL's id_* artifacts count; an optional README is not a crash.
    WinAFL writes statistics periodically. A bounded forced stop may leave
    additional saved artifacts after the last stats snapshot; preserve both
    observations without changing or inventing the reported counters.
    """
    if kind not in ('crashes', 'hangs'):
        raise EvidenceError(f'Unsupported finding kind: {kind}')
    folder = run_dir / kind
    if not folder.exists():
        if observed_count == 0:
            return []
        raise EvidenceError(f'Missing {kind} artifacts for {observed_count} measured findings')
    if folder.is_symlink() or not folder.is_dir():
        raise EvidenceError(f'Unsafe or invalid {kind} artifact directory')
    candidates = sorted(p for p in folder.iterdir() if p.name.startswith('id_'))
    if any(p.is_symlink() or not p.is_file() for p in candidates):
        raise EvidenceError(f'Unsafe {kind} sample: nonregular file or symlink')
    if len(candidates) < observed_count:
        raise EvidenceError(
            f'{kind} artifact count {len(candidates)} differs from measured unique findings {observed_count}'
        )
    return [
        {
            'path': f'{kind}/{p.name}',
            'sha256': digest(p),
            'bytes': p.stat().st_size,
            'classification': 'untriaged',
            'replay_argv': ['sumatrafuzz-harness.exe', f'{kind}/{p.name}'],
        }
        for p in candidates
    ]

def collect(*,run_dir:Path,toolchain_lock:Path,a4_manifest:Path,harness:Path,before_stats:Path,after_stats:Path)->dict:
    lock=read_json(toolchain_lock)
    a4=read_json(a4_manifest)
    if lock.get('source_commit') != PIN or a4.get('target_commit') != PIN:
        raise EvidenceError('Pinned SumatraPDF source SHA mismatch')
    compare_file(toolchain_lock,a4.get('toolchain_lock_sha256'), 'A4 toolchain lock')
    if a4.get('cycles') != 10 or not a4.get('confirmed_modules') or a4.get('confirmed_map_nonzero_bytes',0)<=0:
        raise EvidenceError('A4 genuine ten-cycle coverage evidence missing')
    for name,entry in lock['tools'].items():
        compare_file(Path(entry['path']),entry['sha256'],f'{name} binary')
    compare_file(harness,a4['harness_sha256'],'harness')
    folder=harness.parent
    compare_file(folder/'PdfFilter.dll',a4['pdf_filter_sha256'],'PDF parser')
    compare_file(folder/'libmupdf.dll',a4['mupdf_sha256'],'MuPDF component')
    raw_log=Path(a4['confirmed_log'])
    compare_file(raw_log,a4['confirmed_log_sha256'],'raw DynamoRIO log')
    try:
        observed=inspect_debug_log(raw_log.read_bytes(),expected_cycles=10,require_nonzero=True)
    except (OSError,DebugLogError) as exc:
        raise EvidenceError(f'Invalid raw DynamoRIO instrumentation: {exc}') from exc
    if (observed['bitmap_nonzero_bytes'] != a4['confirmed_map_nonzero_bytes'] or
        observed['confirmed_coverage_modules'] != a4['confirmed_modules']):
        raise EvidenceError('A4 manifest coverage does not match raw instrumentation')
    try:
        before=parse_stats(before_stats.read_text(encoding='utf-8'))
        after=parse_stats(after_stats.read_text(encoding='utf-8'))
        final=parse_stats((run_dir/'fuzzer_stats').read_text(encoding='utf-8'))
        verify_progress(before,after)
        if final['execs_done'] < after['execs_done']:
            raise EvidenceError('Final execution counter is older than last snapshot')
        if final['execs_done'] < 1000:
            raise EvidenceError('WinAFL reference campaign has fewer than 1000 real executions')
    except (OSError,StatsError) as e:
        raise EvidenceError(f'Invalid WinAFL stats: {e}') from e
    metadata=read_json(run_dir/'campaign-metadata.json')
    compare_file(a4_manifest,metadata.get('a4_evidence_sha256'),'A4 evidence linkage')
    compare_file(before_stats,metadata.get('stats_initial'),'first WinAFL snapshot')
    compare_file(after_stats,metadata.get('stats_later'),'second WinAFL snapshot')
    try:
        start=datetime.fromisoformat(metadata['start_utc'])
        end=datetime.fromisoformat(metadata['end_utc'])
        if start.utcoffset() is None or end.utcoffset() is None or end <= start:
            raise EvidenceError('Invalid campaign time range')
        argv=metadata['argv']
        if not isinstance(argv,list) or len(argv)<3 or not all(isinstance(v,str) for v in argv):
            raise EvidenceError('Missing executed WinAFL argument array')
        if metadata['stop_reason'] != 'bounded_limit_reached':
            raise EvidenceError('Unrecognized or early campaign stop')
    except (KeyError,TypeError,ValueError) as exc:
        raise EvidenceError(f'Incomplete campaign run metadata: {exc}') from exc
    queue_dir=run_dir/'queue'
    if not queue_dir.is_dir():raise EvidenceError('Queue directory missing')
    inputs=sorted(p for p in queue_dir.iterdir() if p.is_file() and not p.name.startswith('.'))
    if not inputs:raise EvidenceError('No actual WinAFL queued input files')
    crashes = finding_inventory(run_dir, 'crashes', final['unique_crashes'])
    hangs = finding_inventory(run_dir, 'hangs', final['unique_hangs'])
    return {
      'schema_version':1,'source_commit':PIN,
      'start_utc':start.astimezone(timezone.utc).isoformat(),
      'end_utc':end.astimezone(timezone.utc).isoformat(),
      'command':argv,'stop_reason':metadata['stop_reason'],
      'toolchain_lock_sha256':digest(toolchain_lock),
      'a4_manifest_sha256':digest(a4_manifest),
      'raw_debug_log_sha256':digest(raw_log),
      'confirmed_coverage_modules':a4['confirmed_modules'],
      'metric_units':'WinAFL execution counts and discovered paths; not source coverage percentage',
      'metrics':final,'first_snapshot':before,'later_snapshot':after,
      'queue':[{'name':p.name,'sha256':digest(p),'bytes':p.stat().st_size} for p in inputs],
      'crashes': crashes,
      'hangs': hangs,
      'finding_counts': {
          kind: {'reported_in_stats': final[counter], 'saved_artifacts': len(items),
                 'additional_saved_artifacts': len(items) - final[counter]}
          for kind, counter, items in (('crashes','unique_crashes',crashes),
                                      ('hangs','unique_hangs',hangs))
      },
      'raw_stats_sha256':digest(run_dir/'fuzzer_stats'),
      'binary_hashes':{
         'harness':digest(harness),'PdfFilter.dll':digest(folder/'PdfFilter.dll'),
         'libmupdf.dll':digest(folder/'libmupdf.dll'),
         **{name:digest(Path(entry['path'])) for name,entry in lock['tools'].items()}
      }
    }

def main() -> None:
    parser=argparse.ArgumentParser()
    for arg in ('run-dir','toolchain-lock','a4-manifest','harness','before-stats','after-stats','output'):
        parser.add_argument('--'+arg,required=True,type=Path)
    args=parser.parse_args()
    try:
        evidence=collect(run_dir=args.run_dir,toolchain_lock=args.toolchain_lock,
               a4_manifest=args.a4_manifest,harness=args.harness,before_stats=args.before_stats,
               after_stats=args.after_stats)
        if args.output.exists():raise EvidenceError(f'Will not overwrite evidence: {args.output}')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    except EvidenceError as exc:parser.error(str(exc))
    print(f'Verified actual WinAFL evidence: {args.output}')

if __name__=='__main__':main()
