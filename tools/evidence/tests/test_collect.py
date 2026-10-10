import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from sys import path as sys_path
sys_path.insert(0,str(Path(__file__).resolve().parents[1]))
from collect import collect, EvidenceError

SHA='16c59fde8b824ab54c56f23aef910a6fdd874ad0'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='Sumatra Fuzz A6 spaces ')
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.run=root/'campaign';self.run.mkdir()
        (self.run/'queue').mkdir()
        (self.run/'queue'/'id_000000').write_bytes(b'%PDF-1.4')
        (self.run/'fuzzer_stats').write_text('execs_done: 2000\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n')
        self.before=root/'before.stats';self.before.write_text('execs_done: 900\npaths_total: 1\nunique_crashes: 0\nunique_hangs: 0\n')
        self.after=root/'after.stats';self.after.write_text('execs_done: 2000\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n')
        self.h=root/'harness.exe';self.h.write_bytes(b'h')
        self.p=root/'PdfFilter.dll';self.p.write_bytes(b'p')
        self.m=root/'libmupdf.dll';self.m.write_bytes(b'm')
        self.dr=root/'drrun.exe';self.dr.write_bytes(b'dr')
        self.w=root/'winafl.dll';self.w.write_bytes(b'w')
        self.afl=root/'afl-fuzz.exe';self.afl.write_bytes(b'afl')
        self.lock=root/'target-lock.json';self.lock.write_text(json.dumps({'source_commit':SHA,'tools':{
            'drrun':{'path':str(self.dr),'sha256':sha(self.dr)},
            'winafl_client':{'path':str(self.w),'sha256':sha(self.w)},
            'afl_fuzz':{'path':str(self.afl),'sha256':sha(self.afl)}
        }}))
        self.log=root/'winafl-debug-proc.log';self.log.write_bytes(b'real log content')
        self.a4=root/'a4-confirmed.json';self.a4.write_text(json.dumps({
            'target_commit':SHA,'cycles':10,'confirmed_modules':['PdfFilter.dll','libmupdf.dll'],
            'confirmed_map_nonzero_bytes':10,'harness_sha256':sha(self.h),
            'pdf_filter_sha256':sha(self.p),'mupdf_sha256':sha(self.m),
            'toolchain_lock_sha256':sha(self.lock),'confirmed_log':str(self.log),
            'confirmed_log_sha256':sha(self.log)}))
        (self.run/'campaign-metadata.json').write_text(json.dumps({'start_utc':'2026-10-10T00:00:00+00:00','end_utc':'2026-10-10T00:03:00+00:00','stop_reason':'bounded_limit_reached','argv':['afl-fuzz.exe','-i','seeds','--','@@'],'a4_evidence_sha256':sha(self.a4),'stats_initial':sha(self.before),'stats_later':sha(self.after)}))
    def kwargs(self):return dict(run_dir=self.run,toolchain_lock=self.lock,a4_manifest=self.a4,
                               harness=self.h,before_stats=self.before,after_stats=self.after)
    def test_complete_evidence(self):
        x=collect(**self.kwargs())
        self.assertEqual(x['metrics']['execs_done'],2000)
        self.assertEqual(len(x['queue']),1)
        self.assertEqual(x['metrics']['unique_crashes'],0)
    def test_provenance_and_argv(self):
        x=collect(**self.kwargs())
        self.assertEqual(x['command'][0],'afl-fuzz.exe')
        self.assertEqual(x['stop_reason'],'bounded_limit_reached')
    def test_modified_raw_snapshot_rejected(self):
        self.after.write_text('execs_done: 1900\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n')
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_missing_metadata_rejected(self):
        (self.run/'campaign-metadata.json').unlink()
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_modified_binary_rejected(self):
        self.p.write_bytes(b'modified')
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_missing_raw_debug_log_rejected(self):
        self.log.unlink()
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_missing_counter_rejected(self):
        (self.run/'fuzzer_stats').write_text('execs_done: 2000\n')
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_stats_progress_required(self):
        self.after.write_text(self.before.read_text())
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_too_few_executions_rejected(self):
        (self.run/'fuzzer_stats').write_text('execs_done: 999\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n')
        self.after.write_text('execs_done: 998\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0\n')
        metadata=json.loads((self.run/'campaign-metadata.json').read_text())
        metadata['stats_later']=sha(self.after)
        (self.run/'campaign-metadata.json').write_text(json.dumps(metadata))
        with self.assertRaises(EvidenceError):collect(**self.kwargs())
    def test_empty_queue_rejected(self):
        (self.run/'queue'/'id_000000').unlink()
        with self.assertRaises(EvidenceError):collect(**self.kwargs())

if __name__=='__main__':unittest.main()
