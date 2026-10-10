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
        self.log=root/'winafl-debug-proc.log'
        # Synthetic raw WinAFL-shaped log for unit tests; never native-run evidence.
        prefix=('Module loaded, PdfFilter.dll\nModule loaded, libmupdf.dll\n'
                + 'In pre_fuzz_handler\nIn post_fuzz_handler\n' * 10
                + 'Everything appears to be running normally.\nCoverage map follows:\n')
        self.log.write_bytes(prefix.encode() + bytes([1])*10 + bytes(65526))
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
    def test_self_hashed_narrative_log_is_not_instrumentation(self):
        self.log.write_bytes(b'claimed ten cycles without actual WinAFL records')
        a4=json.loads(self.a4.read_text())
        a4['confirmed_log_sha256']=sha(self.log)
        self.a4.write_text(json.dumps(a4))
        metadata=json.loads((self.run/'campaign-metadata.json').read_text())
        metadata['a4_evidence_sha256']=sha(self.a4)
        (self.run/'campaign-metadata.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(EvidenceError,'instrumentation'):
            collect(**self.kwargs())
    def test_manifest_coverage_must_match_raw_log(self):
        a4=json.loads(self.a4.read_text())
        a4['confirmed_map_nonzero_bytes']=999
        self.a4.write_text(json.dumps(a4))
        metadata=json.loads((self.run/'campaign-metadata.json').read_text())
        metadata['a4_evidence_sha256']=sha(self.a4)
        (self.run/'campaign-metadata.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(EvidenceError,'coverage'):
            collect(**self.kwargs())
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
    def set_observed_findings(self, *, crashes=0, hangs=0):
        fields = ('execs_done: 2000\npaths_total: 2\n'
                  f'unique_crashes: {crashes}\nunique_hangs: {hangs}\n')
        self.after.write_text(fields)
        (self.run/'fuzzer_stats').write_text(fields)
        meta_path = self.run/'campaign-metadata.json'
        meta = json.loads(meta_path.read_text())
        meta['stats_later'] = sha(self.after)
        meta_path.write_text(json.dumps(meta))

    def test_hang_artifact_has_hash_replay_path_and_untriaged_status(self):
        self.set_observed_findings(hangs=1)
        hangs=self.run/'hangs'
        hangs.mkdir()
        data=hangs/'id_000001'
        data.write_bytes(b'%PDF-1.4 malformed hang candidate')
        result=collect(**self.kwargs())
        self.assertEqual(len(result['hangs']),1)
        self.assertEqual(result['hangs'][0]['sha256'],sha(data))
        self.assertEqual(result['hangs'][0]['path'],'hangs/id_000001')
        self.assertEqual(result['hangs'][0]['classification'],'untriaged')
        self.assertEqual(result['hangs'][0]['replay_argv'],['sumatrafuzz-harness.exe','hangs/id_000001'])

    def test_reported_hang_requires_genuine_hang_file(self):
        self.set_observed_findings(hangs=1)
        with self.assertRaisesRegex(EvidenceError,'hang'):
            collect(**self.kwargs())

    def test_crash_file_inventory_is_not_a_vulnerability_claim(self):
        self.set_observed_findings(crashes=1)
        folder=self.run/'crashes'
        folder.mkdir()
        sample=folder/'id_000002'
        sample.write_bytes(b'%PDF-1.4 crash candidate')
        result=collect(**self.kwargs())
        self.assertEqual(len(result['crashes']),1)
        self.assertEqual(result['crashes'][0]['sha256'],sha(sample))
        self.assertEqual(result['crashes'][0]['classification'],'untriaged')
        self.assertNotIn('severity',result['crashes'][0])

    def test_untrusted_hang_symlink_cannot_escape_run_directory(self):
        self.set_observed_findings(hangs=1)
        folder=self.run/'hangs'
        folder.mkdir()
        sample=folder/'id_000001'
        try:
            sample.symlink_to(self.h)
        except (OSError,NotImplementedError):
            self.skipTest('symlink creation unavailable')
        with self.assertRaisesRegex(EvidenceError,'Unsafe hangs sample'):
            collect(**self.kwargs())

    def test_winAfl_crash_readme_is_not_a_replayable_crash(self):
        self.set_observed_findings(crashes=1)
        folder=self.run/'crashes'
        folder.mkdir()
        (folder/'README.txt').write_text('This folder contains crashes')
        (folder/'id_000003').write_bytes(b'%PDF-1.4 crash candidate')
        manifest=collect(**self.kwargs())
        self.assertEqual([x['path'] for x in manifest['crashes']],['crashes/id_000003'])

    def test_reported_hangs_cannot_exceed_saved_artifact_count(self):
        self.set_observed_findings(hangs=2)
        folder=self.run/'hangs'
        folder.mkdir()
        (folder/'id_000001').write_bytes(b'only one')
        with self.assertRaisesRegex(EvidenceError,'hangs artifact count'):
            collect(**self.kwargs())

    def test_periodic_hang_counter_can_lag_saved_files_at_forced_stop(self):
        self.set_observed_findings(hangs=1)
        folder=self.run/'hangs'
        folder.mkdir()
        for name in ('id_000000','id_000001'):
            (folder/name).write_bytes(b'synthetic hang candidate')
        manifest=collect(**self.kwargs())
        self.assertEqual(manifest['metrics']['unique_hangs'],1)
        self.assertEqual(len(manifest['hangs']),2)
        self.assertEqual(manifest['finding_counts']['hangs'],{
            'reported_in_stats':1,'saved_artifacts':2,'additional_saved_artifacts':1})

    def test_periodic_zero_crash_counter_does_not_hide_saved_file(self):
        folder=self.run/'crashes'
        folder.mkdir()
        (folder/'id_000000').write_bytes(b'synthetic crash candidate')
        manifest=collect(**self.kwargs())
        self.assertEqual(manifest['metrics']['unique_crashes'],0)
        self.assertEqual(len(manifest['crashes']),1)
        self.assertEqual(manifest['finding_counts']['crashes']['additional_saved_artifacts'],1)

    def test_reported_crash_requires_genuine_crash_file(self):
        self.set_observed_findings(crashes=1)
        with self.assertRaisesRegex(EvidenceError,'crash'):
            collect(**self.kwargs())

    def test_empty_queue_rejected(self):
        (self.run/'queue'/'id_000000').unlink()
        with self.assertRaises(EvidenceError):collect(**self.kwargs())

if __name__=='__main__':unittest.main()
