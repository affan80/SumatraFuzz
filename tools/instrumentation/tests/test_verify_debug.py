import unittest
from tools.instrumentation.verify_debug import inspect_debug_log, DebugLogError

def sample(pairs=10, loaded=("sumatrafuzz-harness.exe", "PdfFilter.dll", "libmupdf.dll"), nonzero=True):
    head = b"".join(f"Module loaded, {n}\n".encode() for n in loaded)
    head += b"".join(b"In pre_fuzz_handler\nIn post_fuzz_handler\n" for _ in range(pairs))
    head += b"Everything appears to be running normally.\nCoverage map follows:\n"
    bitmap = bytearray(65536)
    if nonzero: bitmap[42] = 1
    return head + bitmap

class VerifyDebugTests(unittest.TestCase):
    def test_confirmed_ten_cycles_and_map(self):
        r = inspect_debug_log(sample(), expected_cycles=10, require_nonzero=True)
        self.assertEqual(r["pre_count"], 10)
        self.assertEqual(r["post_count"], 10)
        self.assertEqual(r["confirmed_coverage_modules"], ["PdfFilter.dll", "libmupdf.dll"])
        self.assertGreater(r["bitmap_nonzero_bytes"], 0)
    def test_partial_handler_log_fails(self):
        with self.assertRaises(DebugLogError):
            inspect_debug_log(sample(pairs=9), expected_cycles=10, require_nonzero=True)
    def test_narrative_only_is_not_proof(self):
        with self.assertRaises(DebugLogError):
            inspect_debug_log(b"Everything appears to be running normally.\n", expected_cycles=10, require_nonzero=True)
    def test_mismatched_parser_modules_fail(self):
        with self.assertRaises(DebugLogError):
            inspect_debug_log(sample(loaded=("sumatrafuzz-harness.exe",)), expected_cycles=10, require_nonzero=True)
    def test_empty_bitmap_fails_confirmation(self):
        with self.assertRaises(DebugLogError):
            inspect_debug_log(sample(nonzero=False), expected_cycles=10, require_nonzero=True)
    def test_discovery_can_identify_modules_before_coverage(self):
        r = inspect_debug_log(sample(nonzero=False), expected_cycles=10, require_nonzero=False)
        self.assertEqual(r["bitmap_nonzero_bytes"], 0)
    def test_rejects_crash(self):
        data=sample().replace(b"Coverage map follows:\n", b"Exception caught: c0000005\nCoverage map follows:\n")
        with self.assertRaises(DebugLogError):
            inspect_debug_log(data, expected_cycles=10, require_nonzero=True)
    def test_rejects_truncated_binary_map(self):
        with self.assertRaises(DebugLogError):
            inspect_debug_log(sample()[:-3], expected_cycles=10, require_nonzero=True)

if __name__ == "__main__":
    unittest.main()
