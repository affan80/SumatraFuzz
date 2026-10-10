import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3] / 'scripts' / 'windows'))
from generate_fixtures import generate

class SeedTests(unittest.TestCase):
    def test_deterministic_distinct_valid_pdf_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            first=generate(d)
            self.assertEqual(len(first),3)
            self.assertEqual(len({p.read_bytes() for p in first}),3)
            before={p.name:p.read_bytes() for p in first}
            second=generate(d)
            self.assertEqual(before,{p.name:p.read_bytes() for p in second})
            for p in second:
                contents=p.read_bytes()
                self.assertTrue(contents.startswith(b'%PDF-1.4\n'))
                self.assertTrue(contents.endswith(b'%%EOF\n'))
                xref_offset=int(contents.split(b'startxref\n')[1].split(b'\n')[0])
                self.assertEqual(contents[xref_offset:xref_offset+5], b'xref\n')
    def test_does_not_overwrite_unknown_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'private.pdf').write_bytes(b'private')
            with self.assertRaises(ValueError):generate(root)

if __name__=='__main__':unittest.main()
