import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "generate-fixtures.py"
spec = importlib.util.spec_from_file_location("generate_fixtures", SCRIPT)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

class FixtureTests(unittest.TestCase):
    def test_distinct_and_deterministic_valid_pdf_seeds(self):
        with tempfile.TemporaryDirectory(prefix="sumatra seeds ") as a, tempfile.TemporaryDirectory() as b:
            x = fixtures.generate(pathlib.Path(a))
            y = fixtures.generate(pathlib.Path(b))
            self.assertEqual(len(x), 2)
            self.assertEqual([p.name for p in x], [p.name for p in y])
            self.assertEqual([p.read_bytes() for p in x], [p.read_bytes() for p in y])
            self.assertEqual(len({p.read_bytes() for p in x}), 2)
            for p in x:
                self.assertTrue(p.read_bytes().startswith(b"%PDF-1.4\n"))
                self.assertTrue(p.read_bytes().endswith(b"%%EOF\n"))
                self.assertIn(b"xref\n", p.read_bytes())

if __name__ == "__main__":
    unittest.main()
