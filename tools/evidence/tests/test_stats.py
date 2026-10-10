import unittest
from pathlib import Path
from sys import path as sys_path
sys_path.insert(0, str(Path(__file__).resolve().parents[1]))
from stats import parse_stats, verify_progress, StatsError

class StatsTests(unittest.TestCase):
    def test_real_shape(self):
        d=parse_stats('execs_done        : 45\npaths_total       : 2\nunique_crashes    : 0\nunique_hangs      : 0\n')
        self.assertEqual(d['execs_done'],45)
        self.assertEqual(d['paths_total'],2)
    def test_bad_counter(self):
        with self.assertRaises(StatsError):
            parse_stats('execs_done: NA\npaths_total: 2\nunique_crashes: 0\nunique_hangs: 0')
    def test_missing(self):
        with self.assertRaises(StatsError):parse_stats('execs_done: 12\n')
    def test_duplicate(self):
        with self.assertRaises(StatsError):
            parse_stats('execs_done: 20\nexecs_done: 21\npaths_total: 1\nunique_crashes: 0\nunique_hangs: 0')
    def test_unchanged_is_not_progress(self):
        a={'execs_done':100,'paths_total':1,'unique_crashes':0,'unique_hangs':0}
        with self.assertRaises(StatsError):verify_progress(a,dict(a))
    def test_actual_progress(self):
        a={'execs_done':100,'paths_total':1,'unique_crashes':0,'unique_hangs':0}
        b={'execs_done':105,'paths_total':1,'unique_crashes':0,'unique_hangs':0}
        verify_progress(a,b)
    def test_regression(self):
        a={'execs_done':105,'paths_total':1,'unique_crashes':0,'unique_hangs':0}
        b={'execs_done':100,'paths_total':1,'unique_crashes':0,'unique_hangs':0}
        with self.assertRaises(StatsError):verify_progress(a,b)

if __name__=='__main__':unittest.main()
