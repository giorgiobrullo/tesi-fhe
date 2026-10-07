"""Five offline tests only; root executes, no native/server/key work."""
import copy
import importlib.util
from pathlib import Path
import unittest

loader = importlib.util.spec_from_file_location('prepared_profile_http', Path(__file__).with_name('profile_http.py'))
driver = importlib.util.module_from_spec(loader)
loader.loader.exec_module(driver)

COUNTS = {'br': 1111, 'pfks': 509, 'ks': 1080, 'marginals': 1709, 'initial_samples': 120}


def profile():
    return {'schema': 'smallcuts-stage-profile.v1', 'mode': 'both', 'gallery_size': 120,
            'narrow_id_active': True, 'requested_parallel': True, 'tail_cutoff': 0,
            'scoring_wall_ns': 10, 'extraction_wall_ns': 20, 'tournament_wall_ns': 60,
            'final_wall_ns': 10, 'evaluate_wall_ns': 110,
            'levels': [{'candidates': 120, 'ready_merges': 60, 'carried_candidates': 0,
                        'scheduled_parallel': True, 'wall_ns': 50}],
            'primitive_work_counts': COUNTS, 'duration_semantics': 'levels are included in tournament'}


def rows():
    result = []
    for _, block, position, role in driver.schedule():
        for phase, reps in (('warmup', 1), ('measured', 2)):
            for rep in range(reps):
                for scene in driver.SCENES:
                    elapsed = (100 + block) * (1.02 if role else 1)
                    result.append({'block': block, 'position': position, 'arm': ('off', 'on')[role],
                                   'scene': scene, 'phase': phase, 'repetition': rep, 'correct': True,
                                   'elapsed_ms': elapsed, 'http_elapsed_ns': int((elapsed + 1) * 1e6),
                                   'input_sha256': scene, 'server_key_sha256': 'same-key',
                                   'binary_sha256': 'same-bin', 'circuit_sha256': 'same-contract',
                                   'stage_profile': profile() if role else None})
    return result


class MetadataTests(unittest.TestCase):
    def test_schedule_exact_and_balanced(self):
        steps = driver.schedule()
        self.assertEqual(len(steps), 8)
        self.assertEqual([[role for _, b, _, role in steps if b == block] for block in range(4)],
                         [[0, 1], [1, 0], [0, 1], [1, 0]])

    def test_real_profile_and_nested_levels(self):
        self.assertEqual(driver.validate_profile(profile(), COUNTS, 0), profile())
        p = profile(); p['levels'] = []
        self.assertEqual(driver.validate_profile(p, COUNTS, 0)['levels'], [])

    def test_missing_stage_overlaps_or_changed_counts_rejected(self):
        for field, value in (('scoring_wall_ns', 0), ('evaluate_wall_ns', 99),
                             ('tail_cutoff', 1), ('primitive_work_counts', {}),
                             ('mode', 'baseline'), ('narrow_id_active', False)):
            p = profile(); p[field] = value
            with self.assertRaises(RuntimeError):
                driver.validate_profile(p, COUNTS, 0)
        p = profile(); p['levels'][0]['wall_ns'] = 61
        with self.assertRaises(RuntimeError):
            driver.validate_profile(p, COUNTS, 0)

    def test_summary_exact_counts_and_block_ratio(self):
        summary = driver.summarize(rows())
        self.assertEqual(summary['warmup_calls'], 24)
        self.assertEqual(summary['measured_calls'], 48)
        self.assertEqual(summary['on_measured_profiles'], 24)
        self.assertAlmostEqual(summary['scenes']['curie']['median_block_ratio'], 1.02)
        self.assertEqual(summary['level_records'][0]['profile_count'], 24)

    def test_incomplete_or_unpaired_samples_rejected(self):
        with self.assertRaises(RuntimeError):
            driver.summarize(rows()[:-1])
        broken = copy.deepcopy(rows()); broken[-1]['input_sha256'] = 'different'
        with self.assertRaises(RuntimeError):
            driver.summarize(broken)
        broken = copy.deepcopy(rows()); broken[0]['stage_profile'] = profile()
        with self.assertRaises(RuntimeError):
            driver.summarize(broken)


if __name__ == '__main__':
    unittest.main()
