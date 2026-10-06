"""Three offline metadata tests; only root executes, no native/server work."""
import copy
import importlib.util
from pathlib import Path
import unittest

loader = importlib.util.spec_from_file_location('prepared_merge_http', Path(__file__).with_name('merge_http.py'))
driver = importlib.util.module_from_spec(loader)
loader.loader.exec_module(driver)


def profile():
    node = {'schema': 'smallcuts-designated-merge.v1', 'candidates': 120, 'ready_merges': 60,
            'level_index': 0, 'index': 0, 'payloads': 4, 'group_count': 1,
            'internal_parallel': False, 'completed': True, 'node_wall_ns': 120, 'unassigned_wall_ns': 20,
            'duration_semantics': 'one worker wall time; node is included in first level'}
    node.update({field: 20 for field in driver.PARTS})
    return {'schema': 'smallcuts-stage-profile.v1', 'mode': 'both', 'gallery_size': 120,
            'narrow_id_active': True, 'requested_parallel': True, 'tail_cutoff': 0,
            'scoring_wall_ns': 10, 'extraction_wall_ns': 20, 'tournament_wall_ns': 160,
            'final_wall_ns': 10, 'evaluate_wall_ns': 210, 'primitive_work_counts': driver.COUNTS,
            'levels': [{'candidates': 120, 'ready_merges': 60, 'carried_candidates': 0,
                        'scheduled_parallel': True, 'wall_ns': 150}],
            'duration_semantics': 'levels are included in tournament', 'designated_merge': node}


class MetadataTests(unittest.TestCase):
    def test_actual_mode_and_exact_designated_node(self):
        p = profile()
        self.assertEqual(driver.validate_designated(p, driver.COUNTS, 0), p['designated_merge'])
        for field, value in (('index', 1), ('level_index', 1), ('completed', False),
                             ('internal_parallel', True), ('payloads', 5), ('group_count', 2)):
            bad = profile(); bad['designated_merge'][field] = value
            with self.assertRaises(RuntimeError):
                driver.validate_designated(bad, driver.COUNTS, 0)
        bad = profile(); bad['mode'] = 'baseline'
        with self.assertRaises(RuntimeError):
            driver.validate_designated(bad, driver.COUNTS, 0)

    def test_positive_disjoint_durations_and_containing_level(self):
        for field in driver.PARTS:
            bad = profile(); bad['designated_merge'][field] = 0
            with self.assertRaises(RuntimeError):
                driver.validate_designated(bad, driver.COUNTS, 0)
        bad = profile(); bad['designated_merge']['comparison_wall_ns'] = 50
        with self.assertRaises(RuntimeError):
            driver.validate_designated(bad, driver.COUNTS, 250000)
        bad = profile(); bad['designated_merge']['node_wall_ns'] = 151
        bad['designated_merge']['unassigned_wall_ns'] = 51
        with self.assertRaises(RuntimeError):
            driver.validate_designated(bad, driver.COUNTS, 0)
        bad = profile(); bad['designated_merge']['unassigned_wall_ns'] = 21
        with self.assertRaises(RuntimeError):
            driver.validate_designated(bad, driver.COUNTS, 0)

    def test_only_four_query_coverage(self):
        rows = [{'phase': phase, 'scene': scene, 'correct': True, 'elapsed_ms': 1.0,
                 'http_elapsed_ns': 1000001, 'stage_profile': profile()} for phase, scene in driver.sequence()]
        self.assertEqual(len(driver.sequence()), 4)
        self.assertEqual(driver.summarize(rows)['measured_calls'], 3)
        for bad in (rows[:-1], rows + [rows[-1]], rows[::-1]):
            with self.assertRaises(RuntimeError):
                driver.summarize(bad)
        bad = copy.deepcopy(rows); bad[-1]['correct'] = False
        with self.assertRaises(RuntimeError):
            driver.summarize(bad)


if __name__ == '__main__':
    unittest.main()
