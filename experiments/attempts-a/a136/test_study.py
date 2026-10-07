"""Protocol and integer-boundary regressions; no accuracy outcomes used here."""

import itertools
import unittest

import numpy as np

import study


class StudyTests(unittest.TestCase):
    def test_threshold_maximal_with_ties(self):
        scores = np.array([-5, -5, -1, 4, 4, 8, 11, 15])
        threshold = study.threshold(scores, 0.25)
        self.assertEqual(threshold, -2)
        self.assertLessEqual(np.count_nonzero(scores <= threshold), 2)
        self.assertGreater(np.count_nonzero(scores <= threshold + 1), 2)

    def test_threshold_gap_is_explicit_against_legacy(self):
        scores = np.array([1] * 5 + [7] * 495)
        self.assertEqual(study.threshold(scores), 6)
        self.assertEqual(study.legacy_threshold(scores), 1)

    def test_winner_threshold_cannot_be_resurrected_by_another_template(self):
        scores = np.array([[2, 3], [2, 2]])
        code, winner, minimum = study.decide(scores, np.array([1, 100]))
        self.assertEqual(code.tolist(), [0, 0])
        self.assertEqual(winner.tolist(), [0, 0])
        self.assertEqual(minimum.tolist(), [2, 2])
        self.assertEqual(study.decide(scores, 2)[0].tolist(), [1, 1])

    def test_single_thread_float_path_equals_integer_dot(self):
        values = np.array(list(itertools.product(range(-3, 4), repeat=3)))
        gallery = np.array([[-3, 2, 1], [1, -1, -3]], dtype=np.int64)
        reference = (gallery * gallery).sum(1)[None, :] - 2 * values @ gallery.T
        np.testing.assert_array_equal(study.integer_scores(gallery, values), reference)
        with self.assertRaises(ValueError):
            study.integer_scores(gallery.astype(float), values)

    def test_domain_contains_all_admissible_tiny_cube_probes(self):
        gallery = np.array([[-3, 2, 1], [1, -1, -3]], dtype=np.int64)
        for qmax, normcap in ((1, 2), (2, 5), (3, 9)):
            probes = np.array(
                [
                    q
                    for q in itertools.product(range(-qmax, qmax + 1), repeat=3)
                    if sum(x * x for x in q) <= normcap
                ]
            )
            domain = study.score_domain(gallery, qmax, normcap, 0)
            scores = study.integer_scores(gallery, probes)
            self.assertGreaterEqual(scores.min(), domain["lower"])
            self.assertLessEqual(scores.max(), domain["upper"])
            self.assertEqual(domain["width"], domain["upper"] - domain["lower"] + 1)

    def test_cap_removes_whole_coefficients_with_stable_ties_without_mutating_input(
        self,
    ):
        original = np.array([[1, -1, 2, -3]])
        np.testing.assert_array_equal(study.cap_gallery(original, 5), [[0, 0, 2, -3]])
        np.testing.assert_array_equal(original, [[1, -1, 2, -3]])
        np.testing.assert_array_equal(study.cap_gallery(original, 0), [[0, 0, 0, 0]])

    def test_cohort_and_image_disjointness_and_scale_fit_isolation(self):
        labels = np.repeat(np.arange(1640), 6)
        split = study.plan(labels, 0)
        roles = [set(v) for v in split["roles"].values()]
        self.assertEqual(sum(map(len, roles)), len(set.union(*roles)))
        for images in split["indices"]["enrolled"]:
            self.assertFalse(set(images[:2]) & set(images[2:5]))
        embeddings = study.normalize(
            np.random.default_rng(7).normal(size=(len(labels), 8))
        )
        fitted, _ = study.floats(embeddings, split, 128, 3)
        altered = embeddings.copy()
        indices = np.concatenate(
            [v for k, rows in split["indices"].items() if k != "fit" for v in rows]
        )
        altered[indices] *= 100
        fitted_after, _ = study.floats(altered, split, 128, 3)
        self.assertEqual(fitted, fitted_after)

    def test_zero_accepts_still_has_nonzero_uncertainty(self):
        lower, upper = study.wilson(0, 500)
        self.assertAlmostEqual(lower, 0)
        self.assertGreater(upper, 0.007)
        self.assertLess(upper, 0.008)


if __name__ == "__main__":
    unittest.main()
