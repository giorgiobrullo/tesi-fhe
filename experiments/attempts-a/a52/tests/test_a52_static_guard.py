from __future__ import annotations

import importlib.util
import itertools
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "a52_static_guard.py"
SPEC = importlib.util.spec_from_file_location("a52_static_guard", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class TorusTests(unittest.TestCase):
    def test_every_center_and_open_margin_are_exact(self) -> None:
        for error in (0, model.OPEN_MARGIN - 1, -(model.OPEN_MARGIN - 1)):
            for score in range(model.SCORE_DOMAIN):
                self.assertEqual(model.clear_high(score, error), score >> 8)

    def test_positive_margin_boundary_is_tight(self) -> None:
        failures = [
            score
            for score in range(model.SCORE_DOMAIN)
            if model.clear_high(score, model.OPEN_MARGIN) != score >> 8
        ]
        self.assertTrue(failures)
        self.assertIn(255, failures)

    def test_each_high_block_maps_to_one_complete_box(self) -> None:
        for high in range(16):
            rotations = [
                model.modulus_switch(
                    (((high << 8) + residue) << model.INPUT_DELTA_LOG)
                    + model.PUBLIC_OFFSET
                )
                for residue in range(256)
            ]
            signed = [
                rotation if rotation < 2048 else rotation - 4096
                for rotation in rotations
            ]
            self.assertEqual(
                (min(signed), max(signed)),
                (128 * high - 64, 128 * high + 63),
            )


class LayoutTests(unittest.TestCase):
    def test_fourth_lane_is_the_only_source_at_degree_2047(self) -> None:
        hits, wrapped = model.lane_hits()
        self.assertEqual(hits, (0, 0, 0, 512))
        self.assertEqual(wrapped, (0, 0, 0, 0))

    def test_diagonal_pairs_hit_and_off_diagonal_pairs_do_not(self) -> None:
        offset = 1_536
        for probe_coordinate, template_coordinate in itertools.product(
            (0, 1, 255, 510, 511), repeat=2
        ):
            raw = offset + probe_coordinate + 511 - template_coordinate
            self.assertEqual(
                raw % 2_048 == 2_047,
                probe_coordinate == template_coordinate,
            )


class SourceGuardTests(unittest.TestCase):
    def test_copied_crate_is_fail_closed_and_nonpersistent(self) -> None:
        sources = model.validate_sources()
        self.assertEqual(set(sources), {
            "lib_sha256",
            "bin_sha256",
            "cargo_toml_sha256",
            "cargo_lock_sha256",
            "config_sha256",
        })

    def test_report_keeps_all_evidence_boundaries_false(self) -> None:
        report = model.validate()
        self.assertEqual(
            report["status"],
            "static_materialization_ready_not_compiled_not_fhe_validated",
        )
        self.assertEqual(report["per_template_counts"], {
            "blind_rotations": 1,
            "classical_key_switches": 1,
            "output_marginals": 1,
            "sample_extractions": 1,
            "public_plaintext_additions": 2,
        })
        self.assertEqual(report["n127_counts"]["blind_rotations"], 127)
        self.assertTrue(all(value is False for value in report["claims"].values()))


if __name__ == "__main__":
    unittest.main()
