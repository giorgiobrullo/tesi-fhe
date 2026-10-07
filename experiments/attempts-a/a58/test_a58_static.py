from __future__ import annotations

import pathlib
import unittest

import a58_static_audit as a58


class A58RustMaterializationStaticTests(unittest.TestCase):
    def test_frozen_a38_a44_a50_a53_provenance_and_parameter_binding(self) -> None:
        audit = a58.provenance_audit()
        self.assertEqual(audit["inputs"], 9)
        self.assertTrue(audit["all_hashes_match"])
        self.assertEqual(
            audit["a44_fingerprint"],
            "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        )

    def test_literal_local_or_and_base15_digit_luts_cover_strict_margin(self) -> None:
        audit = a58.literal_lut_audit()
        self.assertEqual(audit["local_patterns"], 30)
        self.assertEqual(audit["strict_margin_radius"], 63)

    def test_every_literal_selector_layout_checks_both_negacyclic_samples(self) -> None:
        audit = a58.selector_layout_audit()
        self.assertEqual(audit["ordinary_layouts"], 128)
        self.assertEqual(audit["direct_layouts"], 4)
        self.assertEqual(audit["signed_states"], list(range(-4, 5)))
        self.assertTrue(audit["all_centers_and_margins_exact"])

    def test_clear_contract_is_exhaustive_and_first_tie_exact(self) -> None:
        audit = a58.semantics_audit()
        self.assertEqual(audit["exhaustive_masks_n1_12"], 8_190)
        self.assertEqual(audit["all_size_boundary_cases"], 8_512)
        self.assertEqual(a58.clear_scan((False,) * 128), 0)
        self.assertEqual(a58.clear_scan((True,) * 128), 1)
        self.assertEqual(a58.clear_scan((False,) * 127 + (True,)), 128)

    def test_counts_match_frozen_a53_for_every_gallery_size(self) -> None:
        audit = a58.count_audit()
        self.assertTrue(audit["all_n1_128_match_a53"])
        self.assertEqual(
            audit["n127_scan"],
            {
                "blind_rotations": 136,
                "key_switches": 136,
                "output_marginals": 168,
            },
        )
        self.assertEqual(
            audit["n127_full_projection"],
            {
                "blind_rotations": 3_390,
                "key_switches": 3_009,
                "output_marginals": 3_930,
            },
        )

    def test_future_fhe_adapter_is_default_off_and_fail_closed(self) -> None:
        audit = a58.future_harness_audit()
        self.assertTrue(audit["feature_default_off"])
        self.assertTrue(audit["parameter_source_pfail_and_counter_guards"])
        self.assertFalse(audit["cargo_entry_point_present"])

    def test_scope_contains_no_build_key_or_measurement_artifacts(self) -> None:
        root = pathlib.Path(__file__).parent
        files = tuple(path for path in root.rglob("*") if path.is_file())
        forbidden_suffixes = {".rlib", ".rmeta", ".dylib", ".so", ".key", ".ct"}
        self.assertFalse(any(path.suffix in forbidden_suffixes for path in files))
        self.assertFalse((root / "target").exists())
        self.assertFalse((root / "Cargo.toml").exists())
        self.assertFalse((root / "Cargo.lock").exists())
        self.assertFalse(any("benchmark" in path.name.lower() for path in files))


if __name__ == "__main__":
    unittest.main()
