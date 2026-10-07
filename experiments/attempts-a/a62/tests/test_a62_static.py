from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


AUDIT_PATH = pathlib.Path(__file__).parents[1] / "a62_static_audit.py"


def load_audit():
    spec = importlib.util.spec_from_file_location("_a62_static_audit_tests", AUDIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A62 audit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A62StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit()

    def test_frozen_a44_a50_a53_a58_inputs(self) -> None:
        result = self.audit.provenance_audit()
        self.assertEqual(result["pinned_inputs"], 18)
        self.assertTrue(result["all_hashes_match"])

    def test_active_crate_has_concrete_a50_and_a53_integration(self) -> None:
        result = self.audit.integration_source_audit()
        self.assertTrue(result["active_cargo_crate"])
        self.assertTrue(result["concrete_core_crypto_backend"])
        self.assertTrue(result["a50_selection_materialized"])
        self.assertTrue(result["a53_scan_materialized"])

    def test_wire_contract_is_two_p16_roots_with_no_encrypted_recomposition(
        self,
    ) -> None:
        result = self.audit.integration_source_audit()
        self.assertEqual(result["wire_output_lwes"], 2)
        self.assertEqual(result["root_delta_log"], 59)
        self.assertFalse(result["server_recomposition"])
        self.assertEqual(result["client_reconstruction"], "low + 15*high")

    def test_a44_parameter_is_fail_closed_at_max_noise_15(self) -> None:
        result = self.audit.integration_source_audit()
        self.assertTrue(result["a44_parameter_fail_closed"])

    def test_n127_count_decomposition_requires_both_a50_and_a53(self) -> None:
        n127 = self.audit.count_audit()["n127"]
        self.assertEqual(n127["a44"]["blind_rotations"], 3_655)
        self.assertEqual(n127["a50"]["blind_rotations"], 3_455)
        self.assertEqual(n127["old_scan"]["blind_rotations"], 201)
        self.assertEqual(n127["a53_scan"]["blind_rotations"], 136)
        self.assertEqual(3_655 - 201 + 136, 3_590)
        self.assertNotEqual(3_590, 3_390)
        self.assertEqual(
            n127["a62_full"],
            {
                "blind_rotations": 3_390,
                "key_switches": 3_009,
                "output_marginals": 3_930,
            },
        )

    def test_all_gallery_sizes_match_the_frozen_a53_model(self) -> None:
        self.assertTrue(self.audit.count_audit()["all_n1_128_match"])

    def test_clear_composition_preserves_reject_exact_id_and_first_tie(self) -> None:
        result = self.audit.semantics_audit()
        self.assertEqual(result["fixtures"], 512)
        self.assertTrue(result["reject_and_first_tie_exact"])
        self.assertTrue(result["last_identity_exact_through_n128"])

    def test_scope_has_no_build_key_or_fhe_artifacts(self) -> None:
        result = self.audit.scope_audit()
        self.assertFalse(result["cargo_invoked"])
        self.assertFalse(result["keygen_or_fhe_executed"])
        self.assertFalse(result["target_present"])


if __name__ == "__main__":
    unittest.main()
