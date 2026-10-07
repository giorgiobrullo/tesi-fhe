from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


A112 = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a112_static_model", A112 / "a112_static_model.py"
)
assert SPEC is not None and SPEC.loader is not None
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class A112StaticModelTest(unittest.TestCase):
    def test_key_topology_is_exact_a44_ks_then_pbs(self) -> None:
        self.assertEqual(model.BIG_LWE_DIMENSION, 2048)
        self.assertEqual(model.SMALL_LWE_DIMENSION, 859)
        self.assertEqual(
            model.BIG_LWE_DIMENSION,
            model.GLWE_DIMENSION * model.POLYNOMIAL_SIZE,
        )
        self.assertEqual(model.KS_PRECISION, 15)
        self.assertEqual(model.BLIND_ROTATION_MODULUS, 4096)

    def test_reference_and_local_digits_exhaust_all_states(self) -> None:
        for state in range(1 << model.KS_PRECISION):
            with self.subTest(state=state):
                reference = model.reference_patch_digits(state)
                local = model.local_a98_digits(state)
                self.assertEqual(reference, local)
                self.assertEqual(
                    model.recompose_digits(local),
                    state << model.KS_DISCARDED_BITS,
                )

    def test_named_public_decomposer_boundary_states(self) -> None:
        expected = {
            16_384: (0, 0, 0, 0, 4),
            16_385: (1, 0, 0, 0, 4),
            18_204: (4, 3, 4, 3, 4),
            18_205: (-3, -4, -3, -4, -3),
        }
        for state, stream in expected.items():
            with self.subTest(state=state):
                self.assertEqual(model.local_a98_digits(state), stream)

    def test_rounding_and_signed_half_cover_wrap(self) -> None:
        values = (
            0,
            1,
            model.KS_ROUNDING_HALF - 1,
            model.KS_ROUNDING_HALF,
            model.KS_ROUNDING_HALF + 1,
            (1 << 63) - 1,
            1 << 63,
            model.WORD_MASK - 1,
            model.WORD_MASK,
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(
                    model.reference_round_mask(value), model.local_round_mask(value)
                )
                self.assertEqual(
                    model.reference_half_wrapped(value),
                    model.local_half_wrapped(value),
                )

    def test_fixture_ledger_separates_honest_and_constructed_inputs(self) -> None:
        fixtures = model.fixture_ledger()
        self.assertEqual(len(fixtures), 16)
        counts: dict[str, int] = {}
        for fixture in fixtures:
            counts[fixture.family] = counts.get(fixture.family, 0) + 1
            if fixture.family == "honest_gaussian_encryption":
                self.assertIsNone(fixture.injected_error_torus)
                self.assertEqual(
                    fixture.mask_pattern, "random_uniform_from_encryption_api"
                )
            else:
                self.assertIsNotNone(fixture.injected_error_torus)
                mask = model.injected_mask(fixture.mask_pattern)
                self.assertEqual(len(mask), model.BIG_LWE_DIMENSION)
        self.assertEqual(
            counts,
            {"honest_gaussian_encryption": 9, "key_consistent_non_gaussian": 7},
        )

    def test_delta51_score_domain_keeps_padding_clean(self) -> None:
        self.assertEqual(model.score_plaintext(0), 0)
        self.assertLess(model.score_plaintext(model.SCORE_MAX), 1 << 63)
        with self.assertRaises(AssertionError):
            model.score_plaintext(model.SCORE_MAX + 1)

    def test_r2b_raw_is_pinned_passed_and_did_not_run_r3_r4(self) -> None:
        row = model.verify_raw_r2b()
        self.assertEqual(
            row["sha256"],
            "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1",
        )
        self.assertEqual(row["status"], "PASS_COMPONENT_FHE_SMOKE_R2B")
        self.assertEqual(row["cases_passed"], 14)
        self.assertGreater(row["tie_zero_cases"], 0)
        self.assertGreater(row["tie_one_cases"], 0)

    def test_preregistration_keeps_exact_id_promotion_forbidden(self) -> None:
        prereg = json.loads((A112 / "PREREGISTRATION.json").read_text())
        self.assertFalse(prereg["authorization"]["keygen_or_fhe"])
        self.assertEqual(prereg["decision"]["PROMOTE_EXACT_ID"], "forbidden at A112")
        self.assertIn(
            "stable first argmin",
            prereg["exact_id_contract_linkage"]["system_contract"],
        )
        self.assertIn(
            "inclusive threshold",
            prereg["exact_id_contract_linkage"]["system_contract"],
        )

    def test_full_static_report_is_clean_and_non_promoting(self) -> None:
        report = model.static_report()
        self.assertEqual(report["status"], "PASS_STATIC_PREFLIGHT_NOT_COMPILED_NOT_RUN")
        self.assertEqual(report["finite_checks"]["reference_local_digit_mismatches"], 0)
        self.assertEqual(report["finite_checks"]["recomposition_failures"], 0)
        self.assertEqual(report["executions"]["fhe"], 0)
        self.assertFalse(report["promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
