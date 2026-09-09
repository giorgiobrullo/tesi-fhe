"""Fast deterministic tests for A29/A38 validation metadata and count mirrors."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fhe_digiface_validation_under_test",
    ROOT / "benchmark" / "fhe_digiface_validation.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import benchmark/fhe_digiface_validation.py")
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class A38CountAndDomainTest(unittest.TestCase):
    def test_aligned_count_fixtures_match_the_rust_core(self) -> None:
        for gallery_size, expected in (
            (1, 25),
            (2, 60),
            (3, 85),
            (64, 1835),
            (127, 3655),
            (128, 3682),
        ):
            self.assertEqual(
                validation.expected_pbs_count(
                    gallery_size,
                    [4] * gallery_size,
                    {"l": -1019, "u": 2329, "larghezza": 3349},
                ),
                expected,
            )

        self.assertEqual(validation.expected_pbs_count(127), 5524)
        self.assertEqual(
            validation.expected_pbs_count(127, [4] * 127, {"l": -987, "u": 2329}),
            4965,
        )

    def test_execution_planner_is_fail_closed_at_every_alignment_edge(self) -> None:
        tight = {"l": -987, "u": 2329, "larghezza": 3317}
        cases = (
            ([4] * 127, validation.A38_ALIGNED_PATH, (-1019, 2329, 3349)),
            ([4, 5, 4], validation.A29_GENERAL_PATH, (-987, 2329, 3317)),
            ([37], validation.A29_GENERAL_PATH, (-987, 2329, 3317)),
            ([-743], validation.A38_ALIGNED_PATH, (-1766, 2329, 4096)),
            ([-744], validation.A29_GENERAL_PATH, (-987, 2329, 3317)),
            (
                [validation.I64_MIN],
                validation.A29_GENERAL_PATH,
                (-987, 2329, 3317),
            ),
        )
        for thresholds, path, bounds in cases:
            with self.subTest(thresholds=thresholds):
                plan = validation.expected_execution_plan(thresholds, tight)
                self.assertEqual(plan["percorso_argmin"], path)
                self.assertEqual(
                    (
                        plan["dominio_esecuzione"]["l"],
                        plan["dominio_esecuzione"]["u"],
                        plan["dominio_esecuzione"]["larghezza"],
                    ),
                    bounds,
                )

        identical = validation.expected_execution_plan([4], {"l": -1019, "u": 2329})
        self.assertEqual(identical["percorso_argmin"], validation.A38_ALIGNED_PATH)
        self.assertEqual(identical["dominio_esecuzione"], identical["dominio"])

        accept_all = validation.expected_execution_plan([100], {"l": 0, "u": 0})
        self.assertEqual(accept_all["dominio_esecuzione"]["l"], -923)
        self.assertEqual(accept_all["percorso_argmin"], validation.A38_ALIGNED_PATH)
        reject_all = validation.expected_execution_plan([-1], {"l": 0, "u": 0})
        self.assertEqual(reject_all["dominio_esecuzione"]["l"], -1024)
        self.assertEqual(reject_all["percorso_argmin"], validation.A38_ALIGNED_PATH)

        with self.assertRaises(validation.ValidationError):
            validation.expected_execution_plan([4], {"l": 2, "u": 1})


class ExecutionMetadataCompatibilityTest(unittest.TestCase):
    def state(self) -> dict[str, object]:
        return {
            "iscritti": 2,
            "chiave": True,
            "chiave_sha256": "a" * 64,
            "dim": validation.EXPECTED_DIMENSION,
            "soglia_default": validation.EXPECTED_THRESHOLD,
            "epoch": 7,
            "revision": 2,
            "nomi": ["a", "b"],
            "soglie": [validation.EXPECTED_THRESHOLD] * 2,
            "dominio": {"l": -987, "u": 2329, "larghezza": 3317},
            "contratto_esatto": dict(validation.EXPECTED_CONTRACT),
        }

    def test_frozen_a28_a29_state_remains_valid_by_default(self) -> None:
        validation.validate_server_state(self.state(), gallery_size=2, key_present=True)
        with self.assertRaisesRegex(validation.ValidationError, "execution metadata"):
            validation.validate_server_state(
                self.state(),
                gallery_size=2,
                key_present=True,
                require_execution_metadata=True,
            )

    def test_current_state_requires_a_recomputed_a38_plan(self) -> None:
        state = self.state()
        state.update(
            {
                "dominio_esecuzione": {
                    "l": -1019,
                    "u": 2329,
                    "larghezza": 3349,
                },
                "percorso_argmin": validation.A38_ALIGNED_PATH,
            }
        )
        validation.validate_server_state(
            state,
            gallery_size=2,
            key_present=True,
            require_execution_metadata=True,
        )

        tampered = copy.deepcopy(state)
        tampered["percorso_argmin"] = validation.A29_GENERAL_PATH
        with self.assertRaisesRegex(validation.ValidationError, "argmin path"):
            validation.validate_server_state(
                tampered,
                gallery_size=2,
                key_present=True,
                require_execution_metadata=True,
            )

    def test_empty_current_state_reports_null_execution_metadata(self) -> None:
        state = self.state()
        state.update(
            {
                "iscritti": 0,
                "nomi": [],
                "soglie": [],
                "dominio": None,
                "dominio_esecuzione": None,
                "percorso_argmin": None,
            }
        )
        validation.validate_server_state(
            state,
            gallery_size=0,
            key_present=True,
            require_execution_metadata=True,
        )


if __name__ == "__main__":
    unittest.main()
