from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest


GATE_PATH = pathlib.Path(__file__).with_name("run_gate.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("_a63_a44_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A63 gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A63A44EvidenceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()

    def parameter_line(self) -> str:
        fields = self.gate.PARAMETER_FIELDS
        return "PARAMETER," + ",".join(f"{key}={value}" for key, value in fields.items())

    def key_line(self, key_block: int) -> str:
        return (
            f"KEY,key_block={key_block},generation_s=0.500000,ephemeral=true,"
            "secret_material_persisted=false,"
            f"params_id={self.gate.PARAMS_ID},"
            f"params_fingerprint_sha256={self.gate.PARAMS_FINGERPRINT}"
        )

    def pass_line(self, case, key_block: int) -> str:
        pbs, key_switches, marginals = self.gate.expected_counts(case.gallery_size)
        return (
            f"PASS,case={case.name},key_block={key_block},N={case.gallery_size},"
            f"code={case.code},low={case.low},high={case.high},pbs={pbs},"
            f"ks={key_switches},marginals={marginals},wire_lwes=2,"
            "root_delta_log=59,linear_postprocessing=false,"
            f"params_id={self.gate.PARAMS_ID},"
            f"params_fingerprint_sha256={self.gate.PARAMS_FINGERPRINT},"
            "eval_s=1.000000"
        )

    def summary_line(self, suite) -> str:
        total = len(suite.cases) * suite.key_blocks
        return (
            f"SUMMARY,status=PASS,cases_per_key={len(suite.cases)},"
            f"key_blocks={suite.key_blocks},total_evaluations={total},"
            "keys=ephemeral_in_memory,secret_material_persisted=false,"
            f"params_id={self.gate.PARAMS_ID},"
            f"params_fingerprint_sha256={self.gate.PARAMS_FINGERPRINT}"
        )

    def suite_text(self, suite) -> str:
        lines = [self.parameter_line()]
        for key_block in range(suite.key_blocks):
            lines.append(self.key_line(key_block))
            lines.extend(self.pass_line(case, key_block) for case in suite.cases)
        lines.append(self.summary_line(suite))
        return "\n".join(lines) + "\n"

    def test_suite_shapes_are_exact(self) -> None:
        self.assertEqual(len(self.gate.SUITES["small"].cases), 21)
        self.assertEqual(self.gate.SUITES["small"].key_blocks, 1)
        self.assertEqual(len(self.gate.SUITES["focused"].cases), 4)
        self.assertEqual(self.gate.SUITES["focused"].key_blocks, 3)
        self.assertEqual(len(self.gate.SUITES["full"].cases), 29)
        self.assertEqual(self.gate.SUITES["full"].key_blocks, 3)

    def test_count_model_has_frozen_anchors(self) -> None:
        self.assertEqual(self.gate.expected_counts(1), (25, 22, 30))
        self.assertEqual(self.gate.expected_counts(3), (85, 76, 98))
        self.assertEqual(self.gate.expected_counts(64), (1835, 1643, 2113))
        self.assertEqual(self.gate.expected_counts(127), (3655, 3274, 4206))
        self.assertEqual(self.gate.expected_counts(128), (3682, 3298, 4237))

    def test_all_three_valid_suites_are_accepted(self) -> None:
        for suite in self.gate.SUITES.values():
            with self.subTest(suite=suite.name):
                result = self.gate.validate_suite_text(self.suite_text(suite), suite)
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["exact_low_plus_16_high_verified"])
                self.assertEqual(
                    result["total_evaluations"],
                    len(suite.cases) * suite.key_blocks,
                )

    def test_parameter_and_max15_mismatch_fail_closed(self) -> None:
        suite = self.gate.SUITES["small"]
        text = self.suite_text(suite).replace(
            "max_noise_level=15", "max_noise_level=5", 1
        )
        with self.assertRaisesRegex(RuntimeError, "parameter record.*mismatch"):
            self.gate.validate_suite_text(text, suite)

        text = self.suite_text(suite).replace(
            self.gate.PARAMS_FINGERPRINT, "0" * 64, 1
        )
        with self.assertRaisesRegex(RuntimeError, "parameter record.*mismatch"):
            self.gate.validate_suite_text(text, suite)

    def test_fixture_reconstruction_and_count_mismatch_fail_closed(self) -> None:
        suite = self.gate.SUITES["focused"]
        text = self.suite_text(suite).replace(
            "case=n128_last_identity,key_block=0,N=128,code=128,low=0,high=8",
            "case=n128_last_identity,key_block=0,N=128,code=128,low=0,high=7",
            1,
        )
        with self.assertRaisesRegex(RuntimeError, "PASS.*mismatch"):
            self.gate.validate_suite_text(text, suite)

        text = self.suite_text(suite).replace("pbs=3655", "pbs=3654", 1)
        with self.assertRaisesRegex(RuntimeError, "PASS.*mismatch"):
            self.gate.validate_suite_text(text, suite)

    def test_key_persistence_and_failure_markers_fail_closed(self) -> None:
        suite = self.gate.SUITES["small"]
        text = self.suite_text(suite).replace(
            "secret_material_persisted=false", "secret_material_persisted=true", 1
        )
        with self.assertRaisesRegex(RuntimeError, "key block 0.*mismatch"):
            self.gate.validate_suite_text(text, suite)

        text = self.suite_text(suite) + "thread 'main' panicked at source.rs:1\n"
        with self.assertRaisesRegex(RuntimeError, "failure marker"):
            self.gate.validate_suite_text(text, suite)

    def test_partial_or_duplicate_full_run_fails_closed(self) -> None:
        suite = self.gate.SUITES["full"]
        full = self.suite_text(suite)
        partial = "\n".join(full.splitlines()[:-2]) + "\n"
        with self.assertRaisesRegex(RuntimeError, "record count mismatch"):
            self.gate.validate_suite_text(partial, suite)

        duplicate = full.replace(
            self.pass_line(suite.cases[0], 0),
            self.pass_line(suite.cases[0], 0) + "\n" + self.pass_line(suite.cases[0], 0),
            1,
        )
        with self.assertRaisesRegex(RuntimeError, "record count mismatch"):
            self.gate.validate_suite_text(duplicate, suite)

    def test_full_absence_is_optional_until_explicitly_required(self) -> None:
        missing = self.gate.RESULTS_ROOT / "definitely-missing-a63-full.log"
        self.assertFalse(self.gate.full_log_is_available(missing, required=False))
        with self.assertRaisesRegex(FileNotFoundError, "required full A44 log missing"):
            self.gate.full_log_is_available(missing, required=True)

    def test_preflight_requires_exact_success_evidence(self) -> None:
        plan = "PLAN," + ",".join(
            f"{key}={value}" for key, value in self.gate.DRY_PLAN_FIELDS.items()
        )
        texts = {
            "build": (
                "Compiling a44_p16_retune_prototype v0.1.0\n"
                "    Finished `release` profile [optimized] target(s) in 0.47s\n"
            ),
            "dry_plan": plan + "\n",
            "harness_tests": (
                "Running unittests src/bin/a44_p16_retune_prototype.rs\n"
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            ),
            "lib_tests": (
                "Running unittests src/lib.rs\n"
                "test result: ok. 19 passed; 0 failed; 3 ignored; 0 measured; "
                "0 filtered out; finished in 0.09s\n"
            ),
        }
        result = self.gate.validate_preflight_texts(texts)
        self.assertTrue(result["dry_plan_binding"])

        texts["lib_tests"] += "error: could not compile\n"
        with self.assertRaisesRegex(RuntimeError, "failure marker"):
            self.gate.validate_preflight_texts(texts)

    def test_json_is_canonical_and_failure_output_is_json(self) -> None:
        left = self.gate.canonical_json({"z": 2, "a": {"y": 1, "x": 0}})
        right = self.gate.canonical_json({"a": {"x": 0, "y": 1}, "z": 2})
        self.assertEqual(left, right)
        self.assertEqual(left, '{"a":{"x":0,"y":1},"z":2}')

        stdout = io.StringIO()
        missing = self.gate.RESULTS_ROOT / "definitely-missing-a63.log"
        with contextlib.redirect_stdout(stdout):
            result = self.gate.main(["--build-log", str(missing)])
        self.assertEqual(result, 1)
        payload = self.gate.json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
