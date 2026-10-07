from __future__ import annotations

import ast
import copy
import importlib.util
import pathlib
import sys
import unittest


GATE_PATH = pathlib.Path(__file__).with_name("run_gate.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("_a61_a53_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A61 gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A61A53CargoGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()
        cls.manifest = cls.gate.load_json_object(
            cls.gate.MANIFEST_FILE, "test materialization manifest"
        )

    def test_static_preflight_pins_sources_and_preserves_exact_identity(self) -> None:
        result = self.gate.static_validation(exhaustive=True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["scope"],
            "static_preflight_only_no_cargo_build_keygen_fhe_docker_network",
        )
        self.assertEqual(result["pinned_files"], 30)
        self.assertFalse(result["future_crate_exists"])
        self.assertEqual(
            result["exact_contract_boundaries"],
            {
                "reject_N128": 0,
                "first_ID_N128": 1,
                "ID60": 60,
                "ID127": 127,
                "ID128": 128,
                "tail_tie_first_127": 127,
            },
        )
        self.assertEqual(
            result["count_anchors"]["N127"]["full"],
            {
                "blind_rotations": 3_390,
                "key_switches": 3_009,
                "output_marginals": 3_930,
            },
        )

    def test_pin_scope_rejects_missing_extra_or_edited_critical_input(self) -> None:
        records = self.gate.parse_pin_manifest()
        self.gate.validate_pin_scope(records)

        missing = copy.copy(records)
        missing.pop("tmp/a58-a53-rust-materialization/src/future_fhe.rs")
        with self.assertRaisesRegex(RuntimeError, "incomplete or extra scope"):
            self.gate.validate_pin_scope(missing)

        extra = copy.copy(records)
        extra["tmp/unreviewed-source.rs"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "incomplete or extra scope"):
            self.gate.validate_pin_scope(extra)

        drifted = copy.copy(records)
        drifted["tmp/a44-p16-retune-prototype/src/private_argmin.rs"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "critical provenance mismatch"):
            self.gate.validate_pin_scope(drifted)

    def test_manifest_freezes_integration_boundary_and_parameter(self) -> None:
        self.assertEqual(
            self.manifest["integration_contract"], self.gate.EXPECTED_CONTRACT
        )
        self.assertEqual(
            self.manifest["parameter_contract"], self.gate.EXPECTED_PARAMETER
        )
        self.assertEqual(
            self.manifest["integration_contract"]["semantics"],
            "0=reject; otherwise i+1 for the first exact admitted nearest identity",
        )
        self.assertFalse(
            self.manifest["parameter_contract"][
                "current_a38_tuniform_max5_allowed"
            ]
        )
        self.assertEqual(self.manifest["parameter_contract"]["headroom"], 0)
        mapping = self.manifest["future_crate"]["source_mapping"]
        self.assertEqual(len(mapping), 8)
        self.assertEqual(len({entry["to"] for entry in mapping}), 8)

    def test_focused_funnel_covers_reject_boundaries_transitions_and_tie(self) -> None:
        cases = self.gate.focused_cases(self.manifest)
        self.assertEqual(len(cases), 10)
        self.assertEqual(cases["n1_reject"], {"gallery_size": 1, "code": 0})
        self.assertEqual(
            cases["n60_last_identity"], {"gallery_size": 60, "code": 60}
        )
        self.assertEqual(
            cases["n127_all_reject"], {"gallery_size": 127, "code": 0}
        )
        self.assertEqual(
            cases["n128_last_identity"], {"gallery_size": 128, "code": 128}
        )
        self.assertEqual(
            cases["n128_tail_tie_first_127"],
            {"gallery_size": 128, "code": 127},
        )

    def test_future_commands_are_data_only_locked_offline_and_fresh_keyed(self) -> None:
        commands = self.gate.future_commands()
        self.assertEqual(
            [entry["label"] for entry in commands],
            [
                "rustfmt",
                "lib-tests",
                "harness-tests",
                "build",
                "plan-only",
                "primitive-fhe",
                "focused-fhe",
            ],
        )
        for entry in commands:
            command = entry["command"]
            if command[0] == "cargo":
                self.assertIn("--locked", command)
                self.assertIn("--offline", command)
                self.assertIn("--release", command)
                self.assertIn("diagnostic-trace", command)
        primitive = next(
            entry["command"] for entry in commands if entry["label"] == "primitive-fhe"
        )
        self.assertIn("--fresh-key", primitive)
        self.assertIn("--no-persist-secrets", primitive)
        focused = next(
            entry["command"] for entry in commands if entry["label"] == "focused-fhe"
        )
        for name in self.gate.focused_cases(self.manifest):
            self.assertIn(name, focused)

    def test_runner_has_no_execution_surface_and_scope_has_no_cargo_artifacts(self) -> None:
        tree = ast.parse(GATE_PATH.read_text())
        imported_modules = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        function_names = {
            node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        self.assertNotIn("subprocess", imported_modules)
        self.assertNotIn("execute_gate", function_names)
        self.assertNotIn("run_command", function_names)
        self.assertFalse(self.gate.FUTURE_CRATE.exists())
        self.assertFalse((self.gate.GATE_ROOT / "Cargo.toml").exists())
        self.assertFalse((self.gate.GATE_ROOT / "Cargo.lock").exists())
        self.assertFalse((self.gate.GATE_ROOT / "target").exists())

    def test_probability_claim_stays_open_and_blocks_promotion(self) -> None:
        probability = self.manifest["probability_boundary"]
        self.assertFalse(probability["end_to_end_pfail_certificate"])
        self.assertIsNone(probability["numeric_upper_bound"])
        self.assertFalse(probability["promotion_allowed"])
        plan = self.gate.print_future_plan()
        self.assertEqual(plan["status"], "PLAN_ONLY_NOT_EXECUTED")
        self.assertFalse(plan["end_to_end_pfail_certificate"])


if __name__ == "__main__":
    unittest.main()
