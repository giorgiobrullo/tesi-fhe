from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE_PATH = pathlib.Path(__file__).with_name("run_gate.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("_a57_a41_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load A57 gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class A57A41GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_gate()
        cls.plan = cls.gate.load_json_object(cls.gate.PLAN_FILE, "test plan")
        cls.model = cls.gate.load_model()

    def test_static_provenance_and_contract(self) -> None:
        result = self.gate.static_validation(exhaustive=False)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["pinned_files"], 17)
        self.assertEqual(
            result["count_anchors"]["N127"],
            {
                "blind_rotations": 3655,
                "key_switches": 3274,
                "output_marginals": 4206,
            },
        )
        terminal = result["terminal_representation"]
        self.assertEqual(terminal["wire_output_lwes"], 2)
        self.assertEqual(terminal["root_delta_log"], 59)
        self.assertFalse(terminal["linear_encrypted_postprocessing"])

    def test_focused_fixture_plan_covers_required_boundaries(self) -> None:
        focused = self.gate.expected_cases(self.plan, "focused")
        self.assertEqual(
            focused,
            {
                "n127_last_identity": {
                    "gallery_size": 127,
                    "code": 127,
                    "low": 15,
                    "high": 7,
                },
                "n128_last_identity": {
                    "gallery_size": 128,
                    "code": 128,
                    "low": 0,
                    "high": 8,
                },
                "n128_tail_tie_first_127": {
                    "gallery_size": 128,
                    "code": 127,
                    "low": 15,
                    "high": 7,
                },
                "n127_all_reject": {
                    "gallery_size": 127,
                    "code": 0,
                    "low": 0,
                    "high": 0,
                },
            },
        )
        self.assertEqual(len(self.gate.expected_cases(self.plan, "small")), 21)

    def test_parser_requires_exact_two_lwe_reconstruction_and_counts(self) -> None:
        expected = self.gate.expected_cases(self.plan, "focused")
        lines = [
            "KEY,generation_s=1.0,ephemeral=true,secret_material_persisted=false"
        ]
        for name, case in expected.items():
            counts = self.model.a41_counts(case["gallery_size"])
            lines.append(
                "PASS,"
                f"case={name},N={case['gallery_size']},code={case['code']},"
                f"low={case['low']},high={case['high']},"
                f"pbs={counts.blind_rotations},ks={counts.key_switches},"
                f"marginals={counts.output_marginals},wire_lwes=2,"
                "root_delta_log=59,linear_postprocessing=false,eval_s=1.0"
            )
        lines.append(
            "SUMMARY,status=PASS,cases=4,keys=ephemeral_in_memory,"
            "secret_material_persisted=false"
        )
        result = self.gate.validate_fhe_output("\n".join(lines), expected, self.model)
        self.assertTrue(result["two_lwe_exact_reconstruction_verified"])

        corrupted = "\n".join(lines).replace(
            "case=n128_last_identity,N=128,code=128,low=0,high=8",
            "case=n128_last_identity,N=128,code=128,low=0,high=7",
        )
        with self.assertRaisesRegex(RuntimeError, "oracle mismatch|reconstruction"):
            self.gate.validate_fhe_output(corrupted, expected, self.model)

    def test_future_commands_are_locked_offline_and_focused(self) -> None:
        commands = self.gate.cargo_commands()
        labels = [label for label, _, _ in commands]
        self.assertEqual(
            labels,
            [
                "rustfmt",
                "lib-tests",
                "harness-tests",
                "build",
                "dry-plan",
                "small-fhe",
                "focused-fhe",
            ],
        )
        for label, command, _ in commands:
            if command[0] == "cargo":
                self.assertIn("--locked", command, label)
                self.assertIn("--offline", command, label)
        focused = dict((label, command) for label, command, _ in commands)[
            "focused-fhe"
        ]
        for name in self.gate.expected_cases(self.plan, "focused"):
            self.assertIn(f"--case={name}", focused)

    def test_probability_claim_remains_separate(self) -> None:
        boundary = self.plan["probability_boundary"]
        self.assertFalse(boundary["end_to_end_pfail_certificate"])
        self.assertIn("conditional only", boundary["terminal_pfail"])
        self.assertGreaterEqual(len(boundary["open_obligations"]), 5)


if __name__ == "__main__":
    unittest.main()
