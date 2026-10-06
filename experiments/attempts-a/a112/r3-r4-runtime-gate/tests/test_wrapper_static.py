from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


RUNTIME = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "a112_wrapper_static_model", RUNTIME / "wrapper_static_model.py"
)
assert SPEC is not None and SPEC.loader is not None
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class A112WrapperStaticTest(unittest.TestCase):
    def test_wrapper_hash_chain_is_exact(self) -> None:
        observed = model.verify_wrapper_hashes()
        self.assertEqual(observed, model.EXPECTED_WRAPPER_HASHES)

    def test_parent_a112_freeze_is_untouched(self) -> None:
        observed = model.verify_parent_hashes()
        self.assertEqual(observed, model.EXPECTED_PARENT_HASHES)

    def test_source_and_tfhe_archive_pins_hold(self) -> None:
        report = model.verify_source_pins()
        self.assertEqual(report["tfhe_version"], "1.7.0")
        self.assertGreaterEqual(report["files_checked"], 20)

    def test_a98_raw_is_exact_and_explicitly_did_not_run_r3_r4(self) -> None:
        report = model.verify_r2b_raw()
        self.assertEqual(report["status"], "PASS_COMPONENT_FHE_SMOKE_R2B")
        self.assertEqual(report["cases_passed"], 14)
        self.assertEqual(report["tie_zero_cases"], 6)
        self.assertEqual(report["tie_one_cases"], 8)

    def test_source_uses_exact_key_domains_and_glwe_decryption_key(self) -> None:
        report = model.verify_source_contract()
        self.assertEqual(report["fixture_count"], 16)
        self.assertEqual(report["honest_gaussian_count"], 9)
        self.assertEqual(report["key_consistent_non_gaussian_count"], 7)

    def test_source_has_no_subprocess_escape_hatch(self) -> None:
        source = (RUNTIME / "src/main.rs").read_text(encoding="utf-8")
        self.assertNotIn("std::process::Command", source)
        self.assertNotIn("Command::new", source)
        self.assertNotIn("into_glwe_secret_key", source)

    def test_manifest_is_exact_and_preregistration_is_non_authorizing(self) -> None:
        report = model.verify_manifest_and_preregistration()
        self.assertEqual(report["dependencies_exact"], 4)
        self.assertEqual(report["runtime_environment_gates"], 10)
        self.assertTrue(report["root_gate_required"])

    def test_build_report_is_absent_but_its_contract_is_preregistered(self) -> None:
        prereg = json.loads(
            (RUNTIME / "WRAPPER_PREREGISTRATION.json").read_text(encoding="utf-8")
        )
        contract = prereg["runtime_fail_closed"]["build_report_contract"]
        self.assertFalse(contract["current_report_present"])
        self.assertEqual(contract["required_build"]["jobs"], 1)
        self.assertTrue(contract["required_build"]["offline"])
        self.assertTrue(contract["required_build"]["locked"])

    def test_no_compiled_or_runtime_artifact_exists(self) -> None:
        state = model.verify_absence_of_runtime_artifacts()
        self.assertFalse(state["Cargo.lock"])
        self.assertFalse(state["target"])
        self.assertFalse(state["WRAPPER_BUILD_REPORT.json"])
        self.assertEqual(state["runtime_jsonl_count"], 0)

    def test_exact_id_contract_is_linked_but_promotion_is_forbidden(self) -> None:
        prereg = json.loads(
            (RUNTIME / "WRAPPER_PREREGISTRATION.json").read_text(encoding="utf-8")
        )
        self.assertEqual(prereg["decision"]["PROMOTE_EXACT_ID"], "forbidden")
        self.assertIn("stable first argmin", prereg["claim_boundary"])
        self.assertIn("inclusive threshold", prereg["claim_boundary"])
        self.assertIn("0/ID", prereg["claim_boundary"])

    def test_full_static_report_is_source_only(self) -> None:
        report = model.static_report()
        self.assertEqual(
            report["status"],
            "PASS_STATIC_WRAPPER_READY_FOR_ROOT_BUILD_GATE_NOT_COMPILED_NOT_RUN",
        )
        self.assertTrue(all(value == 0 for value in report["executions"].values()))
        self.assertFalse(report["promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
