import os
from pathlib import Path
import tempfile
import unittest

import audit
import model
from run_gate import private_file


def fixture(wrong_displacements=(-192, -192, 192, 192)):
    rows = []
    for arm in ("baseline", "wrong_lane"):
        displacements = (0, 0, 0, 0) if arm == "baseline" else wrong_displacements
        for offset in model.OFFSETS:
            for i in range(4):
                center = int(i == 0) * 512
                degree = (center + displacements[i]) % 4096
                shifted = (degree + (-128 if offset < 0 else 128)) % 4096
                phase = degree << 52
                rows.append(
                    dict(
                        arm=arm,
                        offset=offset,
                        index=i,
                        original_degree=degree,
                        shifted_degree=shifted,
                        original_phase=phase,
                        shifted_phase=(phase + offset) % model.Q,
                        output_phase=model.lut_value(shifted) * model.A44_DELTA,
                        mask_unchanged=True,
                    )
                )
    return rows


class A155Tests(unittest.TestCase):
    def test_all4096_negacyclic_degrees_and_wrap_cells(self):
        # Bind the Rust function being checked to this exhaustive cross-language comparison.
        rust = (audit.HERE / "src/margin_controls.rs").read_text()
        actual = rust.split("fn identity_value(")[1].split("fn retained(")[0]
        actual = "".join(actual.split())
        self.assertEqual(
            actual,
            "degree:usize)->u64{letcell=((degree+256)/512)%8;ifcell<4{cellasu64}else{0u64.wrapping_sub((cell-4)asu64)%32}}",
        )
        for degree in range(4096):
            cell = ((degree + 256) // 512) % 8
            rust_formula = (cell if cell < 4 else -(cell - 4)) % 32
            self.assertEqual(model.lut_value(degree), rust_formula)
            self.assertEqual(model.lut_value(degree + 4096), rust_formula)
            self.assertEqual(model.lut_value(degree - 4096), rust_formula)
        self.assertEqual(
            [model.lut_value(i * 512) for i in range(8)], [0, 1, 2, 3, 0, 31, 30, 29]
        )
        self.assertEqual(
            [model.lut_value(x) for x in (3839, 3840, 4095, 0, 255, 256)],
            [29, 0, 0, 0, 0, 1],
        )

    def test_public_offsets_translate_exact_body_switch_including_wrap(self):
        # Every address and values on both sides of the rounding threshold.
        for degree in range(4096):
            for tail in (0, (1 << 51) - 1, 1 << 51, (1 << 52) - 1):
                word = (degree << 52) + tail
                for offset in model.OFFSETS:
                    expected = (
                        model.modulus_switch(word) + (-128 if offset < 0 else 128)
                    ) % 4096
                    self.assertEqual(
                        model.modulus_switch((word + offset) % model.Q), expected
                    )

    def test_fixed16_control_can_discriminate_with_no_runtime_claim(self):
        result = model.summarize(fixture())
        self.assertTrue(result["passed"])
        self.assertEqual(result["wrong_discriminators"], [2, 2])

    def test_undetected_wrong_map_remains_failed(self):
        result = model.summarize(fixture((0, 0, 0, 0)))
        self.assertFalse(result["passed"])
        self.assertEqual(result["wrong_discriminators"], [0, 0])

    def test_unrelated_pbs_error_cannot_credit_wrong_mapping(self):
        rows = fixture((0, 0, 0, 0))
        rows[8]["output_phase"] = (rows[8]["output_phase"] + model.A44_DELTA) % model.Q
        result = model.summarize(rows)
        self.assertFalse(result["passed"])
        self.assertFalse(result["all_outputs_match_lut"])
        self.assertEqual(sum(result["wrong_discriminators"]), 0)

    def test_baseline_failure_or_lost_binding_is_not_accepted(self):
        for key, value in [
            ("mask_unchanged", False),
            ("shifted_phase", 17),
            ("shifted_degree", 21),
            ("output_phase", 21 * model.A44_DELTA),
        ]:
            rows = fixture()
            rows[0][key] = value
            self.assertFalse(model.summarize(rows)["passed"])

    def test_missing_duplicate_or_reordered_probe_is_rejected(self):
        rows = fixture()
        for bad in (rows[:-1], rows + rows[:1], [rows[1], rows[0]] + rows[2:]):
            with self.assertRaises(ValueError):
                model.summarize(bad)

    def test_historical_failure_is_separate_from_new_gate(self):
        self.assertEqual(
            model.gate_values(True, True, True, True, False, True), (False, True)
        )
        self.assertEqual(
            model.gate_values(True, True, True, True, False, False), (False, False)
        )
        for failed in range(4):
            values = [True] * 6
            values[failed] = False
            self.assertEqual(model.gate_values(*values), (False, False))

    def test_original_crypto_prefix_and_graph_inputs_unchanged(self):
        result = audit.source_check()
        self.assertTrue(result["original_crypto_byte_identical_prefix"])
        self.assertEqual(
            result["additional_margin_operations"],
            dict(body_additions=16, ordinary_pbs=16, ordinary_ks=0),
        )
        source = (audit.HERE / "src/margin_controls.rs").read_text()
        self.assertLess(
            source.index("crypto::egress_margin_probe("),
            source.index("crypto::decrypt_trace("),
        )
        self.assertEqual(source.count("crypto::egress_margin_probe("), 1)
        self.assertIn("for index in 0..4", source)

    def test_runner_private_initial_create_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "private.jsonl"
            with private_file(path) as out:
                self.assertEqual(os.fstat(out.fileno()).st_mode & 0o777, 0o600)
                out.write("synthetic only\n")
            with self.assertRaises(FileExistsError):
                private_file(path)

    def test_scope_defaults_and_original_result_fields_exist(self):
        main = (audit.HERE / "src/main.rs").read_text()
        runner = (audit.HERE / "run_gate.py").read_text()
        self.assertIn('default="witness"', runner)
        self.assertIn(
            "target-a155-only/release/a155-common-mask-egress-margin-control", runner
        )
        for field in [
            "original_a150_bounded_diagnostic_gate_pass",
            "original_a150_graph_negatives_pass",
            "a155_margin_control_gate_pass",
        ]:
            self.assertIn(field, main)
        self.assertIn("let passed = a155_passed.unwrap_or(original_passed);", main)


if __name__ == "__main__":
    unittest.main()
