import ast
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from model import (  # noqa: E402 - local isolated package bootstrap
    DELTA,
    ROOT,
    Expression,
    a133_tools,
    adapt_event,
    formulas,
    ks_rows,
    psd,
    rms_bound,
    variance,
    verify_sources,
)
from crosscheck import check_library  # noqa: E402


def synthetic_factory():
    # Execute only the two frozen arithmetic fixture constructors, never its tests/materializer.
    source = (ROOT / "tmp/a133-a126-runtime-noise-witness/test_witness.py").read_text()
    tree = ast.parse(source)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in ["center", "ct_record", "synthetic_event"]
    ]
    namespace = {"hashlib": hashlib, "struct": struct}
    exec(
        compile(
            ast.Module(body=selected, type_ignores=[]), "frozen_a133_fixture", "exec"
        ),
        namespace,
    )
    return namespace["synthetic_event"]


class CrosscheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = a133_tools()
        cls.fixture = staticmethod(synthetic_factory())

    def test_source_pins_and_api_loss_of_information(self):
        self.assertEqual(verify_sources(), 29)
        sources = json.loads((HERE / "SOURCE_PINS.json").read_text())["sources"]
        by_name = {
            item["path"]: Path(item["path"]).read_text()
            for item in sources
            if "/noise_simulation/" in item["path"]
        }
        simulator = next(
            text
            for name, text in by_name.items()
            if name.endswith("/noise_simulation/mod.rs")
        )
        start = simulator.index("pub struct NoiseSimulationLwe {")
        fields = simulator[start : simulator.index("}", start)]
        self.assertIn("variance: Variance", fields)
        self.assertNotIn("covariance", fields)
        self.assertNotIn("producer", fields)
        self.assertNotIn("mean", fields)
        ks = next(
            text
            for name, text in by_name.items()
            if name.endswith("/noise_simulation/lwe_keyswitch.rs")
        )
        pbs = next(
            text
            for name, text in by_name.items()
            if name.endswith("/noise_simulation/lwe_programmable_bootstrap.rs")
        )
        self.assertIn("match self.noise_distribution", ks)
        self.assertIn("DynamicDistribution::Gaussian(_)", ks)
        self.assertIn("DynamicDistribution::Gaussian(_)", pbs)
        classic = pbs[
            pbs.index("fn lwe_classic_fft_pbs(") : pbs.index(
                "pub struct NoiseSimulationLweFourier128Bsk"
            )
        ]
        self.assertNotIn("input.variance()", classic)
        self.assertIn(
            "accumulator.variance_per_occupied_slot().0 + br_additive_variance.0",
            classic,
        )

    def test_exact_aliases_and_nonzero_bias(self):
        atom = Expression.atom("cipher-A")
        self.assertEqual(variance(atom.add(atom.scale(-1)), {})["variance"], "0")
        doubled = atom.add(atom)
        self.assertEqual(
            variance(doubled, {("cipher-A", "cipher-A"): 1})["variance"], "4"
        )
        constant = Expression({}, DELTA)
        self.assertEqual(variance(constant, {})["variance"], "0")
        self.assertEqual(rms_bound(constant, {})["rms_torus_bound"], str(DELTA))

    def test_same_marginals_different_correlations(self):
        a, b = Expression.atom("a"), Expression.atom("b")
        for correlation, total, affine in [
            (1, "4", "49"),
            (-1, "0", "25"),
            (0, "2", "37"),
        ]:
            covariance = {
                ("a", "a"): 1,
                ("b", "b"): 1,
                ("a", "b"): correlation,
                ("b", "a"): correlation,
            }
            self.assertEqual(variance(a.add(b), covariance)["variance"], total)
            self.assertEqual(
                variance(a.add(b.scale(6)), covariance)["variance"], affine
            )
        self.assertEqual(
            variance(a.add(b), {("a", "a"): 1, ("b", "b"): 1})["status"], "OPEN"
        )

    def test_invalid_covariance_rejected(self):
        a = Expression({"a": 1, "b": 1, "c": 1})
        covariance = {
            (x, y): (Fraction(1) if x == y else Fraction(-9, 10))
            for x in a.terms
            for y in a.terms
        }
        with self.assertRaises(ValueError):
            variance(a, covariance)
        self.assertFalse(psd([[Fraction(0), Fraction(1)], [Fraction(1), Fraction(1)]]))

    def test_a131_singleton_provenance(self):
        expression = Expression.atom("initial")
        for level in range(4):
            zero = Expression.atom("same-zero-" + str(level))
            expression = expression.add(zero).add(zero.scale(-1))
        expression = expression.add(Expression.atom("positive-b3").scale(6))
        self.assertEqual(expression.summary()["l1"], 7)
        generic = Expression.atom("initial")
        for level in range(4):
            generic = generic.add(Expression.atom("zero-" + str(level))).add(
                Expression.atom("any-" + str(level)).scale(-1)
            )
        generic = generic.add(Expression.atom("positive-b3").scale(6))
        self.assertEqual(generic.summary()["l1"], 15)
        self.assertEqual(rms_bound(generic, {})["status"], "OPEN")
        self.assertEqual(
            rms_bound(generic, {key: 1 for key in generic.terms})["rms_torus_bound"],
            "15",
        )

    def test_shared_ks_row_id_and_no_body_decomposition(self):
        decompose = self.tools[2].decomposition
        words = [1 << 61, 3 << 61, 12345]
        a = ks_rows(words, "same-key", decompose)
        b = ks_rows(words[:-1] + [999999], "same-key", decompose)
        self.assertEqual(a, b)
        self.assertEqual(a.add(b.scale(-1)).terms, {})
        distinct = ks_rows(words, "different-key", decompose)
        self.assertNotEqual(a.terms, distinct.terms)

    def test_a133_actual_support_alias_and_raw_binding(self):
        pins = self.tools[1]
        inside = adapt_event(self.fixture(pins), self.tools)
        outside = adapt_event(self.fixture(pins, outside=True), self.tools)
        bad_raw = adapt_event(self.fixture(pins, raw_error=DELTA), self.tools)
        self.assertTrue(inside["observed_checks"]["exact_joint_support"])
        self.assertFalse(outside["observed_checks"]["exact_joint_support"])
        self.assertTrue(outside["observed_checks"]["raw_nearest_cell"])
        self.assertTrue(bad_raw["observed_checks"]["exact_joint_support"])
        self.assertFalse(bad_raw["observed_checks"]["raw_nearest_cell"])
        self.assertEqual(inside["update_expression"]["atoms"], 1)
        self.assertEqual(inside["update_variance"]["status"], "OPEN")
        self.assertFalse(inside["library_pbs_variance_attached_to_actual_atoms"])
        self.assertFalse(outside["p_fail_claimed"])

    def test_a133_bad_provenance_rejected(self):
        event = self.fixture(self.tools[1])
        event["raw_samples"][1]["producer_id"] += "different"
        with self.assertRaises(ValueError):
            adapt_event(event, self.tools)
        event = self.fixture(self.tools[1])
        event["immediate_update"]["any_ciphertext_aliases_sample768"] = False
        with self.assertRaises(ValueError):
            adapt_event(event, self.tools)

    def test_formula_port_and_library_replay_mutations(self):
        values = formulas()
        self.assertTrue(
            all(
                values[k] > 0
                for k in [
                    "ks_additive_variance",
                    "ms_additive_variance",
                    "pbs_marginal_model_variance",
                ]
            )
        )
        # This synthetic report tests the comparator, not an actual linked library result.
        record = {key: value for key, value in values.items() if "variance" in key}
        record.update(
            source_binding=json.loads((HERE / "SOURCE_BINDING.json").read_text()),
            ks_changed_supplied_sigma_variance=values["ks_additive_variance"],
            pbs_changed_supplied_sigma_variance=values["pbs_marginal_model_variance"],
            pbs_huge_input_variance_result=values["pbs_marginal_model_variance"],
            api_misuse_negative_controls={
                "uncorrelated_alias_sub": 2.0,
                "correct_alias_sub": 0,
                "uncorrelated_alias_sum": 2.0,
                "correct_alias_sum": 4,
                "scalar_six": 36.0,
            },
            ms_keeps_original_modulus=True,
            fhe_executed=False,
            p_fail_claimed=False,
        )
        self.assertEqual(
            check_library(record)["status"], "CONSISTENT_SUPPLIED_LIBRARY_MODEL_REPORT"
        )
        for key in [
            "ks_additive_variance",
            "ms_additive_variance",
            "pbs_marginal_model_variance",
        ]:
            altered = copy.deepcopy(record)
            altered[key] *= 1.1
            with self.assertRaises(ValueError):
                check_library(altered)


if __name__ == "__main__":
    unittest.main()
