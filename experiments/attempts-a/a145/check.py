"""Bounded exact source/model checks; no compiler, keygen, or FHE."""

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import unittest

from graph import Graph
import regions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = [
    [15, 0, 255, 1024],
    [7, 8, 15, 1024],
    [255, 256, 254, 4095],
    [1023, 1023, 1024, 4095],
    [1024, 4095, 2048, 4094],
    [4095, 511, 512, 510],
    [128, 127, 127, 129],
    [16, 16, 15, 15],
]
ARMS = [
    dict(
        name="canonical_shared",
        independent=False,
        padding=False,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="canonical_separate",
        independent=True,
        padding=False,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="padding_shared",
        independent=False,
        padding=True,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="padding_separate",
        independent=True,
        padding=True,
        wrong_final=False,
        wrong_scale=False,
    ),
    dict(
        name="negative_final_delta63",
        independent=False,
        padding=True,
        wrong_final=True,
        wrong_scale=False,
    ),
    dict(
        name="negative_digit_scale",
        independent=False,
        padding=True,
        wrong_final=False,
        wrong_scale=True,
    ),
]


def verify_sources():
    pins = json.loads((HERE / "SOURCE_PINS.json").read_text())
    for path, sha in pins.items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != sha:
            raise ValueError("frozen source changed: " + path)
    for name in ["regions.py", "a138_model.py", "a135_model.py"]:
        original = ROOT / "tmp/a142-nibble-joint-noise-domain" / name
        if (HERE / name).read_bytes() != original.read_bytes():
            raise ValueError("copied reference drift: " + name)
    return len(pins)


def evaluate(scores, arm, perturbations=None, low_errors=None, full_errors=None):
    graph = Graph(
        padding=arm["padding"],
        wrong_final=arm["wrong_final"],
        perturbations=perturbations,
    )
    result, outputs = graph.evaluate(
        scores,
        full_errors or [0] * 4,
        low_errors or [0] * 4,
        independent=arm["independent"],
        wrong_scale=arm["wrong_scale"],
    )
    result["final_phase_words"] = [str(graph.actual(v)) for v in outputs["flags"]]
    return result, graph


def rust_function(source, name):
    match = re.search(r"\bfn " + re.escape(name) + r"\b[^{}]*\{", source)
    if not match:
        raise ValueError("missing function " + name)
    start = match.end() - 1
    depth = 1
    for end in range(start + 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return re.sub(r"\s+", "", source[start : end + 1])
    raise ValueError("unterminated function " + name)


def active_error_examples():
    scores = [1, 0, 2, 3]
    out = {}
    for name, arm, error in [
        ("canonical_absolute_error", ARMS[0], 1 << 56),
        ("padding_same_absolute_error", ARMS[2], 1 << 56),
        ("padding_same_relative_error", ARMS[2], 1 << 60),
    ]:
        result, graph = evaluate(scores, arm, {"a34.candidate/1": {"error": error}})
        log = 63 if arm["padding"] else 59
        out[name] = dict(
            scores=scores,
            injected_candidate_error=str(error),
            output_log=log,
            candidate_native_pass=regions.native_safe(error, log),
            flags=result["flags"],
            expected_flags=result["expected_flags"],
            native_ingress_pass=result["native_decode_pass"],
            composed_pass=result["composed_a34_a135_pass"],
            region_failures=[
                r["stage"] for r in graph.reports if not r["conditional_region_pass"]
            ],
        )
    return out


class Checks(unittest.TestCase):
    def test_frozen_inputs_and_unchanged_crypto_functions(self):
        self.assertEqual(verify_sources(), 8)
        original = (ROOT / "tmp/a138-nibble-ingress-gate/src/main.rs").read_text()
        current = (HERE / "src/main.rs").read_text()
        for name in [
            "scale",
            "add",
            "sub",
            "offset",
            "digest",
            "switch_word",
            "body_pbs",
            "table",
            "msb",
            "nibble",
        ]:
            self.assertEqual(
                rust_function(original, name), rust_function(current, name), name
            )
        for arm in ARMS:
            declaration = re.search(
                r'Arm\s*\{\s*name:\s*"' + arm["name"] + r'"(.*?)\}', current, re.S
            ).group(1)
            for key, value in arm.items():
                if key != "name":
                    self.assertRegex(declaration, key + r":\s*" + str(value).lower())
        self.assertIn("vec![2]", current)
        self.assertIn('"target-a145-only"', current)

    def test_all_nominal_positive_profiles_and_ledgers(self):
        for scores in FIXTURES:
            for arm in ARMS[:4]:
                result, _ = evaluate(scores, arm)
                self.assertTrue(result["native_decode_pass"])
                self.assertTrue(result["composed_a34_a135_pass"])
                self.assertEqual(result["pbs_ks"], 63 if arm["independent"] else 55)
                self.assertTrue(
                    all(int(w) in (0, 1 << 59) for w in result["final_phase_words"])
                )

    def test_canonical_trace_matches_frozen_a142(self):
        path = ROOT / "tmp/a142-nibble-joint-noise-domain/graph.py"
        spec = importlib.util.spec_from_file_location("a145_old_graph", path)
        old = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = old
        spec.loader.exec_module(old)
        perturbations = {"a34.candidate/1": {"error": 1 << 40, "ks": 17, "ms": 1}}
        for independent in (False, True):
            first = old.Graph(perturbations=perturbations)
            second = Graph(perturbations=perturbations)
            self.assertEqual(
                first.evaluate(FIXTURES[2], [4, 3, 2, 1], [1, 2, 3, 4], independent)[0],
                second.evaluate(FIXTURES[2], [4, 3, 2, 1], [1, 2, 3, 4], independent)[
                    0
                ],
            )
            self.assertEqual(first.generated, second.generated)

    def test_active_error_absolute_versus_relative(self):
        cases = active_error_examples()
        self.assertTrue(all(c["candidate_native_pass"] for c in cases.values()))
        self.assertFalse(cases["canonical_absolute_error"]["composed_pass"])
        self.assertTrue(cases["padding_same_absolute_error"]["composed_pass"])
        self.assertFalse(cases["padding_same_relative_error"]["composed_pass"])

    def test_negative_controls_smallest_case(self):
        for arm in ARMS[4:]:
            result, _ = evaluate(FIXTURES[2], arm)
            self.assertFalse(result["composed_a34_a135_pass"], arm["name"])
        wrong, _ = evaluate(FIXTURES[2], ARMS[4])
        self.assertIn(16, wrong["flags"])
        self.assertIn(str(1 << 63), wrong["final_phase_words"])

    def test_padding_does_not_repair_ingress_shared_fold(self):
        change = {"ingress/1/low.msb54": {"error": 3 << 48}}
        for arm in [ARMS[0], ARMS[2]]:
            result, _ = evaluate([1, 0, 255, 1024], arm, change, [0, -(1 << 58), 0, 0])
            self.assertFalse(result["composed_a34_a135_pass"])
        for arm in [ARMS[1], ARMS[3]]:
            result, _ = evaluate([1, 0, 255, 1024], arm, change, [0, -(1 << 58), 0, 0])
            self.assertTrue(result["composed_a34_a135_pass"])

    def test_only_declared_flag_lut_amplitudes_change(self):
        for pair in [(0, 2), (1, 3)]:
            _, canonical = evaluate(FIXTURES[2], ARMS[pair[0]])
            _, padding = evaluate(FIXTURES[2], ARMS[pair[1]])
            for old, new in zip(canonical.generated, padding.generated):
                stage = old["stage"]
                self.assertEqual(stage, new["stage"])
                changed = (
                    stage.startswith("a34.candidate/")
                    or stage.startswith("middle_round.update/")
                    or stage in ("middle_round.valid", "low_round.valid")
                )
                self.assertEqual(old["big_phase_word"], new["big_phase_word"])
                if changed:
                    self.assertNotEqual(old["body_sha256"], new["body_sha256"])
                    self.assertEqual(
                        regions.word(16 * int(old["output_phase_word"])),
                        int(new["output_phase_word"]),
                    )
                else:
                    self.assertEqual(old["body_sha256"], new["body_sha256"])
                    self.assertEqual(old["output_phase_word"], new["output_phase_word"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Reserve before checking so an existing report can never be replaced.
    with args.output.open("x") as output:
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
        )
        report = dict(
            status="PASS_STATIC_SOURCE_ONLY"
            if result.wasSuccessful()
            else "STATIC_FAILURE",
            tests=result.testsRun,
            log=stream.getvalue(),
            source_pins=verify_sources(),
            active_error_examples=active_error_examples(),
            first_fixture_index=2,
            positive_arms=4,
            negative_arms=2,
            br_ks_per_fixture=[55, 63, 55, 63, 55, 55],
            cargo_run=False,
            fhe_run=False,
            noise_improvement_claimed=False,
            p_fail_certified=False,
            output_interface="Delta59 canonical flags only; no A53/service",
        )
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps({k: report[k] for k in ["status", "tests", "source_pins"]}))
    if not result.wasSuccessful():
        print(stream.getvalue())
        raise SystemExit(1)


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("assertions must remain enabled")
    main()
