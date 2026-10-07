import copy
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import a138_model as frozen
from checker import analyze_case, analyze_records, main
import regions as r
from synthetic import FAKE_BINARY_HASH, complete_safe_log, make_case


class Regions(unittest.TestCase):
    def test_cli_preserves_existing_report(self):
        with tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        ) as directory:
            report = Path(directory) / "existing.json"
            report.write_text("preserved evidence\n")
            argv = [
                "checker.py",
                "not-read.jsonl",
                "--expected-binary-sha256",
                FAKE_BINARY_HASH,
                "--output",
                str(report),
            ]
            with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main()
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(report.read_text(), "preserved evidence\n")

    def test_actual_p8_regions_and_zero_alias(self):
        body = frozen.stock_body([x << 51 for x in range(8)])
        self.assertEqual(
            r.matching_degrees(body, 0), ((0, 127), (1920, 2175), (3968, 4095))
        )
        for digit in range(1, 8):
            self.assertEqual(
                r.matching_degrees(body, digit << 51),
                ((digit * 256 - 128, digit * 256 + 127),),
            )

    def test_exact_phase_preimages_include_rounding_ties(self):
        body = frozen.stock_body([x << 51 for x in range(8)])
        for target in (0, 1 << 51, 7 << 51):
            addresses = r.matching_degrees(body, target)
            for shift in (-64, -1, 0, 1, 64):
                preimage = r.phase_preimage(addresses, shift)
                for lo, hi in preimage:
                    for x in (lo - 1, lo, hi, hi + 1):
                        expected = r.lut(body, r.round_phase(x) + shift) == target
                        self.assertEqual(r.contains(preimage, r.word(x)), expected)

    def test_native_half_slot_is_asymmetric_at_tie(self):
        self.assertTrue(r.native_safe(-(1 << 50), 51))
        self.assertFalse(r.native_safe(1 << 50, 51))

    def test_p8_rounding_cell_is_not_native_half_slot(self):
        body = frozen.stock_body([x << 51 for x in range(8)])
        domain = r.error_domain(body, 0, 0, 0)["total_phase_error_intervals"]
        upper = 255 * r.U // 2 - 1
        lower = -257 * r.U // 2
        self.assertTrue(r.contains(domain, upper))
        self.assertFalse(r.contains(domain, upper + 1))
        self.assertTrue(r.contains(domain, lower))
        self.assertFalse(r.contains(domain, lower - 1))
        misleading = 128 * r.U - r.U // 4
        self.assertTrue(r.native_safe(misleading, 60))
        self.assertFalse(r.contains(domain, misleading))

    def test_shared512_affine_coefficient_and_control(self):
        for arm in (0, 1):
            _, _, graph = make_case([1, 0, 255, 1024], arm)
            event = next(x for x in graph.reports if x["stage"] == "ingress/1/low.low3")
            key = "ingress/1/low.msb54/pbs_error"
            if arm == 0:
                self.assertEqual(event["input_affine_error_terms"][key], -512)
            else:
                self.assertNotIn(key, event["input_affine_error_terms"])
                self.assertEqual(
                    event["input_affine_error_terms"][
                        "ingress/1/low.msb63_independent_scale/pbs_error"
                    ],
                    -1,
                )

    def test_old_joint_witness_through_event_replay(self):
        for arm, flags in [(0, [1, 0, 0, 0]), (1, [0, 1, 0, 0])]:
            case, events, _ = make_case(
                [1, 0, 255, 1024],
                arm,
                low_errors=[0, -(1 << 58), 0, 0],
                perturbations={"ingress/1/low.msb54": dict(error=3 << 48)},
            )
            replay = analyze_case(case, events)
            self.assertEqual(replay["flags"], flags)
            self.assertEqual(replay["conditional_joint_safe_region_pass"], arm == 1)

    def test_native_ingress_and_active_still_insufficient_for_consumer(self):
        case, events, _ = make_case(
            [1, 0, 2, 3], perturbations={"a34.candidate/1": dict(error=1 << 56)}
        )
        replay = analyze_case(case, events)
        self.assertTrue(replay["native_decode_pass"])
        self.assertTrue(replay["native_msb_outputs_pass"])
        self.assertTrue(r.native_safe(1 << 56, 59))
        self.assertFalse(replay["composed_a34_a135_pass"])
        self.assertIn("middle_round.mask/1", replay["region_failures"])

    def test_zero_alias_does_not_certify_correct_fold(self):
        case, events, _ = make_case(
            [1, 0, 2, 3],
            1,
            perturbations={
                "ingress/1/low.msb63_independent_scale": dict(error=1 << 63)
            },
        )
        replay = analyze_case(case, events)
        self.assertTrue(replay["native_decode_pass"])
        self.assertTrue(replay["composed_a34_a135_pass"])
        self.assertTrue(replay["conditional_joint_safe_region_pass"])
        self.assertFalse(replay["native_msb_outputs_pass"])

    def test_actual_ms_displacement_can_change_region_at_zero_phase_error(self):
        case, events, _ = make_case(
            [1, 0, 2, 3], perturbations={"middle_round.mask/1": dict(ms=64)}
        )
        replay = analyze_case(case, events)
        event = next(
            e for e in replay["event_domains"] if e["stage"] == "middle_round.mask/1"
        )
        self.assertEqual(event["input_affine_error"], "0")
        self.assertEqual(event["ks_phase_increment"], "0")
        self.assertEqual(event["observed_ms_displacement"], 64)
        self.assertFalse(event["conditional_region_pass"])

    def test_event_mutations_and_missing_observations_fail(self):
        case, events, _ = make_case([1, 0, 2, 3])
        mutations = [
            ("big_phase_word", "1"),
            ("small_phase_word", "1"),
            ("output_phase_word", "1"),
            ("ks_phase_increment", "1"),
            ("actual_ms_address", 4000),
            ("body_sha256", "0" * 64),
            ("lut_word_at_actual_address", "1"),
            ("output_error_at_actual_address", "1"),
            ("stage", "fake"),
        ]
        for field, value in mutations:
            changed = copy.deepcopy(events)
            changed[0][field] = value
            with self.assertRaises(AssertionError, msg=field):
                analyze_case(case, changed)
        with self.assertRaises(AssertionError):
            analyze_case(case, events[:-1])

    def test_native_only_false_completion_is_rejected(self):
        case, events, _ = make_case(
            [1, 0, 2, 3], perturbations={"a34.candidate/1": dict(error=1 << 56)}
        )
        case["pass"] = True
        case["composed_a34_a135_pass"] = True
        with self.assertRaises(AssertionError):
            analyze_case(case, events)

    def test_complete_source_pinned_synthetic_log(self):
        records = complete_safe_log()
        result = analyze_records(records, FAKE_BINARY_HASH)
        self.assertTrue(result["joint_witness_pass"])
        self.assertEqual(result["status"], "SYNTHETIC_REPLAY")
        self.assertEqual(result["cases_checked"], 24)
        self.assertEqual(result["events_checked"], 8 * (55 + 63 + 55))
        with self.assertRaises(AssertionError):
            analyze_records(records[:-1], FAKE_BINARY_HASH)
        with self.assertRaises(AssertionError):
            analyze_records(records, "1" * 64)


if __name__ == "__main__":
    unittest.main()
