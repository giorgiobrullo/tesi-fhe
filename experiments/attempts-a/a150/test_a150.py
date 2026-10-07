"""Light exact/source tests. No compiled library or FHE coverage is implied."""

import copy
from fractions import Fraction
import json
import os
from pathlib import Path
import tempfile
import unittest

import audit
import a146_model as m
import replay
from run_gate import private_file


def synthetic_event():
    keys = tuple(tuple(int(i == j) for i in range(m.N)) for j in range(4))
    before = m.algebra_ciphertext(
        [m.U // 2 - 1] * m.N, [0, 1, 2, 3], [5, -6, 7, -8], keys
    )
    zero = m.algebra_ciphertext(
        [m.word(-a) for a in before.mask], [0] * 4, [1, -2, 3, -4], keys
    )
    after = before.add(zero)
    lanes = []
    for i, (p, q, z, d) in enumerate(
        zip(
            before.phases(keys),
            after.phases(keys),
            zero.phases(keys),
            after.addresses(keys),
        )
    ):
        displacement = (d - i * 128 + 512) % 1024 - 512
        lanes.append(
            dict(
                lane=i,
                expected=i,
                before_phase_u64=str(p),
                corrected_phase_u64=str(q),
                selected_zero_phase_i64=str(m.signed(z)),
                phase_addition_closure=True,
                corrected_coefficientwise_degree=d,
                corrected_center_displacement=displacement,
                corrected_inside_center_box=(-64 <= displacement < 64),
            )
        )
    return dict(
        before_words_hex=[f"{x:016x}" for x in before.mask + before.bodies],
        corrected_words_hex=[f"{x:016x}" for x in after.mask + after.bodies],
        selected_zero_words_hex=[f"{x:016x}" for x in zero.mask + zero.bodies],
        selected_index=0,
        zero_additions=1,
        word_addition_closure=True,
        corrected_is_actual_br_input=True,
        pbs_executed=True,
        allowed=True,
        input_variance_justified_for_actual_stage=False,
        formal_failure_claim=False,
        policy="SharedZerosStockAssumption",
        chooser_invocations=1,
        assumed_normalized_input_variance=m.PROFILE["ms_input_variance"],
        estimator_satisfied=True,
        status="SATISFYING_ESTIMATOR_ASSUMPTION_ONLY",
        source_derived_zero_candidates_examined=1,
        lanes=lanes,
    )


def synthetic_stock_records():
    # Entirely clear all-zero words; never evidence of noisy encryption or valid sampled keys.
    rows = [
        dict(
            type="meta",
            experiment="A150",
            suite="stock",
            tfhe="1.7.0",
            fresh_keys=1,
            source_sha256=audit.digest(),
            runner_verified_binary_sha256="0" * 64,
            catalog_certification=False,
            client_local_key_sensitive=True,
        ),
        dict(type="key_ready", zero_rows=1515, zero_pool_payload_bytes=9405120),
        dict(
            type="stock_preparation_counts",
            counts=dict(
                packing=0,
                cm_ks=1,
                cm_pbs=0,
                ordinary_ks=0,
                ordinary_pbs=0,
                extraction=0,
            ),
            fresh_cm_big_encryption=1,
            nu_multiplier=3,
            steps=1,
            lanes=4,
        ),
    ]
    for case in replay.STOCK:
        plain = case == "stock_plain"
        negative = case == "stock_forced_unmet"
        event = synthetic_event()
        event.update(
            type="cm_zero_pool_event",
            case=case,
            index=0,
            stage="stock_input",
            policy=replay.policy_for(case),
            before_words_hex=["0" * 16] * 776,
            corrected_words_hex=["0" * 16] * 776,
            selected_zero_words_hex=None,
            selected_index=None,
            zero_additions=0,
            chooser_invocations=int(not plain),
            source_derived_zero_candidates_examined=1515 if negative else 0,
            estimator_satisfied=None if plain else not negative,
            assumed_normalized_input_variance=None
            if plain
            else m.PROFILE["ms_input_variance"] * (2 if negative else 1),
            status="PLAIN_A132"
            if plain
            else (
                "INCONCLUSIVE_ESTIMATOR_BOUND"
                if negative
                else "SATISFYING_ESTIMATOR_ASSUMPTION_ONLY"
            ),
            allowed=not negative,
            pbs_executed=not negative,
            corrected_is_actual_br_input=not negative,
        )
        for lane in event["lanes"]:
            lane.update(
                expected=0,
                before_phase_u64="0",
                corrected_phase_u64="0",
                selected_zero_phase_i64="0",
                corrected_coefficientwise_degree=0,
                corrected_center_displacement=0,
                corrected_inside_center_box=True,
            )
        rows.append(event)
        rows.append(
            dict(
                type="cm_zero_pool_summary",
                case=case,
                event_count=1,
                chooser_invocations=int(not plain),
                zero_additions=0,
                observed_pbs=int(not negative),
                closure_pass=True,
            )
        )
        rows.append(
            dict(
                type="stock_case",
                case=case,
                completed=not negative,
                positive_pass=not negative,
                unmet_negative_detected=negative,
                counts=dict(cm_pbs=int(not negative)),
                outputs=[]
                if negative
                else [dict(lane=i, phase_u64="0", decoded=0) for i in range(4)],
            )
        )
    rows.append(
        dict(
            type="summary",
            suite="stock",
            stock_pair_pass=True,
            forced_unmet_detected=True,
            bounded_diagnostic_gate_pass=True,
            n4_pair_pass=None,
            graph_negatives_pass=None,
            full_c1_requirement_satisfied=False,
            noise_improvement_claim=False,
            formal_failure_claim=False,
            service_claim=False,
            timing_claim=False,
        )
    )
    return rows


class A150Tests(unittest.TestCase):
    def test_pins_graph_transformation_and_unchanged_model(self):
        r = audit.source_check()
        self.assertEqual(r["source_pins"], 42)
        self.assertEqual(
            r["n4_ledger"],
            dict(
                packing=3,
                cm_ks=2,
                cm_pbs=3,
                ordinary_ks=9,
                ordinary_pbs=7,
                extraction=8,
            ),
        )
        self.assertEqual(
            (audit.HERE / "src/model.rs").read_bytes(),
            (audit.BASE / "src/model.rs").read_bytes(),
        )

    def test_lock_dependency_graph_unchanged(self):
        original = (audit.BASE / "Cargo.lock").read_text()
        self.assertEqual(
            (audit.HERE / "Cargo.lock").read_text(),
            original.replace(
                "a132-common-mask-round-gate", "a150-common-mask-zero-pool-gate"
            ),
        )
        self.assertEqual(
            (audit.HERE / "a146_model.py").read_bytes(),
            (audit.HERE.parent / "a146-common-mask-cmnr-audit/model.py").read_bytes(),
        )

    def test_exact_shared_zero_preserves_four_different_lane_errors(self):
        e = synthetic_event()
        self.assertTrue(replay.check_event(e))
        self.assertEqual(
            [int(x["selected_zero_phase_i64"]) for x in e["lanes"]], [1, -2, 3, -4]
        )
        self.assertEqual(
            [x["corrected_coefficientwise_degree"] for x in e["lanes"]],
            [0, 128, 256, 384],
        )

    def test_changed_row_or_phase_cannot_close(self):
        base = synthetic_event()
        for field in [
            "before_words_hex",
            "corrected_words_hex",
            "selected_zero_words_hex",
        ]:
            e = copy.deepcopy(base)
            e[field][773] = f"{(int(e[field][773], 16) + 1) % m.Q:016x}"
            with self.assertRaises(ValueError):
                replay.check_event(e)
        e = copy.deepcopy(base)
        e["lanes"][2]["selected_zero_phase_i64"] = "4"
        with self.assertRaises(ValueError):
            replay.check_event(e)

    def test_wrong_body_and_per_lane_merge_remain_invalid(self):
        ex = m.examples()
        self.assertNotEqual(
            ex["invalid_per_lane_merge"]["native_decoded_messages"], [0, 1, 2, 3]
        )
        self.assertNotEqual(
            ex["invalid_copied_zero_body"]["native_decoded_messages"], [0, 1, 2, 3]
        )

    def test_double_variance_forces_unmet_for_every_mask(self):
        # Exact rational strict lower bound, not a probabilistic claim or 1515-row runtime.
        r = Fraction(str(m.PROFILE["r_sigma_factor"]))
        v = Fraction(str(m.PROFILE["ms_input_variance"]))
        b = Fraction(m.PROFILE["ms_bound_word"], m.Q)
        self.assertGreater(r * r * 2 * v, b * b)
        ct = m.Cm((0,) * m.N, (0,) * 4)
        zero = ct
        choice = m.choose_candidate(ct, [zero], 2 * m.PROFILE["ms_input_variance"])
        self.assertEqual(choice["status"], "BestNotSatisfyingBound")
        self.assertIsNone(choice["candidate"])

    def test_legal_no_add_invocation_is_not_missing_reduction(self):
        ct = m.Cm((0,) * m.N, (0,) * 4)
        choice = m.choose_candidate(ct, [ct])
        self.assertEqual(choice["status"], "SatisfyingBound")
        self.assertIsNone(choice["candidate"])
        e = synthetic_event()
        e["selected_zero_words_hex"] = None
        e["selected_index"] = None
        e["zero_additions"] = 0
        e["corrected_words_hex"] = e["before_words_hex"]
        e["source_derived_zero_candidates_examined"] = 0
        raw = [int(x, 16) for x in e["before_words_hex"]]
        for lane in e["lanes"]:
            degree = (
                m.rounded_degree(raw[772 + lane["lane"]])
                - m.rounded_degree(raw[lane["lane"]])
            ) % 1024
            lane["corrected_coefficientwise_degree"] = degree
            displacement = (degree - lane["expected"] * 128 + 512) % 1024 - 512
            lane["corrected_center_displacement"] = displacement
            lane["corrected_inside_center_box"] = -64 <= displacement < 64
            lane["corrected_phase_u64"] = lane["before_phase_u64"]
            lane["selected_zero_phase_i64"] = "0"
        self.assertTrue(replay.check_event(e))

    def test_status_and_actual_input_label_corruptions(self):
        for key, value in [
            ("allowed", False),
            ("pbs_executed", False),
            ("chooser_invocations", 0),
            ("estimator_satisfied", False),
            ("input_variance_justified_for_actual_stage", True),
            ("source_derived_zero_candidates_examined", 2),
        ]:
            e = synthetic_event()
            e[key] = value
            with self.assertRaises(ValueError):
                replay.check_event(e)

    def test_native_address_support_is_not_estimator_certification(self):
        ex = m.examples()["satisfying_estimator_not_deterministic_correctness"]
        self.assertEqual(ex["choice"]["status"], "SatisfyingBound")
        self.assertEqual(ex["actual_addresses"], [225, 32, 128, 128])
        self.assertEqual(ex["identity_output_messages"], [2, 0, 1, 1])

    def test_n4_witness_and_two_algebraic_graph_negatives(self):
        active = [1] * 4
        bits = [0, 1, 1, 1]
        z = [a * (1 - b) for a, b in zip(active, bits)]
        any_zero = int(any(z))
        out = [int(a + zz - any_zero + 1 == 2) for a, zz in zip(active, z)]
        self.assertEqual(out, [1, 0, 0, 0])
        missing_offset = [int(a + zz - any_zero == 2) for a, zz in zip(active, z)]
        self.assertNotEqual(out, missing_offset)
        # Omitted bit7 rescale uses beta/4, so b=1 rows are 2.25 rather than 3 CM units.
        wrong_z = [
            int(Fraction(2 * a) + Fraction(b, 4) < Fraction(5, 2))
            for a, b in zip(active, bits)
        ]
        self.assertEqual(wrong_z, [1, 1, 1, 1])
        self.assertNotEqual(wrong_z, z)
        # Wrong-lane key control has no deterministic clear probability guarantee; runtime detection required.

    def test_complete_stock_record_binding_and_negative_completion(self):
        rows = synthetic_stock_records()
        report = replay.inspect(rows, "0" * 64)
        self.assertEqual(report["cm_events"], 3)
        self.assertFalse(report["execution_attested"])
        for mutate in [
            lambda r: r.pop(5),
            lambda r: r[0].update(suite="witness"),
            lambda r: r[0].update(source_sha256="0" * 64),
            lambda r: r[-1].update(forced_unmet_detected=False),
            lambda r: r[-2].update(completed=True),
            lambda r: r[5]["outputs"][0].update(phase_u64=str(m.DELTA)),
            lambda r: r[1].update(zero_rows=1514),
        ]:
            altered = copy.deepcopy(rows)
            mutate(altered)
            with self.assertRaises(ValueError):
                replay.inspect(altered, "0" * 64)

    def test_private_initial_open_and_collision(self):
        with tempfile.TemporaryDirectory(dir=audit.HERE) as temp:
            p = Path(temp) / "private.json"
            with private_file(p) as f:
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
                f.write(json.dumps({"synthetic": True}))
            with self.assertRaises(FileExistsError):
                private_file(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
