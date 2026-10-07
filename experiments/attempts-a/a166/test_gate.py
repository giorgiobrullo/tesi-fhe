"""Synthetic P1 byte/phase/negacyclic checks only; no actual key or producer."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit
from audit import HERE, a158
import replay as p1
from p0_replay import verify_records as verify_p0
from synthetic_p0 import synthetic_chain
import run_gate


def synthetic_p1(chain, error=0):
    p0, _, p0_key, _, _, complete = chain
    address = p0["client"]["direct_address"]
    bsk_hash = hashlib.sha256(b"SYNTHETIC_NO_BSK").hexdigest()
    binding = dict(
        schema="a166.p1-key-binding.v1",
        p0_bindings=p0_key,
        fourier_bsk_re_im_f64le_sha256=bsk_hash,
        p1_keyset_id=hashlib.sha256(
            b"A166-KEYSET-V1\0"
            + bytes.fromhex(p0_key["keyset_id"])
            + bytes.fromhex(bsk_hash)
        ).hexdigest(),
        secret_key_membership_attested=False,
    )
    ideal = p1.raw_lut_value(address)
    phase = (ideal + error) % p1.Q
    rotated = [17 * i + 1 for i in range(p1.N)] + [phase] + [0] * (p1.N - 1)
    raw = p1.degree_zero_sample(rotated)
    output = raw[:-1] + [(raw[-1] + p1.ALPHA) % p1.Q]
    switched = dict(
        log_modulus=12,
        body_degree=p0["actual_body_degree"],
        mask_degrees=p0["actual_mask_degrees"],
    )
    decoded = ((output[-1] + p1.ALPHA) % p1.Q) >> 60
    raw_error = p1.signed(phase - ideal)
    predicates = dict(
        p0_prefix_pass=address >= 2048,
        retained_ms_input_unchanged=True,
        degree0_extraction_matches_rotated=True,
        output_only_public_add=True,
        raw_error_inside_actual_lut_decode_cell=-p1.ALPHA <= raw_error < p1.ALPHA,
        raw_to_output_phase_addition=True,
        output_decodes_fixture_bit=decoded == 1,
    )
    body = [p1.Q - p1.ALPHA] * p1.N
    record = dict(
        schema="a166.first_low_p1_trace.v1",
        kind="client_observed",
        bindings=binding,
        p0_snapshot=dict(
            schema="a166.frozen-p0-snapshot.v1", trace=p0, completed=complete
        ),
        counts=dict(ordinary_ks=1, configured_ms=1, blind_rotations=1),
        counter_scope="producer post-call increments; not library-internal instrumentation",
        consumed_input_origin="same retained Standard lazy-MS object; no second KS/MS",
        switched_before=switched,
        switched_after=deepcopy(switched),
        accumulator_body_u64le_sha256=a158.digest_words(body),
        input_accumulator=a158.ct_record([0] * p1.N + body),
        rotated_accumulator=a158.ct_record(rotated),
        raw_sample=a158.ct_record(raw),
        output=a158.ct_record(output),
        extraction_degree=0,
        public_output_add_words=p1.ALPHA,
        expected_fixture_bit=1,
        output_delta_words=p1.DELTA,
        actual_address=address,
        ideal_raw_at_actual_address_words=ideal,
        ideal_output_at_actual_address_words=(ideal + p1.ALPHA) % p1.Q,
        client=dict(
            raw_mask_dot_words=0,
            output_mask_dot_words=0,
            raw_phase_words=phase,
            output_phase_words=output[-1],
            raw_error_centered_lift=raw_error,
            output_error_vs_fixture_centered_lift=p1.signed(output[-1] - p1.DELTA),
            decoded_delta60=decoded,
        ),
        predicates=predicates,
        p1_selected_consumer_gate_pass=all(predicates.values()),
        client_key_membership_attested=False,
        full_n4_evaluation=False,
        actual_sampler_p_fail=None,
        fixed_key_p_fail=None,
        pipeline_p_fail=None,
    )
    return record, p0, complete, binding


class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = synthetic_chain()
        cls.good = synthetic_p1(cls.chain)

    def test_frozen_origin_and_single_call_source(self):
        pins = audit.verify_origins()
        self.assertGreater(pins["upstream_pins"], 20)
        self.assertEqual(pins["origin_pins"], 20)

    def test_independent_nested_p0_and_p1(self):
        p0 = verify_p0(*self.chain)
        p = p1.verify_p1(*self.good)
        self.assertTrue(p0["selected_prefix_gate_pass"])
        self.assertTrue(p["p1_selected_consumer_gate_pass"])
        self.assertEqual(len(p["predicates"]), 7)
        self.assertIsNone(p["actual_sampler_p_fail"])

    def test_all_4096_raw_lut_cells_with_rotation_sign(self):
        poly = [-p1.ALPHA] * p1.N
        wrong_direction = 0
        for degree in range(2 * p1.N):
            quotient, index = divmod(degree, p1.N)
            exact = ((-1) ** quotient * poly[index]) % p1.Q
            self.assertEqual(p1.raw_lut_value(degree), exact)
            opposite = (-degree) % (2 * p1.N)
            wrong_direction += p1.raw_lut_value(opposite) != exact
        self.assertEqual(wrong_direction, 4094)

    def test_asymmetric_decode_cell_boundaries(self):
        for error, expected in (
            (-p1.ALPHA - 1, False),
            (-p1.ALPHA, True),
            (p1.ALPHA - 1, True),
            (p1.ALPHA, False),
        ):
            result = p1.verify_p1(*synthetic_p1(self.chain, error))
            self.assertEqual(result["p1_selected_consumer_gate_pass"], expected)

    def test_rehashed_rotated_raw_and_output_mutations(self):
        for field, coordinate in (
            ("rotated_accumulator", 17),
            ("raw_sample", 17),
            ("raw_sample", 2048),
            ("output", 17),
            ("output", 2048),
        ):
            args = deepcopy(self.good)
            count = 4096 if field == "rotated_accumulator" else 2049
            words = p1.native(args[0][field], count)
            words[coordinate] ^= 1
            args[0][field] = a158.ct_record(words)
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)

    def test_lut_scale_sign_offset_and_degree_mutations(self):
        for key, value in (
            ("extraction_degree", 1),
            ("public_output_add_words", 1 << 58),
            ("output_delta_words", 1 << 59),
            ("ideal_raw_at_actual_address_words", p1.Q - p1.ALPHA),
        ):
            args = deepcopy(self.good)
            args[0][key] = value
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)
        args = deepcopy(self.good)
        args[0]["input_accumulator"] = a158.ct_record([0] * 2048 + [p1.ALPHA] * 2048)
        args[0]["accumulator_body_u64le_sha256"] = a158.digest_words([p1.ALPHA] * 2048)
        with self.assertRaises(AssertionError):
            p1.verify_p1(*args)

    def test_actual_ms_and_p0_snapshot_mutations(self):
        for field in ("switched_before", "switched_after"):
            args = deepcopy(self.good)
            args[0][field]["mask_degrees"][0] += 1
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)
        args = deepcopy(self.good)
        args[0]["p0_snapshot"]["trace"]["counts"]["blind_rotations"] = 1
        # Deepcopy retains aliases: explicitly detach the mutation from expected P0.
        with self.assertRaises(AssertionError):
            p1.verify_p1(args[0], self.good[1], self.good[2], self.good[3])

    def test_phase_error_predicate_and_type_mutations(self):
        for key in self.good[0]["client"]:
            args = deepcopy(self.good)
            args[0]["client"][key] += 1
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)
        for key in self.good[0]["predicates"]:
            args = deepcopy(self.good)
            args[0]["predicates"][key] = False
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)
        args = deepcopy(self.good)
        args[0]["counts"]["ordinary_ks"] = True
        with self.assertRaises(AssertionError):
            p1.verify_p1(*args)
        args = deepcopy(self.good)
        args[0]["expected_fixture_bit"] = True
        with self.assertRaises(AssertionError):
            p1.verify_p1(*args)

    def test_key_binding_and_tail_overclaim_mutations(self):
        for key, value in (
            ("p1_keyset_id", "a" * 64),
            ("secret_key_membership_attested", True),
        ):
            args = deepcopy(self.good)
            args[0]["bindings"][key] = value
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)
        for field in ("actual_sampler_p_fail", "fixed_key_p_fail", "pipeline_p_fail"):
            args = deepcopy(self.good)
            args[0][field] = "1/100"
            with self.assertRaises(AssertionError):
                p1.verify_p1(*args)

    def test_noargs_and_missing_ack_never_launch(self):
        with (
            patch("run_gate.subprocess.Popen", side_effect=AssertionError("no child")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_gate.main([]), 0)
            with (
                patch.dict("os.environ", {}, clear=True),
                self.assertRaises(SystemExit),
                patch("sys.stderr", io.StringIO()),
            ):
                run_gate.main(
                    [
                        "--run-authorized",
                        "--run-id",
                        "synthetic",
                        "--binary-sha256",
                        "a" * 64,
                    ]
                )

    def test_private_exclusive_duplicate_and_float_rejection(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "record.json"
            run_gate.write_new(path, {"a": 1})
            self.assertEqual(p1.read(path), {"a": 1})
            with self.assertRaises(FileExistsError):
                run_gate.write_new(path, {})
            for bad in ('{"a":1,"a":1}', '{"a":0.0}', '{"a":NaN}'):
                path.write_text(bad)
                with self.assertRaises(AssertionError):
                    p1.read(path)
            path.chmod(0o644)
            with self.assertRaises(AssertionError):
                p1.read(path)
            alias = path.parent / "alias"
            alias.symlink_to(path)
            with self.assertRaises(AssertionError):
                p1.read(alias)

    def test_p0_aggregate_failure_is_still_rejected(self):
        chain = deepcopy(self.chain)
        chain[1]["row_noise_signed_sum_direct_lift"] += 1
        with self.assertRaises(AssertionError):
            verify_p0(*chain)

    def test_completion_and_ledger_mutations(self):
        record = dict(
            status="P1_SINGLE_RETAINED_MS_CONSUMER_PASS",
            ordinary_ks=1,
            configured_ms=1,
            blind_rotations=1,
            p0_prefix_pass=True,
            p1_selected_consumer_gate_pass=True,
            actual_sampler_p_fail=None,
            fixed_key_p_fail=None,
            pipeline_p_fail=None,
            independent_replay_pending=True,
        )
        p1.verify_completion(record)
        for key, value in (
            ("blind_rotations", 0),
            ("ordinary_ks", True),
            ("p1_selected_consumer_gate_pass", False),
            ("status", "P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS"),
        ):
            bad = deepcopy(record)
            bad[key] = value
            with self.assertRaises(AssertionError):
                p1.verify_completion(bad)
        bad = deepcopy(record)
        bad.pop("pipeline_p_fail")
        with self.assertRaises(AssertionError):
            p1.verify_completion(bad)

    def test_launch_exit_pid_and_time_envelope_mutations(self):
        run = HERE / "runs" / "synthetic-envelope"
        binding = dict(run_id=run.name, source_sha256="1" * 64, binary_sha256="2" * 64)
        records = {
            "prepared.json": dict(
                **binding,
                status="PREPARED",
                timed_benchmark=False,
                no_automatic_retries=True,
                workload_check_is_external_root_obligation=True,
                prepared_at_utc="2026-09-05T00:00:00+00:00",
                command=[
                    str(
                        HERE / "candidate/target-a166-only/release/a166_first_ks_prefix"
                    ),
                    "--run-authorized",
                    str(run),
                    run.name,
                ],
            ),
            "started.json": dict(pid=1),
            "child.json": dict(
                **binding, child_pid=1, started_at_utc="2026-09-05T00:00:01+00:00"
            ),
            "exit.json": dict(
                **binding,
                child_pid=1,
                exit_code=0,
                status="EXITED",
                source_unchanged=True,
                binary_unchanged=True,
                exited_at_utc="2026-09-05T00:00:02+00:00",
            ),
        }
        p1.verify_envelope(run, "2" * 64, "1" * 64, records)
        for name, key, value in (
            ("child.json", "child_pid", 2),
            ("exit.json", "exit_code", 1),
            ("exit.json", "source_sha256", "3" * 64),
            ("exit.json", "exited_at_utc", "2026-09-04T00:00:00+00:00"),
        ):
            bad = deepcopy(records)
            bad[name][key] = value
            with self.assertRaises(AssertionError):
                p1.verify_envelope(run, "2" * 64, "1" * 64, bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
