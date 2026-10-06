"""SYNTHETIC A155 envelopes/probes around unmodified saved A150 legacy outcomes.

No generated A155 row is encrypted or treated as an actual A155 observation.
"""

import copy
from functools import lru_cache
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import common as c
import legacy as l
import validate as v

BINARY, SOURCE, MANIFEST = "a" * 64, "b" * 64, "c" * 64
LEGACY_HASH = "1b6e7ba8430f5d156e98615898f47c5c46bc2de9e218f9360bf896048a6d980a"


@lru_cache(maxsize=1)
def legacy_records():
    path = (
        v.A155.parent / "a150-common-mask-zero-pool-gate/runs/witness-key2/stdout.jsonl"
    )
    c.same(c.sha(path), LEGACY_HASH, "preserved A150 fixture changed")
    return [c.parse(line) for line in path.read_text().splitlines()]


def synthetic(suite="witness", undetected=False, unrelated_output_error=False):
    rows = copy.deepcopy(legacy_records())
    if suite == "stock":
        # Only the stock slice is retained; these are new SYNTHETIC envelope fields.
        rows = rows[:24] + [
            dict(
                type="summary",
                suite="stock",
                fresh_keys=1,
                stock_pair_pass=True,
                forced_unmet_detected=True,
                n4_pair_pass=None,
                graph_negatives_pass=None,
                bounded_diagnostic_gate_pass=True,
                full_c1_requirement_satisfied=False,
                noise_improvement_claim=False,
                formal_failure_claim=False,
                service_claim=False,
                timing_claim=False,
            )
        ]
    rows[0].update(
        experiment="A155",
        suite=suite,
        key_id="SYNTHETIC_KEY",
        pid=12345,
        source_sha256=SOURCE,
        runner_verified_binary_sha256=BINARY,
    )
    rows[1]["key_id"] = "SYNTHETIC_KEY"
    if undetected:
        # An explicit synthetic wrong-map case whose egress equals the baseline.
        for index in range(4):
            old = next(
                r
                for r in rows
                if r.get("type") == "phase"
                and r["case"] == "n4_plain"
                and r["stage"] == f"egress_small/{index}"
            )
            wrong = next(
                r
                for r in rows
                if r.get("type") == "phase"
                and r["case"] == "n4_negative_WrongLaneKsk"
                and r["stage"] == f"egress_small/{index}"
            )
            for key in ("phase_u64", "signed_error_i64", "br_geometry"):
                wrong[key] = copy.deepcopy(old[key])
    legacy = l.check_legacy(rows, suite)
    margin_pass = None
    if suite == "witness":
        probes = []
        mismatch, discrimination = [0, 0], [0, 0]
        all_lut = True
        for arm in ("baseline", "wrong_lane"):
            case = "n4_plain" if arm == "baseline" else "n4_negative_WrongLaneKsk"
            for offset in v.OFFSETS:
                for index in range(4):
                    row = legacy["egress"][case, index]
                    expected = int(index == 0)
                    original_phase = c.word(row["phase_u64"])
                    original_degree = row["br_geometry"]["coefficientwise_degree"]
                    degree_offset = -128 if offset < 0 else 128
                    shifted_degree = (original_degree + degree_offset) % 4096
                    lut = v.identity_lut(shifted_degree)
                    value = lut
                    if (
                        unrelated_output_error
                        and arm == "wrong_lane"
                        and offset < 0
                        and index == 0
                    ):
                        value = (lut + 1) % 32
                    # These exact-center output phases are SYNTHETIC, not FHE results.
                    output_phase = value * c.A44_DELTA % c.Q
                    output_error = c.signed(output_phase - expected * c.A44_DELTA)
                    matches = value == expected and abs(output_error) < c.A44_DELTA // 2
                    matches_lut = value == lut
                    all_lut &= matches_lut
                    if arm == "wrong_lane":
                        slot = int(offset > 0)
                        mismatch[slot] += int(not matches)
                        discrimination[slot] += int(
                            lut != expected and not matches and matches_lut
                        )
                    probes.append(
                        dict(
                            type="egress_margin_probe",
                            arm=arm,
                            offset_i64=str(offset),
                            index=index,
                            source_case=case,
                            source_stage=f"egress_small/{index}",
                            expected=expected,
                            input_delta_u64=str(c.CM_DELTA),
                            output_delta_u64=str(c.A44_DELTA),
                            original_phase_u64=str(original_phase),
                            shifted_phase_u64=str((original_phase + offset) % c.Q),
                            output_phase_u64=str(output_phase),
                            output_signed_error_i64=str(output_error),
                            output_decoded=value,
                            original_coefficientwise_degree=original_degree,
                            shifted_coefficientwise_degree=shifted_degree,
                            degree_offset=degree_offset,
                            address_closure=True,
                            phase_closure=True,
                            mask_unchanged=True,
                            input_lut_value=lut,
                            input_expected_cell=lut == expected,
                            output_matches_expected=matches,
                            output_matches_lut=matches_lut,
                            counts=dict(v.PROBE_COUNTS),
                            client_local_key_sensitive=True,
                            clear_address_prediction_is_fhe_result=False,
                        )
                    )
        margin_pass = sum(discrimination) > 0 and all_lut
        summary = dict(
            type="egress_margin_summary",
            probe_count=16,
            baseline_probe_count=8,
            wrong_lane_probe_count=8,
            offsets_i64=[str(x) for x in v.OFFSETS],
            baseline_outputs_pass=True,
            baseline_support_pass=True,
            binding_pass=True,
            counts=dict(v.ALL_COUNTS),
            count_pass=True,
            wrong_output_mismatches_by_offset=mismatch,
            wrong_discriminators_by_offset=discrimination,
            all_outputs_match_lut=all_lut,
            finite_wrong_output_coverage=sum(discrimination) > 0,
            coverage_rule=v.COVERAGE,
            passed=margin_pass,
            original_a150_control_reinterpreted=False,
            no_retry_until_pass=True,
            scope="one deterministic N4 bit7 witness, one fresh key; no universal detection or probability claim",
        )
        rows[-1:-1] = probes + [summary]
    final = rows[-1]
    final.update(
        bounded_diagnostic_gate_scope="original A150 criterion retained without reinterpretation",
        original_a150_bounded_diagnostic_gate_pass=legacy["original_pass"],
        original_a150_graph_negatives_pass=all(legacy["original_detections"])
        if suite == "witness"
        else None,
        original_non_wrong_graph_negatives_pass=True if suite == "witness" else None,
        egress_margin_controls_pass=margin_pass,
        a155_margin_control_gate_pass=margin_pass,
        exit_status_criterion="A155 finite margin gate for witness; original stock gate for stock-only",
        historical_a150_witness_key2_gate="FAILED and frozen; no retrospective change",
    )
    metadata = dict(
        prepared=dict(
            status="PREPARED",
            utc="2026-09-05T00:00:00+00:00",
            command=[
                str(v.A155 / v.BINARY_REL),
                "--run-authorized",
                "--suite",
                suite,
                "--key-id",
                "SYNTHETIC_KEY",
            ],
            suite=suite,
            key_id="SYNTHETIC_KEY",
            binary_sha256=BINARY,
            source_sha256=SOURCE,
            manifest_sha256=MANIFEST,
            workload_reservation=False,
            root_clearance_required=True,
            client_local_key_sensitive=True,
        ),
        started=dict(
            status="STARTED", child_pid=12345, utc="2026-09-05T00:00:01+00:00"
        ),
        exit=dict(
            status="EXITED",
            child_pid=12345,
            returncode=0 if suite == "stock" or margin_pass else 2,
            utc="2026-09-05T00:00:02+00:00",
            correctness_independently_validated=False,
        ),
    )
    kwargs = dict(
        suite=suite,
        key_id="SYNTHETIC_KEY",
        source_sha=SOURCE,
        manifest_sha=MANIFEST,
        binary_sha=BINARY,
    )
    return rows, metadata, kwargs


class ValidatorTests(unittest.TestCase):
    def rejected(self, mutate):
        rows, metadata, kwargs = synthetic()
        mutate(rows, metadata)
        with self.assertRaises(c.Invalid):
            v.inspect(rows, metadata, **kwargs)

    def test_actual_a150_legacy_false_preserved(self):
        result = l.check_legacy(copy.deepcopy(legacy_records()), "witness")
        self.assertFalse(result["original_pass"])
        self.assertEqual(result["original_detections"], [True, True, False])
        self.assertEqual(result["cm_events"], 18)

    def test_synthetic_margin_pass_with_original_failure(self):
        rows, metadata, kwargs = synthetic()
        result = v.inspect(rows, metadata, **kwargs)
        self.assertEqual(result["records"], 381)
        self.assertTrue(result["a155_margin_control_gate_pass"])
        self.assertFalse(result["original_a150_criterion_on_this_new_run"])
        self.assertFalse(result["original_wrong_lane_detected"])
        self.assertEqual(result["margin"]["wrong_lut_crossings_by_offset"], [1, 2])
        self.assertFalse(result["execution_attestation"])

    def test_synthetic_stock_has_no_margin_claim(self):
        rows, metadata, kwargs = synthetic(suite="stock")
        result = v.inspect(rows, metadata, **kwargs)
        self.assertEqual(result["records"], 25)
        self.assertIsNone(result["a155_margin_control_gate_pass"])
        self.assertIsNone(result["margin"])

    def test_undetected_fixed_probe_gate_stays_failed(self):
        rows, metadata, kwargs = synthetic(undetected=True)
        result = v.inspect(rows, metadata, **kwargs)
        self.assertFalse(result["selected_runtime_gate_pass"])
        self.assertEqual(result["original_returncode"], 2)
        self.assertEqual(result["margin"]["wrong_discriminators_by_offset"], [0, 0])

    def test_wrong_output_without_consumed_lut_agreement_cannot_pass(self):
        rows, metadata, kwargs = synthetic(unrelated_output_error=True)
        result = v.inspect(rows, metadata, **kwargs)
        self.assertFalse(result["selected_runtime_gate_pass"])
        self.assertEqual(result["original_returncode"], 2)
        self.assertGreater(sum(result["margin"]["wrong_discriminators_by_offset"]), 0)

    def test_missing_duplicate_or_wrongly_ordered_probe_rejected(self):
        self.rejected(lambda r, _: r.pop(-18))
        self.rejected(lambda r, _: r.insert(-17, copy.deepcopy(r[-18])))

        def swap(r, _):
            r[-18], r[-17] = r[-17], r[-18]

        self.rejected(swap)

    def test_probe_binding_phase_degree_and_expected_mutations_rejected(self):
        for key, value in [
            ("expected", 0),
            ("source_case", "n4_shared_zero"),
            ("offset_i64", str(1 << 59)),
            ("phase_closure", False),
            ("mask_unchanged", False),
            ("shifted_phase_u64", "0"),
            ("shifted_coefficientwise_degree", 0),
            ("output_signed_error_i64", "1"),
            ("input_lut_value", 29),
        ]:
            self.rejected(lambda r, _, k=key, vv=value: r[-18].update({k: vv}))

    def test_counter_and_discriminator_totals_rejected(self):
        self.rejected(lambda r, _: r[-18]["counts"].update(ordinary_ks=1))
        self.rejected(lambda r, _: r[-2]["counts"].update(ordinary_pbs=15))
        self.rejected(lambda r, _: r[-2].update(wrong_discriminators_by_offset=[0, 0]))
        self.rejected(lambda r, _: r[-2].update(all_outputs_match_lut=False))

    def test_original_control_flags_never_patched(self):
        self.rejected(
            lambda r, _: next(
                x
                for x in r
                if x.get("type") == "graph_negative" and x["mutation"] == "WrongLaneKsk"
            ).update(detected=True)
        )
        self.rejected(lambda r, _: r[-1].update(bounded_diagnostic_gate_pass=True))
        self.rejected(
            lambda r, _: r[-1].update(original_a150_bounded_diagnostic_gate_pass=True)
        )
        self.rejected(
            lambda r, _: r[-1].update(historical_a150_witness_key2_gate="PASS")
        )

    def test_missing_legacy_phase_or_changed_expected_rejected(self):
        self.rejected(lambda r, _: r.pop(24))
        self.rejected(
            lambda r, _: next(x for x in r if x.get("type") == "phase").update(
                expected=0
            )
        )

    def test_source_binary_pid_exit_summary_bindings(self):
        self.rejected(lambda r, _: r[0].update(source_sha256="d" * 64))
        self.rejected(lambda _, m: m["prepared"].update(binary_sha256="d" * 64))
        self.rejected(lambda _, m: m["started"].update(child_pid=999))
        self.rejected(lambda _, m: m["exit"].update(returncode=2))
        self.rejected(lambda r, _: r.pop())

    def test_strict_recursive_types_and_json(self):
        self.rejected(lambda r, _: r[-2]["counts"].update(ordinary_ks=False))
        self.rejected(lambda r, _: r[-18].update(index=False))
        self.rejected(
            lambda r, _: r[1]["original_added_payload_bytes"].__setitem__(0, False)
        )
        with self.assertRaises(c.Invalid):
            c.parse('{"passed":false,"passed":true}')
        with self.assertRaises(c.Invalid):
            c.parse('{"phase":NaN}')

    def test_exact_raw_identity_anchor_values(self):
        self.assertEqual(
            [
                v.identity_lut(x)
                for x in [0, 255, 256, 767, 768, 1791, 1792, 2304, 3741, 3840]
            ],
            [0, 0, 1, 1, 2, 3, 0, 31, 29, 0],
        )
        self.assertEqual(len(l.phase_oracle()), 62)
        self.assertEqual(
            l.N4_COUNTS,
            dict(
                packing=3,
                cm_ks=2,
                cm_pbs=3,
                ordinary_ks=9,
                ordinary_pbs=7,
                extraction=8,
            ),
        )

    def test_frozen_files_and_synthetic_private_filesystem_replay(self):
        original = v.A155
        pins = v.verify_frozen()
        legacy_records()  # Pin/read the real A150 base before patching the synthetic directory.
        with tempfile.TemporaryDirectory(
            prefix="synthetic-files-", dir=c.HERE
        ) as directory:
            root = Path(directory)
            manifest = c.read_json(original / "MANIFEST.json")
            for relative in ["MANIFEST.json", *manifest["files"]]:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((original / relative).read_bytes())
            binary = root / v.BINARY_REL
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"SYNTHETIC NONEXECUTABLE A155 BINARY FIXTURE")
            binary_hash = c.sha(binary)
            run = root / "runs/synthetic"
            run.mkdir(parents=True, mode=0o700)
            with (
                mock.patch.object(v, "A155", root),
                mock.patch(__name__ + ".SOURCE", pins["source_sha256"]),
                mock.patch(__name__ + ".MANIFEST", pins["manifest_sha256"]),
                mock.patch(__name__ + ".BINARY", binary_hash),
            ):
                rows, metadata, kwargs = synthetic()
                for name, record in metadata.items():
                    c.write_private(run / (name + ".json"), record)
                content = "".join(json.dumps(row) + "\n" for row in rows)
                (run / "stdout.jsonl").write_text(content)
                (run / "stderr.log").write_text("")
                result = v.validate_run(
                    run, suite="witness", key_id="SYNTHETIC_KEY", binary_sha=binary_hash
                )
                self.assertTrue(result["a155_margin_control_gate_pass"])
                self.assertFalse(result["original_a150_criterion_on_this_new_run"])
                self.assertFalse(result["execution_attestation"])
                self.assertEqual((run / "exit.json").stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    c.write_private(run / "exit.json", {})
                (run / "stdout.jsonl").write_text(content[:-1])
                with self.assertRaises(c.Invalid):
                    v.validate_run(
                        run,
                        suite="witness",
                        key_id="SYNTHETIC_KEY",
                        binary_sha=binary_hash,
                    )
                (run / "stdout.jsonl").write_text(content)
                binary.write_bytes(b"CHANGED SYNTHETIC BINARY")
                with self.assertRaises(c.Invalid):
                    v.validate_run(
                        run,
                        suite="witness",
                        key_id="SYNTHETIC_KEY",
                        binary_sha=binary_hash,
                    )
                binary.write_bytes(b"SYNTHETIC NONEXECUTABLE A155 BINARY FIXTURE")
                (run / "interrupted.json").write_text("{}")
                with self.assertRaises(c.Invalid):
                    v.validate_run(
                        run,
                        suite="witness",
                        key_id="SYNTHETIC_KEY",
                        binary_sha=binary_hash,
                    )
                (root / "src/margin_controls.rs").write_text("MUTATED SOURCE")
                with self.assertRaises(c.Invalid):
                    v.verify_frozen()


if __name__ == "__main__":
    unittest.main(verbosity=2)
