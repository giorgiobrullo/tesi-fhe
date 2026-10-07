from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import a90_attestation_gate as gate  # noqa: E402


def fake_sha(character: str) -> str:
    return character * 64


def make_run(*, implementation: str = "a66") -> dict:
    return {
        "schema": gate.RUN_SCHEMA,
        "run_id": "a90-test-run",
        "implementation": implementation,
        "build_kind": "audit-instrumented-not-for-latency",
        "glwe_hashing_enabled": True,
        "latency_claim_allowed": False,
        "binary_sha256": fake_sha("1"),
        "source_set_sha256": fake_sha("2"),
        "coverage_policy_sha256": gate.EXPECTED_COVERAGE_POLICY_SHA256,
        "a79_trace_schema": gate.A79_TRACE_SCHEMA,
        "a79_trace_sha256": fake_sha("3"),
        "a79_manifest_schema": gate.A79_MANIFEST_SCHEMA,
        "a79_manifest_sha256": fake_sha("4"),
        "a84_manifest_schema": gate.A84_MANIFEST_SCHEMA,
        "a84_manifest_sha256": gate.A84_CANONICAL_MANIFEST_SHA256,
        "a84_bundle_sha256": gate.A84_BUNDLE_SHA256,
        "parameter_fingerprint": gate.A44_PARAMETER_FINGERPRINT,
        "gallery_size": 127,
        "keyset_id": "test-keyset-fingerprint",
        "expected_a84_scan_br_events": 136,
        "claim_boundary": {
            "diagnostic_local_provenance_only": True,
            "adversarial_remote_attestation": False,
            "a84_embedded_projection_is_raw_pbs_compatible": False,
            "runtime_activation_ready": False,
            "runtime_plaintext_membership_attested": False,
            "a79_value_id_to_runtime_lwe_digest_attested": False,
            "post_extraction_public_offset_execution_attested": False,
            "canonical_a53_invocation_topology_attested": False,
            "full_3390_br_runtime_coverage_attested": False,
            "latency_claim_allowed": False,
        },
    }


def make_linked_events(
    manifest: dict,
    run: dict,
    accumulator_id: str,
    *,
    sequence: int = 0,
    suffix: str = "0",
) -> tuple[dict, dict, dict, dict]:
    record = manifest["accumulators"][accumulator_id]
    run_binding_sha256 = gate.canonical_json_sha256(run)
    expected_plan = gate.expected_sample_plan(record)
    output_ids = [f"a79-output-{suffix}-{index}" for index in range(len(expected_plan))]
    a79_event = {
        "seq": 100 + sequence,
        "op": "pbs",
        "stage": "scan_output",
        "input": f"a79-input-{suffix}",
        "blind_rotation_id": f"a79-br-{suffix}",
        "accumulator_id": accumulator_id,
        "pbs_mode": "raw_br_small_input",
        "strict_margin_radius": record["a79_contract"]["strict_margin_radius"],
        "strict_margin_unit": record["a79_contract"]["strict_margin_unit"],
        "input_max_degree": record["a79_contract"]["input_max_degree"],
        "outputs": [
            {
                "id": output_id,
                "encoding": sample["encoding"],
                "reachable_overapprox": plan["raw_reachable_overapprox"],
                "sample_degree": plan["sample_degree"],
                "shortint_degree": sample["shortint_degree"],
            }
            for output_id, sample, plan in zip(
                output_ids,
                record["a79_contract"]["samples"],
                expected_plan,
                strict=True,
            )
        ],
    }
    dual = len(expected_plan) == 2
    pre_event = {
        "schema": gate.PRE_EVENT_SCHEMA,
        "seq": sequence,
        "op": "raw_br_pre",
        "run_id": run["run_id"],
        "run_binding_sha256": run_binding_sha256,
        "event_id": f"a90-event-{suffix}",
        "binary_sha256": run["binary_sha256"],
        "source_set_sha256": run["source_set_sha256"],
        "coverage_policy_sha256": run["coverage_policy_sha256"],
        "source_callsite_id": gate.A84_BOUND_CALLSITES[run["implementation"]][
            "dual" if dual else "single"
        ],
        "primitive": (
            "blind_rotate_assign"
            if dual
            else "programmable_bootstrap_lwe_ciphertext"
        ),
        "a79_trace_sha256": run["a79_trace_sha256"],
        "a79_manifest_sha256": run["a79_manifest_sha256"],
        "a79_blind_rotation_id": a79_event["blind_rotation_id"],
        "a79_input_value_id": a79_event["input"],
        "a84_manifest_sha256": run["a84_manifest_sha256"],
        "a84_bundle_sha256": run["a84_bundle_sha256"],
        "accumulator_id": accumulator_id,
        "contract_id": record["contract_id"],
        "pre_rotation_glwe": {
            "codec": gate.FULL_GLWE_CODEC,
            "glwe_size": 2,
            "polynomial_size": 2048,
            "coefficient_count": 4096,
            "sha256": record["expected_pre_rotation_glwe"]["full_glwe_sha256"],
        },
        "input_lwe": {
            "codec": gate.INPUT_LWE_CODEC,
            "lwe_size": 860,
            "coefficient_count": 860,
            "sha256": fake_sha("5"),
        },
        "input_contract": gate._expected_input_contract(record, run["keyset_id"]),
        "sample_plan": [
            {
                **sample,
                "a79_raw_output_value_id": output_id,
            }
            for sample, output_id in zip(expected_plan, output_ids, strict=True)
        ],
        "claim": gate.PRE_CLAIM,
    }
    commit_event = {
        "schema": gate.COMMIT_EVENT_SCHEMA,
        "seq": sequence + 1,
        "op": "raw_br_commit",
        "run_id": run["run_id"],
        "run_binding_sha256": run_binding_sha256,
        "event_id": pre_event["event_id"],
        "binary_sha256": run["binary_sha256"],
        "source_set_sha256": run["source_set_sha256"],
        "a79_blind_rotation_id": pre_event["a79_blind_rotation_id"],
        "pre_event_sha256": gate.canonical_json_sha256(pre_event),
        "output_value_ids": output_ids,
        "status": "completed",
    }
    a79_input_snapshot = {
        "trace_sha256": run["a79_trace_sha256"],
        "manifest_sha256": run["a79_manifest_sha256"],
        "value_id": pre_event["a79_input_value_id"],
        "encoding": pre_event["input_contract"]["encoding"],
        "crypto_domain": pre_event["input_contract"]["crypto_domain"],
        "wire_kind": pre_event["input_contract"]["wire_kind"],
        "shortint_degree": pre_event["input_contract"]["shortint_degree"],
        "reachable_overapprox": pre_event["input_contract"][
            "reachable_overapprox"
        ],
    }
    return pre_event, commit_event, a79_event, a79_input_snapshot


class A90StaticArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.a84_result = gate.verify_frozen_a84()

    def test_static_audit_and_source_inventory_are_frozen(self):
        result = gate.static_audit()
        self.assertEqual(
            result["status"], "PASS_STATIC_DESIGN_RUNTIME_ACTIVATION_BLOCKED"
        )
        self.assertEqual(result["frozen_inputs"], 21)
        self.assertEqual(result["baseline_inventory"]["primitive_call"], 16)
        self.assertEqual(result["baseline_inventory"]["a53_wrapper_definition"], 8)
        self.assertEqual(result["baseline_inventory"]["a53_wrapper_call"], 8)
        self.assertEqual(
            result["baseline_inventory"]["source_set_sha256"],
            gate.EXPECTED_SOURCE_SET_SHA256,
        )
        self.assertEqual(
            result["baseline_inventory"]["coverage_policy_sha256"],
            gate.EXPECTED_COVERAGE_POLICY_SHA256,
        )
        self.assertFalse(result["runtime_events_observed"])
        self.assertFalse(result["adversarial_remote_attestation"])
        self.assertFalse(result["runtime_activation_ready"])
        self.assertEqual(
            result["a84_raw_projection_audit"]["mismatched_samples"], 55
        )

    def test_real_frozen_a84_and_a79_v3_path_is_executed(self):
        self.assertEqual(
            self.a84_result["status"],
            "PASS_SOURCE_BOUND_BODIES_AND_DECLARED_TRUTH_TABLES",
        )
        self.assertEqual(self.a84_result["actual_a79_contracts_parsed"], 35)
        self.assertEqual(self.a84_result["actual_a79_samples_parsed"], 67)
        self.assertEqual(
            self.a84_result["actual_a79_parser_sha256"], gate.A79_REPLAY_SHA256
        )

    def test_scanner_ignores_comments_and_strings(self):
        source = r'''
// blind_rotate_assign(&a, &mut b, key);
const TEXT: &str = "programmable_bootstrap_lwe_ciphertext(x)";
const RAW: &str = r#"blind_rotate_assign(x)"#;
fn harmless() {}
'''
        self.assertEqual(gate.scan_rust_text(source, "fixture.rs"), ())

    def test_scanner_finds_current_and_memoptimized_primitive_calls(self):
        source = """
fn bridge() {
    tfhe::x::blind_rotate_assign(a, b, c);
    programmable_bootstrap_lwe_ciphertext_mem_optimized(a, b, c, d, e, f);
}
"""
        findings = gate.scan_rust_text(source, "fixture.rs")
        self.assertEqual(
            [(finding.line, finding.name) for finding in findings],
            [
                (3, "blind_rotate_assign"),
                (4, "programmable_bootstrap_lwe_ciphertext_mem_optimized"),
            ],
        )

    def test_future_policy_accepts_only_hash_pinned_gateway(self):
        gateway_source = """
fn audited_gateway() {
    blind_rotate_assign(input, accumulator, key);
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            gateway_path = root / "src/a90_attested_br.rs"
            gateway_path.write_text(gateway_source, encoding="utf-8")
            (root / "src/lib.rs").write_text("mod a90_attested_br;\n", encoding="utf-8")
            digest = hashlib.sha256(gateway_source.encode()).hexdigest()
            result = gate.enforce_future_source_policy(
                root,
                expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                gateway_relative_path="src/a90_attested_br.rs",
                expected_gateway_sha256=digest,
            )
        self.assertEqual(result["status"], "PASS_STATIC_SOURCE_CLOSURE_NO_RAW_BYPASS")
        self.assertFalse(result["runtime_attested"])

    def test_future_policy_rejects_direct_and_alias_bypasses(self):
        gateway_source = "fn gateway(){ blind_rotate_assign(a,b,c); }\n"
        bypasses = (
            "fn bypass(){ blind_rotate_assign(a,b,c); }\n",
            "use tfhe::x::blind_rotate_assign as hidden;\nfn bypass(){ hidden(a,b,c); }\n",
            "fn bypass(){ blind_rotate_assign_mem_optimized(a,b,c,d,e); }\n",
            "fn bypass(){ fourier_bsk.as_view().bootstrap(a,b,c,d,e); }\n",
            "fn bypass(){ FourierLweBootstrapKey::bootstrap(a,b,c,d,e); }\n",
            "fn bypass(){ programmable_bootstrap_ntt64_lwe_ciphertext(a,b,c,d); }\n",
            "fn bypass(){ batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(a,b,c,d); }\n",
            "fn bypass(){ std_multi_bit_programmable_bootstrap_lwe_ciphertext(a,b,c,d); }\n",
            "fn bypass(){ cuda_programmable_bootstrap_lwe_ciphertext(a,b,c,d); }\n",
        )
        for bypass in bypasses:
            with self.subTest(bypass=bypass):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "src").mkdir()
                    gateway_path = root / "src/a90_attested_br.rs"
                    gateway_path.write_text(gateway_source, encoding="utf-8")
                    (root / "src/lib.rs").write_text(bypass, encoding="utf-8")
                    digest = hashlib.sha256(gateway_source.encode()).hexdigest()
                    with self.assertRaisesRegex(gate.A90Error, "outside the sole gateway"):
                        gate.enforce_future_source_policy(
                            root,
                            expected_source_files={
                                "src/lib.rs",
                                "src/a90_attested_br.rs",
                            },
                            gateway_relative_path="src/a90_attested_br.rs",
                            expected_gateway_sha256=digest,
                        )

    def test_future_policy_rejects_include_extra_file_and_gateway_drift(self):
        gateway_source = "fn gateway(){ blind_rotate_assign(a,b,c); }\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            gateway_path = root / "src/a90_attested_br.rs"
            gateway_path.write_text(gateway_source, encoding="utf-8")
            (root / "src/lib.rs").write_text('include!("hidden.rs");\n', encoding="utf-8")
            digest = hashlib.sha256(gateway_source.encode()).hexdigest()
            with self.assertRaisesRegex(gate.A90Error, "include macro"):
                gate.enforce_future_source_policy(
                    root,
                    expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                    gateway_relative_path="src/a90_attested_br.rs",
                    expected_gateway_sha256=digest,
                )
            (root / "src/lib.rs").write_text(
                '#[path = "../hidden.rs"] mod hidden;\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(gate.A90Error, "path attribute"):
                gate.enforce_future_source_policy(
                    root,
                    expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                    gateway_relative_path="src/a90_attested_br.rs",
                    expected_gateway_sha256=digest,
                )
            (root / "src/lib.rs").write_text("mod a90_attested_br;\n", encoding="utf-8")
            (root / "src/extra.rs").write_text("fn extra() {}\n", encoding="utf-8")
            with self.assertRaisesRegex(gate.A90Error, "source closure changed"):
                gate.enforce_future_source_policy(
                    root,
                    expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                    gateway_relative_path="src/a90_attested_br.rs",
                    expected_gateway_sha256=digest,
                )
            (root / "src/extra.rs").unlink()
            with self.assertRaisesRegex(gate.A90Error, "gateway differs"):
                gate.enforce_future_source_policy(
                    root,
                    expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                    gateway_relative_path="src/a90_attested_br.rs",
                    expected_gateway_sha256=fake_sha("9"),
                )

    def test_future_policy_rejects_symlinked_source_components(self):
        gateway_source = "fn gateway(){ blind_rotate_assign(a,b,c); }\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            gateway_path = root / "src/a90_attested_br.rs"
            gateway_path.write_text(gateway_source, encoding="utf-8")
            target = root / "target.rs"
            target.write_text("fn linked() {}\n", encoding="utf-8")
            (root / "src/lib.rs").symlink_to(target)
            digest = hashlib.sha256(gateway_source.encode()).hexdigest()
            with self.assertRaisesRegex(gate.A90Error, "must not contain symlinks"):
                gate.enforce_future_source_policy(
                    root,
                    expected_source_files={"src/lib.rs", "src/a90_attested_br.rs"},
                    gateway_relative_path="src/a90_attested_br.rs",
                    expected_gateway_sha256=digest,
                )


class A90EventContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, _ = gate.verify_frozen_a84()

    def test_single_and_dual_events_bind_a79_a84_source_and_binary(self):
        run = make_run()
        for accumulator_id, expected_degrees in (
            ("a53.group_or", [0]),
            ("a53.selector.g00.len4", [0, 1024]),
        ):
            with self.subTest(accumulator_id=accumulator_id):
                pre, commit, a79_event, input_snapshot = make_linked_events(
                    self.manifest, run, accumulator_id
                )
                result = gate.validate_pre_event(
                    pre,
                    run,
                    gate.canonical_json_sha256(run),
                    a79_event,
                    input_snapshot,
                    self.manifest,
                )
                self.assertEqual(result["sample_degrees"], expected_degrees)
                self.assertFalse(result["runtime_activation_ready"])
                self.assertFalse(result["runtime_plaintext_membership_attested"])
                self.assertFalse(
                    result["post_extraction_public_offset_execution_attested"]
                )
                commit_result = gate.validate_commit_event(
                    commit,
                    pre,
                    run,
                    expected_run_binding_sha256=gate.canonical_json_sha256(run),
                )
                self.assertEqual(
                    commit_result["status"], "PASS_PAIRED_COMPLETED_SELF_REPORT"
                )

    def test_pre_event_rejects_binding_and_contract_mutations(self):
        run = make_run()
        pre, _, a79_event, input_snapshot = make_linked_events(
            self.manifest, run, "a53.selector.g00.len4"
        )
        mutations = (
            ("binary", lambda item: item.__setitem__("binary_sha256", fake_sha("a"))),
            ("source", lambda item: item.__setitem__("source_set_sha256", fake_sha("b"))),
            ("contract", lambda item: item.__setitem__("contract_id", "wrong")),
            (
                "glwe",
                lambda item: item["pre_rotation_glwe"].__setitem__("sha256", fake_sha("c")),
            ),
            (
                "modulus",
                lambda item: item["input_contract"]["crypto_domain"].__setitem__(
                    "ciphertext_modulus", "native"
                ),
            ),
            (
                "reachable",
                lambda item: item["input_contract"].__setitem__(
                    "reachable_overapprox", [999]
                ),
            ),
            (
                "sample-degree",
                lambda item: item["sample_plan"][1].__setitem__("sample_degree", 1023),
            ),
            (
                "public-offset",
                lambda item: item["sample_plan"][0].__setitem__("public_offset", 999),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(pre)
                mutate(changed)
                with self.assertRaises(gate.A90Error):
                    gate.validate_pre_event(
                        changed,
                        run,
                        gate.canonical_json_sha256(run),
                        a79_event,
                        input_snapshot,
                        self.manifest,
                    )

    def test_pre_event_rejects_a79_link_mutations_and_unknown_fields(self):
        run = make_run()
        pre, _, a79_event, input_snapshot = make_linked_events(
            self.manifest, run, "a53.selector.g00.len4"
        )
        changed_a79 = copy.deepcopy(a79_event)
        changed_a79["blind_rotation_id"] = "other"
        with self.assertRaisesRegex(gate.A90Error, "does not match"):
            gate.validate_pre_event(
                pre,
                run,
                gate.canonical_json_sha256(run),
                changed_a79,
                input_snapshot,
                self.manifest,
            )
        changed_pre = copy.deepcopy(pre)
        changed_pre["unexpected"] = True
        with self.assertRaisesRegex(gate.A90Error, "keys mismatch"):
            gate.validate_pre_event(
                changed_pre,
                run,
                gate.canonical_json_sha256(run),
                a79_event,
                input_snapshot,
                self.manifest,
            )
        changed_snapshot = copy.deepcopy(input_snapshot)
        changed_snapshot["reachable_overapprox"] = [999]
        with self.assertRaisesRegex(gate.A90Error, "independently replayed"):
            gate.validate_pre_event(
                pre,
                run,
                gate.canonical_json_sha256(run),
                a79_event,
                changed_snapshot,
                self.manifest,
            )

    def test_selector_raw_projection_is_not_confused_with_post_offset_values(self):
        record = self.manifest["accumulators"]["a53.selector.g00.len4"]
        plan = gate.expected_sample_plan(record)
        self.assertEqual(plan[0]["public_offset"], 2)
        self.assertEqual(plan[0]["raw_reachable_overapprox"], [0, 1, 2, 30, 31])
        self.assertEqual(
            plan[0]["post_offset_reachable_overapprox"], [0, 1, 2, 3, 4]
        )
        self.assertEqual(plan[1]["public_offset"], 30)
        self.assertEqual(plan[1]["raw_reachable_overapprox"], [2])
        self.assertEqual(plan[1]["post_offset_reachable_overapprox"], [0])

        run = make_run()
        pre, _, a79_event, input_snapshot = make_linked_events(
            self.manifest, run, "a53.selector.g00.len4"
        )
        false_raw_projection = copy.deepcopy(a79_event)
        for output, embedded_sample in zip(
            false_raw_projection["outputs"],
            record["a79_contract"]["samples"],
            strict=True,
        ):
            output["reachable_overapprox"] = embedded_sample["reachable_overapprox"]
        with self.assertRaisesRegex(gate.A90Error, "pre-offset sample plan"):
            gate.validate_pre_event(
                pre,
                run,
                gate.canonical_json_sha256(run),
                false_raw_projection,
                input_snapshot,
                self.manifest,
            )
    def test_pre_event_rejects_noncanonical_a84_manifest_argument(self):
        run = make_run()
        pre, _, a79_event, input_snapshot = make_linked_events(
            self.manifest, run, "a53.group_or"
        )
        changed_manifest = copy.deepcopy(self.manifest)
        changed_manifest["accumulators"]["a53.group_or"]["contract_id"] = "forged"
        with self.assertRaisesRegex(gate.A90Error, "frozen canonical manifest"):
            gate.validate_pre_event(
                pre,
                run,
                gate.canonical_json_sha256(run),
                a79_event,
                input_snapshot,
                changed_manifest,
            )

    def test_run_binding_rejects_claim_inflation(self):
        run = make_run()
        expected_digest = gate.canonical_json_sha256(run)
        run["claim_boundary"]["adversarial_remote_attestation"] = True
        with self.assertRaisesRegex(gate.A90Error, "independently supplied"):
            gate.validate_run_binding(
                run, expected_run_binding_sha256=expected_digest
            )
        with self.assertRaisesRegex(gate.A90Error, "overstated"):
            gate.validate_run_binding(
                run,
                expected_run_binding_sha256=gate.canonical_json_sha256(run),
            )

    def test_commit_rejects_missing_exact_preimage_binding(self):
        run = make_run()
        pre, commit, _, _ = make_linked_events(self.manifest, run, "a53.group_or")
        commit["pre_event_sha256"] = fake_sha("d")
        with self.assertRaisesRegex(gate.A90Error, "exact pre-event"):
            gate.validate_commit_event(
                commit,
                pre,
                run,
                expected_run_binding_sha256=gate.canonical_json_sha256(run),
            )

    def test_complete_set_requires_bijection_count_and_pairs(self):
        run = make_run()
        events = []
        a79_events = []
        input_snapshots = {}
        for index in range(136):
            pre, commit, a79_event, input_snapshot = make_linked_events(
                self.manifest,
                run,
                "a53.group_or",
                sequence=2 * index,
                suffix=str(index),
            )
            events.extend((pre, commit))
            a79_events.append(a79_event)
            input_snapshots[input_snapshot["value_id"]] = input_snapshot
        result = gate.validate_complete_event_set(
            events,
            run,
            gate.canonical_json_sha256(run),
            a79_events,
            input_snapshots,
            self.manifest,
        )
        self.assertEqual(result["pre_events"], 136)
        self.assertEqual(result["commit_events"], 136)
        self.assertFalse(result["canonical_a53_invocation_topology_attested"])
        self.assertFalse(result["full_3390_br_runtime_coverage_attested"])
        with self.assertRaisesRegex(gate.A90Error, "exactly 136"):
            gate.validate_complete_event_set(
                events[:-2],
                run,
                gate.canonical_json_sha256(run),
                a79_events[:-1],
                {key: value for key, value in input_snapshots.items() if key != "a79-input-135"},
                self.manifest,
            )
        changed_a79 = copy.deepcopy(a79_events)
        changed_a79[-1]["blind_rotation_id"] = "not-present-in-a90"
        with self.assertRaisesRegex(gate.A90Error, "not bijective"):
            gate.validate_complete_event_set(
                events,
                run,
                gate.canonical_json_sha256(run),
                changed_a79,
                input_snapshots,
                self.manifest,
            )


if __name__ == "__main__":
    unittest.main()
