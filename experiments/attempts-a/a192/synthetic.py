"""Synthetic complete records; never ciphertext execution or empirical evidence."""

import copy
import component as r
from graph import Graph
import coefficients as c

BINARY = "b" * 64


def records(scores, keyset=0, fixture_index=0, new_changes=None, old_changes=None):
    reference = r.nominal_reference(scores)
    rows = [
        dict(
            record="plan",
            schema="a192.precision_n4.v1",
            execution_requested=True,
            fixture_index=fixture_index,
            keyset=keyset,
            control_required=fixture_index == 0,
            scores=scores,
            keysets=1,
            arms=r.ARMS,
            pbs_ks_per_arm=r.COUNTS,
            pbs=205,
            ks=205,
            input_glwe_encryptions=1,
            public_glwe_products=4,
            input_sample_extractions=8,
            pbs_output_sample_extractions=205,
            total_sample_extractions=213,
            raw_records=211,
            timing_allowed=False,
            automatic_expansion=False,
            survivor_flags_only=True,
            coefficient_degree_replay_is_extra_crypto_ms=False,
        ),
        dict(
            record="provenance",
            schema="a192.precision_n4.v1",
            source_id="SYNTHETIC_SOURCE",
            binary_sha256=BINARY,
            child_pid=123,
            reference_sha256=r.sha(r.HERE / "REFERENCE.json"),
            params="V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
            parameter_fingerprint="b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
            big_key_sha256=r.sha_bytes(f"big/key{keyset}".encode()),
            small_key_sha256=r.sha_bytes(f"small/key{keyset}".encode()),
            raw_secret_bits_serialized=False,
            key_sensitive_client_local_only=True,
        ),
    ]
    cases = []
    for arm in range(3):
        if arm == 0:
            graph = Graph(padding=True, perturbations=old_changes)
            result, values = graph.evaluate(scores, [0] * 4, [0] * 4, True)
            outputs = {
                name: [graph.actual(v) for v in values[old]]
                for name, old in [
                    ("low_words", "low51"),
                    ("middle_words", "middle51"),
                    ("top_words", "top60"),
                    ("flag_words", "flags"),
                ]
            }
            outputs.update(
                correction_low_words=outputs["low_words"],
                correction_middle_words=outputs["middle_words"],
            )
            preimages = all(x["conditional_region_pass"] for x in graph.reports)
            old = result["native_decode_pass"] and result["composed_a34_a135_pass"]
        else:
            graph = r.Precision(
                wrong=arm == 2, changes=copy.deepcopy(new_changes) if arm == 1 else None
            )
            graph.evaluate(scores)
            outputs = graph.outputs
            preimages = all(x["exact_preimage_pass"] for x in graph.events)
            old = None
        for event, ref in zip(graph.generated, reference["arms"][arm]["events"]):
            event = dict(
                event,
                record="event",
                arm=arm,
                keyset=keyset,
                case=fixture_index,
                client_only=True,
                stock_degree_formula_match=True,
                expected_lut_word=ref["expected_lut_word"],
                exact_preimage_pass=event["lut_word_at_actual_address"]
                == ref["expected_lut_word"],
            )
            # Different arms may differ in noise; synthetic identities must reflect the words.
            for name in ("input_sha256", "output_sha256"):
                phase = event[
                    "big_phase_word" if name == "input_sha256" else "output_phase_word"
                ]
                event[name] = r.sha_bytes(
                    (str(arm) + event["stage"] + name + phase).encode()
                )
            rows.append(c.realize_synthetic_event(event))
        predicates = r.output_predicates(outputs, 51 if arm == 0 else 54, scores)
        joint = (
            all(
                predicates[k]
                for k in (
                    "low_native_pass",
                    "middle_native_pass",
                    "top_native_pass",
                    "final_native_pass",
                )
            )
            and preimages
        )
        case = dict(
            record="case",
            arm=arm,
            arm_name=r.ARMS[arm],
            keyset=keyset,
            case=fixture_index,
            scores=scores,
            full_sha256=[r.sha_bytes(f"full/{i}".encode()) for i in range(4)],
            packed_low_sha256=[r.sha_bytes(f"packed/{i}".encode()) for i in range(4)],
            input_full_errors=["0"] * 4,
            input_packed_low_errors=["0"] * 4,
            digit_log=51 if arm == 0 else 54,
            **{name: [str(x) for x in words] for name, words in outputs.items()},
            **predicates,
            all_preimages_pass=preimages,
            coefficient_closure_pass=True,
            stock_degree_formula_pass=True,
            joint_gate_pass=joint,
            old_a149_functional_pass=old,
            wrong_scale_detected=not predicates["final_flags_pass"]
            if arm == 2
            else None,
            br=r.COUNTS[arm],
            ks=r.COUNTS[arm],
            refreshes=0,
        )
        rows.append(case)
        cases.append(case)
    gate = cases[1]["joint_gate_pass"] and (
        fixture_index != 0 or cases[2]["wrong_scale_detected"]
    )
    rows.append(
        dict(
            record="summary",
            status="A192_COMPONENT_PASS" if gate else "A192_COMPONENT_NEGATIVE",
            gate_pass=gate,
            old_a149_functional_pass=cases[0]["old_a149_functional_pass"],
            new_joint_gate_pass=cases[1]["joint_gate_pass"],
            wrong_scale_detected=cases[2]["wrong_scale_detected"],
            coefficient_events=205,
            pbs=205,
            ks=205,
            input_glwe_encryptions=1,
            public_glwe_products=4,
            input_sample_extractions=8,
            pbs_output_sample_extractions=205,
            actual_coefficient_degree_replays=205,
            extra_crypto_ms_calls=0,
            refresh_calls=0,
            formal_tail=False,
            latency_claim=False,
            a53_or_service=False,
            keysets=1,
            cases=1,
        )
    )
    return rows, 0 if gate else 1
