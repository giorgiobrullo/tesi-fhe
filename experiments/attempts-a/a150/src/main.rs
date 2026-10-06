mod crypto;
mod model;
mod zero_pool;

use crypto::{ClientKeys, EvaluationKeys, Mutation, Trace};
use model::{Counts, Fixture, Layout, LAYOUTS};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, Write};
use zero_pool::Policy;

const SOURCE_DIGEST: &str = include_str!("../SOURCE_DIGEST.txt");
const ACK: &str = "A150_EXCLUSIVE_NOISY_DIAGNOSTIC_AUTHORIZED";

fn emit(value: Value) {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}").expect("write JSONL");
    stdout.flush().expect("flush JSONL");
}

fn counts_json(c: Counts) -> Value {
    json!({"packing":c.packing,"cm_ks":c.cm_ks,"cm_pbs":c.cm_pbs,
        "ordinary_ks":c.ordinary_ks,"ordinary_pbs":c.ordinary_pbs,"extraction":c.extraction})
}

fn decode(phase: u64, delta: u64) -> u64 {
    (((phase as u128 + (delta / 2) as u128) / delta as u128) % ((1u128 << 64) / delta as u128))
        as u64
}

fn pbs_geometry(tag: &str) -> Option<(usize, usize)> {
    if ["active_pack/", "z_input/", "reduce_input/", "update_input/"]
        .iter()
        .any(|p| tag.starts_with(p))
    {
        Some((512, 4))
    } else if tag.starts_with("pair_input/") || tag.starts_with("egress_small/") {
        Some((2048, 4))
    } else if tag == "any_input" {
        Some((2048, 16))
    } else {
        None
    }
}

struct Check {
    passed: bool,
    output_mismatches: usize,
    stage_mismatches: usize,
}

/// All client secret access occurs only AFTER prepare_inputs and run_round have returned.
fn check(
    client: &ClientKeys,
    fixture: &Fixture,
    layout: Layout,
    mutation: Mutation,
    input_trace: &[Trace],
    result: &crypto::RoundResult,
    case_id: &str,
) -> Check {
    let expected = model::expectations(fixture, layout);
    let expected_keys: BTreeSet<_> = expected
        .iter()
        .flat_map(|(tag, row)| (0..row.values.len()).map(move |lane| (tag.clone(), lane)))
        .collect();
    let mut seen = BTreeSet::new();
    let mut stage_mismatches = 0;
    let mut output_mismatches = 0;
    let mut outside_center_boxes = 0;
    let mut duplicate = false;
    for item in input_trace.iter().chain(&result.traces) {
        if !seen.insert((item.tag.clone(), item.lane)) {
            duplicate = true;
        }
        let row = expected.get(&item.tag).expect("unrecognized stage");
        let value = row.values[item.lane];
        let phase = crypto::decrypt_trace(client, item);
        let got = decode(phase, row.delta);
        let error = phase.wrapping_sub(value.wrapping_mul(row.delta)) as i64;
        let okay = got == value && (error as i128).abs() < (row.delta / 2) as i128;
        stage_mismatches += usize::from(!okay);
        output_mismatches += usize::from(item.tag.starts_with("output/") && !okay);
        // A132's retained CM stage trace is PRE-correction. Actual CM degrees are emitted below.
        let geometry = pbs_geometry(&item.tag)
            .filter(|&(poly, _)| poly != 512)
            .map(|(poly, modulus)| {
                let degree = crypto::coefficientwise_degree(client, item, poly);
                let phase_degree = crypto::modulus_switch_word(phase, poly);
                let center = value as i64 * (poly / modulus) as i64;
                let displacement = (degree as i64 - center + poly as i64)
                    .rem_euclid((2 * poly) as i64)
                    - poly as i64;
                let halfbox = (poly / modulus / 2) as i64;
                let inside = -halfbox <= displacement && displacement < halfbox;
                outside_center_boxes += usize::from(!inside);
                json!({"polynomial_size":poly,"input_modulus":modulus,
                "coefficientwise_degree":degree,"rounded_phase_degree":phase_degree,
                "center_displacement":displacement,"inside_center_box":inside})
            });
        emit(
            json!({"type":"phase","case":case_id,"fixture":fixture.name,"bit":layout.bit,
            "mutation":format!("{mutation:?}"),"stage":item.tag,"lane":item.lane,
            "domain":format!("{:?}",item.domain),"expected":value,"decoded":got,
            "phase_u64":phase.to_string(),"delta_u64":row.delta.to_string(),
            "signed_error_i64":error.to_string(),"okay":okay,"br_geometry":geometry}),
        );
    }
    let ledger_ok = result.counts == model::expected_counts(fixture.active.len());
    let trace_complete = !duplicate && seen == expected_keys;
    let output_shape_ok = result.outputs.len() == fixture.active.len();
    let (reduction_closure, corrected_outside) =
        observe_reductions(client, result, &expected, case_id);
    let passed = result.completed
        && reduction_closure
        && stage_mismatches == 0
        && ledger_ok
        && trace_complete
        && output_shape_ok;
    emit(
        json!({"type":"case_summary","case":case_id,"fixture":fixture.name,"bit":layout.bit,
        "n":fixture.active.len(),"mutation":format!("{mutation:?}"),"passed":passed,
        "stage_mismatches":stage_mismatches,"output_mismatches":output_mismatches,
        "completed":result.completed,"reduction_closure_pass":reduction_closure,
        "actual_cm_br_outside_center_boxes":corrected_outside,
        "outside_center_boxes":outside_center_boxes,"outside_center_boxes_scope":"ordinary BR inputs only","trace_complete":trace_complete,
        "all_observed_br_inputs_inside_center_boxes":outside_center_boxes == 0 && corrected_outside == 0,
        "support_classification":if outside_center_boxes == 0 && corrected_outside == 0 { "OBSERVED_CENTER_SUPPORT_ONLY_NO_BOUND" }
            else { "LEFT_INTENDED_CENTER_BOX_DECODED_CORRECTNESS_IS_SEPARATE" },
        "output_shape_ok":output_shape_ok,"counts":counts_json(result.counts),
        "expected_counts":counts_json(model::expected_counts(fixture.active.len())),"ledger_ok":ledger_ok,
        "fixture_preparation_a44_pbs":2*fixture.active.len(),
        "diagnostic_lwe_copies":input_trace.len()+result.traces.len()}),
    );
    Check {
        passed,
        output_mismatches,
        stage_mismatches,
    }
}

fn prepare(
    client: &ClientKeys,
    key: &EvaluationKeys,
    fixture: &Fixture,
    layout: Layout,
) -> (Vec<crypto::Lwe>, Vec<crypto::Lwe>, Vec<Trace>) {
    fixture.validate();
    let active = crypto::client_encrypt(client, &fixture.active);
    let bits = crypto::client_encrypt(client, &fixture.bits);
    // This is public preprocessing from genuinely noisy encrypted Boolean inputs.
    crypto::prepare_inputs(key, &active, &bits, layout)
}

fn cm_trace(ct: &crypto::Cm, lane: usize, tag: &str) -> Trace {
    Trace {
        tag: tag.into(),
        domain: crypto::Domain::CmSmall,
        lane,
        ct: ct.extract_lwe_ciphertext(lane),
    }
}

fn hex_words(ct: &crypto::Cm) -> Vec<String> {
    ct.as_ref().iter().map(|x| format!("{x:016x}")).collect()
}

/// Key-sensitive observations, after the complete server arm returns (or refuses a BR).
fn observe_reductions(
    client: &ClientKeys,
    result: &crypto::RoundResult,
    expected: &model::Expectations,
    case_id: &str,
) -> (bool, usize) {
    let mut closure = true;
    let mut outside = 0;
    for (index, event) in result.reductions.iter().enumerate() {
        let ideal = expected
            .get(&event.stage)
            .expect("missing reduction-stage oracle");
        let word_closure = event.before.as_ref().iter().enumerate().all(|(i, &w)| {
            w.wrapping_add(
                event
                    .selected_zero
                    .as_ref()
                    .map_or(0, |zero| zero.as_ref()[i]),
            ) == event.corrected.as_ref()[i]
        });
        let mut lanes = Vec::new();
        for lane in 0..4 {
            let pre = cm_trace(&event.before, lane, &event.stage);
            let post = cm_trace(&event.corrected, lane, &event.stage);
            let pre_phase = crypto::decrypt_trace(client, &pre);
            let post_phase = crypto::decrypt_trace(client, &post);
            let zero_phase = event.selected_zero.as_ref().map_or(0, |zero| {
                crypto::decrypt_trace(client, &cm_trace(zero, lane, &event.stage))
            });
            let phase_closure = pre_phase.wrapping_add(zero_phase) == post_phase;
            closure &= word_closure && phase_closure;
            let pre_degree = crypto::coefficientwise_degree(client, &pre, 512);
            let post_degree = crypto::coefficientwise_degree(client, &post, 512);
            let value = ideal.values[lane];
            let displacement =
                (post_degree as i64 - value as i64 * 128 + 512).rem_euclid(1024) - 512;
            let inside = (-64..64).contains(&displacement);
            outside += usize::from(event.pbs_executed && !inside);
            lanes.push(json!({"lane":lane,"expected":value,
                "before_phase_u64":pre_phase.to_string(),"corrected_phase_u64":post_phase.to_string(),
                "selected_zero_phase_i64":(zero_phase as i64).to_string(),"phase_addition_closure":phase_closure,
                "before_coefficientwise_degree":pre_degree,"corrected_coefficientwise_degree":post_degree,
                "corrected_rounded_phase_degree":crypto::modulus_switch_word(post_phase,512),
                "corrected_center_displacement":displacement,"corrected_inside_center_box":inside,
                "corrected_signed_error_i64":(post_phase.wrapping_sub(value.wrapping_mul(model::CM_DELTA)) as i64).to_string()}));
        }
        emit(
            json!({"type":"cm_zero_pool_event","case":case_id,"index":index,"stage":event.stage,
            "policy":format!("{:?}",event.policy),"status":event.status,
            "chooser_invocations":event.chooser_invocations,"zero_additions":event.zero_additions,
            "source_derived_zero_candidates_examined":event.source_derived_zero_candidates_examined,
            "selected_index":event.selected_index,"estimator_satisfied":event.estimator_satisfied,
            "assumed_normalized_input_variance":event.assumed_normalized_input_variance,
            "input_variance_justified_for_actual_stage":false,"estimator_body_is_zero":true,
            "allowed":event.allowed,"pbs_executed":event.pbs_executed,
            "corrected_is_actual_br_input":event.pbs_executed,"word_addition_closure":word_closure,
            "before_words_hex":hex_words(&event.before),"corrected_words_hex":hex_words(&event.corrected),
            "selected_zero_words_hex":event.selected_zero.as_ref().map(hex_words),"lanes":lanes,
            "client_local_key_sensitive":true,"formal_failure_claim":false}),
        );
    }
    let invocations: usize = result
        .reductions
        .iter()
        .map(|e| e.chooser_invocations)
        .sum();
    let additions: usize = result.reductions.iter().map(|e| e.zero_additions).sum();
    let pbs: usize = result
        .reductions
        .iter()
        .map(|e| usize::from(e.pbs_executed))
        .sum();
    let unmet: usize = result
        .reductions
        .iter()
        .filter(|e| e.estimator_satisfied == Some(false))
        .count();
    closure &= pbs == result.counts.cm_pbs;
    emit(
        json!({"type":"cm_zero_pool_summary","case":case_id,"chooser_invocations":invocations,
        "zero_additions":additions,"unmet_bounds":unmet,"observed_pbs":pbs,
        "event_count":result.reductions.len(),"closure_pass":closure,
        "actual_br_outside_center_boxes":outside,"completed":result.completed}),
    );
    (closure, outside)
}

fn run_stock(client: &ClientKeys, key: &EvaluationKeys) -> (bool, bool) {
    let (small, preparation, preparation_counts) = crypto::stock_input(client, key);
    let mut expected = model::Expectations::new();
    expected.insert(
        "stock_input".into(),
        model::Expected {
            values: vec![0; 4],
            delta: model::CM_DELTA,
        },
    );
    for item in &preparation {
        let phase = crypto::decrypt_trace(client, item);
        emit(
            json!({"type":"stock_preparation_phase","stage":item.tag,"lane":item.lane,
            "phase_u64":phase.to_string(),"decoded":decode(phase,model::CM_DELTA),
            "client_local_key_sensitive":true}),
        );
    }
    emit(
        json!({"type":"stock_preparation_counts","counts":counts_json(preparation_counts),
        "fresh_cm_big_encryption":1,"nu_multiplier":3,"steps":1,"lanes":4}),
    );
    let mut positive = true;
    let mut negative = false;
    for (case_id, policy) in [
        ("stock_plain", Policy::Plain),
        ("stock_shared_zero", Policy::SharedZerosStockAssumption),
        ("stock_forced_unmet", Policy::ForcedUnmetDoubleVariance),
    ] {
        let result = crypto::stock_arm(key, &small, policy);
        let (closed, _) = observe_reductions(client, &result, &expected, case_id);
        let outputs: Vec<_> = result.traces.iter().map(|item| {
            let phase = crypto::decrypt_trace(client,item);
            json!({"lane":item.lane,"phase_u64":phase.to_string(),"decoded":decode(phase,model::CM_DELTA)})
        }).collect();
        let okay = result.completed
            && result.outputs.len() == 4
            && result.counts.cm_pbs == 1
            && result.traces.len() == 4
            && outputs.iter().all(|v| v["decoded"] == 0)
            && closed;
        if policy == Policy::ForcedUnmetDoubleVariance {
            negative = !result.completed
                && result.outputs.is_empty()
                && result.counts.cm_pbs == 0
                && result.reductions.len() == 1
                && result.reductions[0].estimator_satisfied == Some(false)
                && result.reductions[0].chooser_invocations == 1
                && closed;
        } else {
            positive &= okay;
        }
        emit(
            json!({"type":"stock_case","case":case_id,"completed":result.completed,
            "positive_pass":okay,"unmet_negative_detected":policy==Policy::ForcedUnmetDoubleVariance && negative,
            "counts":counts_json(result.counts),"outputs":outputs,"client_local_key_sensitive":true}),
        );
    }
    (positive, negative)
}

fn run_witness(client: &ClientKeys, key: &EvaluationKeys) -> (bool, bool) {
    let fixture = Fixture::witness(4);
    let layout = LAYOUTS[0];
    let (active, bits, trace) = prepare(client, key, &fixture, layout);
    let baseline = crypto::run_round(key, &active, &bits, layout, Mutation::None, Policy::Plain);
    let base = check(
        client,
        &fixture,
        layout,
        Mutation::None,
        &trace,
        &baseline,
        "n4_plain",
    );
    let adapted = crypto::run_round(
        key,
        &active,
        &bits,
        layout,
        Mutation::None,
        Policy::SharedZerosStockAssumption,
    );
    let adapted_check = check(
        client,
        &fixture,
        layout,
        Mutation::None,
        &trace,
        &adapted,
        "n4_shared_zero",
    );
    let mut negative_detections = 0;
    // Original A132 graph negatives use the unchanged plain arm, on the same prepared inputs.
    for mutation in [
        Mutation::OmitOffset,
        Mutation::OmitBitRescale,
        Mutation::WrongLaneKsk,
    ] {
        let result = crypto::run_round(key, &active, &bits, layout, mutation, Policy::Plain);
        let checked = check(
            client,
            &fixture,
            layout,
            mutation,
            &trace,
            &result,
            &format!("n4_negative_{mutation:?}"),
        );
        let detected = base.passed && checked.output_mismatches > 0 && checked.stage_mismatches > 0;
        negative_detections += usize::from(detected);
        emit(
            json!({"type":"graph_negative","mutation":format!("{mutation:?}"),
            "detected":detected,"baseline_passed":base.passed,"no_detection_if_baseline_fails":true}),
        );
    }
    emit(
        json!({"type":"n4_pair_summary","plain_pass":base.passed,"shared_zero_pass":adapted_check.passed,
        "shared_zero_completed":adapted.completed,"negative_detections":negative_detections,
        "estimator_unmet_is_correctness_failure":false,"noise_improvement_claim":false}),
    );
    (
        base.passed && adapted_check.passed,
        negative_detections == 3,
    )
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--plan"] {
        emit(
            json!({"type":"plan","experiment":"A150","status":"NO_KEYGEN_PLAN_ONLY",
            "tfhe":"1.7.0","source_sha256":SOURCE_DIGEST.trim(),"suites":["stock","witness"],
            "default_first_gate":"stock: one nu3/CMKS/identity step, plain/shared-zero/forced-unmet",
            "witness":"stock plus one N4 bit7 paired round and original three graph negatives",
            "fresh_keys_per_process":1,"stock_supplied_variance_is_assumption":true,
            "requires_exclusive_workload_clearance":true,"requires_env_ack":ACK,
            "n4_counts":counts_json(model::expected_counts(4)),"timing_claim":false}),
        );
        return;
    }
    assert_eq!(
        args.len(),
        5,
        "use --run-authorized --suite stock|witness --key-id LABEL"
    );
    assert_eq!(args[0], "--run-authorized");
    assert_eq!(args[1], "--suite");
    assert_eq!(args[3], "--key-id");
    let suite = &args[2];
    let key_id = &args[4];
    assert!(suite == "stock" || suite == "witness");
    assert!(!key_id.is_empty());
    assert_eq!(std::env::var("A150_RUN_ACK").unwrap_or_default(), ACK);
    assert_eq!(
        std::env::var("A150_SOURCE_SHA256").unwrap_or_default(),
        SOURCE_DIGEST.trim()
    );
    let binary_sha = std::env::var("A150_BINARY_SHA256").expect("use hash-verifying run_gate.py");
    assert!(binary_sha.len() == 64 && binary_sha.bytes().all(|b| b.is_ascii_hexdigit()));
    emit(
        json!({"type":"meta","experiment":"A150","suite":suite,"key_id":key_id,"pid":std::process::id(),
        "source_sha256":SOURCE_DIGEST.trim(),"runner_verified_binary_sha256":binary_sha,"tfhe":"1.7.0",
        "fresh_keys":1,"independent_lane_secrets":true,"lanes":4,
        "ordinary_profile":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64","cm_profile":"CM_PARAM_4_2_MINUS_64",
        "noise_reduction":"shared complete encrypted-zero chooser; ordinary CMNR absent",
        "input_variance_assumption":"stock 3.11402591442555e-5 at every strict input; unverified for actual A132 stages",
        "normalization":"variance of torus fraction; raw q^2 multiplication occurs inside cached chooser",
        "strict_unmet_behavior":"retain candidate/input and stop before BR; inconclusive estimator bound",
        "timing_claim":false,"catalog_certification":false,"client_local_key_sensitive":true}),
    );
    let (client, key) = crypto::generate_keys();
    emit(
        json!({"type":"key_ready","key_id":key_id,"original_added_payload_bytes":key.added_payload_bytes,
        "zero_pool_payload_bytes":key.zero_pool_payload_bytes,"zero_rows":1515,"payload_is_rss":false}),
    );
    let (stock_positive, unmet_negative) = run_stock(&client, &key);
    let (witness_positive, graph_negative) = if suite == "witness" {
        run_witness(&client, &key)
    } else {
        (true, true)
    };
    let passed = stock_positive && unmet_negative && witness_positive && graph_negative;
    emit(
        json!({"type":"summary","suite":suite,"fresh_keys":1,"stock_pair_pass":stock_positive,
        "forced_unmet_detected":unmet_negative,"n4_pair_pass":if suite=="witness"{Some(witness_positive)}else{None},
        "graph_negatives_pass":if suite=="witness"{Some(graph_negative)}else{None},
        "bounded_diagnostic_gate_pass":passed,"full_c1_requirement_satisfied":false,
        "noise_improvement_claim":false,"formal_failure_claim":false,"service_claim":false,"timing_claim":false}),
    );
    if !passed {
        std::process::exit(2);
    }
}
