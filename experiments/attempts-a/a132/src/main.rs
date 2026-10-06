mod crypto;
mod model;

use crypto::{ClientKeys, EvaluationKeys, Mutation, Trace};
use model::{Counts, Fixture, Layout, LAYOUTS};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, Write};

const SOURCE_DIGEST: &str = include_str!("../SOURCE_DIGEST.txt");
const ACK: &str = "A132_EXCLUSIVE_NOISY_DIAGNOSTIC_AUTHORIZED";

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
        let geometry = pbs_geometry(&item.tag).map(|(poly, modulus)| {
            let degree = crypto::coefficientwise_degree(client, item, poly);
            let phase_degree = crypto::modulus_switch_word(phase, poly);
            let center = value as i64 * (poly / modulus) as i64;
            let displacement =
                (degree as i64 - center + poly as i64).rem_euclid((2 * poly) as i64) - poly as i64;
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
    let passed = stage_mismatches == 0 && ledger_ok && trace_complete && output_shape_ok;
    emit(
        json!({"type":"case_summary","case":case_id,"fixture":fixture.name,"bit":layout.bit,
        "n":fixture.active.len(),"mutation":format!("{mutation:?}"),"passed":passed,
        "stage_mismatches":stage_mismatches,"output_mismatches":output_mismatches,
        "outside_center_boxes":outside_center_boxes,"trace_complete":trace_complete,
        "all_observed_br_inputs_inside_center_boxes":outside_center_boxes == 0,
        "support_classification":if outside_center_boxes == 0 { "OBSERVED_CENTER_SUPPORT_ONLY_NO_BOUND" }
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

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--plan"] {
        emit(
            json!({"type":"plan","experiment":"A132","status":"NO_KEYGEN_PLAN_ONLY",
            "source_sha256":SOURCE_DIGEST.trim(),"tfhe":"1.7.0",
            "smallest_gate":"one N4 b7 witness + paired baseline and three negative controls",
            "suites":["witness","smoke","n4-exhaustive","n127"],
            "fresh_keys_per_process":1,"requires_exclusive_authorized_workload_window":true,
            "requires_env_ack":ACK,"n4_counts":counts_json(model::expected_counts(4)),
            "n127_one_round_counts":counts_json(model::expected_counts(127))}),
        );
        return;
    }
    assert_eq!(
        args.len(),
        5,
        "use --run-authorized --suite SUITE --key-id LABEL"
    );
    assert_eq!(args[0], "--run-authorized");
    assert_eq!(args[1], "--suite");
    assert_eq!(args[3], "--key-id");
    let suite = &args[2];
    let key_id = &args[4];
    assert!(!key_id.is_empty());
    assert_eq!(
        std::env::var("A132_RUN_ACK").unwrap_or_default(),
        ACK,
        "missing workload acknowledgement"
    );
    assert_eq!(
        std::env::var("A132_SOURCE_SHA256").unwrap_or_default(),
        SOURCE_DIGEST.trim(),
        "source acknowledgement differs"
    );
    let fixtures = model::fixtures(suite);
    let layouts: &[Layout] = if suite == "witness" {
        &LAYOUTS[..1]
    } else {
        &LAYOUTS
    };
    emit(
        json!({"type":"meta","experiment":"A132","suite":suite,"key_id":key_id,
        "pid":std::process::id(),"source_sha256":SOURCE_DIGEST.trim(),"tfhe":"1.7.0",
        "fresh_keys_per_process":1,"lanes":4,"independent_lane_secrets":true,
        "ordinary_profile":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "cm_profile":"CM_PARAM_4_2_MINUS_64","cm_noise_reduction_invoked":false,
        "rayon_threads_env":std::env::var("RAYON_NUM_THREADS").ok(),
        "scope":"one-round diagnostic; fresh PBS input fixtures; no composed A66 or 0/ID gate",
        "timing_claim":false,"positive_cases_planned":fixtures.len()*layouts.len()}),
    );
    let (client, key) = crypto::generate_keys();
    emit(
        json!({"type":"key_ready","key_id":key_id,"added_payload_bytes":key.added_payload_bytes,
        "payload_sum":key.added_payload_bytes.iter().sum::<usize>(),"payload_is_rss":false}),
    );
    let mut positive_passes = 0;
    let mut positive_cases = 0;
    for fixture in &fixtures {
        for &layout in layouts {
            let (active, bits, trace) = prepare(&client, &key, fixture, layout);
            let result = crypto::run_round(&key, &active, &bits, layout, Mutation::None);
            let checked = check(
                &client,
                fixture,
                layout,
                Mutation::None,
                &trace,
                &result,
                &format!("positive_{positive_cases}"),
            );
            positive_cases += 1;
            positive_passes += usize::from(checked.passed);
        }
    }
    // Same noisy ciphertexts and keyset for the causal negative controls and their fresh baseline.
    let witness = Fixture::witness(4);
    let layout = LAYOUTS[0];
    let (active, bits, trace) = prepare(&client, &key, &witness, layout);
    let baseline = crypto::run_round(&key, &active, &bits, layout, Mutation::None);
    let baseline_check = check(
        &client,
        &witness,
        layout,
        Mutation::None,
        &trace,
        &baseline,
        "negative_baseline",
    );
    let mut negative_detections = 0;
    for mutation in [
        Mutation::OmitOffset,
        Mutation::OmitBitRescale,
        Mutation::WrongLaneKsk,
    ] {
        let result = crypto::run_round(&key, &active, &bits, layout, mutation);
        let checked = check(
            &client,
            &witness,
            layout,
            mutation,
            &trace,
            &result,
            &format!("negative_{mutation:?}"),
        );
        let detected =
            baseline_check.passed && checked.output_mismatches > 0 && checked.stage_mismatches > 0;
        negative_detections += usize::from(detected);
        emit(
            json!({"type":"negative_control","mutation":format!("{mutation:?}"),
            "baseline_passed":baseline_check.passed,"final_mismatch_detected":detected,
            "classification":if !baseline_check.passed { "INCONCLUSIVE_POSITIVE_BASELINE_FAILED" }
                else if detected { "DETECTED" } else { "NOT_DETECTED" }}),
        );
    }
    let passed =
        positive_passes == positive_cases && baseline_check.passed && negative_detections == 3;
    emit(
        json!({"type":"summary","suite":suite,"key_id":key_id,"fresh_keys":1,
        "positive_cases":positive_cases,"positive_passes":positive_passes,
        "negative_baseline_passed":baseline_check.passed,"negative_controls_detected":negative_detections,
        "bounded_component_gate_pass":passed,"full_c1_requirement_satisfied":false,
        "why_not_full_c1":"Requires N4 exhaustive and N127 fixtures, each under at least three fresh keysets; external aggregation and evidence review still required.",
        "performance_claim":false,"composed_failure_bound_claim":false,"end_to_end_exact_id_claim":false}),
    );
    if !passed {
        std::process::exit(1);
    }
}
