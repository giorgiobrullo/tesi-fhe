//! A133: A126's unchanged fused circuit with exact client-side KS/MS/sample witnesses.
//! Untimed diagnostic only. Correctness, address support and raw error evidence stay separate.
#![recursion_limit = "512"]
mod witness;

use a133_a126_runtime_noise_witness::{
    a126_aligned_operation_counts, a62_aligned_operation_counts, clear_private_argmin,
    plan_private_argmin_execution, private_argmin_a126_with_trace, private_argmin_a62_with_trace,
    TemplateView, A44_PARAMETER_BINDING, A44_PARAMETER_CANONICAL, FULL_DELTA_LOG,
    LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn emit(value: Value) {
    println!("{value}");
}

fn plaintext_states(flips: &[usize]) -> Vec<Vec<i64>> {
    let scores: Vec<usize> = flips.iter().map(|count| 512 + 4 * count).collect();
    let minimum_high = scores
        .iter()
        .filter(|score| **score <= 1023)
        .map(|score| score >> 8)
        .min();
    let mut states: Vec<i64> = scores
        .iter()
        .map(|score| i64::from(*score <= 1023 && Some(score >> 8) == minimum_high))
        .collect();
    let mut rows = Vec::new();
    for bit in (4..=7).rev() {
        let zeros: Vec<i64> = states
            .iter()
            .zip(&scores)
            .map(|(state, score)| i64::from(*state == 1 && ((score >> bit) & 1) == 0))
            .collect();
        let any = i64::from(zeros.contains(&1));
        states = states
            .iter()
            .zip(zeros)
            .map(|(state, zero)| state + zero - any)
            .collect();
        rows.push(states.clone());
    }
    rows
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let keys = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--keys="))
        .map(|x| x.parse::<usize>().expect("integer --keys"))
        .unwrap_or(1);
    assert!((1..=8).contains(&keys));
    let basic = vec![64, 66, 32, 34, 16, 18, 8, 10, 4, 6, 0, 2];
    let mut reverse = basic.clone();
    reverse.reverse();
    let mut cases = vec![
        ("all12_phases".to_string(), basic),
        ("all12_phases_reverse".to_string(), reverse),
    ];
    if args.iter().any(|arg| arg == "--full") {
        cases.extend([
            ("n1_accept".into(), vec![0]),
            ("n2_tie_first".into(), vec![0, 0]),
            ("n2_all_reject".into(), vec![128, 130]),
            ("n2_threshold_1020_1024".into(), vec![127, 128]),
        ]);
        for n in [64, 127, 128] {
            let mut flips = vec![128; n];
            flips[n - 1] = 0;
            cases.push((format!("n{n}_last_id"), flips));
        }
    }
    let source = json!({
        "core_sha256": hash(include_bytes!("../private_argmin.rs")),
        "observer_sha256": hash(include_bytes!("witness.rs")),
        "harness_sha256": hash(include_bytes!("a133_a126_runtime_noise_witness.rs")),
        "body_sha256": hash(include_bytes!("../../artifacts/fused_candidate_zero_body.u64le")),
        "upstream_pin_manifest_sha256": hash(include_bytes!("../../SOURCE_PINS.json")),
        "parameter_canonical": A44_PARAMETER_CANONICAL
    });
    emit(json!({"record":"plan","variant":"A133","source":source,
        "keys":keys,"cases_per_key":cases.len(),"timed":false,"noise_tail_status":"OPEN",
        "runtime_execution_attested":false,"scope":"fused level4 event and immediate update only"}));
    if !args.iter().any(|arg| arg == "--run") {
        return;
    }
    let expected_hash = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--expected-binary-sha256="))
        .expect("--run requires independently pinned --expected-binary-sha256");
    let executable = std::env::current_exe().expect("executable");
    assert!(
        executable
            .components()
            .any(|part| part.as_os_str() == "target-a133-only"),
        "isolated target required"
    );
    let binary_hash = hash(&std::fs::read(&executable).expect("binary bytes"));
    assert_eq!(expected_hash, binary_hash, "binary digest mismatch");
    assert_eq!(PARAMS.polynomial_size.0, 2048);
    assert_eq!(PARAMS.lwe_dimension.0, 859);
    emit(
        json!({"record":"run_start","source":source,"binary_sha256":binary_hash,
        "cases":cases.iter().map(|(name,flips)| json!({"name":name,"flips":flips})).collect::<Vec<_>>(),
        "keys":keys,"secret_key_bytes_persisted":false,"contains_secret_derived_observations":true,"timed":false}),
    );
    let mut totals = [0usize; 6]; // cases, witnesses, correctness failures, identity failures, support escapes, raw-cell escapes
    for key in 0..keys {
        let client = ClientKey::new(PARAMS);
        let server = ServerKey::new(&client);
        // Both secrets remain in this client harness; neither enters the evaluation call or log.
        let (glwe_secret, small_secret, parameters) = client.into_raw_parts();
        let big_secret = glwe_secret.as_lwe_secret_key();
        let small_view = small_secret.as_view();
        let key_id =
            witness::hash_words("public_ksk_2048_to_859", server.key_switching_key.as_ref());
        emit(json!({"record":"key_block","key_index":key,"key_id":key_id,
            "key_id_definition":"SHA256 of public native KSK words with A133 domain/length framing",
            "fresh_generation_called":true,"secret_key_bytes_persisted":false,"contains_secret_derived_observations":true}));
        let mut boxed = new_seeder();
        let seeder = boxed.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        for (name, flips) in &cases {
            let case_id = format!("{key_id}/{name}");
            emit(json!({"record":"case_start","key_id":key_id,"case_id":case_id,"n":flips.len()}));
            let gallery: Vec<Vec<i64>> = flips
                .iter()
                .map(|count| {
                    assert!(*count <= PROBE_DIM);
                    let mut g = vec![1i64; PROBE_DIM];
                    g[..*count].fill(-1);
                    g
                })
                .collect();
            let templates: Vec<TemplateView<'_>> = gallery
                .iter()
                .map(|g| TemplateView {
                    template: g,
                    norm2: 512,
                    threshold: -1,
                })
                .collect();
            let plan = plan_private_argmin_execution(&templates).expect("scene plan");
            assert!(plan.aligned_fast_path);
            assert_eq!(plan.execution_domain.lower, -1024);
            let raw_scores: Vec<i64> = flips.iter().map(|k| -512 + 4 * *k as i64).collect();
            let clear = clear_private_argmin(&raw_scores, &templates).expect("clear oracle");
            let mut plaintext = vec![0u64; 2048];
            for coordinate in 0..PROBE_DIM {
                plaintext[coordinate] = 1u64 << FULL_DELTA_LOG;
                plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] = 1u64 << LOW_MOD16_DELTA_LOG;
            }
            let mut encrypted = GlweCiphertext::new(
                0u64,
                glwe_secret.glwe_dimension().to_glwe_size(),
                glwe_secret.polynomial_size(),
                CiphertextModulus::new_native(),
            );
            encrypt_glwe_ciphertext(
                &glwe_secret,
                &mut encrypted,
                &PlaintextList::from_container(plaintext),
                parameters.glwe_noise_distribution(),
                &mut generator,
            );
            let (baseline, baseline_trace) = private_argmin_a62_with_trace(
                A44_PARAMETER_BINDING,
                &server,
                &encrypted,
                &templates,
                plan.execution_domain,
            )
            .expect("A66 baseline");
            let (candidate, trace) = private_argmin_a126_with_trace(
                A44_PARAMETER_BINDING,
                &server,
                &encrypted,
                &templates,
                plan.execution_domain,
            )
            .expect("A133 observed A126 circuit");
            let old_counts = a62_aligned_operation_counts(flips.len()).unwrap();
            let new_counts = a126_aligned_operation_counts(flips.len()).unwrap();
            let counts_ok = baseline.metrics.total_pbs_count == old_counts.blind_rotations
                && candidate.metrics.total_pbs_count == new_counts.blind_rotations
                && baseline.metrics.select.pbs_count
                    == candidate.metrics.select.pbs_count + flips.len() as u64
                && baseline.metrics.extract.pbs_count == candidate.metrics.extract.pbs_count
                && baseline.metrics.scan.pbs_count == candidate.metrics.scan.pbs_count;
            assert_eq!(trace.a133_fusion_post_ks.len(), flips.len());
            let states = plaintext_states(flips);
            let bits: Vec<i64> = flips
                .iter()
                .map(|k| (((512 + 4 * k) >> 3) & 1) as i64)
                .collect();
            let any = i64::from(states[3].iter().zip(&bits).any(|(&c, &b)| c == 1 && b == 0));
            let mut identities = true;
            let mut support = true;
            let mut raw_cells = true;
            for index in 0..flips.len() {
                let event_id = format!("{case_id}/fusion/{index}");
                let event = witness::observe(
                    &event_id,
                    &key_id,
                    index,
                    states[3][index],
                    bits[index],
                    any,
                    &trace,
                    &big_secret,
                    &small_view,
                );
                let identity_ok = event["observer_identities_pass"].as_bool().unwrap();
                let support_ok = event["modulus_switch"]["inside_connected_margin"]
                    .as_bool()
                    .unwrap();
                let raw_ok = event["raw_samples"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|sample| {
                        sample["strict_nearest_cell_for_actual_ideal"]
                            .as_bool()
                            .unwrap()
                    });
                identities &= identity_ok;
                support &= support_ok;
                raw_cells &= raw_ok;
                totals[1] += 1;
                totals[3] += usize::from(!identity_ok);
                totals[4] += usize::from(!support_ok);
                totals[5] += usize::from(!raw_ok);
                emit(event);
            }
            let low = witness::decode(&big_secret, &candidate.low_digit);
            let high = witness::decode(&big_secret, &candidate.high_digit);
            let baseline_low = witness::decode(&big_secret, &baseline.low_digit);
            let baseline_high = witness::decode(&big_secret, &baseline.high_digit);
            let code = low + 15 * high;
            let canonical = trace.candidates_by_level[7]
                .iter()
                .all(|ct| witness::decode(&big_secret, ct) <= 1);
            let final_matches = trace.candidates_by_level[7]
                .iter()
                .zip(&baseline_trace.candidates_by_level[7])
                .all(|(left, right)| {
                    witness::decode(&big_secret, left) == witness::decode(&big_secret, right)
                });
            let correct = low < 15
                && high < 15
                && code == clear.code
                && baseline_low < 15
                && baseline_high < 15
                && baseline_low + 15 * baseline_high == clear.code
                && canonical
                && final_matches
                && baseline.parameter_binding == candidate.parameter_binding;
            totals[0] += 1;
            totals[2] += usize::from(!correct || !counts_ok);
            emit(
                json!({"record":"case_result","case_id":case_id,"key_id":key_id,"n":flips.len(),
                "expected_code":clear.code,"candidate_low":low,"candidate_high":high,"candidate_code":code,
                "baseline_low":baseline_low,"baseline_high":baseline_high,"final_correctness":correct,
                "final_candidates_canonical":canonical,"final_candidates_match_baseline":final_matches,
                "parameter_binding_equal":baseline.parameter_binding==candidate.parameter_binding,
                "counts_match_unchanged_A126":counts_ok,"observed_baseline_br":baseline.metrics.total_pbs_count,
                "observed_candidate_br":candidate.metrics.total_pbs_count,"structural_candidate_ks":new_counts.key_switches,
                "structural_candidate_output_marginals":new_counts.output_marginals,
                "observer_identities_pass":identities,"all_joint_connected_margins_hold":support,
                "all_raw_samples_inside_actual_ideal_nearest_cell":raw_cells,"noise_tail_status":"OPEN","timed":false}),
            );
        }
    }
    emit(
        json!({"record":"summary","status":"DIAGNOSTIC_COMPLETE","key_blocks":keys,"cases":totals[0],
        "fusion_witnesses":totals[1],"correctness_or_count_failures":totals[2],"observer_identity_failures":totals[3],
        "joint_connected_margin_escapes":totals[4],"raw_nearest_cell_escapes":totals[5],
        "noise_tail_status":"OPEN","runtime_execution_attested":false,"secret_key_bytes_persisted":false,"contains_secret_derived_observations":true,
        "timed":false,"scope":"fused event and immediate update; no full-trace or service promotion"}),
    );
    if totals[2] > 0 || totals[3] > 0 {
        std::process::exit(1);
    }
}
