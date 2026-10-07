//! A126 diagnostic gate. Not a latency benchmark or a noise-tail certificate.
//! Same fresh key and genuinely encrypted score inputs feed A66 and A126.
//! Decryption happens only in this client-side harness after both executions.

use a126_refresh_schedule_gate::TemplateView;
use a126_refresh_schedule_gate::{
    a126_aligned_operation_counts, a62_aligned_operation_counts, clear_private_argmin,
    plan_private_argmin_execution, private_argmin_a126_with_trace, private_argmin_a62_with_trace,
    A44_PARAMETER_BINDING, BOOL_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG,
    LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM,
};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

type Lwe = LweCiphertextOwned<u64>;

fn decode(secret: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> u64 {
    decrypt_lwe_ciphertext(secret, ciphertext)
        .0
        .wrapping_add(1u64 << (BOOL_DELTA_LOG - 1))
        >> BOOL_DELTA_LOG
}

fn signed_decode(secret: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> i64 {
    let value = decode(secret, ciphertext) as i64;
    if value >= 16 {
        value - 32
    } else {
        value
    }
}

fn phase_error(secret: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe, expected: i64) -> u64 {
    let encoded = (expected as u64).wrapping_mul(1u64 << BOOL_DELTA_LOG);
    let phase = decrypt_lwe_ciphertext(secret, ciphertext).0;
    (phase.wrapping_sub(encoded) as i64).unsigned_abs()
}

fn plaintext_states(flips: &[usize]) -> Vec<Vec<i64>> {
    // Independent lexicographic oracle with unrefreshed integer candidate drift.
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
        .map(|value| value.parse::<usize>().expect("integer --keys"))
        .unwrap_or(3);
    assert!((1..=8).contains(&keys));
    let full = args.iter().any(|arg| arg == "--full");
    let basic = vec![64, 66, 32, 34, 16, 18, 8, 10, 4, 6, 0, 2];
    let mut reverse = basic.clone();
    reverse.reverse();
    let mut cases = vec![
        ("all12_phases".to_string(), basic),
        ("all12_phases_reverse".to_string(), reverse),
    ];
    if full {
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
    let core_hash = format!(
        "{:x}",
        Sha256::digest(include_bytes!("../private_argmin.rs"))
    );
    let body_hash = format!(
        "{:x}",
        Sha256::digest(include_bytes!(
            "../../artifacts/fused_candidate_zero_body.u64le"
        ))
    );
    println!("PLAN,variant=A126,real_fhe_validated=false,noise_tail_certified=false,timed=false,keys={keys},cases_per_key={},core_sha256={core_hash},body_sha256={body_hash},sample_degrees=0:768,delta_log=59", cases.len());
    if !args.iter().any(|arg| arg == "--run") {
        return;
    }
    let expected_hash = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--expected-binary-sha256="))
        .expect("--run requires --expected-binary-sha256=<pinned binary>");
    let executable = std::env::current_exe().expect("current executable");
    assert!(
        executable.to_string_lossy().contains("target-a126-only"),
        "isolated target required"
    );
    let actual_hash = format!(
        "{:x}",
        Sha256::digest(std::fs::read(executable).expect("binary bytes"))
    );
    assert_eq!(expected_hash, actual_hash, "binary hash mismatch");
    assert_eq!(PARAMS.polynomial_size.0, 2048);
    assert_eq!(PARAMS.max_noise_level.get(), 15);

    for key in 0..keys {
        let client = ClientKey::new(PARAMS);
        let server = ServerKey::new(&client);
        let (glwe_secret, _small_secret, parameters) = client.into_raw_parts();
        let big_secret = glwe_secret.as_lwe_secret_key();
        let modulus = CiphertextModulus::<u64>::new_native();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        for (name, flips) in &cases {
            // q=[1;512], ||q||²=512; every g has the same norm and flips a prefix.
            // score=-512+4K; the real planner aligns to lower=-1024, T=-1.
            let gallery: Vec<Vec<i64>> = flips
                .iter()
                .map(|count| {
                    assert!(*count <= PROBE_DIM);
                    let mut template = vec![1i64; PROBE_DIM];
                    template[..*count].fill(-1);
                    template
                })
                .collect();
            let templates: Vec<TemplateView<'_>> = gallery
                .iter()
                .map(|template| TemplateView {
                    template,
                    norm2: 512,
                    threshold: -1,
                })
                .collect();
            let plan = plan_private_argmin_execution(&templates).expect("valid scene");
            assert!(plan.aligned_fast_path);
            assert_eq!(plan.execution_domain.lower, -1024);
            let raw_scores: Vec<i64> = flips.iter().map(|count| -512 + 4 * *count as i64).collect();
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
                modulus,
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
            .expect("A126 candidate");
            let old_counts = a62_aligned_operation_counts(flips.len()).unwrap();
            let new_counts = a126_aligned_operation_counts(flips.len()).unwrap();
            assert_eq!(baseline.metrics.total_pbs_count, old_counts.blind_rotations);
            assert_eq!(
                candidate.metrics.total_pbs_count,
                new_counts.blind_rotations
            );
            assert_eq!(
                baseline.metrics.select.pbs_count - candidate.metrics.select.pbs_count,
                flips.len() as u64
            );
            assert_eq!(
                baseline.metrics.extract.pbs_count,
                candidate.metrics.extract.pbs_count
            );
            assert_eq!(
                baseline.metrics.scan.pbs_count,
                candidate.metrics.scan.pbs_count
            );
            assert_eq!(baseline.parameter_binding, candidate.parameter_binding);
            let low = decode(&big_secret, &candidate.low_digit);
            let high = decode(&big_secret, &candidate.high_digit);
            assert!(low < 15 && high < 15, "noncanonical base15 digit");
            let code = low + 15 * high;
            assert_eq!(code, clear.code);
            assert_eq!(
                decode(&big_secret, &baseline.low_digit)
                    + 15 * decode(&big_secret, &baseline.high_digit),
                code
            );
            let expected_states = plaintext_states(flips);
            assert_eq!(trace.a126_fusion_inputs.len(), flips.len());
            assert_eq!(trace.a126_fresh_candidates.len(), flips.len());
            assert_eq!(trace.a126_zero_candidates.len(), flips.len());
            for index in 0..flips.len() {
                let state = expected_states[3][index];
                let bit = (((512 + 4 * flips[index]) >> 3) & 1) as i64;
                let phase = state + 6 * bit;
                let live = i64::from(state == 1);
                let zero = i64::from(state == 1 && bit == 0);
                assert_eq!(
                    signed_decode(&big_secret, &trace.candidates_by_level[3][index]),
                    state
                );
                assert_eq!(
                    signed_decode(&big_secret, &trace.a126_fusion_inputs[index]),
                    phase
                );
                assert_eq!(
                    decode(&big_secret, &trace.a126_fresh_candidates[index]),
                    live as u64
                );
                assert_eq!(
                    decode(&big_secret, &trace.a126_zero_candidates[index]),
                    zero as u64
                );
                let final_candidate = decode(&big_secret, &trace.candidates_by_level[7][index]);
                assert!(final_candidate <= 1, "scan requires canonical full decode");
                assert_eq!(
                    final_candidate,
                    decode(&big_secret, &baseline_trace.candidates_by_level[7][index])
                );
                println!("PHASE,key={key},case={name},lane={index},state={state},bit3={bit},phase={phase},input_error={},candidate_error={},zero_error={},correlated_samples=true",
                    phase_error(&big_secret, &trace.a126_fusion_inputs[index], phase),
                    phase_error(&big_secret, &trace.a126_fresh_candidates[index], live),
                    phase_error(&big_secret, &trace.a126_zero_candidates[index], zero));
            }
            println!("PASS,key={key},case={name},n={},code={code},br_old={},br_new={},ks_structural_new={},marginals_structural_new={},wire_lwes=2,timed=false", flips.len(), old_counts.blind_rotations, new_counts.blind_rotations, new_counts.key_switches, new_counts.output_marginals);
        }
    }
    println!("SUMMARY,status=PASS,keys={keys},cases_per_key={},fhe_pairs={},secret_material_persisted=false,timed=false,noise_tail_certified=false", cases.len(), keys * cases.len());
}
