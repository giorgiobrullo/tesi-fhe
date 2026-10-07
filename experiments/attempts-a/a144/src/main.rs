mod bridge;
use serde_json::json;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::ks32::KS32AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::ks32::KS32AtomicPatternClientKey;
use tfhe::shortint::engine::ShortintEngine;
use tfhe::shortint::parameters::v1_7::V1_7_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;

fn signed64(x: u64) -> String {
    (x as i64).to_string()
}
fn signed32(x: u32) -> i64 {
    i64::from(x as i32)
}
fn ideal_at(body: &[u64], address: usize, degree: usize) -> u64 {
    let at = (address + degree) % (2 * body.len());
    let value = body[at % body.len()];
    if at < body.len() {
        value
    } else {
        value.wrapping_neg()
    }
}

/// This invokes the actual library KS32 on an explicit, insecure algebra fixture (no keygen/PBS).
fn synthetic() {
    let decomposer =
        SignedDecomposer::<u64>::new(DecompositionBaseLog(4), DecompositionLevelCount(4));
    let body_round =
        SignedDecomposer::<u64>::new(DecompositionBaseLog(32), DecompositionLevelCount(1));
    let direct_input = (1u64 << 47) - 1;
    let pre = (body_round.closest_representable(direct_input) >> 32) as u32;
    let low_decomposer =
        SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(4));
    assert_eq!(decomposer.closest_representable(direct_input), 0);
    assert_eq!(low_decomposer.closest_representable(pre), 1 << 16);
    // KSK input secret [1], output secret [0]; no masks or row error, shape-only negative.
    let rows: Vec<u32> = (1..=4)
        .rev()
        .flat_map(|level| [0, 1u32 << (32 - 4 * level)])
        .collect();
    let ksk = LweKeyswitchKey::from_container(
        rows,
        DecompositionBaseLog(4),
        DecompositionLevelCount(4),
        LweSize(2),
        CiphertextModulus::new_native(),
    );
    let input = LweCiphertext::from_container(
        vec![direct_input, direct_input + (1u64 << 59)],
        CiphertextModulus::new_native(),
    );
    let mut direct = LweCiphertext::new(0u32, LweSize(2), CiphertextModulus::new_native());
    keyswitch_lwe_ciphertext_with_scalar_change(&ksk, &input, &mut direct);
    let rounded = LweCiphertext::from_container(
        input
            .as_ref()
            .iter()
            .map(|&x| (body_round.closest_representable(x) >> 32) as u32)
            .collect::<Vec<_>>(),
        CiphertextModulus::new_native(),
    );
    let mut wrong = direct.clone();
    keyswitch_lwe_ciphertext(&ksk, &rounded, &mut wrong);
    assert_eq!(
        direct.get_body().data.wrapping_sub(*wrong.get_body().data),
        1 << 16
    );
    println!(
        "{}",
        json!({"type":"synthetic_library_ks32", "direct":direct.as_ref(),
        "wrong_prerounded":wrong.as_ref(), "difference_u32":1u32 << 16,
        "scope":"insecure deterministic rows; actual library invocation, no FHE correctness/tail claim"})
    );
    println!(
        "{}",
        json!({"type":"summary","arm":"synthetic","synthetic_pass":true})
    );
}

/// Future primitive gate: one actual A44-layout Gaussian packed GLWE, two clear templates,
/// original full/low score polynomial and one dual-output LSB correction per channel/template.
/// This does not run the high-fan-in selector, A53 scan, or certify the stock max5 preset for A62.
fn fresh_key() {
    let params = V1_7_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    let client = KS32AtomicPatternClientKey::new(params);
    let server = ShortintEngine::with_thread_local_mut(|engine| {
        KS32AtomicPatternServerKey::new(&client, engine)
    });
    let (glwe_secret, small_secret, _) = client.into_raw_parts();
    let large_secret = glwe_secret.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut words = vec![0u64; 2048];
    words[..512].fill(1 << 52);
    words[1024..1536].fill(1 << 60);
    let mut packed = GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
    encrypt_glwe_ciphertext(
        &glwe_secret,
        &mut packed,
        &PlaintextList::from_container(words),
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.845267479601915e-15)),
        &mut generator,
    );
    assert!(packed.as_ref()[..2048].iter().any(|&word| word != 0));
    let mut all_correct = true;
    let mut all_support = true;
    for zero_last in [false, true] {
        let mut g = vec![1i64; 512];
        if zero_last {
            g[511] = 0;
        }
        let norm: i64 = g.iter().map(|x| x * x).sum();
        let x = (norm - 2 * g.iter().sum::<i64>() + 1024) as u64; // 512 or 513.
        let mut coefficients = vec![0u64; 2048];
        for coordinate in 0..512 {
            coefficients[511 - coordinate] = (-2 * g[coordinate]) as u64;
        }
        let polynomial = Polynomial::from_container(coefficients);
        let mut product = GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
        for (mut output, input) in product
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(packed.as_polynomial_list().iter())
        {
            polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
        }
        for (channel, delta, degree, bytes) in [
            (
                "full",
                52u32,
                511,
                include_bytes!("../artifacts/dual_lut_delta52.u64le").as_slice(),
            ),
            (
                "low",
                60u32,
                1535,
                include_bytes!("../artifacts/dual_lut_delta60.u64le").as_slice(),
            ),
        ] {
            let mut score = LweCiphertext::new(0u64, LweSize(2049), modulus);
            extract_lwe_sample_from_glwe_ciphertext(&product, &mut score, MonomialDegree(degree));
            lwe_ciphertext_plaintext_add_assign(
                &mut score,
                Plaintext(((norm + 1024) as u64).wrapping_mul(1u64 << delta)),
            );
            let score_phase = decrypt_lwe_ciphertext(&large_secret, &score).0;
            let mut shifted = score.clone();
            for coefficient in shifted.as_mut() {
                *coefficient <<= 63 - delta;
            }
            let shifted_phase = decrypt_lwe_ciphertext(&large_secret, &shifted).0;
            let small = bridge::switch_large(&server, &shifted);
            let small_phase = decrypt_lwe_ciphertext(&small_secret, &small).0;
            let body: Vec<u64> = bytes
                .chunks_exact(8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let mut accumulator =
                GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
            accumulator.get_mut_body().as_mut().copy_from_slice(&body);
            let observed =
                bridge::rotate_and_extract(&server, &small, 1 << 29, &accumulator, &[0, 1024]);
            let actual_address = observed
                .switched_mask
                .iter()
                .zip(small_secret.as_ref())
                .fold(observed.switched_body, |at, (&a, &s)| {
                    at.wrapping_sub(a * s as usize)
                })
                % 4096;
            let alpha = 1u64 << (delta - 1);
            let beta = 1u64 << 58;
            let mut output_records = Vec::new();
            for (j, (&degree, (&offset, &out_delta))) in [0usize, 1024]
                .iter()
                .zip([alpha, beta].iter().zip([delta, 59].iter()))
                .enumerate()
            {
                let raw_phase = decrypt_lwe_ciphertext(&large_secret, &observed.outputs[j]).0;
                let raw_ideal = ideal_at(&body, actual_address, degree);
                let corrected = raw_phase.wrapping_add(offset);
                let expected = (x & 1) << out_delta;
                let decoded = corrected.wrapping_add(1u64 << (out_delta - 1)) >> out_delta;
                let correct = decoded == (x & 1);
                let support_correct = raw_ideal.wrapping_add(offset) == expected;
                all_correct &= correct;
                all_support &= support_correct;
                output_records.push(json!({"degree":degree,"output_delta_log":out_delta,
                    "raw_phase":raw_phase,"ideal_body_at_actual_address":raw_ideal,
                    "raw_error_signed":signed64(raw_phase.wrapping_sub(raw_ideal)),
                    "semantic_error_signed":signed64(corrected.wrapping_sub(expected)),
                    "support_correct":support_correct,
                    "decoded":decoded,"expected_bit":x & 1,"correct":correct}));
            }
            println!(
                "{}",
                json!({"type":"fresh_key_bridge", "channel":channel,"translated_score":x,
                "input_delta_log":delta,"unshifted_intermediate_delta_log":delta-32,
                "actual_shifted_input_delta_log":63,"actual_small_delta_log":31,
                "source_id":include_str!("../source-id.txt").trim(),
                "score_error_signed":signed64(score_phase.wrapping_sub(x.wrapping_mul(1u64 << delta))),
                "shifted_input_error_signed":signed64(shifted_phase.wrapping_sub((x & 1) << 63)),
                "ks_error_lifted_signed":signed64(((small_phase as u64) << 32).wrapping_sub(shifted_phase)),
                "actual_ms_error_signed_u32":signed32(((actual_address as u32) << 20).wrapping_sub(small_phase.wrapping_add(1 << 29))),
                "post_ks_u32":small.as_ref(),"centered_small_u32":observed.centered_small.as_ref(),
                "cmnr_body_correction_signed_u32":signed32(observed.body_correction),
                "actual_address":actual_address,"nominal_centered_address":512+2048*(x & 1),
                "switched_body":observed.switched_body,"switched_mask":observed.switched_mask,
                "outputs":output_records,"scope":"diagnostic raw gate; aggregate errors, no row tails; timing/RSS excluded"})
            );
        }
    }
    println!(
        "{}",
        json!({"type":"summary", "arm":"fresh-key", "ks32_calls":4,"cmnr_br_calls":4,
        "marginals":8,"all_outputs_correct":all_correct,"all_support_correct":all_support,"tails":"OPEN","graph_compatibility":"OPEN"})
    );
    assert!(
        all_correct && all_support,
        "preserve failed diagnostic records; do not expand gate"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!(
            "{}",
            json!({"type":"plan","status":"SOURCE_GATE_REQUIRES_CLEAR_WORKLOAD_WINDOW",
            "arms":["--synthetic","--fresh-key"],"source_id":include_str!("../source-id.txt").trim()})
        );
        return;
    }
    assert_eq!(args.len(), 1, "exactly one arm argument is required");
    assert!(
        matches!(args[0].as_str(), "--synthetic" | "--fresh-key"),
        "unknown arm"
    );
    let arm = args[0].trim_start_matches("--");
    if arm == "fresh-key" {
        assert_eq!(
            std::env::var("A144_CLEARED_SOURCE_ID").ok().as_deref(),
            Some(include_str!("../source-id.txt").trim()),
            "use run_gate.py after live workload clearance; direct fresh-key execution is disabled"
        );
    }
    println!(
        "{}",
        json!({"type":"meta","arm":arm,
        "source_id":include_str!("../source-id.txt").trim(),
        "profile":"stock_v1_7_KS32_M2C2_max5_CMNR",
        "input_noise":"A44 Gaussian GLWE; diagnostic mixed-path fixture, not catalog qualification"})
    );
    match arm {
        "synthetic" => synthetic(),
        "fresh-key" => fresh_key(),
        _ => unreachable!(),
    }
}
