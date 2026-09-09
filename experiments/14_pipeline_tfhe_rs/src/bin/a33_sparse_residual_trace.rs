//! Validazione FHE del classificatore A33 sul residuo rumoroso prodotto dal core A29.
//!
//! Il binario usa il trace diagnostico, sottrae da `score_full` le correzioni dei bit `b0..b8`
//! e passa lo stesso ciphertext al classificatore sparso. Una decifratura diagnostica ne misura
//! prima l'errore senza modificarlo o sostituirlo; non esiste decrypt->reencrypt. Il binario non
//! modifica il core e non fa parte del protocollo o del servizio.

use pipeline_tfhe_rs::{
    private_argmin_with_trace, ScoreDomain, TemplateView, BOOL_DELTA_LOG, FULL_DELTA_LOG,
    LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM, PROBE_NORM2_MAX,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const KEY_COUNT: usize = 3;
const SCORE_BITS: usize = 12;
const RESIDUAL_LAST_CORRECTION: usize = 8;
const RESIDUAL_DELTA_LOG: u32 = 61;
const CLASSIFIER_BOXES: usize = 8;
const GROUP_BOXES: usize = 16;
const CLASSIFIER_EXTRACTION_DEGREE: usize = 256;

// Questi punti coprono h'=0..7, entrambi i lati delle transizioni e, in particolare,
// 1022/1023/1024/1025 attorno alla soglia allineata e due punti nello stato alto h'=7 compatibili
// con il dominio Cauchy di questa scena sintetica.
const TARGETS: [u64; 18] = [
    256, 511, 512, 1022, 1023, 1024, 1025, 1535, 1536, 2047, 2048, 2559, 2560, 3071, 3072, 3348,
    3584, 3839,
];

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Default)]
struct KeyStats {
    cases: usize,
    residual_mismatches: usize,
    classifier_checks: usize,
    classifier_mismatches: usize,
    group_checks: usize,
    group_mismatches: usize,
    max_abs_residual_error_delta: f64,
    max_abs_r_error_delta: f64,
    max_abs_flag_error_delta: f64,
    max_abs_group_input_error_delta: f64,
    max_abs_group_output_error_delta: f64,
    core_seconds: f64,
    classifier_seconds: f64,
    group_seconds: f64,
}

fn decode_symbol(phase: u64, delta_log: u32, modulus_mask: u64) -> u64 {
    (phase.wrapping_add(1u64 << (delta_log - 1)) >> delta_log) & modulus_mask
}

fn phase_error_delta(phase: u64, expected: u64, delta_log: u32) -> f64 {
    let target = expected.wrapping_mul(1u64 << delta_log);
    (phase.wrapping_sub(target) as i64) as f64 / (1u64 << delta_log) as f64
}

fn expected_r(h: u64) -> u64 {
    [2, 3, 4, 4, 30, 29, 28, 28][h as usize]
}

fn expected_signed_flag(h: u64, weight: u64) -> u64 {
    match h {
        0 => weight,
        4 => 32 - weight,
        _ => 0,
    }
}

fn classifier_accumulator(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
    weight: u64,
) -> Glwe {
    let delta = 1u64 << BOOL_DELTA_LOG;
    generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        CLASSIFIER_BOXES,
        modulus,
        delta,
        move |slot| match slot {
            0 => 2,
            2 => 3,
            4 | 6 => 4,
            1 => weight,
            3 | 5 | 7 => 0,
            _ => unreachable!("la LUT p=8 valuta soltanto gli slot 0..7"),
        },
    )
}

fn group_accumulator(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
) -> Glwe {
    let delta = 1u64 << BOOL_DELTA_LOG;
    generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        GROUP_BOXES,
        modulus,
        delta,
        |slot| u64::from(matches!(slot, 2 | 5 | 6 | 7 | 8)),
    )
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn encode_probe(probe: &[i64], polynomial_size: usize) -> Vec<u64> {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM <= polynomial_size);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= PROBE_NORM2_MAX);
    let mut plaintext = vec![0u64; polynomial_size];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << 60);
    }
    plaintext
}

fn main() {
    let whole_started = Instant::now();
    let template: Vec<i64> = (0..PROBE_DIM)
        .map(|coordinate| i64::from(coordinate < 16))
        .collect();
    let probe = vec![0i64; PROBE_DIM];
    let template_norm2 = squared_norm(&template);
    let score = template_norm2;
    assert_eq!(template_norm2, 16);
    assert_eq!(squared_norm(&probe), 0);
    assert!(TARGETS.iter().all(|x| (256..=3839).contains(x)));
    assert_eq!(TARGETS.iter().map(|x| x >> 9).min(), Some(0));
    assert_eq!(TARGETS.iter().map(|x| x >> 9).max(), Some(7));
    println!(
        "CONFIG,keys={KEY_COUNT},cases_per_key={},pair_states_per_key=64,template_nonzero_coordinates=16,template_norm2={template_norm2},probe_norm2=0,score={score},residual=score_full-minus-b0-through-b8,classifier_p=8,classifier_degrees=0/{CLASSIFIER_EXTRACTION_DEGREE},group_p=16,secret_material_persisted=false",
        TARGETS.len()
    );

    let mut global = KeyStats::default();
    let mut total_key_seconds = 0.0;

    for key_index in 0..KEY_COUNT {
        let key_started = Instant::now();
        let client_key = ClientKey::new(PARAMS);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let key_seconds = key_started.elapsed().as_secs_f64();
        total_key_seconds += key_seconds;

        let bootstrap_key = match &server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key,
            _ => panic!("il harness richiede una bootstrap key classica"),
        };
        let key_switching_key = &server_key.key_switching_key;
        let polynomial_size = bootstrap_key.polynomial_size();
        let glwe_size = bootstrap_key.glwe_size();
        let big_size = bootstrap_key.output_lwe_dimension().to_lwe_size();
        let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
        let modulus = CiphertextModulus::<u64>::new_native();
        assert_eq!(
            polynomial_size.0 / CLASSIFIER_BOXES,
            CLASSIFIER_EXTRACTION_DEGREE
        );

        let classifiers = [
            classifier_accumulator(polynomial_size, glwe_size, modulus, 1),
            classifier_accumulator(polynomial_size, glwe_size, modulus, 3),
        ];
        let group_lut = group_accumulator(polynomial_size, glwe_size, modulus);
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let classify = |input: &Lwe, accumulator: &Glwe| {
            let mut switched = LweCiphertext::new(0u64, small_size, modulus);
            keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
            let mut rotated = accumulator.clone();
            blind_rotate_assign(&switched, &mut rotated, bootstrap_key);
            let mut r = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut r, MonomialDegree(0));
            let mut flag = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &rotated,
                &mut flag,
                MonomialDegree(CLASSIFIER_EXTRACTION_DEGREE),
            );
            (r, flag)
        };

        let apply_group_gate = |left: &Lwe, right: &Lwe| {
            let mut packed = left.clone();
            lwe_ciphertext_add_assign(&mut packed, right);
            lwe_ciphertext_plaintext_add_assign(&mut packed, Plaintext(4u64 << BOOL_DELTA_LOG));
            let mut switched = LweCiphertext::new(0u64, small_size, modulus);
            keyswitch_lwe_ciphertext(key_switching_key, &packed, &mut switched);
            let mut result = LweCiphertext::new(0u64, big_size, modulus);
            programmable_bootstrap_lwe_ciphertext(
                &switched,
                &mut result,
                &group_lut,
                bootstrap_key,
            );
            (packed, result)
        };

        let mut stats = KeyStats::default();
        let mut representatives: [Option<(Lwe, Lwe)>; 8] = std::array::from_fn(|_| None);

        for &x in &TARGETS {
            let h = x >> 9;
            let mut packed_probe = GlweCiphertextOwned::new(
                0u64,
                glwe_secret_key.glwe_dimension().to_glwe_size(),
                polynomial_size,
                modulus,
            );
            encrypt_glwe_ciphertext(
                &glwe_secret_key,
                &mut packed_probe,
                &PlaintextList::from_container(encode_probe(&probe, polynomial_size.0)),
                client_params.glwe_noise_distribution(),
                &mut generator,
            );
            let entry = TemplateView {
                template: &template,
                norm2: template_norm2,
                threshold: score,
            };
            let domain = ScoreDomain {
                lower: score - x as i64,
                upper: score - x as i64 + (1i64 << SCORE_BITS) - 1,
            };

            let core_started = Instant::now();
            let (_output, trace) =
                private_argmin_with_trace(&server_key, &packed_probe, &[entry], domain)
                    .expect("il core A29 ha rifiutato uno scenario valido");
            stats.core_seconds += core_started.elapsed().as_secs_f64();
            assert_eq!(trace.score_full.len(), 1);
            assert_eq!(trace.full_corrections_lsb_first.len(), 1);
            assert!(trace.full_corrections_lsb_first[0].len() > RESIDUAL_LAST_CORRECTION);

            let mut residual = trace.score_full[0].clone();
            for correction in &trace.full_corrections_lsb_first[0][..=RESIDUAL_LAST_CORRECTION] {
                lwe_ciphertext_sub_assign(&mut residual, correction);
            }
            let residual_phase = decrypt_lwe_ciphertext(&big_secret_key, &residual).0;
            let residual_actual = decode_symbol(residual_phase, RESIDUAL_DELTA_LOG, 7);
            let residual_error = phase_error_delta(residual_phase, h, RESIDUAL_DELTA_LOG).abs();
            stats.max_abs_residual_error_delta =
                stats.max_abs_residual_error_delta.max(residual_error);
            stats.residual_mismatches += usize::from(residual_actual != h);

            let classifier_started = Instant::now();
            let (r_left, flag_left) = classify(&residual, &classifiers[0]);
            let (r_right, flag_right) = classify(&residual, &classifiers[1]);
            stats.classifier_seconds += classifier_started.elapsed().as_secs_f64();
            let outputs = [(&r_left, &flag_left, 1u64), (&r_right, &flag_right, 3u64)];
            for (r, flag, weight) in outputs {
                let r_phase = decrypt_lwe_ciphertext(&big_secret_key, r).0;
                let flag_phase = decrypt_lwe_ciphertext(&big_secret_key, flag).0;
                let wanted_r = expected_r(h);
                let wanted_flag = expected_signed_flag(h, weight);
                let actual_r = decode_symbol(r_phase, BOOL_DELTA_LOG, 31);
                let actual_flag = decode_symbol(flag_phase, BOOL_DELTA_LOG, 31);
                stats.classifier_checks += 2;
                stats.classifier_mismatches +=
                    usize::from(actual_r != wanted_r) + usize::from(actual_flag != wanted_flag);
                stats.max_abs_r_error_delta = stats
                    .max_abs_r_error_delta
                    .max(phase_error_delta(r_phase, wanted_r, BOOL_DELTA_LOG).abs());
                stats.max_abs_flag_error_delta = stats
                    .max_abs_flag_error_delta
                    .max(phase_error_delta(flag_phase, wanted_flag, BOOL_DELTA_LOG).abs());
            }
            if representatives[h as usize].is_none() {
                representatives[h as usize] = Some((flag_left, flag_right));
            }
            stats.cases += 1;
            println!(
                "CASE,key={key_index},x={x},h={h},residual_actual={residual_actual},residual_abs_error_delta={residual_error:.6},classifier_mismatches_so_far={}",
                stats.classifier_mismatches
            );
        }

        assert!(representatives.iter().all(Option::is_some));
        let group_started = Instant::now();
        for left_h in 0..8u64 {
            for right_h in 0..8u64 {
                let left = &representatives[left_h as usize].as_ref().unwrap().0;
                let right = &representatives[right_h as usize].as_ref().unwrap().1;
                let (packed, result) = apply_group_gate(left, right);
                let expected_packed =
                    (expected_signed_flag(left_h, 1) + expected_signed_flag(right_h, 3) + 4) & 31;
                let packed_phase = decrypt_lwe_ciphertext(&big_secret_key, &packed).0;
                let result_phase = decrypt_lwe_ciphertext(&big_secret_key, &result).0;
                let actual = decode_symbol(result_phase, BOOL_DELTA_LOG, 31);
                let expected = u64::from(left_h == 0 || right_h == 0);
                stats.group_checks += 1;
                stats.group_mismatches += usize::from(actual != expected);
                stats.max_abs_group_input_error_delta = stats
                    .max_abs_group_input_error_delta
                    .max(phase_error_delta(packed_phase, expected_packed, BOOL_DELTA_LOG).abs());
                stats.max_abs_group_output_error_delta = stats
                    .max_abs_group_output_error_delta
                    .max(phase_error_delta(result_phase, expected, BOOL_DELTA_LOG).abs());
            }
        }
        stats.group_seconds += group_started.elapsed().as_secs_f64();

        let mismatches =
            stats.residual_mismatches + stats.classifier_mismatches + stats.group_mismatches;
        println!(
            "KEY_SUMMARY,key={key_index},key_s={key_seconds:.6},cases={},residual={}/{},classifier={}/{},groups={}/{},mismatches={mismatches},max_residual_error_delta={:.6},residual_min_halfstep_margin_delta={:.6},max_r_error_delta={:.6},max_flag_error_delta={:.6},max_group_input_error_delta={:.6},group_input_min_halfstep_margin_delta={:.6},max_group_output_error_delta={:.6},core_s={:.6},classifier_s={:.6},group_s={:.6}",
            stats.cases,
            stats.cases - stats.residual_mismatches,
            stats.cases,
            stats.classifier_checks - stats.classifier_mismatches,
            stats.classifier_checks,
            stats.group_checks - stats.group_mismatches,
            stats.group_checks,
            stats.max_abs_residual_error_delta,
            0.5 - stats.max_abs_residual_error_delta,
            stats.max_abs_r_error_delta,
            stats.max_abs_flag_error_delta,
            stats.max_abs_group_input_error_delta,
            0.5 - stats.max_abs_group_input_error_delta,
            stats.max_abs_group_output_error_delta,
            stats.core_seconds,
            stats.classifier_seconds,
            stats.group_seconds,
        );

        global.cases += stats.cases;
        global.residual_mismatches += stats.residual_mismatches;
        global.classifier_checks += stats.classifier_checks;
        global.classifier_mismatches += stats.classifier_mismatches;
        global.group_checks += stats.group_checks;
        global.group_mismatches += stats.group_mismatches;
        global.max_abs_residual_error_delta = global
            .max_abs_residual_error_delta
            .max(stats.max_abs_residual_error_delta);
        global.max_abs_r_error_delta = global
            .max_abs_r_error_delta
            .max(stats.max_abs_r_error_delta);
        global.max_abs_flag_error_delta = global
            .max_abs_flag_error_delta
            .max(stats.max_abs_flag_error_delta);
        global.max_abs_group_input_error_delta = global
            .max_abs_group_input_error_delta
            .max(stats.max_abs_group_input_error_delta);
        global.max_abs_group_output_error_delta = global
            .max_abs_group_output_error_delta
            .max(stats.max_abs_group_output_error_delta);
        global.core_seconds += stats.core_seconds;
        global.classifier_seconds += stats.classifier_seconds;
        global.group_seconds += stats.group_seconds;
    }

    let total_mismatches =
        global.residual_mismatches + global.classifier_mismatches + global.group_mismatches;
    println!(
        "SUMMARY,keys={KEY_COUNT},cases={}/{},residual={}/{},classifier={}/{},groups={}/{},total_mismatches={total_mismatches},max_residual_error_delta={:.6},residual_min_halfstep_margin_delta={:.6},max_r_error_delta={:.6},max_flag_error_delta={:.6},max_group_input_error_delta={:.6},group_input_min_halfstep_margin_delta={:.6},max_group_output_error_delta={:.6},key_s={total_key_seconds:.6},core_s={:.6},classifier_s={:.6},group_s={:.6},total_s={:.6},fresh_probe_ciphertexts={},secret_material_persisted=false",
        global.cases,
        KEY_COUNT * TARGETS.len(),
        global.cases - global.residual_mismatches,
        global.cases,
        global.classifier_checks - global.classifier_mismatches,
        global.classifier_checks,
        global.group_checks - global.group_mismatches,
        global.group_checks,
        global.max_abs_residual_error_delta,
        0.5 - global.max_abs_residual_error_delta,
        global.max_abs_r_error_delta,
        global.max_abs_flag_error_delta,
        global.max_abs_group_input_error_delta,
        0.5 - global.max_abs_group_input_error_delta,
        global.max_abs_group_output_error_delta,
        global.core_seconds,
        global.classifier_seconds,
        global.group_seconds,
        whole_started.elapsed().as_secs_f64(),
        global.cases,
    );
    assert_eq!(
        total_mismatches, 0,
        "il classificatore A33 diverge sul residuo A29"
    );
}
