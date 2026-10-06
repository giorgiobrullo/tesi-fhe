//! Client-local observations for the unchanged A52 component. No extra cryptography.

use a52_canonical_high_lane_prototype::{
    A52HighTrace, Lwe, BLIND_ROTATION_MODULUS, CANONICAL_SCORE_DELTA_LOG,
    HIGH_PRE_PBS_OFFSET_TORUS, P16_DELTA_LOG, POLYNOMIAL_SIZE,
};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use tfhe::core_crypto::prelude::*;

fn hash_words(words: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

pub fn source_record() {
    println!(
        "{{\"record\":\"SOURCE\",\"schema\":\"a52.actual-ks-ms-diagnostic.v1\",\"lib_sha256\":\"{:x}\",\"harness_sha256\":\"{:x}\",\"observer_sha256\":\"{:x}\",\"crypto_repair_claim\":false,\"extra_ks\":0,\"extra_pbs\":0,\"timing_claim\":false}}",
        Sha256::digest(include_bytes!("lib.rs")),
        Sha256::digest(include_bytes!("bin/a52_canonical_high_lane_prototype.rs")),
        Sha256::digest(include_bytes!("diagnostics.rs")),
    );
}

fn decode(phase: u64, delta_log: u32, mask: u64) -> u64 {
    (phase.wrapping_add(1u64 << (delta_log - 1)) >> delta_log) & mask
}

pub fn record_high(
    case_index: usize,
    score_value: u64,
    score: &Lwe,
    high: &Lwe,
    trace: &A52HighTrace,
    big_secret: &LweSecretKeyView<'_, u64>,
    small_secret: &LweSecretKeyOwned<u64>,
) {
    let score_phase = decrypt_lwe_ciphertext(big_secret, score).0;
    let shifted_phase = decrypt_lwe_ciphertext(big_secret, &trace.shifted).0;
    let switched_phase = decrypt_lwe_ciphertext(small_secret, &trace.switched).0;
    let high_phase = decrypt_lwe_ciphertext(big_secret, high).0;
    let round = |word| pbs_modulus_switch(word, PolynomialSize(POLYNOMIAL_SIZE));
    let mask_dot = trace
        .switched
        .get_mask()
        .as_ref()
        .iter()
        .zip(small_secret.as_ref())
        .fold(0u64, |sum, (&word, &bit)| {
            sum.wrapping_add(word.wrapping_mul(bit))
        });
    let degree_dot = trace
        .mask_degrees
        .iter()
        .zip(small_secret.as_ref())
        .fold(0usize, |sum, (&degree, &bit)| {
            (sum + degree * bit as usize) % BLIND_ROTATION_MODULUS
        });
    let actual_degree =
        (trace.body_degree + BLIND_ROTATION_MODULUS - degree_dot) % BLIND_ROTATION_MODULUS;
    let phase_only_degree = round(switched_phase);
    let lut_word = trace.accumulator_body[actual_degree % POLYNOMIAL_SIZE];
    let ideal_phase = if actual_degree < POLYNOMIAL_SIZE {
        lut_word
    } else {
        lut_word.wrapping_neg()
    };
    let expected = score_value >> 8;
    let ideal_digit = decode(ideal_phase, P16_DELTA_LOG, 31);
    let actual_digit = decode(high_phase, P16_DELTA_LOG, 31);
    let nominal_phase =
        (score_value << CANONICAL_SCORE_DELTA_LOG).wrapping_add(HIGH_PRE_PBS_OFFSET_TORUS);
    let nominal_degree = round(nominal_phase);
    let closure = shifted_phase == score_phase.wrapping_add(HIGH_PRE_PBS_OFFSET_TORUS)
        && switched_phase == trace.switched.get_body().data.wrapping_sub(mask_dot)
        && trace.mask_degrees.len() == small_secret.as_ref().len()
        && trace
            .mask_degrees
            .iter()
            .zip(trace.switched.get_mask().as_ref())
            .all(|(&degree, &word)| degree == round(word))
        && trace.body_degree == round(*trace.switched.get_body().data);
    println!(
        concat!(
            "{{\"record\":\"HIGH_DIAGNOSTIC\",\"case_index\":{},\"score\":{},",
            "\"expected_high\":{},\"actual_high\":{},\"ideal_at_actual_degree\":{},",
            "\"nominal_degree\":{},\"phase_only_degree\":{},\"coefficientwise_degree\":{},",
            "\"body_degree\":{},\"secret_weighted_mask_degree_mod4096\":{},\"mask_degrees\":{:?},",
            "\"score_phase\":{},\"shifted_phase\":{},\"switched_phase\":{},\"high_phase\":{},",
            "\"ideal_phase\":{},\"small_mask_dot\":{},\"input_error_signed\":{},",
            "\"ks_phase_increment_signed\":{},\"ms_residual_signed\":{},",
            "\"pbs_error_vs_actual_lut_signed\":{},\"coefficient_closure\":{},",
            "\"actual_address_semantic_match\":{},\"output_matches_actual_lut_decode\":{},",
            "\"original_high_gate_pass\":{},\"small_secret_sha256\":\"{}\",",
            "\"big_secret_sha256\":\"{}\",\"score_words\":{:?},\"shifted_words\":{:?},",
            "\"switched_words\":{:?},\"output_words\":{:?},\"lut_body_words\":{:?},",
            "\"degree_scope\":\"same_cached_coefficient_function_on_retained_actual_PBS_input_not_phase_only\",",
            "\"extra_crypto_calls\":0}}"
        ),
        case_index, score_value, expected, actual_digit, ideal_digit,
        nominal_degree, phase_only_degree, actual_degree, trace.body_degree, degree_dot,
        trace.mask_degrees, score_phase, shifted_phase, switched_phase, high_phase,
        ideal_phase, mask_dot,
        score_phase.wrapping_sub(score_value << CANONICAL_SCORE_DELTA_LOG) as i64,
        switched_phase.wrapping_sub(shifted_phase) as i64,
        ((actual_degree as u64) << 52).wrapping_sub(switched_phase) as i64,
        high_phase.wrapping_sub(ideal_phase) as i64,
        closure, ideal_digit == expected, actual_digit == ideal_digit, actual_digit == expected,
        hash_words(small_secret.as_ref()), hash_words(big_secret.as_ref()),
        score.as_ref(), trace.shifted.as_ref(), trace.switched.as_ref(), high.as_ref(),
        trace.accumulator_body,
    );
    assert!(closure, "A52 diagnostic coefficient/phase closure");
}
