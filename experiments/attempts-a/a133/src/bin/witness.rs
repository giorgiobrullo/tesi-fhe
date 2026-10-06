//! Client-side diagnostic observer. No secret is serialized or passed to the server core.
use a133_a126_runtime_noise_witness::PrivateArgminTrace;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;

pub type Lwe = LweCiphertextOwned<u64>;
pub const DELTA: u64 = 1 << 59;
pub const U: u64 = 1 << 52;
const Q: i128 = 1i128 << 64;

pub fn hash_words(domain: &str, words: &[u64]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"A133/u64LE/native/v1\0");
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update((words.len() as u64).to_le_bytes());
    for word in words {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

pub fn decode(secret: &LweSecretKeyView<'_, u64>, ct: &Lwe) -> u64 {
    decrypt_lwe_ciphertext(secret, ct).0.wrapping_add(DELTA / 2) >> 59
}

fn encoded(value: i64) -> u64 {
    (value as u64).wrapping_mul(DELTA)
}
fn error(phase: u64, ideal: u64) -> i64 {
    phase.wrapping_sub(ideal) as i64
}
pub fn ms(word: u64) -> usize {
    (word.wrapping_add(U / 2) >> 52) as usize
}
fn rho(word: u64) -> i64 {
    ((ms(word) as u64).wrapping_mul(U).wrapping_sub(word)) as i64
}

pub fn body() -> Vec<u64> {
    include_bytes!("../../artifacts/fused_candidate_zero_body.u64le")
        .chunks_exact(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .collect()
}

pub fn sample(body: &[u64], address: usize, degree: usize) -> u64 {
    let index = address + degree;
    let word = body[index % 2048];
    if (index / 2048) % 2 == 1 {
        word.wrapping_neg()
    } else {
        word
    }
}

fn safe(body: &[u64], t: i64, displacement: i64, expected: [u64; 2]) -> bool {
    let address = (128 * t + displacement).rem_euclid(4096) as usize;
    [sample(body, address, 0), sample(body, address, 768)] == expected
}

fn margin(body: &[u64], t: i64, expected: [u64; 2]) -> (i64, i64) {
    assert!(safe(body, t, 0, expected));
    let (mut lower, mut upper) = (0, 0);
    while lower > -4096 && safe(body, t, lower - 1, expected) {
        lower -= 1;
    }
    while upper < 4096 && safe(body, t, upper + 1, expected) {
        upper += 1;
    }
    (lower, upper)
}

fn linear_equal(output: &Lwe, inputs: &[(i64, &Lwe)]) -> bool {
    inputs
        .iter()
        .all(|(_, ct)| ct.as_ref().len() == output.as_ref().len())
        && output.as_ref().iter().enumerate().all(|(i, word)| {
            inputs.iter().fold(0u64, |sum, (coefficient, ct)| {
                sum.wrapping_add(ct.as_ref()[i].wrapping_mul(*coefficient as u64))
            }) == *word
        })
}

fn ciphertext(ct: &Lwe, domain: &str, phase: u64) -> Value {
    json!({
        "ciphertext_id": hash_words(domain, ct.as_ref()), "domain": domain,
        "lwe_dimension": ct.lwe_size().0 - 1, "ciphertext_modulus": "native_u64",
        "words_u64le_hex": ct.as_ref().iter().map(|v| format!("{v:016x}")).collect::<Vec<_>>(),
        "client_observed_phase_torus": phase.to_string(),
        "phase_observation_attested": false
    })
}

#[allow(clippy::too_many_arguments)]
pub fn observe(
    event_id: &str,
    key_id: &str,
    index: usize,
    state: i64,
    bit: i64,
    any_expected: i64,
    trace: &PrivateArgminTrace,
    big: &LweSecretKeyView<'_, u64>,
    small: &LweSecretKeyView<'_, u64>,
) -> Value {
    assert!((-4..=1).contains(&state) && (0..=1).contains(&bit));
    let previous = &trace.candidates_by_level[3][index];
    let positive_bit = &trace.bridged_bits_by_level[4][index];
    let input = &trace.a126_fusion_inputs[index];
    let switched = &trace.a133_fusion_post_ks[index];
    let output0 = &trace.a126_fresh_candidates[index];
    let output768 = &trace.a126_zero_candidates[index];
    let any = &trace.any_zero_by_level[4];
    let update = &trace.candidates_by_level[4][index];
    assert_eq!(switched.lwe_size().0 - 1, 859);
    assert_eq!(input.lwe_size().0 - 1, 2048);
    assert_eq!(small.as_ref().len(), switched.lwe_size().0 - 1);
    assert_eq!(big.as_ref().len(), input.lwe_size().0 - 1);
    assert!(small.as_ref().iter().chain(big.as_ref()).all(|&x| x <= 1));
    let t = state + 6 * bit;
    let live = i64::from(state == 1);
    let zero = i64::from(state == 1 && bit == 0);
    let expected = [encoded(live), encoded(zero)];
    let phi_previous = decrypt_lwe_ciphertext(big, previous).0;
    let phi_bit = decrypt_lwe_ciphertext(big, positive_bit).0;
    let phi_input = decrypt_lwe_ciphertext(big, input).0;
    let phi_small = decrypt_lwe_ciphertext(small, switched).0;
    let phi0 = decrypt_lwe_ciphertext(big, output0).0;
    let phi768 = decrypt_lwe_ciphertext(big, output768).0;
    let phi_any = decrypt_lwe_ciphertext(big, any).0;
    let phi_update = decrypt_lwe_ciphertext(big, update).0;
    let e_input = error(phi_input, encoded(t));
    let e_small = error(phi_small, encoded(t));
    let ks_increment = error(phi_small, phi_input);
    let decomposer =
        SignedDecomposer::<u64>::new(DecompositionBaseLog(3), DecompositionLevelCount(5));
    let ks_remainder: i128 = input
        .get_mask()
        .as_ref()
        .iter()
        .zip(big.as_ref())
        .map(|(&a, &s)| i128::from(error(a, decomposer.closest_representable(a))) * i128::from(s))
        .sum();
    // Aggregate inferred from the ACTUAL input/output phases; not an independent per-row measurement.
    let ks_row_contribution = (ks_increment as u64).wrapping_sub(ks_remainder as u64) as i64;
    let rounding_body = rho(*switched.get_body().data);
    let rounding_mask_sum: i128 = switched
        .get_mask()
        .as_ref()
        .iter()
        .zip(small.as_ref())
        .map(|(&a, &s)| i128::from(rho(a)) * i128::from(s))
        .sum();
    let rounding_correction = i128::from(rounding_body) - rounding_mask_sum;
    let switched_body = ms(*switched.get_body().data) as i64;
    let switched_mask_sum: i64 = switched
        .get_mask()
        .as_ref()
        .iter()
        .zip(small.as_ref())
        .map(|(&a, &s)| ms(a) as i64 * s as i64)
        .sum();
    let address = (switched_body - switched_mask_sum).rem_euclid(4096) as usize;
    let nominal_address = (128 * t).rem_euclid(4096) as usize;
    let displacement = (address as i64 - nominal_address as i64 + 2048).rem_euclid(4096) - 2048;
    let polynomial = body();
    let ideals = [
        sample(&polynomial, address, 0),
        sample(&polynomial, address, 768),
    ];
    let (lower, upper) = margin(&polynomial, t, expected);
    let raw_errors = [error(phi0, ideals[0]), error(phi768, ideals[1])];
    let expected_errors = [error(phi0, expected[0]), error(phi768, expected[1])];
    let update_expected = live + zero - any_expected;
    let update_error = error(phi_update, encoded(update_expected));
    let any_error = error(phi_any, encoded(any_expected));
    let input_linear_ok = linear_equal(input, &[(1, previous), (6, positive_bit)]);
    let update_linear_ok = linear_equal(update, &[(1, output0), (1, output768), (-1, any)]);
    let ms_identity_ok = (i128::from(e_small) + rounding_correction
        - i128::from(displacement) * i128::from(U))
    .rem_euclid(Q)
        == 0;
    let input_error_identity_ok = (i128::from(e_input)
        - i128::from(error(phi_previous, encoded(state)))
        - 6 * i128::from(error(phi_bit, encoded(bit))))
    .rem_euclid(Q)
        == 0;
    let ks_identity_ok = (i128::from(e_small)
        - i128::from(e_input)
        - ks_remainder
        - i128::from(ks_row_contribution))
    .rem_euclid(Q)
        == 0;
    let update_error_identity_ok = (i128::from(update_error)
        - i128::from(expected_errors[0])
        - i128::from(expected_errors[1])
        + i128::from(any_error))
    .rem_euclid(Q)
        == 0;
    let big_domain = format!("{key_id}/big");
    let small_domain = format!("{key_id}/small");
    json!({
        "record": "fusion_witness", "schema": "a133.fusion.v1", "event_id": event_id,
        "core_sha256":format!("{:x}",Sha256::digest(include_bytes!("../private_argmin.rs"))),
        "body_sha256":format!("{:x}",Sha256::digest(include_bytes!("../../artifacts/fused_candidate_zero_body.u64le"))),
        "key_id": key_id, "gallery_index": index, "producer_id": format!("{event_id}/BR"),
        "ks_producer_id": format!("{event_id}/KS"), "state": state, "positive_b3": bit, "t": t,
        "ciphertexts": {
            "previous_candidate": ciphertext(previous, &big_domain, phi_previous),
            "positive_b3": ciphertext(positive_bit, &big_domain, phi_bit),
            "input": ciphertext(input, &big_domain, phi_input),
            "post_ks_consumed_by_br": ciphertext(switched, &small_domain, phi_small),
            "raw_sample0": ciphertext(output0, &big_domain, phi0),
            "raw_sample768": ciphertext(output768, &big_domain, phi768),
            "any_zero_level4": ciphertext(any, &big_domain, phi_any),
            "immediate_update": ciphertext(update, &big_domain, phi_update)
        },
        "input": {
            "expected_torus": encoded(t).to_string(), "signed_error_torus": e_input.to_string(),
            "previous_candidate_error_torus": error(phi_previous, encoded(state)).to_string(),
            "positive_b3_error_torus": error(phi_bit, encoded(bit)).to_string(),
            "linear_coefficients": [1,6], "ciphertext_linear_identity": input_linear_ok,
            "error_identity_mod_q": input_error_identity_ok,
            "decoded_prerequisites_match_oracle": decode(big, previous) == (state as u64 & 31) && decode(big, positive_bit) == bit as u64
        },
        "ks": {
            "small_signed_error_torus": e_small.to_string(), "observed_signed_increment_torus": ks_increment.to_string(),
            "decomposition_remainder_lift_torus": ks_remainder.to_string(),
            "inferred_aggregate_row_contribution_torus": ks_row_contribution.to_string(),
            "aggregate_identity_mod_q": ks_identity_ok, "independent_per_row_measurement": false,
            "ksk_id": key_id, "decomposition_base_log":3, "decomposition_levels":5, "tail_status":"OPEN"
        },
        "modulus_switch": {
            "polynomial_size":2048, "rotation_modulus":4096, "quantum_torus": U.to_string(),
            "body_switched": switched_body, "secret_weighted_mask_switched_sum": switched_mask_sum,
            "body_rounding_error_torus": rounding_body.to_string(),
            "secret_weighted_mask_rounding_error_sum_torus": rounding_mask_sum.to_string(),
            "rounding_correction_lift_torus": rounding_correction.to_string(), "identity_mod_q": ms_identity_ok,
            "actual_address":address, "nominal_address":nominal_address, "signed_displacement":displacement,
            "round_decrypted_phase_only_address":ms(phi_small),
            "joint_connected_margin":[lower,upper], "inside_connected_margin":lower<=displacement && displacement<=upper,
            "exact_joint_lut_values_match_expected":ideals==expected
        },
        "raw_samples": [
            {"degree":0,"producer_id":format!("{event_id}/BR"),"public_offset_torus":"0",
             "expected_torus":expected[0].to_string(),"ideal_at_actual_address_torus":ideals[0].to_string(),
             "signed_error_to_actual_ideal_torus":raw_errors[0].to_string(),"signed_error_to_expected_torus":expected_errors[0].to_string(),
             "strict_nearest_cell_for_actual_ideal":raw_errors[0].unsigned_abs()<DELTA/2,"tail_status":"OPEN"},
            {"degree":768,"producer_id":format!("{event_id}/BR"),"public_offset_torus":"0",
             "expected_torus":expected[1].to_string(),"ideal_at_actual_address_torus":ideals[1].to_string(),
             "signed_error_to_actual_ideal_torus":raw_errors[1].to_string(),"signed_error_to_expected_torus":expected_errors[1].to_string(),
             "strict_nearest_cell_for_actual_ideal":raw_errors[1].unsigned_abs()<DELTA/2,"tail_status":"OPEN"}
        ],
        "immediate_update": {
            "producer_id":format!("{event_id}/update"),"linear_coefficients":[1,1,-1],
            "expected_any_zero":any_expected,"expected_plaintext":update_expected,
            "signed_any_error_torus":any_error.to_string(),"signed_error_torus":update_error.to_string(),
            "ciphertext_linear_identity":update_linear_ok,"error_identity_mod_q":update_error_identity_ok,
            "any_ciphertext_aliases_sample768":any.as_ref()==output768.as_ref(),
            "raw_outputs_decode_expected":decode(big, output0)==live as u64 && decode(big, output768)==zero as u64
        },
        "observer_identities_pass":input_linear_ok && update_linear_ok && input_error_identity_ok && ks_identity_ok && ms_identity_ok && update_error_identity_ok,
        "raw_samples_independent":false,"runtime_execution_attested":false,"noise_tail_status":"OPEN"
    })
}
