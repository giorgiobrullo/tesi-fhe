//! One exact public-mask mean correction; observations run after all server work.
use super::*;

pub(super) const POLICY: &str = "MEAN_ONLY_INTEGER_CENTER";
const LOG: usize = 12;
const HALF: u64 = 1 << 51;

pub(super) struct Centered {
    pub original: Lwe,
    pub corrected: Lwe,
    pub stock_correction: u64,
    pub mean_correction: u64,
}

pub(super) fn apply(original: Lwe) -> Centered {
    assert_eq!(original.lwe_size().0, 860);
    assert!(original.ciphertext_modulus().is_native_modulus());
    // Obtain the actual cached integer correction. This lazy view is never passed to BR.
    let (_, stock_correction, log) = lwe_ciphertext_centered_binary_modulus_switch::<u64, usize, _>(
        original.as_view(), CiphertextModulusLog(LOG),
    ).into_raw_parts();
    assert_eq!(log.0, LOG);
    let mean_correction = stock_correction.wrapping_add(HALF);
    let mut corrected = original.clone();
    *corrected.get_mut_body().data = corrected.get_body().data.wrapping_add(mean_correction);
    Centered { original, corrected, stock_correction, mean_correction }
}

pub(super) fn observe(
    original: &Lwe, corrected: &Lwe, stock_correction: u64, mean_correction: u64,
    original_ks: &Value, secret: &LweSecretKeyView<'_, u64>,
) -> (Value, bool) {
    let mut half_sum = 0i128;
    let mut error_sum = 0i128;
    let mut halving_error_sum = 0i128;
    for &word in original.get_mask().as_ref() {
        let rounded = (pbs_modulus_switch(word, PolynomialSize(2048)) as u64)
            .wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE);
        let error = rounded.wrapping_sub(word) as i64 as i128;
        let half = error / 2;
        half_sum += half;
        error_sum += error;
        halving_error_sum += 2 * half - error;
    }
    let expected_mean = (half_sum - halving_error_sum / 2) as u64;
    let formula = mean_correction == expected_mean
        && stock_correction == expected_mean.wrapping_sub(HALF)
        && mean_correction == stock_correction.wrapping_add(HALF);
    let corrected_node = comparator::lwe(corrected, secret);
    let old_phase = original_ks["small"]["phase"].as_u64().unwrap();
    let new_phase = corrected_node["phase"].as_u64().unwrap();
    let old_body = *original.get_body().data;
    let new_body = *corrected.get_body().data;
    let masks_unchanged = original.get_mask().as_ref() == corrected.get_mask().as_ref();
    let body_addition = new_body == old_body.wrapping_add(mean_correction);
    let phase_translation = new_phase == old_phase.wrapping_add(mean_correction);
    let degrees: Vec<usize> = corrected.as_ref().iter()
        .map(|&word| pbs_modulus_switch(word, PolynomialSize(2048))).collect();
    let body_degree = *degrees.last().unwrap();
    let mask_degrees = &degrees[..degrees.len() - 1];
    let same_degrees = json!(mask_degrees) == original_ks["mask_degrees"];
    let weighted_degrees = original_ks["client_weighted_degrees_decimal"].as_str().unwrap().parse::<i128>().unwrap();
    let weighted_residues = original_ks["client_weighted_residues_decimal"].as_str().unwrap().parse::<i128>().unwrap();
    let body_residue = new_body.wrapping_sub((body_degree as u64)
        .wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE)) as i64;
    let address = (body_degree as i128 - weighted_degrees).rem_euclid(4096) as usize;
    let identity = (address as u64).wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE)
        .wrapping_add(body_residue as u64).wrapping_sub(weighted_residues as u64) == new_phase;
    let original_hash = observer::hash_words(original.as_ref());
    let original_bound = original_ks["small"]["sha256"] == original_hash
        && original_ks["small"]["words"] == json!(original.as_ref());
    let body_changed = old_body != new_body;
    let address_changed = json!(body_degree) != original_ks["body_degree"];
    let pass = formula && masks_unchanged && body_addition && phase_translation && same_degrees
        && identity && original_bound && corrected_node["direct_phase_matches"] == true;
    (json!({"policy":POLICY,"log_modulus":LOG,"mask_terms":859,
        "original_small_sha256":original_hash,"original_body_word":old_body,
        "original_mask_sha256":observer::hash_words(original.get_mask().as_ref()),
        "cached_stock_correction_word":stock_correction,"half_unit_word":HALF,"mean_correction_word":mean_correction,
        "public_half_sum_decimal":half_sum.to_string(),"public_halving_error_sum_decimal":halving_error_sum.to_string(),
        "public_rounding_error_sum_decimal":error_sum.to_string(),"corrected":corrected_node,
        "mask_degrees":mask_degrees,"body_degree":body_degree,"body_residue":body_residue,"actual_address":address,
        "client_weighted_degrees_decimal":weighted_degrees.to_string(),
        "client_weighted_residues_decimal":weighted_residues.to_string(),
        "formula_pass":formula,"masks_unchanged_pass":masks_unchanged,"body_addition_pass":body_addition,
        "phase_translation_pass":phase_translation,"mask_degrees_unchanged_pass":same_degrees,
        "coefficient_identity_pass":identity,"original_ks_output_bound":original_bound,
        "body_word_changed":body_changed,"body_address_changed":address_changed,"pass":pass}), pass)
}
