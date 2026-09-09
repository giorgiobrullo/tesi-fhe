//! One exact, post-summary client scan of the actual resident functional key.
//! This module emits only one global maximum, never an atom, secret, or location.
use super::{key_envelope_core::{silent_boundary, Maximum}, observer, Poly, SOURCE};
use serde_json::{json, Value};
use tfhe::core_crypto::prelude::*;

const ROWS: usize = 2049;
const N: usize = 2048;
const ATOMS: usize = ROWS * N;
const KEY_BYTES: usize = 67_141_632;

#[derive(Clone, Copy)]
enum Reason { Geometry, BinarySecret, KeyHash, Coverage, Decryption, Internal }

impl Reason {
    fn public(self) -> &'static str {
        match self {
            Self::Geometry => "geometry_mismatch",
            Self::BinarySecret => "binary_secret_requirement_failed",
            Self::KeyHash => "key_hash_mismatch",
            Self::Coverage => "coverage_mismatch",
            Self::Decryption => "decryption_failed",
            Self::Internal => "observer_internal_error",
        }
    }
}

#[derive(Default)]
struct Progress {
    binary_checks: usize,
    decryptions: usize,
    rows: usize,
    body: bool,
    post_hash: Option<String>,
    maximum: Maximum,
    in_decryption: bool,
}

fn scan(
    key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    glwe: &GlweSecretKeyOwned<u64>, window: &Poly, pre_hash: &str,
    plan: &Value, progress: &mut Progress,
) -> Result<u64, Reason> {
    let big = glwe.as_lwe_secret_key();
    let geometry = key.input_key_lwe_dimension().0 == N
        && key.output_glwe_size().0 == 2 && key.output_polynomial_size().0 == N
        && key.decomposition_base_log().0 == 22 && key.decomposition_level_count().0 == 1
        && key.ciphertext_modulus().is_native_modulus()
        && glwe.glwe_dimension().0 == 1 && glwe.polynomial_size().0 == N
        && big.as_ref().len() == N && std::mem::size_of_val(key.as_ref()) == KEY_BYTES
        && window.as_ref().len() == N
        && window.as_ref().iter().all(|word| *word <= 1)
        && window.as_ref().iter().filter(|word| **word == 1).count() == 287
        && observer::hash_words(window.as_ref()) == plan["function_sha256"].as_str().unwrap_or("");
    if !geometry { return Err(Reason::Geometry); }
    for bit in big.as_ref() {
        progress.binary_checks += 1;
        if *bit > 1 { return Err(Reason::BinarySecret); }
    }
    // Exactly one extra full key hash, performed after the ordinary summary.
    progress.post_hash = Some(observer::hash_words(key.as_ref()));
    if progress.post_hash.as_deref() != Some(pre_hash) { return Err(Reason::KeyHash); }
    let mut phase = PlaintextList::new(0u64, PlaintextCount(N));
    for (row_index, row) in key.iter().enumerate() {
        if row_index >= ROWS || row.glwe_ciphertext_count().0 != 1 { return Err(Reason::Geometry); }
        // Native key generation appends u_n = -1; logical levels descend and L=1.
        let multiplier = if row_index < N { big.as_ref()[row_index] } else { u64::MAX };
        for (physical_level, ciphertext) in row.iter().enumerate() {
            if physical_level != 0 { return Err(Reason::Geometry); }
            progress.in_decryption = true;
            decrypt_glwe_ciphertext(glwe, &ciphertext, &mut phase);
            progress.in_decryption = false;
            progress.decryptions += 1;
            for (coefficient, word) in phase.as_ref().iter().enumerate() {
                progress.maximum.inspect(*word, multiplier, window.as_ref()[coefficient]);
            }
        }
        progress.rows += 1;
        if row_index == N { progress.body = true; }
    }
    if progress.rows != ROWS || !progress.body || progress.decryptions != ROWS {
        return Err(Reason::Coverage);
    }
    progress.maximum.complete_value(ATOMS).ok_or(Reason::Coverage)
}

pub(super) fn observe(
    key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>, glwe: &GlweSecretKeyOwned<u64>,
    window: &Poly, pre_hash: &str, summary_hash: &str, ordinary_pass: bool,
    binary_hash: &str, plan: &Value,
) -> (Value, bool) {
    let mut progress = Progress::default();
    let outcome = silent_boundary(|| scan(key, glwe, window, pre_hash, plan, &mut progress));
    let result = match outcome {
        Ok(result) => result,
        Err(()) => Err(if progress.in_decryption { Reason::Decryption } else { Reason::Internal }),
    };
    let (maximum, reason) = match result { Ok(value) => (Some(value), None), Err(reason) => (None, Some(reason.public())) };
    let complete = maximum.is_some();
    let atoms = progress.maximum.coefficients;
    let hashed = usize::from(progress.post_hash.is_some());
    let counts = json!({
        "additional_full_key_hashes_after_existing_pre_use_hash":hashed,
        "additional_key_hash_bytes":hashed*KEY_BYTES,"additional_terminal_observer_records":1,
        "binary_secret_checks_private":progress.binary_checks,"br":0,"centered_magnitudes":atoms,
        "glwe_decryptions":progress.decryptions,"input_encryptions":0,"key_generations":0,
        "maximum_comparisons":atoms,"negacyclic_mask_secret_products":progress.decryptions,
        "ordinary_ks":0,"pfks_evaluations":0,"phase_coefficients_inspected":atoms,
        "row_plaintext_residual_subtractions":atoms,"serialized_error_locations":0,
        "serialized_global_maxima":usize::from(complete),"serialized_individual_errors":0,
        "serialized_per_row_maxima":0,"serialized_secret_hashes":0,"serialized_secret_values":0});
    let row = json!({"record":"key_envelope","schema":"pfks-split32-key-envelope.observation.v1",
        "source_sha256":SOURCE.trim(),"binary_sha256":binary_hash,"pid":std::process::id(),
        "ordinary_summary_raw_sha256":summary_hash,"ordinary_gate_pass":ordinary_pass,
        "ordinary_exit_expected":usize::from(!ordinary_pass),"pre_use_window_key_sha256":pre_hash,
        "post_use_window_key_sha256":progress.post_hash,"function_sha256":plan["function_sha256"],
        "pfks":[22,1],"input_dimension":N,"glwe_size":2,"polynomial_size":N,
        "ciphertext_modulus":"native","identity_function":true,"same_secret_view":true,
        "status":if complete {"complete"} else {"incomplete"},"reason":reason,
        "coverage":{"rows_completed":progress.rows,"levels_per_row":1,"coefficients_seen":atoms,
            "body_row_included":progress.body,"all_window_zero_positions_included":complete},
        "counts":counts,"B_observed":maximum.map(|value|value.to_string()),"B_reference":629832,
        "reference_envelope_pass":maximum.map(|value|value<=629832),"resampled":false,"early_stop":false,
        "individual_errors_serialized":false,"ordinary_gate_result_changed":false,
        "trusted_native_client_observation":true,"key_membership_attested":false,"formal_failure_bound":null});
    (row, complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_small_ring_decrypts_zero_one_and_body_rows_exactly() {
        const SIZE: usize = 4;
        let bits = [1u64, 0, 1, 1];
        let secret = GlweSecretKey::from_container(bits.to_vec(), PolynomialSize(SIZE));
        let window = [0u64, 1, 0, 1];
        let mut phase = PlaintextList::new(0u64, PlaintextCount(SIZE));
        let mut maximum = Maximum::default();
        for (row, multiplier) in bits.into_iter().chain([u64::MAX]).enumerate() {
            let mask = [7*row as u64+3, 11*row as u64+5, 13*row as u64+7, 17*row as u64+9];
            let mut body = [0u64; SIZE];
            // Literal negacyclic multiplication is independent of native decryption.
            for (i, a) in mask.into_iter().enumerate() {
                for (j, bit) in bits.into_iter().enumerate() {
                    let product = a.wrapping_mul(bit);
                    let index = (i+j)%SIZE;
                    body[index] = if i+j < SIZE { body[index].wrapping_add(product) }
                        else { body[index].wrapping_sub(product) };
                }
            }
            let errors = [629833i64, -2, if row == SIZE { 700000 } else { 4 },
                if row == SIZE { i64::MIN } else { 3 }];
            for coefficient in 0..SIZE {
                body[coefficient] = body[coefficient]
                    .wrapping_add(multiplier.wrapping_shl(42).wrapping_mul(window[coefficient]))
                    .wrapping_add(errors[coefficient] as u64);
            }
            let words: Vec<_> = mask.into_iter().chain(body).collect();
            let ciphertext = GlweCiphertext::from_container(words, PolynomialSize(SIZE), CiphertextModulus::new_native());
            decrypt_glwe_ciphertext(&secret, &ciphertext, &mut phase);
            for coefficient in 0..SIZE {
                let plaintext = multiplier.wrapping_shl(42).wrapping_mul(window[coefficient]);
                assert_eq!(phase.as_ref()[coefficient].wrapping_sub(plaintext), errors[coefficient] as u64);
                maximum.inspect(phase.as_ref()[coefficient], multiplier, window[coefficient]);
            }
        }
        assert_eq!(maximum.complete_value(20), Some(1u64 << 63));
    }
}
