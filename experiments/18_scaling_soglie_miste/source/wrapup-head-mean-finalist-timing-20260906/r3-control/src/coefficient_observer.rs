//! Client-only coefficient witness. This module contains no FHE operation.
//! Public ciphertext words plus secret-derived aggregates are key-sensitive local evidence.
use serde_json::{json, Value};

const N: usize = 859;
const SHIFT: u32 = 52;
const DEGREES: u64 = 4096;

fn rounded(word: u64) -> u64 {
    word.wrapping_add(1u64 << (SHIFT - 1)) >> SHIFT
}

/// Recompute from the exact small LWE retained before the existing BR. No secret bits
/// are returned. The sums nevertheless disclose secret-derived linear relations.
pub fn observe(
    words: &[u64],
    secret: &[u64],
    tfhe_phase: u64,
    existing_address: usize,
    keyset: usize,
) -> Value {
    assert_eq!(words.len(), N + 1);
    assert_eq!(secret.len(), N);
    assert!(secret.iter().all(|bit| *bit <= 1));
    let mask = &words[..N];
    let body = words[N];
    let mask_degrees: Vec<u64> = mask.iter().map(|word| rounded(*word)).collect();
    let body_degree = rounded(body);
    let body_residue = body.wrapping_sub(body_degree.wrapping_shl(SHIFT)) as i64;

    let mut weighted_words = 0u64;
    let mut weighted_degrees = 0u64;
    let mut weighted_residues = 0i128;
    for ((word, degree), bit) in mask.iter().zip(&mask_degrees).zip(secret) {
        weighted_words = weighted_words.wrapping_add(word.wrapping_mul(*bit));
        weighted_degrees += degree * bit;
        let residue = word.wrapping_sub(degree.wrapping_shl(SHIFT)) as i64;
        weighted_residues += residue as i128 * *bit as i128;
    }
    let direct_phase = body.wrapping_sub(weighted_words);
    let direct_address = (body_degree + DEGREES - weighted_degrees % DEGREES) % DEGREES;
    let reconstructed_mask = weighted_degrees
        .wrapping_shl(SHIFT)
        .wrapping_add(weighted_residues as u64);
    let reconstructed_phase = direct_address
        .wrapping_shl(SHIFT)
        .wrapping_add(body_residue as u64)
        .wrapping_sub(weighted_residues as u64);
    let phase_matches_tfhe = direct_phase == tfhe_phase;
    let address_matches_existing = direct_address as usize == existing_address;
    let mask_identity = weighted_words == reconstructed_mask;
    let phase_identity = direct_phase == reconstructed_phase;
    json!({
        "schema":"A143_POST_KS_V1", "keyset":keyset,
        "lwe_dimension":N, "torus_bits":64, "log_degree_modulus":12,
        "post_ks_words_hex":words.iter().map(|x|format!("{x:016x}")).collect::<Vec<_>>(),
        "public_mask_degrees":mask_degrees, "public_body_degree":body_degree,
        "public_body_residue_decimal":body_residue.to_string(),
        "client_weighted_mask_words_hex":format!("{weighted_words:016x}"),
        "client_weighted_mask_degrees":weighted_degrees,
        "client_weighted_mask_residues_decimal":weighted_residues.to_string(),
        "direct_phase_word_hex":format!("{direct_phase:016x}"),
        "direct_address":direct_address,
        "phase_matches_tfhe_decrypt":phase_matches_tfhe,
        "address_matches_existing_observer":address_matches_existing,
        "mask_decomposition_identity":mask_identity,
        "phase_ms_identity":phase_identity,
        "closure_pass":phase_matches_tfhe && address_matches_existing && mask_identity && phase_identity,
        "secret_key_bits_serialized":false,
        "key_sensitive_client_local_only":true,
        "client_aggregates_independently_attested":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_phase_does_not_imply_zero_switched_address() {
        let mut words = vec![0u64; N + 1];
        let mut secret = vec![0u64; N];
        for i in 0..128 {
            words[i] = (1 << 51) - 1;
            secret[i] = 1;
        }
        words[N] = words[..N]
            .iter()
            .fold(0u64, |sum, word| sum.wrapping_add(*word));
        let witness = observe(&words, &secret, 0, 64, 0);
        assert_eq!(witness["direct_address"], 64);
        assert_eq!(witness["closure_pass"], true);
    }
}
