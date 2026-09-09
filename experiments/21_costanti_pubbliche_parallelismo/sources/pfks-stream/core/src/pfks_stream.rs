//! Read each functional-key block once while updating several independent payloads.
//! Each lane keeps the stock decomposition, subtraction order and u64 ring operator.
use super::{Glwe, Lwe};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tfhe::core_crypto::algorithms::slice_algorithms::slice_wrapping_sub_scalar_mul_assign;
use tfhe::core_crypto::prelude::*;

static ENABLED: AtomicBool = AtomicBool::new(false);
static VERIFY: AtomicBool = AtomicBool::new(false);
static BATCHES: AtomicUsize = AtomicUsize::new(0);
static LANES: AtomicUsize = AtomicUsize::new(0);
static KEY_BLOCKS: AtomicUsize = AtomicUsize::new(0);
static VERIFIED_WORDS: AtomicUsize = AtomicUsize::new(0);

/// Called only between synchronous whole queries, before entering the worker pool.
pub fn configure(enabled: bool, verify: bool) {
    assert!(!verify || enabled);
    ENABLED.store(enabled, Ordering::Relaxed);
    VERIFY.store(verify, Ordering::Relaxed);
    for counter in [&BATCHES, &LANES, &KEY_BLOCKS, &VERIFIED_WORDS] {
        counter.store(0, Ordering::Relaxed);
    }
}

pub(super) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn report() -> Value {
    json!({
        "enabled": enabled(),
        "verify": VERIFY.load(Ordering::Relaxed),
        "batches": BATCHES.load(Ordering::Relaxed),
        "lanes": LANES.load(Ordering::Relaxed),
        "key_block_visits": KEY_BLOCKS.load(Ordering::Relaxed),
        "verified_glwe_words": VERIFIED_WORDS.load(Ordering::Relaxed),
        "scope": "PFKS payload construction only; unchanged rotations and ring operator"
    })
}

fn apply(key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>, inputs: &[Lwe]) -> Vec<Glwe> {
    assert!(!inputs.is_empty());
    let modulus = key.ciphertext_modulus();
    assert!(modulus.is_native_modulus());
    for input in inputs {
        assert_eq!(
            input.lwe_size(),
            key.input_key_lwe_dimension().to_lwe_size()
        );
        assert_eq!(input.ciphertext_modulus(), modulus);
    }
    let mut outputs: Vec<_> = inputs
        .iter()
        .map(|_| {
            Glwe::new(
                0u64,
                key.output_glwe_size(),
                key.output_polynomial_size(),
                modulus,
            )
        })
        .collect();
    let levels = key.decomposition_level_count().0;
    let decomposer = SignedDecomposer::new(
        key.decomposition_base_log(),
        key.decomposition_level_count(),
    );
    // This small lane-by-level buffer is reused at every input coefficient.
    let mut digits = vec![vec![0u64; levels]; inputs.len()];
    for (index, block) in key.iter().enumerate() {
        for (input, lane_digits) in inputs.iter().zip(&mut digits) {
            let rounded = decomposer.closest_representable(input.as_ref()[index]);
            for (digit, term) in lane_digits.iter_mut().zip(decomposer.decompose(rounded)) {
                *digit = term.value();
            }
        }
        for (level, level_key) in block.iter().enumerate() {
            for (output, lane_digits) in outputs.iter_mut().zip(&digits) {
                slice_wrapping_sub_scalar_mul_assign(
                    output.as_mut(),
                    level_key.as_ref(),
                    lane_digits[level],
                );
            }
        }
    }
    outputs
}

pub(super) fn differences(
    key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    left: &[Lwe],
    right: &[Lwe],
    lanes: &[usize],
) -> Vec<Glwe> {
    assert!(enabled());
    assert!(!lanes.is_empty() && lanes.len() <= 9);
    let inputs: Vec<_> = lanes
        .iter()
        .map(|&lane| {
            let mut difference = right[lane].clone();
            lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
            difference
        })
        .collect();
    let outputs = apply(key, &inputs);
    BATCHES.fetch_add(1, Ordering::Relaxed);
    LANES.fetch_add(lanes.len(), Ordering::Relaxed);
    KEY_BLOCKS.fetch_add(
        key.input_key_lwe_dimension().to_lwe_size().0,
        Ordering::Relaxed,
    );
    if VERIFY.load(Ordering::Relaxed) {
        for (input, output) in inputs.iter().zip(&outputs) {
            let mut reference = output.clone();
            private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                key,
                &mut reference,
                input,
            );
            assert_eq!(
                reference.as_ref(),
                output.as_ref(),
                "PFKS stream differs from stock operator"
            );
            VERIFIED_WORDS.fetch_add(output.as_ref().len(), Ordering::Relaxed);
        }
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_operator_matches_stock_on_signed_rounding_and_wrapping_inputs() {
        let modulus = CiphertextModulus::new_native();
        for (base, levels) in [(22, 2), (16, 3), (8, 7)] {
            let mut key = LwePrivateFunctionalPackingKeyswitchKeyOwned::new(
                0u64,
                DecompositionBaseLog(base),
                DecompositionLevelCount(levels),
                LweDimension(7),
                GlweSize(2),
                PolynomialSize(8),
                modulus,
            );
            let mut state = 0x93f1_8752_3155_caddu64;
            for word in key.as_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *word = state;
            }
            let boundary = [
                0,
                1,
                u64::MAX,
                1 << 63,
                (1 << 63) - 1,
                1 << 59,
                (1 << 42) - 1,
                1 << 42,
            ];
            for width in [1, 2, 3, 5, 8, 9] {
                let inputs: Vec<_> = (0..width)
                    .map(|lane| {
                        let words: Vec<_> = (0..8)
                            .map(|i| boundary[(i + lane) % 8].wrapping_add((lane as u64) << 17))
                            .collect();
                        Lwe::from_container(words, modulus)
                    })
                    .collect();
                let outputs = apply(&key, &inputs);
                for (input, output) in inputs.iter().zip(outputs) {
                    let mut reference = output.clone();
                    private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                        &key,
                        &mut reference,
                        input,
                    );
                    assert_eq!(
                        reference.as_ref(),
                        output.as_ref(),
                        "width={width} base={base} levels={levels}"
                    );
                }
            }
        }
    }
}
