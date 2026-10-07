//! Isolated stock KS32 primitive adapter. This is not the A62 graph or a secure custom profile.
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::ks32::KS32AtomicPatternServerKey;
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey};

pub struct RotationWitness {
    pub centered_small: LweCiphertextOwned<u32>,
    pub body_correction: u32,
    pub switched_mask: Vec<usize>,
    pub switched_body: usize,
    pub outputs: Vec<LweCiphertextOwned<u64>>,
}

pub fn require_stock_geometry(key: &KS32AtomicPatternServerKey) {
    let ksk = &key.key_switching_key;
    assert_eq!(ksk.input_key_lwe_dimension(), LweDimension(2048));
    assert_eq!(ksk.output_key_lwe_dimension(), LweDimension(918));
    assert_eq!(ksk.decomposition_base_log(), DecompositionBaseLog(4));
    assert_eq!(ksk.decomposition_level_count(), DecompositionLevelCount(4));
    assert!(ksk.ciphertext_modulus().is_native_modulus());
    assert!(key.ciphertext_modulus.is_native_modulus());
    match &key.bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => {
            assert_eq!(bsk.input_lwe_dimension(), LweDimension(918));
            assert_eq!(bsk.output_lwe_dimension(), LweDimension(2048));
            assert_eq!(bsk.polynomial_size(), PolynomialSize(2048));
            assert_eq!(bsk.glwe_size(), GlweSize(2));
            assert_eq!(bsk.decomposition_base_log(), DecompositionBaseLog(23));
            assert_eq!(bsk.decomposition_level_count(), DecompositionLevelCount(1));
            assert!(matches!(
                modulus_switch_noise_reduction_key,
                ModulusSwitchConfiguration::CenteredMeanNoiseReduction
            ));
        }
        _ => panic!("A144 only binds the stock classic CMNR KS32 primitive"),
    }
}

/// Pass the ORIGINAL large u64 coefficients; never pre-round or cast their masks to u32.
/// The caller performs A44 residual multiplication before this operation.
pub fn switch_large(
    key: &KS32AtomicPatternServerKey,
    input: &LweCiphertextOwned<u64>,
) -> LweCiphertextOwned<u32> {
    require_stock_geometry(key);
    assert_eq!(input.lwe_size(), LweSize(2049));
    assert!(input.ciphertext_modulus().is_native_modulus());
    let mut small = LweCiphertext::new(0u32, LweSize(919), CiphertextModulus::new_native());
    keyswitch_lwe_ciphertext_with_scalar_change(&key.key_switching_key, input, &mut small);
    small
}

/// Reusable small bit: center AFTER KS with 2^29 for the dual LUT (2^30 for single).
/// LUT body and output remain native u64, including negative half-polynomial coefficients.
pub fn rotate_and_extract(
    key: &KS32AtomicPatternServerKey,
    small: &LweCiphertextOwned<u32>,
    center_u32: u32,
    accumulator: &GlweCiphertextOwned<u64>,
    degrees: &[usize],
) -> RotationWitness {
    require_stock_geometry(key);
    assert_eq!(small.lwe_size(), LweSize(919));
    assert!(small.ciphertext_modulus().is_native_modulus());
    assert_eq!(accumulator.polynomial_size(), PolynomialSize(2048));
    assert_eq!(accumulator.glwe_size(), GlweSize(2));
    assert!(accumulator.ciphertext_modulus().is_native_modulus());
    assert!(!degrees.is_empty() && degrees.iter().all(|&degree| degree < 2048));
    let ShortintBootstrappingKey::Classic {
        bsk,
        modulus_switch_noise_reduction_key,
    } = &key.bootstrapping_key
    else {
        unreachable!()
    };
    let mut centered_small = small.clone();
    lwe_ciphertext_plaintext_add_assign(&mut centered_small, Plaintext(center_u32));
    let switched = modulus_switch_noise_reduction_key.lwe_ciphertext_modulus_switch::<usize, _>(
        &centered_small,
        PolynomialSize(2048).to_blind_rotation_input_modulus_log(),
    );
    let (_, body_correction, _) = switched.as_view().into_raw_parts();
    let switched_mask = switched.mask().collect();
    let switched_body = switched.body();
    let mut rotated = accumulator.clone();
    // The exact returned lazy ciphertext is consumed; no Standard convenience-PBS bypass.
    blind_rotate_assign(&switched, &mut rotated, bsk);
    let outputs = degrees
        .iter()
        .map(|&degree| {
            let mut out = LweCiphertext::new(0u64, LweSize(2049), CiphertextModulus::new_native());
            extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut out, MonomialDegree(degree));
            out
        })
        .collect();
    RotationWitness {
        centered_small,
        body_correction,
        switched_mask,
        switched_body,
        outputs,
    }
}
