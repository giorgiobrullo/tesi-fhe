//! A112 source candidate for the Head Start R3/R4 correctness gate.
//!
//! This is deliberately not a Cargo crate yet.  It has not been type-checked, compiled, or run.
//! The two key-switch arms are kept independent until the final scalar multiply/subtract, and both
//! feed the already compiled A98-R2B modulus-switch adapter plus the stock tfhe-rs 1.7 blind rotate.

#[allow(dead_code)]
#[path = "a98.rs"]
mod a98_port;

use a98_port::{
    exact_head_start_modulus_switch, halve_wrapped_rounding_correction, round_mask_coefficient,
    HeadStartDecompositionIter,
};
use tfhe::core_crypto::algorithms::slice_algorithms::slice_wrapping_sub_scalar_mul_assign;
use tfhe::core_crypto::prelude::*;

pub const BIG_LWE_DIMENSION: usize = 2048;
pub const SMALL_LWE_DIMENSION: usize = 859;
pub const GLWE_DIMENSION: usize = 1;
pub const POLYNOMIAL_SIZE: usize = 2048;
pub const KS_BASE_LOG: usize = 3;
pub const KS_LEVEL_COUNT: usize = 5;
pub const PBS_BASE_LOG: usize = 23;
pub const PBS_LEVEL_COUNT: usize = 1;
pub const PBS_LOG_MODULUS: usize = 12;

const TORUS_BITS: usize = u64::BITS as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum A112Error {
    NonNativeCiphertextModulus,
    InputCiphertextDimension { actual: usize },
    OutputCiphertextDimension { actual: usize },
    KeyInputDimension { actual: usize },
    KeyOutputDimension { actual: usize },
    KeyDecompositionGeometry { base_log: usize, level_count: usize },
    CiphertextModulusMismatch,
    InvalidReferenceState { state: u64 },
    InvalidSecretLength { actual: usize },
    NonBinarySecret { index: usize, value: u64 },
    InvalidMaskLength { actual: usize },
    AdapterRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencePatchTerm {
    value: u64,
}

impl ReferencePatchTerm {
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }
}

/// Independent transcription of the private iterator called by the pinned Head Start patch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencePatchIter {
    state: u64,
    level: usize,
    mod_b_mask: u64,
}

impl ReferencePatchIter {
    pub fn new(state: u64) -> Result<Self, A112Error> {
        if state >= 1_u64 << (KS_BASE_LOG * KS_LEVEL_COUNT) {
            return Err(A112Error::InvalidReferenceState { state });
        }
        Ok(Self {
            state,
            level: KS_LEVEL_COUNT,
            mod_b_mask: (1_u64 << KS_BASE_LOG) - 1,
        })
    }
}

impl Iterator for ReferencePatchIter {
    type Item = ReferencePatchTerm;

    fn next(&mut self) -> Option<Self::Item> {
        if self.level == 0 {
            return None;
        }
        let residue = self.state & self.mod_b_mask;
        self.state = ((self.state as i64) >> KS_BASE_LOG) as u64;
        let carry = ((residue.wrapping_sub(1) | self.state) & residue) >> (KS_BASE_LOG - 1);
        self.state = self.state.wrapping_add(carry);
        self.level -= 1;
        Some(ReferencePatchTerm {
            value: residue.wrapping_sub(carry << KS_BASE_LOG),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.level, Some(self.level))
    }
}

impl ExactSizeIterator for ReferencePatchIter {}

fn validate_key_switch_inputs(
    key: &LweKeyswitchKeyOwned<u64>,
    input: &LweCiphertextOwned<u64>,
    output: &LweCiphertextOwned<u64>,
) -> Result<(), A112Error> {
    if !key.ciphertext_modulus().is_native_modulus()
        || !input.ciphertext_modulus().is_native_modulus()
        || !output.ciphertext_modulus().is_native_modulus()
    {
        return Err(A112Error::NonNativeCiphertextModulus);
    }
    if key.ciphertext_modulus() != input.ciphertext_modulus()
        || key.ciphertext_modulus() != output.ciphertext_modulus()
    {
        return Err(A112Error::CiphertextModulusMismatch);
    }
    let input_dimension = input.lwe_size().to_lwe_dimension().0;
    if input_dimension != BIG_LWE_DIMENSION {
        return Err(A112Error::InputCiphertextDimension {
            actual: input_dimension,
        });
    }
    let output_dimension = output.lwe_size().to_lwe_dimension().0;
    if output_dimension != SMALL_LWE_DIMENSION {
        return Err(A112Error::OutputCiphertextDimension {
            actual: output_dimension,
        });
    }
    if key.input_key_lwe_dimension().0 != BIG_LWE_DIMENSION {
        return Err(A112Error::KeyInputDimension {
            actual: key.input_key_lwe_dimension().0,
        });
    }
    if key.output_key_lwe_dimension().0 != SMALL_LWE_DIMENSION {
        return Err(A112Error::KeyOutputDimension {
            actual: key.output_key_lwe_dimension().0,
        });
    }
    if key.decomposition_base_log().0 != KS_BASE_LOG
        || key.decomposition_level_count().0 != KS_LEVEL_COUNT
    {
        return Err(A112Error::KeyDecompositionGeometry {
            base_log: key.decomposition_base_log().0,
            level_count: key.decomposition_level_count().0,
        });
    }
    Ok(())
}

/// Reference R3 arm.  Every expression mirrors the pinned patch without calling A98 helpers.
pub fn reference_patch_corrected_keyswitch(
    key: &LweKeyswitchKeyOwned<u64>,
    input: &LweCiphertextOwned<u64>,
    output: &mut LweCiphertextOwned<u64>,
) -> Result<(), A112Error> {
    validate_key_switch_inputs(key, input, output)?;
    output.as_mut().fill(0);

    let precision = KS_BASE_LOG * KS_LEVEL_COUNT;
    let rounding_mask = 1_u64 << (TORUS_BITS - precision - 1);
    let selection_mask = (1_u64 << (TORUS_BITS - precision)).wrapping_neg();
    let mut correction = 0_u64;

    for (key_block, &mask_element) in key.iter().zip(input.get_mask().as_ref()) {
        let rounded = mask_element.wrapping_add(rounding_mask) & selection_mask;
        correction = correction.wrapping_add(mask_element.wrapping_sub(rounded));
        let state = rounded >> (TORUS_BITS - precision);
        let decomposition = ReferencePatchIter::new(state)?;
        for (level_ciphertext, term) in key_block.iter().zip(decomposition) {
            slice_wrapping_sub_scalar_mul_assign(
                output.as_mut(),
                level_ciphertext.as_ref(),
                term.value(),
            );
        }
    }

    let sign_bit = 1_u64 << (TORUS_BITS - 1);
    let correction_half = (correction >> 1).wrapping_add(correction & sign_bit);
    let accumulated_body = *output.get_body().data;
    *output.get_mut_body().data = accumulated_body
        .wrapping_add(*input.get_body().data)
        .wrapping_sub(correction_half);
    Ok(())
}

/// Local R3 arm.  Rounding, digit stream, and signed half come only from the A98 public port.
pub fn a112_local_corrected_keyswitch(
    key: &LweKeyswitchKeyOwned<u64>,
    input: &LweCiphertextOwned<u64>,
    output: &mut LweCiphertextOwned<u64>,
) -> Result<(), A112Error> {
    validate_key_switch_inputs(key, input, output)?;
    output.as_mut().fill(0);

    let base_log = DecompositionBaseLog(KS_BASE_LOG);
    let level_count = DecompositionLevelCount(KS_LEVEL_COUNT);
    let mut correction = 0_u64;
    for (key_block, &mask_element) in key.iter().zip(input.get_mask().as_ref()) {
        let rounded = round_mask_coefficient(mask_element, base_log, level_count)
            .map_err(|_| A112Error::AdapterRejected)?;
        correction = correction.wrapping_add(rounded.rounding_error);
        let decomposition =
            HeadStartDecompositionIter::from_rounded_torus(rounded.rounded, base_log, level_count)
                .map_err(|_| A112Error::AdapterRejected)?;
        for (level_ciphertext, term) in key_block.iter().zip(decomposition) {
            slice_wrapping_sub_scalar_mul_assign(
                output.as_mut(),
                level_ciphertext.as_ref(),
                term.value(),
            );
        }
    }

    let accumulated_body = *output.get_body().data;
    *output.get_mut_body().data = accumulated_body
        .wrapping_add(*input.get_body().data)
        .wrapping_sub(halve_wrapped_rounding_correction(correction));
    Ok(())
}

fn reference_lifted_round(value: u64) -> u64 {
    let shift = TORUS_BITS - PBS_LOG_MODULUS;
    value.wrapping_add(1_u64 << (shift - 1)) >> shift << shift
}

fn reference_head_start_correction(mask: &[u64]) -> u64 {
    let mut residual_sum = 0_i128;
    for &mask_element in mask {
        let residual = reference_lifted_round(mask_element).wrapping_sub(mask_element) as i64;
        residual_sum += i128::from(residual);
    }
    let ceiling_half = if residual_sum >= 0 {
        (residual_sum + 1) / 2
    } else {
        residual_sum / 2
    };
    (ceiling_half as i64) as u64
}

/// Independent reference construction for R4; it does not call the centered A98 adapter.
pub fn reference_head_start_modulus_switch(
    input: LweCiphertextOwned<u64>,
) -> Result<LazyStandardModulusSwitchedLweCiphertext<u64, usize, Vec<u64>>, A112Error> {
    if !input.ciphertext_modulus().is_native_modulus() {
        return Err(A112Error::NonNativeCiphertextModulus);
    }
    if input.lwe_size().to_lwe_dimension().0 != SMALL_LWE_DIMENSION {
        return Err(A112Error::InputCiphertextDimension {
            actual: input.lwe_size().to_lwe_dimension().0,
        });
    }
    let correction = reference_head_start_correction(input.get_mask().as_ref());
    Ok(LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
        input,
        correction,
        CiphertextModulusLog(PBS_LOG_MODULUS),
    ))
}

#[derive(Clone)]
pub struct ComposedOutput {
    pub post_keyswitch: LweCiphertextOwned<u64>,
    pub post_blind_rotation: GlweCiphertextOwned<u64>,
}

fn validate_pbs_geometry(
    key: &FourierLweBootstrapKeyOwned,
    lut: &GlweCiphertextOwned<u64>,
) -> Result<(), A112Error> {
    if key.input_lwe_dimension().0 != SMALL_LWE_DIMENSION {
        return Err(A112Error::KeyInputDimension {
            actual: key.input_lwe_dimension().0,
        });
    }
    if key.output_lwe_dimension().0 != BIG_LWE_DIMENSION {
        return Err(A112Error::KeyOutputDimension {
            actual: key.output_lwe_dimension().0,
        });
    }
    if key.glwe_size().to_glwe_dimension().0 != GLWE_DIMENSION
        || key.polynomial_size().0 != POLYNOMIAL_SIZE
        || key.decomposition_base_log().0 != PBS_BASE_LOG
        || key.decomposition_level_count().0 != PBS_LEVEL_COUNT
        || lut.glwe_size() != key.glwe_size()
        || lut.polynomial_size() != key.polynomial_size()
    {
        return Err(A112Error::KeyDecompositionGeometry {
            base_log: key.decomposition_base_log().0,
            level_count: key.decomposition_level_count().0,
        });
    }
    if !lut.ciphertext_modulus().is_native_modulus() {
        return Err(A112Error::NonNativeCiphertextModulus);
    }
    Ok(())
}

/// R4 reference path: noisy big LWE -> patch-semantics KS -> direct Head Start MS -> stock PBS.
pub fn run_reference_composed(
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    input: &LweCiphertextOwned<u64>,
    lut: &GlweCiphertextOwned<u64>,
) -> Result<ComposedOutput, A112Error> {
    validate_pbs_geometry(fourier_bootstrap_key, lut)?;
    let mut small = LweCiphertextOwned::new(
        0_u64,
        LweDimension(SMALL_LWE_DIMENSION).to_lwe_size(),
        CiphertextModulus::new_native(),
    );
    reference_patch_corrected_keyswitch(key_switching_key, input, &mut small)?;
    let switched = reference_head_start_modulus_switch(small.clone())?;
    let mut output = lut.clone();
    blind_rotate_assign(&switched, &mut output, fourier_bootstrap_key);
    Ok(ComposedOutput {
        post_keyswitch: small,
        post_blind_rotation: output,
    })
}

/// R4 candidate path: the same big LWE/KSK -> A98 local KS -> R2B adapter -> stock PBS.
pub fn run_a112_composed(
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    input: &LweCiphertextOwned<u64>,
    lut: &GlweCiphertextOwned<u64>,
) -> Result<ComposedOutput, A112Error> {
    validate_pbs_geometry(fourier_bootstrap_key, lut)?;
    let mut small = LweCiphertextOwned::new(
        0_u64,
        LweDimension(SMALL_LWE_DIMENSION).to_lwe_size(),
        CiphertextModulus::new_native(),
    );
    a112_local_corrected_keyswitch(key_switching_key, input, &mut small)?;
    let switched =
        exact_head_start_modulus_switch(small.clone(), CiphertextModulusLog(PBS_LOG_MODULUS))
            .map_err(|_| A112Error::AdapterRejected)?;
    let mut output = lut.clone();
    blind_rotate_assign(&switched, &mut output, fourier_bootstrap_key);
    Ok(ComposedOutput {
        post_keyswitch: small,
        post_blind_rotation: output,
    })
}

/// Build an exact, key-consistent component fixture with a caller-chosen mask and signed error.
/// This is not a Gaussian sample and must never be counted as an honest-encryption trial.
pub fn assemble_key_consistent_large_lwe(
    big_secret: &LweSecretKeyOwned<u64>,
    mask: &[u64],
    plaintext: u64,
    signed_error: i64,
) -> Result<LweCiphertextOwned<u64>, A112Error> {
    if big_secret.as_ref().len() != BIG_LWE_DIMENSION {
        return Err(A112Error::InvalidSecretLength {
            actual: big_secret.as_ref().len(),
        });
    }
    if mask.len() != BIG_LWE_DIMENSION {
        return Err(A112Error::InvalidMaskLength { actual: mask.len() });
    }
    for (index, &bit) in big_secret.as_ref().iter().enumerate() {
        if bit > 1 {
            return Err(A112Error::NonBinarySecret { index, value: bit });
        }
    }
    let body = mask.iter().zip(big_secret.as_ref()).fold(
        plaintext.wrapping_add(signed_error as u64),
        |sum, (&a, &s)| sum.wrapping_add(a.wrapping_mul(s)),
    );
    let mut container = Vec::with_capacity(BIG_LWE_DIMENSION + 1);
    container.extend_from_slice(mask);
    container.push(body);
    Ok(LweCiphertextOwned::from_container(
        container,
        CiphertextModulus::new_native(),
    ))
}
