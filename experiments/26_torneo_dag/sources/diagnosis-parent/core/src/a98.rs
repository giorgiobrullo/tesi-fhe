//! Static A98 port candidate for the two public-surface Head Start adapters.
//!
//! This crate deliberately contains no key generation, FHE execution, or benchmark entrypoint.
//! It has not been compiled while neighboring live runs require timing isolation.  The companion
//! Python gate pins the upstream sources and exhausts the finite integer domains relevant to A44.

use std::fmt::{Display, Formatter};
use std::iter::FusedIterator;

use tfhe::core_crypto::prelude::{
    lwe_ciphertext_centered_binary_modulus_switch, CiphertextModulusLog, Container,
    DecompositionBaseLog, DecompositionLevelCount, LazyStandardModulusSwitchedLweCiphertext,
    LweCiphertext,
};

const TORUS_BITS: usize = u64::BITS as usize;

/// Rejected preconditions for the isolated Head Start port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadStartPortError {
    ModulusLogOutOfRange { log_modulus: usize },
    SwitchedScalarTooNarrow { log_modulus: usize },
    NonNativeCiphertextModulus,
    EmptyDecomposition,
    BaseLogOutOfRange { base_log: usize },
    DecompositionPrecisionOverflow,
    DecompositionPrecisionOutOfRange { precision: usize },
    TruncatedStateOutOfRange { state: u64, precision: usize },
    RoundedValueNotRepresentable { rounded: u64, precision: usize },
    RawPartsLogMismatch,
}

impl Display for HeadStartPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for HeadStartPortError {}

fn validate_modulus_log(log_modulus: CiphertextModulusLog) -> Result<usize, HeadStartPortError> {
    let log_modulus = log_modulus.0;
    if !(1..TORUS_BITS).contains(&log_modulus) {
        return Err(HeadStartPortError::ModulusLogOutOfRange { log_modulus });
    }
    if log_modulus > usize::BITS as usize {
        return Err(HeadStartPortError::SwitchedScalarTooNarrow { log_modulus });
    }
    Ok(log_modulus)
}

fn lifted_modulus_switch_round(value: u64, log_modulus: usize) -> u64 {
    let shift = TORUS_BITS - log_modulus;
    let rounding_bit = 1_u64 << (shift - 1);
    value.wrapping_add(rounding_bit) >> shift << shift
}

/// Compute the one-torus-unit correction omitted by the public centered modulus switch.
///
/// For every public mask coefficient, let `d_i = round(a_i) - a_i`, interpreted as an `i64`,
/// and `h_i = 2 * trunc_zero(d_i / 2) - d_i`.  The returned bit is one exactly when
/// `sum(h_i)` is negative and odd.  A98 uses `i128` only for this public-mask accumulator so its
/// sign cannot wrap for any materializable LWE ciphertext.
pub fn head_start_tie_bit(
    mask: &[u64],
    log_modulus: CiphertextModulusLog,
) -> Result<u64, HeadStartPortError> {
    let log_modulus = validate_modulus_log(log_modulus)?;
    let mut halving_error_doubled_sum = 0_i128;

    for &mask_element in mask {
        let round_error = lifted_modulus_switch_round(mask_element, log_modulus)
            .wrapping_sub(mask_element) as i64;
        let half_error = round_error / 2;
        halving_error_doubled_sum += i128::from(2 * half_error - round_error);
    }

    Ok(u64::from(
        halving_error_doubled_sum < 0 && halving_error_doubled_sum % 2 != 0,
    ))
}

/// Rebuild tfhe-rs 1.7's lazy centered result with the exact Head Start body correction.
///
/// The mask and body degrees exposed to stock `blind_rotate_assign` then match the pinned patch:
/// public centered raw correction + `half_case` + the tie bit above.  This does not claim that a
/// compiled FFT ciphertext, its numerical noise, or its runtime have already been validated.
pub fn exact_head_start_modulus_switch<Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> Result<LazyStandardModulusSwitchedLweCiphertext<u64, usize, Cont>, HeadStartPortError>
where
    Cont: Container<Element = u64>,
{
    let log = validate_modulus_log(log_modulus)?;
    if !lwe_in.ciphertext_modulus().is_native_modulus() {
        return Err(HeadStartPortError::NonNativeCiphertextModulus);
    }

    let tie_bit = head_start_tie_bit(lwe_in.get_mask().as_ref(), log_modulus)?;
    let centered: LazyStandardModulusSwitchedLweCiphertext<u64, usize, Cont> =
        lwe_ciphertext_centered_binary_modulus_switch(lwe_in, log_modulus);
    let (lwe_in, centered_correction, raw_log_modulus) = centered.into_raw_parts();
    if raw_log_modulus != log_modulus {
        return Err(HeadStartPortError::RawPartsLogMismatch);
    }

    let half_case = 1_u64 << (TORUS_BITS - log - 1);
    let head_start_correction = centered_correction
        .wrapping_add(half_case)
        .wrapping_add(tie_bit);

    Ok(LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
        lwe_in,
        head_start_correction,
        raw_log_modulus,
    ))
}

fn validate_decomposition(
    base_log: DecompositionBaseLog,
    level_count: DecompositionLevelCount,
) -> Result<(usize, usize, usize), HeadStartPortError> {
    let base_log = base_log.0;
    let level_count = level_count.0;
    if base_log == 0 || base_log >= TORUS_BITS {
        return Err(HeadStartPortError::BaseLogOutOfRange { base_log });
    }
    if level_count == 0 {
        return Err(HeadStartPortError::EmptyDecomposition);
    }
    let precision = base_log
        .checked_mul(level_count)
        .ok_or(HeadStartPortError::DecompositionPrecisionOverflow)?;
    if precision == 0 || precision >= TORUS_BITS {
        return Err(HeadStartPortError::DecompositionPrecisionOutOfRange { precision });
    }
    Ok((base_log, level_count, precision))
}

/// A mask coefficient rounded exactly as in the pinned Head Start key-switch patch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundedMaskCoefficient {
    pub rounded: u64,
    pub rounding_error: u64,
}

/// Reproduce the patch's wrapping nearest rounding to `base_log * level_count` MSBs.
pub fn round_mask_coefficient(
    value: u64,
    base_log: DecompositionBaseLog,
    level_count: DecompositionLevelCount,
) -> Result<RoundedMaskCoefficient, HeadStartPortError> {
    let (_, _, precision) = validate_decomposition(base_log, level_count)?;
    let discarded_bits = TORUS_BITS - precision;
    let rounding_mask = 1_u64 << (discarded_bits - 1);
    let selection_mask = (1_u64 << discarded_bits).wrapping_neg();
    let rounded = value.wrapping_add(rounding_mask) & selection_mask;
    Ok(RoundedMaskCoefficient {
        rounded,
        rounding_error: value.wrapping_sub(rounded),
    })
}

/// Reproduce the patch's signed arithmetic division of the aggregate wrapping correction by two.
#[must_use]
pub fn halve_wrapped_rounding_correction(correction: u64) -> u64 {
    let sign_bit = 1_u64 << (TORUS_BITS - 1);
    (correction >> 1).wrapping_add(correction & sign_bit)
}

/// Public local replacement for tfhe-rs's crate-private decomposition term.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadStartDecompositionTerm {
    level: usize,
    base_log: usize,
    value: u64,
}

impl HeadStartDecompositionTerm {
    #[must_use]
    pub fn level(&self) -> usize {
        self.level
    }

    /// Return the two's-complement torus representation consumed by scalar-multiply/subtract.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub fn signed_value(&self) -> i64 {
        self.value as i64
    }

    #[must_use]
    pub fn to_recomposition_summand(&self) -> u64 {
        self.value << (TORUS_BITS - self.base_log * self.level)
    }
}

/// Local iterator initialized from the already-truncated state used by the Head Start patch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadStartDecompositionIter {
    base_log: usize,
    level_count: usize,
    state: u64,
    current_level: usize,
    mod_b_mask: u64,
}

impl HeadStartDecompositionIter {
    /// Construct from the patch's `rounded >> (64 - precision)` state.
    pub fn from_truncated_state(
        state: u64,
        base_log: DecompositionBaseLog,
        level_count: DecompositionLevelCount,
    ) -> Result<Self, HeadStartPortError> {
        let (base_log, level_count, precision) = validate_decomposition(base_log, level_count)?;
        if state >> precision != 0 {
            return Err(HeadStartPortError::TruncatedStateOutOfRange { state, precision });
        }
        Ok(Self {
            base_log,
            level_count,
            state,
            current_level: level_count,
            mod_b_mask: (1_u64 << base_log) - 1,
        })
    }

    /// Construct from a coefficient already rounded to the requested precision.
    pub fn from_rounded_torus(
        rounded: u64,
        base_log: DecompositionBaseLog,
        level_count: DecompositionLevelCount,
    ) -> Result<Self, HeadStartPortError> {
        let (_, _, precision) = validate_decomposition(base_log, level_count)?;
        let discarded_bits = TORUS_BITS - precision;
        if rounded & ((1_u64 << discarded_bits) - 1) != 0 {
            return Err(HeadStartPortError::RoundedValueNotRepresentable { rounded, precision });
        }
        Self::from_truncated_state(rounded >> discarded_bits, base_log, level_count)
    }

    #[must_use]
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    #[must_use]
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }
}

impl Iterator for HeadStartDecompositionIter {
    type Item = HeadStartDecompositionTerm;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_level == 0 {
            return None;
        }

        // Exact local transcription of tfhe-rs 1.7's private decompose_one_level, called by the
        // pinned patch on the unbalanced truncated state.
        let residue = self.state & self.mod_b_mask;
        self.state = ((self.state as i64) >> self.base_log) as u64;
        let carry = ((residue.wrapping_sub(1) | self.state) & residue) >> (self.base_log - 1);
        self.state = self.state.wrapping_add(carry);
        let value = residue.wrapping_sub(carry << self.base_log);
        let level = self.current_level;
        self.current_level -= 1;

        Some(HeadStartDecompositionTerm {
            level,
            base_log: self.base_log,
            value,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.current_level, Some(self.current_level))
    }
}

impl ExactSizeIterator for HeadStartDecompositionIter {}
impl FusedIterator for HeadStartDecompositionIter {}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::core_crypto::prelude::CiphertextModulus;

    const A44_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(3);
    const A44_LEVEL_COUNT: DecompositionLevelCount = DecompositionLevelCount(5);

    #[test]
    fn adapter_recovers_both_tie_classes() {
        let log = CiphertextModulusLog(12);
        let step = 1_u64 << (TORUS_BITS - log.0);
        let native = CiphertextModulus::new_native();

        let tie_one = LweCiphertext::from_container(vec![step - 1, 0], native);
        let adapted = exact_head_start_modulus_switch(tie_one, log).unwrap();
        let (_, correction, _) = adapted.into_raw_parts();
        assert_eq!(correction, 1);

        let tie_zero = LweCiphertext::from_container(vec![1, 0], native);
        let adapted = exact_head_start_modulus_switch(tie_zero, log).unwrap();
        let (_, correction, _) = adapted.into_raw_parts();
        assert_eq!(correction, 0);
    }

    #[test]
    fn iterator_preserves_patch_boundary_streams() {
        let stream =
            HeadStartDecompositionIter::from_truncated_state(16_385, A44_BASE_LOG, A44_LEVEL_COUNT)
                .unwrap()
                .map(|term| (term.level(), term.signed_value()))
                .collect::<Vec<_>>();
        assert_eq!(stream, vec![(5, 1), (4, 0), (3, 0), (2, 0), (1, 4)]);

        let stream =
            HeadStartDecompositionIter::from_truncated_state(18_205, A44_BASE_LOG, A44_LEVEL_COUNT)
                .unwrap()
                .map(|term| (term.level(), term.signed_value()))
                .collect::<Vec<_>>();
        assert_eq!(stream, vec![(5, -3), (4, -4), (3, -3), (2, -4), (1, -3)]);
    }

    #[test]
    fn rounded_constructor_recomposes_every_a44_term() {
        for state in 0_u64..(1 << 15) {
            let rounded = state << (TORUS_BITS - 15);
            let recomposed = HeadStartDecompositionIter::from_rounded_torus(
                rounded,
                A44_BASE_LOG,
                A44_LEVEL_COUNT,
            )
            .unwrap()
            .fold(0_u64, |sum, term| {
                sum.wrapping_add(term.to_recomposition_summand())
            });
            assert_eq!(recomposed, rounded);
        }
    }

    #[test]
    fn invalid_inputs_fail_closed() {
        assert!(matches!(
            head_start_tie_bit(&[], CiphertextModulusLog(64)),
            Err(HeadStartPortError::ModulusLogOutOfRange { .. })
        ));
        assert!(matches!(
            HeadStartDecompositionIter::from_truncated_state(
                1 << 15,
                A44_BASE_LOG,
                A44_LEVEL_COUNT,
            ),
            Err(HeadStartPortError::TruncatedStateOutOfRange { .. })
        ));
        assert!(matches!(
            HeadStartDecompositionIter::from_rounded_torus(1, A44_BASE_LOG, A44_LEVEL_COUNT,),
            Err(HeadStartPortError::RoundedValueNotRepresentable { .. })
        ));
    }
}
