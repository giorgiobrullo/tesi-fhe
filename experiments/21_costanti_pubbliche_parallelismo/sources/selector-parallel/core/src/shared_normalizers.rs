//! MVB factorization applied only to the two existing 32-state Head normalizers.
//! The full-resolution switched ciphertext and every target LUT coefficient stay
//! unchanged. Public polynomial operations act on every GLWE component.
use crate::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Scalar,
    ResidualOnly,
    CarryOnly,
    Both,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::ResidualOnly => "residual_only",
            Self::CarryOnly => "carry_only",
            Self::Both => "both",
        }
    }

    pub const fn saved_br_per_score(self) -> u64 {
        match self {
            Self::Scalar => 0,
            Self::ResidualOnly | Self::CarryOnly => 1,
            Self::Both => 2,
        }
    }

    /// Exact source-level public maps added by factor_pair on the reached scores.
    /// These are whole-GLWE operations and coefficient visits, not CPU instructions,
    /// observed instrumentation, allocations, or the separate PFKS rotations.
    pub const fn public_map_counts(self, scores: u64) -> PublicMapCounts {
        let pairs = self.saved_br_per_score() * scores;
        let residual_pairs = if matches!(self, Self::ResidualOnly | Self::Both) {
            scores
        } else {
            0
        };
        PublicMapCounts {
            shared_pairs: pairs,
            glwe_monomial_maps: 6 * pairs,
            polynomial_monomial_permutations: 12 * pairs,
            glwe_additions: 4 * pairs,
            glwe_subtractions: pairs,
            coefficient_additions: 4 * 4096 * pairs,
            coefficient_subtractions: 4096 * pairs,
            coefficient_mul16: 4096 * pairs,
            coefficient_mul2: 4096 * residual_pairs,
        }
    }

    pub(super) const fn shares(self, pair: Pair) -> bool {
        matches!(
            (self, pair),
            (Self::Both, _) | (Self::ResidualOnly, Pair::Residual) | (Self::CarryOnly, Pair::Carry)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicMapCounts {
    pub shared_pairs: u64,
    pub glwe_monomial_maps: u64,
    pub polynomial_monomial_permutations: u64,
    pub glwe_additions: u64,
    pub glwe_subtractions: u64,
    pub coefficient_additions: u64,
    pub coefficient_subtractions: u64,
    pub coefficient_mul16: u64,
    pub coefficient_mul2: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pair {
    Residual,
    Carry,
}

impl Pair {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Residual => "residual",
            Self::Carry => "carry",
        }
    }

    fn common_body(self) -> Vec<u64> {
        let delta = match self {
            Self::Residual => 58,
            Self::Carry => 59,
        };
        let mut body: Vec<u64> = (0..32u64)
            .flat_map(|r| std::iter::repeat_n((r / 16) << delta, 64))
            .collect();
        for word in &mut body[..32] {
            *word = word.wrapping_neg();
        }
        body.rotate_left(32);
        body
    }

    fn low_multiplier(self) -> u64 {
        match self {
            Self::Residual => 2,
            Self::Carry => 1,
        }
    }
}

// Sequential benchmark control only. Change mode between synchronous queries;
// the experimental worker is not a concurrent service API.
static MODE: AtomicU8 = AtomicU8::new(0);
pub fn set_mode(mode: Mode) {
    MODE.store(mode as u8, Ordering::Relaxed);
}
pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        0 => Mode::Scalar,
        1 => Mode::ResidualOnly,
        2 => Mode::CarryOnly,
        3 => Mode::Both,
        _ => unreachable!("only Mode values are stored"),
    }
}

pub type Switched = LazyStandardModulusSwitchedLweCiphertext<u64, usize, Vec<u64>>;

pub struct PairTrace {
    pub pair: Pair,
    pub shared: bool,
    pub input: Lwe,
    pub switched: Switched,
    pub common: Option<Glwe>,
    pub outputs: [Lwe; 2],
}

pub struct IngressTrace {
    pub pairs: Vec<PairTrace>,
    pub outputs: [Lwe; 3],
}

fn rotate(ciphertext: &Glwe, degree: usize) -> Glwe {
    let mut output = ciphertext.clone();
    for mut polynomial in output.as_mut_polynomial_list().iter_mut() {
        polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial, MonomialDegree(degree));
    }
    output
}

/// Rotate the original carry LUT once, then keep the carry ciphertext unchanged.
/// The low kernel is X64*Π(j=0..3)(1+X^(64*2^j))-16*X1024,
/// with one extra factor2 for the residual pair. All components are transformed.
fn factor_pair(common: &Glwe, pair: Pair) -> [Glwe; 2] {
    assert_eq!(common.polynomial_size().0, 2048);
    let mut sum = common.clone();
    for degree in [64, 128, 256, 512] {
        let shifted = rotate(&sum, degree);
        for (word, addend) in sum.as_mut().iter_mut().zip(shifted.as_ref()) {
            *word = word.wrapping_add(*addend);
        }
    }
    let mut low = rotate(&sum, 64);
    let corner = rotate(common, 1024);
    for (word, corner) in low.as_mut().iter_mut().zip(corner.as_ref()) {
        *word = word
            .wrapping_sub(corner.wrapping_mul(16))
            .wrapping_mul(pair.low_multiplier());
    }
    [low, common.clone()]
}

pub(super) fn evaluate(
    switched: &Switched,
    keys: &wide::Keys<'_>,
    pair: Pair,
    retain_common: bool,
) -> ([Lwe; 2], Option<Glwe>) {
    let mut common = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(2048),
        CiphertextModulus::new_native(),
    );
    common
        .get_mut_body()
        .as_mut()
        .copy_from_slice(&pair.common_body());
    tfhe::core_crypto::prelude::blind_rotate_assign(switched, &mut common, keys.bsk);
    let targets = factor_pair(&common, pair);
    let outputs = targets.map(|target| {
        let mut output = Lwe::new(0, LweSize(2049), target.ciphertext_modulus());
        extract_lwe_sample_from_glwe_ciphertext(&target, &mut output, MonomialDegree(0));
        output
    });
    (outputs, retain_common.then_some(common))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sparse_target(input: &[u64], terms: &[(usize, i64)]) -> Vec<u64> {
        let mut output = vec![0u64; input.len()];
        for &(degree, multiplier) in terms {
            for (index, word) in input.iter().enumerate() {
                let exponent = index + degree;
                let value = word.wrapping_mul(multiplier as u64);
                let target = &mut output[exponent % input.len()];
                *target = if exponent < input.len() {
                    target.wrapping_add(value)
                } else {
                    target.wrapping_sub(value)
                };
            }
        }
        output
    }

    #[test]
    fn factorized_ring_operations_match_independent_sparse_convolution_on_all_components() {
        for pair in [Pair::Residual, Pair::Carry] {
            let mut common = Glwe::new(
                0,
                GlweSize(2),
                PolynomialSize(2048),
                CiphertextModulus::new_native(),
            );
            for (index, word) in common.as_mut().iter_mut().enumerate() {
                *word = (index as u64)
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .rotate_left((index % 64) as u32);
            }
            let actual = factor_pair(&common, pair);
            let low: Vec<_> = (0..16)
                .map(|j| {
                    (
                        64 + 64 * j,
                        (if j == 15 { -15 } else { 1 }) * pair.low_multiplier() as i64,
                    )
                })
                .collect();
            let carry = vec![(0, 1)];
            for (output, kernel) in actual.iter().zip([low, carry]) {
                for (input, output) in common
                    .as_ref()
                    .chunks_exact(2048)
                    .zip(output.as_ref().chunks_exact(2048))
                {
                    assert_eq!(sparse_target(input, &kernel), output);
                }
            }
        }
    }

    #[test]
    fn common_factor_reconstructs_every_target_coefficient_and_negacyclic_address() {
        for pair in [Pair::Residual, Pair::Carry] {
            let mut common = Glwe::new(
                0,
                GlweSize(2),
                PolynomialSize(2048),
                CiphertextModulus::new_native(),
            );
            common
                .get_mut_body()
                .as_mut()
                .copy_from_slice(&pair.common_body());
            let actual = factor_pair(&common, pair);
            for (lane, target) in actual.iter().enumerate() {
                let values: Vec<u64> = (0..32)
                    .map(|message| match (pair, lane) {
                        (_, 0) => (message % 16) << 59,
                        (Pair::Residual, 1) => (message / 16) << 58,
                        (Pair::Carry, 1) => (message / 16) << 59,
                        _ => unreachable!(),
                    })
                    .collect();
                let mut expected: Vec<_> = values
                    .iter()
                    .flat_map(|value| std::iter::repeat_n(*value, 64))
                    .collect();
                for value in &mut expected[..32] {
                    *value = value.wrapping_neg();
                }
                expected.rotate_left(32);
                assert!(target.get_mask().as_ref().iter().all(|word| *word == 0));
                for address in 0..4096 {
                    let sign = if address < 2048 { 1u64 } else { u64::MAX };
                    assert_eq!(
                        target.get_body().as_ref()[address % 2048].wrapping_mul(sign),
                        expected[address % 2048].wrapping_mul(sign)
                    );
                }
            }
        }
    }

    #[test]
    fn independent_mode_costs_retain_both_head_calls_and_all_keyswitches() {
        for (mode, br) in [
            (Mode::Scalar, 6),
            (Mode::ResidualOnly, 5),
            (Mode::CarryOnly, 5),
            (Mode::Both, 4),
        ] {
            assert_eq!(6 - mode.saved_br_per_score(), br);
        }
    }
}
