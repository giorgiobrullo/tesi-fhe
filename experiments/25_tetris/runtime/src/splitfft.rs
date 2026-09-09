//! TFHE1.7 port of the primary RevHomTrace split-FFT GLWE keyswitch operator.
//!
//! Source: Stirling75/RevHomTrace commit47c8f6f6b65a451a14b542dc45c873f1e962decd,
//! src/fourier_glwe_keyswitch.rs (MIT license retained alongside this file).
//! The primary source stores negative-secret keys with ascending gadget levels;
//! TFHE1.7 standard keys encrypt positive secrets and store descending levels.
//! Therefore this port subtracts products and uses native physical level order.
//! It does not execute the primary repository or reuse cross-version key bytes.
use tfhe::core_crypto::fft_impl::fft64::{
    c64,
    math::{fft::Fft, polynomial::FourierPolynomialOwned},
};
use tfhe::core_crypto::prelude::*;

pub struct SplitFourierKs {
    data: Vec<FourierPolynomialOwned>,
    input_rank: usize,
    output_size: usize,
    polynomial_size: PolynomialSize,
    base: DecompositionBaseLog,
    levels: DecompositionLevelCount,
    split_bits: usize,
}

impl SplitFourierKs {
    /// Low b and high(64-b) limbs, matching FftType::Split(b) in the source.
    /// Use b=38 for the paper's SetI trace. This is numerical representation,
    /// not a change to the cryptographic decomposition bases or key samples.
    pub fn from_standard(key: &GlweKeyswitchKeyOwned<u64>, split_bits: usize) -> Self {
        assert!(key.ciphertext_modulus().is_native_modulus());
        assert!((1..64).contains(&split_bits));
        let polynomial_size = key.polynomial_size();
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let mut scratch = ComputationBuffers::new();
        scratch.resize(fft.forward_scratch().unaligned_bytes_required());
        let low_mask = (1u64 << split_bits) - 1;
        let mut data = Vec::new();
        for polynomial in key.as_ref().chunks_exact(polynomial_size.0) {
            for limb in 0..2 {
                let pieces: Vec<_> = polynomial
                    .iter()
                    .map(|&word| {
                        if limb == 0 {
                            word & low_mask
                        } else {
                            word >> split_bits
                        }
                    })
                    .collect();
                let mut transformed = FourierPolynomialOwned::new(polynomial_size);
                fft.forward_as_torus(
                    transformed.as_mut_view(),
                    Polynomial::from_container(&pieces[..]).as_view(),
                    scratch.stack(),
                );
                data.push(transformed);
            }
        }
        let output = Self {
            data,
            input_rank: key.input_key_glwe_dimension().0,
            output_size: key.output_key_glwe_dimension().0 + 1,
            polynomial_size,
            base: key.decomposition_base_log(),
            levels: key.decomposition_level_count(),
            split_bits,
        };
        assert_eq!(
            output.data.len(),
            output.input_rank * output.levels.0 * output.output_size * 2
        );
        output
    }

    pub fn fourier_payload_bytes(&self) -> usize {
        self.data.len() * (self.polynomial_size.0 / 2) * std::mem::size_of::<c64>()
    }

    pub fn apply(&self, input: &GlweCiphertextOwned<u64>, output: &mut GlweCiphertextOwned<u64>) {
        assert_eq!(input.glwe_size().0, self.input_rank + 1);
        assert_eq!(output.glwe_size().0, self.output_size);
        assert_eq!(input.polynomial_size(), self.polynomial_size);
        assert_eq!(output.polynomial_size(), self.polynomial_size);
        assert!(input.ciphertext_modulus().is_native_modulus());
        assert!(output.ciphertext_modulus().is_native_modulus());
        let fft = Fft::new(self.polynomial_size);
        let fft = fft.as_view();
        let mut scratch = ComputationBuffers::new();
        scratch.resize(
            fft.forward_scratch()
                .unaligned_bytes_required()
                .max(fft.backward_scratch().unaligned_bytes_required()),
        );
        let mut sums: Vec<_> = (0..self.output_size * 2)
            .map(|_| FourierPolynomialOwned::new(self.polynomial_size))
            .collect();
        let decomposer = SignedDecomposer::new(self.base, self.levels);
        let mut transformed_digit = FourierPolynomialOwned::new(self.polynomial_size);
        for (mask_index, mask) in input
            .get_mask()
            .as_ref()
            .chunks_exact(self.polynomial_size.0)
            .enumerate()
        {
            let mut decomposition = decomposer.decompose_slice(mask);
            for physical_level in 0..self.levels.0 {
                let term = decomposition.next_term().expect("each native gadget level");
                assert_eq!(term.level().0, self.levels.0 - physical_level);
                fft.forward_as_integer(
                    transformed_digit.as_mut_view(),
                    Polynomial::from_container(term.as_slice()).as_view(),
                    scratch.stack(),
                );
                for column in 0..self.output_size {
                    for limb in 0..2 {
                        let index = (((mask_index * self.levels.0 + physical_level)
                            * self.output_size
                            + column)
                            * 2)
                            + limb;
                        for ((sum, &digit), &key) in sums[column * 2 + limb]
                            .data
                            .iter_mut()
                            .zip(transformed_digit.data.iter())
                            .zip(self.data[index].data.iter())
                        {
                            *sum += digit * key;
                        }
                    }
                }
            }
            assert!(decomposition.next_term().is_none());
        }
        output.as_mut().fill(0);
        output
            .get_mut_body()
            .as_mut()
            .copy_from_slice(input.get_body().as_ref());
        let mut product = Polynomial::new(0u64, self.polynomial_size);
        for (column, destination) in output
            .as_mut()
            .chunks_exact_mut(self.polynomial_size.0)
            .enumerate()
        {
            for limb in 0..2 {
                fft.backward_as_torus(
                    product.as_mut_view(),
                    sums[column * 2 + limb].as_view(),
                    scratch.stack(),
                );
                let shift = if limb == 0 { 0 } else { self.split_bits };
                for (word, &value) in destination.iter_mut().zip(product.as_ref()) {
                    *word = word.wrapping_sub(value << shift);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These synthetic matrices are a numerical implementation gate, not FHE or
    // secure-key evidence. The following noisy Tetris/consumer gate remains mandatory.
    #[test]
    fn split38_tracks_native_polynomial_operator_for_both_key_geometries() {
        let mut state = 0x5445545249532026u64;
        let mut word = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (output_rank, base, levels) in [(2, 10, 4), (1, 13, 3)] {
            let mut key = GlweKeyswitchKey::new(
                0u64,
                DecompositionBaseLog(base),
                DecompositionLevelCount(levels),
                GlweDimension(2),
                GlweDimension(output_rank),
                PolynomialSize(1024),
                CiphertextModulus::new_native(),
            );
            key.as_mut().iter_mut().for_each(|value| *value = word());
            let mut input = GlweCiphertext::new(
                0u64,
                GlweSize(3),
                PolynomialSize(1024),
                CiphertextModulus::new_native(),
            );
            input.as_mut().iter_mut().for_each(|value| *value = word());
            let mut exact = GlweCiphertext::new(
                0u64,
                GlweSize(output_rank + 1),
                PolynomialSize(1024),
                CiphertextModulus::new_native(),
            );
            keyswitch_glwe_ciphertext(&key, &input, &mut exact);
            let fourier = SplitFourierKs::from_standard(&key, 38);
            let mut approximate = exact.clone();
            fourier.apply(&input, &mut approximate);
            let maximum = exact
                .as_ref()
                .iter()
                .zip(approximate.as_ref())
                .map(|(&a, &b)| (a.wrapping_sub(b) as i64).unsigned_abs())
                .max()
                .unwrap();
            assert!(
                maximum < (1u64 << 42),
                "numerical implementation guard: {maximum}"
            );
        }
    }
}
