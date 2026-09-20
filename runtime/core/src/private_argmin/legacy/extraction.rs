//! Bit extraction and correction accumulators for the historical circuits.
use super::*;

#[derive(Clone)]
pub(super) struct CapturedExtractedBits {
    pub(super) small_lsb_first: Vec<Lwe>,
    pub(super) corrections_lsb_first: Vec<Lwe>,
    pub(super) canonical_bits_lsb_first: Vec<Option<Lwe>>,
}

#[derive(Clone)]
pub(super) struct WeightedBit {
    pub(super) ciphertext: Lwe,
}

#[derive(Clone)]
pub(super) enum CorrectionAccumulator {
    Single(Glwe),
    WithBoolean(Glwe),
}

pub(super) struct ExtractedCorrection {
    pub(super) correction: Lwe,
    pub(super) boolean: Option<Lwe>,
}

pub(super) fn fused_correction_accumulator_body(
    polynomial_size: PolynomialSize,
    alpha: u64,
    beta: u64,
) -> Vec<u64> {
    assert_eq!(polynomial_size.0 % 4, 0);
    let mut body = vec![alpha.wrapping_neg(); polynomial_size.0];
    body[polynomial_size.0 / 2..].fill(beta.wrapping_neg());
    body
}

pub(super) fn correction_from_small_bit(
    small_bit: &Lwe,
    accumulator: &CorrectionAccumulator,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    output_lwe_size: LweSize,
    alpha: u64,
    pbs_count: &AtomicU64,
) -> ExtractedCorrection {
    let modulus = small_bit.ciphertext_modulus();
    let mut centered = small_bit.clone();
    let (mut correction, boolean) = match accumulator {
        CorrectionAccumulator::Single(accumulator) => {
            lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 62));
            let mut correction = LweCiphertext::new(0u64, output_lwe_size, modulus);
            programmable_bootstrap_lwe_ciphertext(
                &centered,
                &mut correction,
                accumulator,
                fourier_bootstrap_key,
            );
            (correction, None)
        }
        CorrectionAccumulator::WithBoolean(accumulator) => {
            lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 61));
            let mut rotated = accumulator.clone();
            blind_rotate_assign(&centered, &mut rotated, fourier_bootstrap_key);

            let mut correction = LweCiphertext::new(0u64, output_lwe_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut correction, MonomialDegree(0));
            let mut boolean = LweCiphertext::new(0u64, output_lwe_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &rotated,
                &mut boolean,
                MonomialDegree(rotated.polynomial_size().0 / 2),
            );
            lwe_ciphertext_plaintext_add_assign(
                &mut boolean,
                Plaintext(1u64 << (BOOL_DELTA_LOG - 1)),
            );
            (correction, Some(boolean))
        }
    };
    pbs_count.fetch_add(1, Ordering::Relaxed);
    lwe_ciphertext_plaintext_add_assign(&mut correction, Plaintext(alpha));
    ExtractedCorrection {
        correction,
        boolean,
    }
}

/// Variante strumentata dell'algoritmo `extract_bits` di tfhe-rs 0.11.3.
///
/// La sequenza residuo -> shift -> KS -> PBS di correzione e' adattata dall'implementazione
/// Copyright (c) 2024 ZAMA, distribuita con licenza BSD-3-Clause-Clear. I termini completi sono
/// conservati in `LICENSE.tfhe-rs-BSD-3-Clause-Clear`. Questa variante conserva la correzione LWE
/// grande prima che sia sottratta dal residuo.
pub(super) fn extract_bits_with_corrections(
    input: &Lwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    correction_accumulators: &[CorrectionAccumulator],
    delta_log: u32,
    bit_count: u32,
    pbs_count: &AtomicU64,
) -> CapturedExtractedBits {
    assert_eq!(correction_accumulators.len(), bit_count as usize - 1);
    assert!(delta_log + bit_count <= 64);
    let modulus = input.ciphertext_modulus();
    let mut residual = input.clone();
    let mut small_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut corrections_lsb_first = Vec::with_capacity(bit_count as usize - 1);
    let mut canonical_bits_lsb_first = vec![None; bit_count as usize];

    for bit_index in 0..bit_count {
        let shift = 64 - delta_log - bit_index - 1;
        let mut shifted = residual.clone();
        for coefficient in shifted.as_mut() {
            *coefficient <<= shift;
        }
        let mut small = LweCiphertext::new(0u64, key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(key_switching_key, &shifted, &mut small);
        small_lsb_first.push(small.clone());
        if bit_index == bit_count - 1 {
            break;
        }

        let alpha = 1u64 << (delta_log + bit_index - 1);
        let extracted = correction_from_small_bit(
            &small,
            &correction_accumulators[bit_index as usize],
            fourier_bootstrap_key,
            input.lwe_size(),
            alpha,
            pbs_count,
        );
        lwe_ciphertext_sub_assign(&mut residual, &extracted.correction);
        corrections_lsb_first.push(extracted.correction);
        canonical_bits_lsb_first[bit_index as usize] = extracted.boolean;
    }

    CapturedExtractedBits {
        small_lsb_first,
        corrections_lsb_first,
        canonical_bits_lsb_first,
    }
}

/// Variante A34-top che applica anche l'ultima correzione e non esegue il sample terminale.
///
/// Per il ramo alto estrae/corregge esattamente b4..b7. Il residuo successivo e' quindi
/// `h=x>>8` a Delta=2^60; il KS che nel helper generico materializzava b8 non viene eseguito.
pub(super) fn extract_bits_with_all_corrections(
    input: &Lwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    correction_accumulators: &[CorrectionAccumulator],
    delta_log: u32,
    bit_count: u32,
    pbs_count: &AtomicU64,
) -> CapturedExtractedBits {
    assert_eq!(correction_accumulators.len(), bit_count as usize);
    assert!(delta_log + bit_count <= 64);
    let modulus = input.ciphertext_modulus();
    let mut residual = input.clone();
    let mut small_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut corrections_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut canonical_bits_lsb_first = vec![None; bit_count as usize];

    for bit_index in 0..bit_count {
        let shift = 64 - delta_log - bit_index - 1;
        let mut shifted = residual.clone();
        for coefficient in shifted.as_mut() {
            *coefficient <<= shift;
        }
        let mut small = LweCiphertext::new(0u64, key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(key_switching_key, &shifted, &mut small);
        small_lsb_first.push(small.clone());

        let alpha = 1u64 << (delta_log + bit_index - 1);
        let extracted = correction_from_small_bit(
            &small,
            &correction_accumulators[bit_index as usize],
            fourier_bootstrap_key,
            input.lwe_size(),
            alpha,
            pbs_count,
        );
        lwe_ciphertext_sub_assign(&mut residual, &extracted.correction);
        corrections_lsb_first.push(extracted.correction);
        canonical_bits_lsb_first[bit_index as usize] = extracted.boolean;
    }

    CapturedExtractedBits {
        small_lsb_first,
        corrections_lsb_first,
        canonical_bits_lsb_first,
    }
}
