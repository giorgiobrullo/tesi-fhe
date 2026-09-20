//! Ordinary selector B: centered refresh to 4/12, then centered selection control.
//! The two address obligations are separate: refresh ±63, selection ±127.
use super::*;

pub const PAYLOAD_STRIDE: usize = 256;
pub const MAX_PAYLOADS_PER_GROUP: usize = 4;
pub const REFRESH_RADIUS: usize = 63;
pub const SELECTION_RADIUS: usize = 127;

/// This function requires a newly generated PFKS key; W287 keys are incompatible.
pub fn window_function() -> PolynomialOwned<u64> {
    let mut coefficients = vec![0u64; POLYNOMIAL_SIZE];
    coefficients[1536 - SELECTION_RADIUS..=1536 + SELECTION_RADIUS].fill(1);
    Polynomial::from_container(coefficients)
}

fn centered_keyswitch(input: &Lwe, ksk: &LweKeyswitchKeyOwned<u64>) -> Lwe {
    assert_eq!(ksk.output_key_lwe_dimension().0, 859);
    let mut small = Lwe::new(
        0, ksk.output_key_lwe_dimension().to_lwe_size(), input.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext(ksk, input, &mut small);
    mean_center::apply(small).corrected
}

/// One KS, one public mean correction, one ordinary BR and one extraction.
/// The public +8*Delta body addition is separate from payload add-backs.
pub fn refresh_to_large(
    combined: &Lwe,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> Lwe {
    assert_eq!(bsk.polynomial_size().0, POLYNOMIAL_SIZE);
    assert_eq!(bsk.glwe_size().0, GLWE_SIZE);
    let refresh_control = centered_keyswitch(combined, ksk);
    let mut accumulator = Glwe::new(
        0, bsk.glwe_size(), bsk.polynomial_size(), combined.ciphertext_modulus(),
    );
    accumulator.get_mut_body().as_mut().fill(4 * SCORE_DELTA);
    blind_rotate_assign(&refresh_control, &mut accumulator, bsk);
    let mut refreshed = Lwe::new(
        0, bsk.output_lwe_dimension().to_lwe_size(), combined.ciphertext_modulus(),
    );
    extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut refreshed, MonomialDegree(0));
    *refreshed.get_mut_body().data = refreshed.get_body().data.wrapping_add(8 * SCORE_DELTA);
    refreshed
}

/// Immutable small control shared by every payload group of one selector.
/// Total preparation: two KS, two mean corrections, one BR and one sample.
pub fn prepare_control(
    combined: &Lwe,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> Lwe {
    let refreshed = refresh_to_large(combined, ksk, bsk);
    centered_keyswitch(&refreshed, ksk)
}
