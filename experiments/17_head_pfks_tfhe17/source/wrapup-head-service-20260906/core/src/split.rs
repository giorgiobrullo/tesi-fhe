//! Untraced direct-Delta59 Head: the passed split routine with the already-passed output tables.
use tfhe::core_crypto::prelude::*;
pub use crate::wide::Keys;
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
const N: usize = 2048;
const DELTA: u64 = 1 << 58;

fn scalar(input: &Lwe, multiplier: u64) -> Lwe {
    let mut output = input.clone();
    for word in output.as_mut() {
        *word = word.wrapping_mul(multiplier);
    }
    output
}

fn add(left: &Lwe, right: &Lwe) -> Lwe {
    let mut output = left.clone();
    lwe_ciphertext_add_assign(&mut output, right);
    output
}

fn accumulator(values: &[u64]) -> Glwe {
    assert_eq!(values.len(), 32);
    let mut body: Vec<_> = values.iter()
        .flat_map(|value| std::iter::repeat_n(*value, 64)).collect();
    for value in &mut body[..32] {
        *value = value.wrapping_neg();
    }
    body.rotate_left(32);
    let mut output = Glwe::new(
        0, GlweSize(2), PolynomialSize(N), CiphertextModulus::new_native(),
    );
    output.get_mut_body().as_mut().copy_from_slice(&body);
    output
}

fn extract(accumulator: &Glwe) -> Lwe {
    let mut output = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
    extract_lwe_sample_from_glwe_ciphertext(accumulator, &mut output, MonomialDegree(0));
    output
}

// The single switched object is reused by both actual scalar rotations.
fn normalizer_pair(input: &Lwe, tables: &[Vec<u64>; 2], keys: &Keys<'_>) -> [Lwe; 2] {
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(keys.ksk, input, &mut small).unwrap();
    let switched = crate::a98::exact_head_start_modulus_switch(
        small, CiphertextModulusLog(12),
    ).unwrap();
    std::array::from_fn(|lane| {
        let mut accumulator = accumulator(&tables[lane]);
        blind_rotate_assign(&switched, &mut accumulator, keys.bsk);
        extract(&accumulator)
    })
}

pub fn ingress(input51: &Lwe, head_keys: &Keys<'_>, normalizer_keys: &Keys<'_>) -> [Lwe; 3] {
    let mut state = input51.clone();
    let mut digits = Vec::with_capacity(2);
    for (t, multiplier) in [(4usize, 8u64), (5, 16)] {
        let mut shifted = state.clone();
        lwe_ciphertext_plaintext_sub_assign(&mut shifted, Plaintext(DELTA));
        let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
        crate::a112::a112_local_corrected_keyswitch(head_keys.ksk, &shifted, &mut small).unwrap();
        let switched = crate::a98::exact_head_start_modulus_switch(
            small, CiphertextModulusLog(12),
        ).unwrap();
        let offset = ((1u64 << t) - 1) * (DELTA / 2);
        let values: Vec<_> = (0u64..32).map(|m| {
            (m >> (5 - t)).wrapping_mul(DELTA).wrapping_sub(offset)
        }).collect();
        let mut accumulator = accumulator(&values);
        blind_rotate_assign(&switched, &mut accumulator, head_keys.bsk);
        let mut output = extract(&accumulator);
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(offset));
        let correction = scalar(&output, 1 << (5 - t));
        lwe_ciphertext_sub_assign(&mut state, &correction);
        state = scalar(&state, multiplier);
        digits.push(output);
    }
    let residual_tables = [
        (0u64..32).map(|r| (r % 16) << 59).collect(),
        (0u64..32).map(|r| (r / 16) << 58).collect(),
    ];
    let residual = normalizer_pair(&state, &residual_tables, normalizer_keys);
    let v1 = add(&digits[1], &residual[1]);
    let carry_tables = [
        (0u64..32).map(|v| (v % 16) << 59).collect(),
        (0u64..32).map(|v| (v / 16) << 59).collect(),
    ];
    let carry = normalizer_pair(&v1, &carry_tables, normalizer_keys);
    let top = add(&scalar(&digits[0], 2), &carry[1]);
    [residual[0].clone(), carry[0].clone(), top]
}
