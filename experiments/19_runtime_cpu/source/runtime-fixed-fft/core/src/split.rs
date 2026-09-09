//! Untraced direct-Delta59 Head: the passed split routine with the already-passed output tables.
use tfhe::core_crypto::prelude::*;
pub use crate::wide::Keys;
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
const N: usize = 2048;
const DELTA: u64 = 1 << 58;

#[cfg(feature = "opt-lut-cache")]
#[derive(Clone, Copy)]
enum CachedTable {
    Head4,
    Head5,
    ResidualLow,
    ResidualCarry,
    CarryLow,
    CarryTop,
}

#[cfg(not(feature = "opt-lut-cache"))]
type NormalizerTables = [Vec<u64>; 2];
#[cfg(feature = "opt-lut-cache")]
type NormalizerTables = [CachedTable; 2];

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

fn accumulator_body(values: &[u64]) -> Vec<u64> {
    assert_eq!(values.len(), 32);
    let mut body: Vec<_> = values.iter()
        .flat_map(|value| std::iter::repeat_n(*value, 64)).collect();
    for value in &mut body[..32] {
        *value = value.wrapping_neg();
    }
    body.rotate_left(32);
    body
}

fn accumulator_from_body(body: &[u64]) -> Glwe {
    assert_eq!(body.len(), N);
    let mut output = Glwe::new(
        0, GlweSize(2), PolynomialSize(N), CiphertextModulus::new_native(),
    );
    output.get_mut_body().as_mut().copy_from_slice(body);
    output
}

#[cfg(any(test, not(feature = "opt-lut-cache")))]
fn accumulator(values: &[u64]) -> Glwe {
    accumulator_from_body(&accumulator_body(values))
}

#[cfg(feature = "opt-lut-cache")]
fn cached_body(table: CachedTable) -> &'static [u64] {
    static BODIES: std::sync::OnceLock<[Vec<u64>; 6]> = std::sync::OnceLock::new();
    &BODIES.get_or_init(|| {
        let head = |t: usize| {
            let offset = ((1u64 << t) - 1) * (DELTA / 2);
            (0u64..32).map(|m| {
                (m >> (5 - t)).wrapping_mul(DELTA).wrapping_sub(offset)
            }).collect::<Vec<_>>()
        };
        let tables: [Vec<u64>; 6] = [
            head(4),
            head(5),
            (0u64..32).map(|r| (r % 16) << 59).collect(),
            (0u64..32).map(|r| (r / 16) << 58).collect(),
            (0u64..32).map(|v| (v % 16) << 59).collect(),
            (0u64..32).map(|v| (v / 16) << 59).collect(),
        ];
        tables.map(|values| accumulator_body(&values))
    })[table as usize]
}

#[cfg(feature = "opt-lut-cache")]
fn cached_accumulator(table: CachedTable) -> Glwe {
    // Only immutable body bytes are retained; each BR receives a fresh zero mask.
    accumulator_from_body(cached_body(table))
}

fn extract(accumulator: &Glwe) -> Lwe {
    let mut output = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
    extract_lwe_sample_from_glwe_ciphertext(accumulator, &mut output, MonomialDegree(0));
    output
}

// The single switched object is reused by both actual scalar rotations.
fn normalizer_pair(input: &Lwe, tables: &NormalizerTables, keys: &Keys<'_>) -> [Lwe; 2] {
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(keys.ksk, input, &mut small).unwrap();
    let switched = crate::a98::exact_head_start_modulus_switch(
        small, CiphertextModulusLog(12),
    ).unwrap();
    std::array::from_fn(|lane| {
        #[cfg(not(feature = "opt-lut-cache"))]
        let mut accumulator = accumulator(&tables[lane]);
        #[cfg(feature = "opt-lut-cache")]
        let mut accumulator = cached_accumulator(tables[lane]);
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
        #[cfg(not(feature = "opt-lut-cache"))]
        let values: Vec<_> = (0u64..32).map(|m| {
            (m >> (5 - t)).wrapping_mul(DELTA).wrapping_sub(offset)
        }).collect();
        #[cfg(not(feature = "opt-lut-cache"))]
        let mut accumulator = accumulator(&values);
        #[cfg(feature = "opt-lut-cache")]
        let mut accumulator = cached_accumulator(match t {
            4 => CachedTable::Head4,
            5 => CachedTable::Head5,
            _ => unreachable!("the ingress uses only the fixed Head4 and Head5 tables"),
        });
        blind_rotate_assign(&switched, &mut accumulator, head_keys.bsk);
        let mut output = extract(&accumulator);
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(offset));
        let correction = scalar(&output, 1 << (5 - t));
        lwe_ciphertext_sub_assign(&mut state, &correction);
        state = scalar(&state, multiplier);
        digits.push(output);
    }
    #[cfg(not(feature = "opt-lut-cache"))]
    let residual_tables = [
        (0u64..32).map(|r| (r % 16) << 59).collect(),
        (0u64..32).map(|r| (r / 16) << 58).collect(),
    ];
    #[cfg(feature = "opt-lut-cache")]
    let residual_tables = [CachedTable::ResidualLow, CachedTable::ResidualCarry];
    let residual = normalizer_pair(&state, &residual_tables, normalizer_keys);
    let v1 = add(&digits[1], &residual[1]);
    #[cfg(not(feature = "opt-lut-cache"))]
    let carry_tables = [
        (0u64..32).map(|v| (v % 16) << 59).collect(),
        (0u64..32).map(|v| (v / 16) << 59).collect(),
    ];
    #[cfg(feature = "opt-lut-cache")]
    let carry_tables = [CachedTable::CarryLow, CachedTable::CarryTop];
    let carry = normalizer_pair(&v1, &carry_tables, normalizer_keys);
    let top = add(&scalar(&digits[0], 2), &carry[1]);
    [residual[0].clone(), carry[0].clone(), top]
}

#[cfg(all(test, feature = "opt-lut-cache"))]
mod cache_tests {
    use super::*;

    fn table_value(table: CachedTable, message: u64) -> u64 {
        match table {
            CachedTable::Head4 => (message / 2).wrapping_mul(1 << 58)
                .wrapping_sub(15 * (1 << 57)),
            CachedTable::Head5 => message.wrapping_mul(1 << 58)
                .wrapping_sub(31 * (1 << 57)),
            CachedTable::ResidualLow | CachedTable::CarryLow => (message % 16) << 59,
            CachedTable::ResidualCarry => (message / 16) << 58,
            CachedTable::CarryTop => (message / 16) << 59,
        }
    }

    #[test]
    fn cached_ingress_bodies_preserve_every_coefficient_and_reset_mutable_state() {
        for table in [CachedTable::Head4, CachedTable::Head5, CachedTable::ResidualLow,
                      CachedTable::ResidualCarry, CachedTable::CarryLow, CachedTable::CarryTop] {
            let values: Vec<_> = (0..32).map(|message| table_value(table, message)).collect();
            let legacy = accumulator(&values);
            let mut cached = cached_accumulator(table);
            assert_eq!(cached.as_ref(), legacy.as_ref());
            assert!(cached.get_mask().as_ref().iter().all(|word| *word == 0));
            for coefficient in 0..N {
                let before_rotation = (coefficient + 32) % N;
                let value = table_value(table, (before_rotation / 64) as u64);
                let expected = if before_rotation < 32 { value.wrapping_neg() } else { value };
                assert_eq!(cached.get_body().as_ref()[coefficient], expected);
            }
            cached.as_mut().fill(u64::MAX);
            let next = cached_accumulator(table);
            assert_eq!(next.as_ref(), legacy.as_ref());
            assert!(next.ciphertext_modulus().is_native_modulus());
        }
    }
}
