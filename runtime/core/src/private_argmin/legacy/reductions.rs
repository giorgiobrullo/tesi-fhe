//! Encrypted reductions and exclusive prefixes for the historical circuits.
use super::*;

pub(super) fn compact_or<F>(mut bits: Vec<Lwe>, or_gate: &F) -> Lwe
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    while bits.len() > 1 {
        bits = bits.par_chunks(OR_BLOCK).map(or_gate).collect();
    }
    bits.pop().expect("OR non vuoto")
}

pub(super) fn sum_lwes(values: &[Lwe], zero: &Lwe) -> Lwe {
    let mut sum = zero.clone();
    for value in values {
        lwe_ciphertext_add_assign(&mut sum, value);
    }
    sum
}

pub(super) fn scale_lwe_signed(input: &Lwe, multiplier: i64) -> Lwe {
    assert_ne!(multiplier, 0);
    let mut output = input.clone();
    let magnitude = multiplier.unsigned_abs();
    if magnitude != 1 {
        lwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(magnitude));
    }
    if multiplier < 0 {
        lwe_ciphertext_opposite_assign(&mut output);
    }
    output
}

pub(super) fn radix5_exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!flags.is_empty());
    if flags.len() <= A38_REDUCTION_RADIX {
        return (0..flags.len())
            .map(|index| match index {
                0 => zero.clone(),
                1 => flags[0].clone(),
                _ => or_gate(&flags[..index]),
            })
            .collect();
    }
    let block_totals: Vec<Lwe> = flags
        .par_chunks(A38_REDUCTION_RADIX)
        .map(|block| {
            if block.len() == 1 {
                block[0].clone()
            } else {
                or_gate(block)
            }
        })
        .collect();
    let block_prefixes = radix5_exclusive_prefix_or(&block_totals, zero, or_gate);
    (0..flags.len())
        .into_par_iter()
        .map(|index| {
            let block = index / A38_REDUCTION_RADIX;
            let offset = index % A38_REDUCTION_RADIX;
            if offset == 0 {
                return block_prefixes[block].clone();
            }
            let start = block * A38_REDUCTION_RADIX;
            let mut inputs = Vec::with_capacity(offset + usize::from(block > 0));
            if block > 0 {
                inputs.push(block_prefixes[block].clone());
            }
            inputs.extend(flags[start..start + offset].iter().cloned());
            if inputs.len() == 1 {
                inputs.pop().expect("prefisso radix-5 non vuoto")
            } else {
                or_gate(&inputs)
            }
        })
        .collect()
}

pub(super) fn radix4_exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!flags.is_empty());
    if flags.len() <= OR_BLOCK {
        return (0..flags.len())
            .map(|index| match index {
                0 => zero.clone(),
                1 => flags[0].clone(),
                _ => or_gate(&flags[..index]),
            })
            .collect();
    }
    let block_totals: Vec<Lwe> = flags
        .par_chunks(OR_BLOCK)
        .map(|block| {
            if block.len() == 1 {
                block[0].clone()
            } else {
                or_gate(block)
            }
        })
        .collect();
    let block_prefixes = radix4_exclusive_prefix_or(&block_totals, zero, or_gate);
    (0..flags.len())
        .into_par_iter()
        .map(|index| {
            let block = index / OR_BLOCK;
            let offset = index % OR_BLOCK;
            if offset == 0 {
                return block_prefixes[block].clone();
            }
            let start = block * OR_BLOCK;
            let mut inputs = Vec::with_capacity(offset + usize::from(block > 0));
            if block > 0 {
                inputs.push(block_prefixes[block].clone());
            }
            inputs.extend(flags[start..start + offset].iter().cloned());
            if inputs.len() == 1 {
                inputs.pop().unwrap()
            } else {
                or_gate(&inputs)
            }
        })
        .collect()
}
