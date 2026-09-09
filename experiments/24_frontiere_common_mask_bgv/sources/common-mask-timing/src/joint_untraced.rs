//! Source-only CM ingress design. No build, noisy result or performance claim.
//! Existing packed score production supplies full52/low60 under the same A44 big key.
use tfhe::core_crypto::prelude::*;
use rayon::prelude::*;
include!("a34_tables.rs");
const N: usize = 2048;
const BOOL: u64 = 1 << 59;
pub type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

pub struct Keys<'a> {
    pub ksk: &'a LweKeyswitchKeyOwned<u64>,
    pub bsk: &'a FourierLweBootstrapKeyOwned,
}
#[derive(Clone, Copy)]
pub enum Mode {
    /// Both mixed-output BRs are new: 4 BR / 4 KS / 12 marginals per score.
    Joint4,
    /// Keep the tiny remainder correction in a separate scalar BR: 6 / 4 / 12.
    SplitCorrection6,
    /// Preserve the original R3 scalar feedback ciphertexts: 8 / 4 / 12.
    ScalarFeedback8,
}

#[derive(Default)]
pub struct Counts {
    pub br: usize,
    pub ks: usize,
    pub samples: usize,
    pub scalar_muls: usize,
    pub lwe_adds: usize,
    pub lwe_subs: usize,
    pub body_offsets: usize,
}
fn scale(ct: &Lwe, factor: u64, counts: &mut Counts) -> Lwe {
    let mut out = ct.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut out, Cleartext(factor));
    counts.scalar_muls += 1;
    out
}
fn add(a: &Lwe, b: &Lwe, counts: &mut Counts) -> Lwe {
    let mut out = a.clone();
    lwe_ciphertext_add_assign(&mut out, b);
    counts.lwe_adds += 1;
    out
}
fn sub(a: &Lwe, b: &Lwe, counts: &mut Counts) -> Lwe {
    let mut out = a.clone();
    lwe_ciphertext_sub_assign(&mut out, b);
    counts.lwe_subs += 1;
    out
}
fn offset(ct: &Lwe, word: u64, counts: &mut Counts) -> Lwe {
    let mut out = ct.clone();
    lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(word));
    counts.body_offsets += 1;
    out
}

// Every mask coefficient AND body is rounded at the reduced modulus then lifted.
// Rounding at log12 and changing only the body does not preserve lane alignment.
struct Lifted {
    mask: Vec<usize>,
    body: usize,
}
impl ModulusSwitchedLweCiphertext<usize> for Lifted {
    fn log_modulus(&self) -> CiphertextModulusLog {
        CiphertextModulusLog(12)
    }
    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.mask.len())
    }
    fn mask(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.mask.iter().copied()
    }
    fn body(&self) -> usize {
        self.body
    }
}
fn switched(input: &Lwe, keys: &Keys<'_>, counts: &mut Counts) -> Lwe {
    let mut out = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    keyswitch_lwe_ciphertext(keys.ksk, input, &mut out);
    counts.ks += 1;
    out
}
fn br(
    small: &Lwe,
    body: &[u64],
    stride: usize,
    offsets: &[u64],
    keys: &Keys<'_>,
    counts: &mut Counts,
) -> Vec<Lwe> {
    assert!([1, 2, 4].contains(&stride));
    assert!(!offsets.is_empty() && offsets.len() <= stride);
    assert_eq!(body.len(), N);
    let log = 12 - stride.ilog2();
    let round = |word: u64| ((word.wrapping_add(1 << (63 - log)) >> (64 - log)) as usize) * stride;
    let input = Lifted {
        mask: small
            .get_mask()
            .as_ref()
            .iter()
            .map(|word| round(*word))
            .collect(),
        body: round(*small.get_body().data),
    };
    let mut acc = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(N),
        CiphertextModulus::new_native(),
    );
    acc.get_mut_body().as_mut().copy_from_slice(body);
    blind_rotate_assign(&input, &mut acc, keys.bsk);
    counts.br += 1;
    let outputs: Vec<_> = offsets
        .iter()
        .enumerate()
        .map(|(lane, value)| {
            let mut out = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
            extract_lwe_sample_from_glwe_ciphertext(&acc, &mut out, MonomialDegree(lane));
            counts.samples += 1;
            if *value != 0 {
                lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(*value));
                counts.body_offsets += 1;
            }
            out
        })
        .collect();
    outputs
}
fn table_body(tables: &[Vec<u64>], stride: usize) -> Vec<u64> {
    assert!(!tables.is_empty() && tables.len() <= stride);
    let size = N / stride;
    let states = tables[0].len();
    assert!(states.is_power_of_two() && size % states == 0);
    let box_size = size / states;
    let mut body = vec![0; N];
    for (lane, table) in tables.iter().enumerate() {
        assert_eq!(table.len(), states);
        let mut raw: Vec<_> = table
            .iter()
            .flat_map(|v| std::iter::repeat_n(*v, box_size))
            .collect();
        for value in &mut raw[..box_size / 2] {
            *value = value.wrapping_neg();
        }
        raw.rotate_left(box_size / 2);
        for (index, value) in raw.into_iter().enumerate() {
            body[stride * index + lane] = value;
        }
    }
    body
}
fn scalar_table(input: &Lwe, table: Vec<u64>, keys: &Keys<'_>, counts: &mut Counts) -> Lwe {
    let small = switched(input, keys, counts);
    br(&small, &table_body(&[table], 1), 1, &[0], keys, counts).remove(0)
}
struct Nibble {
    correction51: Lwe,
    bits_lsb: [Lwe; 4],
}
fn nibble(
    input60: &Lwe,
    weights: [u64; 3],
    mode: Mode,
    keys: &Keys<'_>,
    counts: &mut Counts,
) -> Nibble {
    let centered = offset(input60, 1 << 59, counts);
    let small = switched(&centered, keys, counts);
    let (msb_correction54, bit3, remainder) = match mode {
        Mode::ScalarFeedback8 => {
            // These three scalar-feedback raw LUTs are the existing R3 values.
            let correction = br(
                &small,
                &vec![(1u64 << 53).wrapping_neg(); N],
                1,
                &[1 << 53],
                keys,
                counts,
            )
            .remove(0);
            let consumer57 = br(
                &small,
                &vec![(1u64 << 56).wrapping_neg(); N],
                1,
                &[1 << 56],
                keys,
                counts,
            )
            .remove(0);
            let correction60 = scale(&consumer57, 64, counts);
            let remainder = sub(input60, &correction60, counts);
            let bit = scale(&consumer57, 4, counts);
            (correction, bit, remainder)
        }
        Mode::Joint4 | Mode::SplitCorrection6 => {
            let constants = [(1u64 << 53).wrapping_neg(), (1u64 << 58).wrapping_neg()];
            let body: Vec<_> = (0..N).map(|i| constants[i % 2]).collect();
            let outputs = br(&small, &body, 2, &[1 << 53, 1 << 58], keys, counts);
            let correction60 = scale(&outputs[1], 16, counts);
            let remainder = sub(input60, &correction60, counts);
            (outputs[0].clone(), outputs[1].clone(), remainder)
        }
    };
    let small = switched(&remainder, keys, counts);
    let correction: Vec<_> = (0u64..8).map(|r| r << 51).collect();
    let bit_tables: Vec<Vec<u64>> = (0..3)
        .rev()
        .map(|bit| {
            (0u64..8)
                .map(|r| ((r >> bit) & 1) * weights[bit] * BOOL)
                .collect()
        })
        .collect();
    let (low_correction51, lower_bits) = match mode {
        Mode::Joint4 => {
            let mut tables = vec![correction];
            tables.extend(bit_tables);
            let out = br(&small, &table_body(&tables, 4), 4, &[0; 4], keys, counts);
            (out[0].clone(), out[1..].to_vec())
        }
        Mode::SplitCorrection6 | Mode::ScalarFeedback8 => {
            let correction =
                br(&small, &table_body(&[correction], 1), 1, &[0], keys, counts).remove(0);
            // Fourth lane is zero padding and is never sample-extracted.
            let bits = br(
                &small,
                &table_body(&bit_tables, 4),
                4,
                &[0; 3],
                keys,
                counts,
            );
            (correction, bits)
        }
    };
    Nibble {
        correction51: add(&msb_correction54, &low_correction51, counts),
        bits_lsb: [
            lower_bits[2].clone(),
            lower_bits[1].clone(),
            lower_bits[0].clone(),
            bit3,
        ],
    }
}

pub struct Prefix {
    pub initial_candidates: Vec<Lwe>,
    pub bits_by_level: Vec<Vec<Lwe>>,
    pub counts: Counts,
}
pub fn prefix(full52: &[Lwe], low60: &[Lwe], mode: Mode, keys: &Keys<'_>, parallel: bool) -> Prefix {
    assert_eq!((full52.len(), low60.len()), (16, 16));
    assert_eq!(keys.bsk.input_lwe_dimension().0, 859);
    assert!(keys.ksk.ciphertext_modulus().is_native_modulus());
    assert!(full52
        .iter()
        .chain(low60)
        .all(|ct| ct.lwe_size() == LweSize(2049) && ct.ciphertext_modulus().is_native_modulus()));
    assert_eq!(
        (
            keys.ksk.input_key_lwe_dimension().0,
            keys.ksk.output_key_lwe_dimension().0
        ),
        (2048, 859)
    );
    assert_eq!(
        (
            keys.ksk.decomposition_base_log().0,
            keys.ksk.decomposition_level_count().0
        ),
        (3, 5)
    );
    assert_eq!(
        (
            keys.bsk.decomposition_base_log().0,
            keys.bsk.decomposition_level_count().0
        ),
        (23, 1)
    );
    assert_eq!(
        (keys.bsk.glwe_size().0, keys.bsk.polynomial_size().0),
        (2, N)
    );
    let mut counts = Counts::default();
    let rows = jobs(16, parallel, &mut counts, |index, counts| {
        let full = &full52[index];
        let packed = &low60[index];
        let low = nibble(packed, [2, 4, 8], mode, keys, counts);
        let correction = scale(&low.correction51, 2, counts);
        let residual = sub(full, &correction, counts);
        let middle_input = scale(&residual, 16, counts);
        let middle = nibble(&middle_input, [1, 1, 1], mode, keys, counts);
        let correction = scale(&middle.correction51, 32, counts);
        let top = sub(&residual, &correction, counts);
        let bits: Vec<_> = middle.bits_lsb.iter().rev()
            .chain(low.bits_lsb.iter().rev()).cloned().collect();
        (top, bits)
    });
    let mut tops = Vec::with_capacity(16);
    let mut bits_by_level = vec![Vec::with_capacity(16); 8];
    for (top, bits) in rows {
        tops.push(top);
        for (level, bit) in bits.into_iter().enumerate() { bits_by_level[level].push(bit); }
    }
    // Same A34 tables, recurrence, pair ordering and canonical Delta59 flags.
    let codes = jobs(16, parallel, &mut counts, |index, counts| {
        scalar_table(&tops[index], (0..16).map(|x| a34_top_classifier_slot_lut(x) << 59).collect(), keys, counts)
    });
    let mut category = jobs(16, parallel, &mut counts, |index, counts| {
        let input = offset(&codes[index], 4 << 59, counts);
        scalar_table(&input, (0..16).map(|x| a34_canonical_category_lut(x) << 59).collect(), keys, counts)
    });
    while category.len() > 1 {
        assert_eq!(category.len() % 2, 0);
        category = jobs(category.len() / 2, parallel, &mut counts, |index, counts| {
            let pair = &category[index * 2..index * 2 + 2];
            let input = add(&pair[0], &pair[1], counts);
            scalar_table(&input, (0..16).map(|x| a34_pair_category_lut(x) << 59).collect(), keys, counts)
        });
    }
    let initial_candidates = jobs(16, parallel, &mut counts, |index, counts| {
        let input = add(&codes[index], &category[0], counts);
        let input = offset(&input, 4 << 59, counts);
        scalar_table(&input, (0..16).map(|x| a34_top_candidate_lut(x) << 59).collect(), keys, counts)
    });
    let expected_br = match mode {
        Mode::Joint4 => 127,
        Mode::SplitCorrection6 => 159,
        Mode::ScalarFeedback8 => 191,
    };
    assert_eq!((counts.br, counts.ks, counts.samples), (expected_br, 127, 255));
    Prefix { initial_candidates, bits_by_level, counts }
}

fn jobs<T: Send, F: Fn(usize, &mut Counts) -> T + Sync>(
    n: usize, parallel: bool, counts: &mut Counts, f: F,
) -> Vec<T> {
    let evaluate = |index| {
        let mut local = Counts::default();
        let output = f(index, &mut local);
        (output, local)
    };
    let rows: Vec<_> = if parallel {
        (0..n).into_par_iter().map(evaluate).collect()
    } else {
        (0..n).map(evaluate).collect()
    };
    rows.into_iter().map(|(output, local)| {
        counts.br += local.br;
        counts.ks += local.ks;
        counts.samples += local.samples;
        counts.scalar_muls += local.scalar_muls;
        counts.lwe_adds += local.lwe_adds;
        counts.lwe_subs += local.lwe_subs;
        counts.body_offsets += local.body_offsets;
        output
    }).collect()
}
