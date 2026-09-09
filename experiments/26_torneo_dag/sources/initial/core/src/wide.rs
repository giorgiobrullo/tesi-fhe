//! Direct Delta59 canonical limbs from Delta51 scores; two Head and four scalar BR calls.
use tfhe::core_crypto::prelude::*;
pub type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
const N: usize = 2048;
const DELTA: u64 = 1 << 58;

pub struct Keys<'a> {
    pub ksk: &'a LweKeyswitchKeyOwned<u64>,
    pub bsk: &'a FourierLweBootstrapKeyOwned,
}

#[derive(Default)]
pub struct Counts {
    pub br: usize,
    pub ks: usize,
    pub samples: usize,
    pub gadget_levels: usize,
}

pub struct Step {
    pub name: &'static str,
    pub input: Lwe,
    pub small: Lwe,
    pub log: usize,
    pub stride: usize,
    pub mask: Vec<usize>,
    pub body: usize,
    pub lut: Vec<u64>,
    pub offsets: Vec<u64>,
    pub raw: Vec<Lwe>,
    pub outputs: Vec<Lwe>,
}

pub fn scalar(input: &Lwe, scalar: u64) -> Lwe {
    let mut out = input.clone();
    for word in out.as_mut() {
        *word = word.wrapping_mul(scalar);
    }
    out
}

pub fn add(a: &Lwe, b: &Lwe) -> Lwe {
    let mut out = a.clone();
    lwe_ciphertext_add_assign(&mut out, b);
    out
}

fn dirty_accumulator(t: usize) -> (Glwe, u64) {
    assert!([4, 5].contains(&t));
    let offset = ((1u64 << t) - 1) * (DELTA / 2);
    let mut values = vec![0u64; N];
    for m in 0..32 {
        let value = ((m >> (5 - t)) as u64)
            .wrapping_mul(DELTA)
            .wrapping_sub(offset);
        values[m * 64..(m + 1) * 64].fill(value);
    }
    for value in &mut values[..32] {
        *value = value.wrapping_neg();
    }
    values.rotate_left(32);
    let mut accumulator = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(N),
        CiphertextModulus::new_native(),
    );
    accumulator.get_mut_body().as_mut().copy_from_slice(&values);
    (accumulator, offset)
}

struct Switch {
    mask: Vec<usize>,
    body: usize,
}
impl ModulusSwitchedLweCiphertext<usize> for Switch {
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

fn bootstrap(
    name: &'static str,
    input: &Lwe,
    mut accumulator: Glwe,
    offsets: Vec<u64>,
    log: usize,
    stride: usize,
    keys: &Keys<'_>,
    counts: &mut Counts,
) -> Step {
    assert_eq!(stride, 1usize << (12 - log));
    assert_eq!(offsets.len(), stride);
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(keys.ksk, input, &mut small).unwrap();
    counts.ks += 1;
    let base =
        crate::a98::exact_head_start_modulus_switch(small.clone(), CiphertextModulusLog(log))
            .unwrap();
    let switched = Switch {
        mask: base.mask().map(|degree| degree * stride).collect(),
        body: base.body() * stride,
    };
    let lut = accumulator.get_body().as_ref().to_vec();
    blind_rotate_assign(&switched, &mut accumulator, keys.bsk);
    counts.br += 1;
    counts.gadget_levels += keys.bsk.decomposition_level_count().0;
    let mut raw = Vec::with_capacity(offsets.len());
    let mut outputs = Vec::with_capacity(offsets.len());
    for (lane, offset) in offsets.iter().enumerate() {
        let mut sample = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
        extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut sample, MonomialDegree(lane));
        counts.samples += 1;
        let mut output = sample.clone();
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(*offset));
        raw.push(sample);
        outputs.push(output);
    }
    Step {
        name,
        input: input.clone(),
        small,
        log,
        stride,
        mask: switched.mask,
        body: switched.body,
        lut,
        offsets,
        raw,
        outputs,
    }
}


// Each pair reuses one actual corrected KS and one log12 switched ciphertext.
// Scalar accumulators use the full ring width; there are no interleaved lanes.
fn split_normalizer_pair(
    names: [&'static str; 2],
    input: &Lwe,
    tables: &[Vec<u64>; 2],
    keys: &Keys<'_>,
    counts: &mut Counts,
) -> [Step; 2] {
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(keys.ksk, input, &mut small).unwrap();
    counts.ks += 1;
    let base = crate::a98::exact_head_start_modulus_switch(
        small.clone(), CiphertextModulusLog(12),
    ).unwrap();
    let switched = Switch { mask: base.mask().collect(), body: base.body() };
    std::array::from_fn(|lane| {
        assert_eq!(tables[lane].len(), 32);
        let mut lut: Vec<_> = tables[lane].iter()
            .flat_map(|value| std::iter::repeat_n(*value, 64)).collect();
        for value in &mut lut[..32] {
            *value = value.wrapping_neg();
        }
        lut.rotate_left(32);
        let mut accumulator = Glwe::new(
            0, GlweSize(2), PolynomialSize(N), CiphertextModulus::new_native(),
        );
        accumulator.get_mut_body().as_mut().copy_from_slice(&lut);
        blind_rotate_assign(&switched, &mut accumulator, keys.bsk);
        counts.br += 1;
        counts.gadget_levels += keys.bsk.decomposition_level_count().0;
        let mut output = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator, &mut output, MonomialDegree(0),
        );
        counts.samples += 1;
        Step {
            name: names[lane], input: input.clone(), small: small.clone(),
            log: 12, stride: 1, mask: switched.mask.clone(), body: switched.body,
            lut, offsets: vec![0], raw: vec![output.clone()], outputs: vec![output],
        }
    })
}

pub struct Result {
    pub outputs: [Lwe; 3],
    pub steps: Vec<Step>,
    pub counts: Counts,
    pub residual_affine_bytes_equal: bool,
}

pub fn ingress(input51: &Lwe, head_keys: &Keys<'_>, norm_keys: &Keys<'_>) -> Result {
    let mut state = input51.clone();
    let mut steps = Vec::with_capacity(6);
    let mut counts = Counts::default();
    for (name, t, multiplier) in [("head.d0", 4usize, 8u64), ("head.d1", 5, 16)] {
        let mut shifted = state.clone();
        lwe_ciphertext_plaintext_sub_assign(&mut shifted, Plaintext(DELTA));
        let (accumulator, offset) = dirty_accumulator(t);
        let step = bootstrap(
            name,
            &shifted,
            accumulator,
            vec![offset],
            12,
            1,
            head_keys,
            &mut counts,
        );
        let correction = scalar(&step.outputs[0], 1 << (5 - t));
        lwe_ciphertext_sub_assign(&mut state, &correction);
        state = scalar(&state, multiplier);
        steps.push(step);
    }
    let mut affine = scalar(input51, 128);
    for (weight, step) in [256, 16].into_iter().zip(&steps) {
        lwe_ciphertext_sub_assign(&mut affine, &scalar(&step.outputs[0], weight));
    }
    let residual_affine_bytes_equal = affine == state;
    let residual_tables = [
        (0u64..32).map(|r| (r % 16) << 59).collect(),
        (0u64..32).map(|r| (r / 16) << 58).collect(),
    ];
    let residual = split_normalizer_pair(
        ["normalize.residual.low", "normalize.residual.carry"],
        &state, &residual_tables, norm_keys, &mut counts,
    );
    let v1 = add(&steps[1].outputs[0], &residual[1].outputs[0]);
    let carry_tables = [
        (0u64..32).map(|v| (v % 16) << 59).collect(),
        (0u64..32).map(|v| (v / 16) << 59).collect(),
    ];
    let carry = split_normalizer_pair(
        ["normalize.carry.middle", "normalize.carry.top"],
        &v1, &carry_tables, norm_keys, &mut counts,
    );
    let top = add(&scalar(&steps[0].outputs[0], 2), &carry[1].outputs[0]);
    let outputs = [residual[0].outputs[0].clone(), carry[0].outputs[0].clone(), top];
    steps.extend(residual);
    steps.extend(carry);
    Result {
        outputs,
        steps,
        counts,
        residual_affine_bytes_equal,
    }
}
