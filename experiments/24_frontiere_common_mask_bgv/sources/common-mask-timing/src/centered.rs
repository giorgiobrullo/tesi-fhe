//! Server-only operations for the fixed centered-output gate. No secret key or clear oracle.
use super::*;

pub struct OrdinaryProbe {
    pub input: Lwe,
    pub raw: Lwe,
    pub output: Lwe,
    pub lut: GlweCiphertextOwned<u64>,
    pub offset: u64,
}

pub struct CmProbe {
    pub input: Cm,
    pub raw: Cm,
    pub output: Cm,
    pub lut: CmGlweCiphertextOwned<u64>,
    pub offset: u64,
}

pub struct Prepared {
    pub ordinary: Vec<OrdinaryProbe>,
    pub cm: CmProbe,
}

pub struct BridgeInputs {
    pub extracted: Vec<Lwe>,
    pub small: Vec<Lwe>,
}

pub struct Consumer {
    pub broadcast: Cm,
    pub sum_big: Cm,
    pub update: CmProbe,
}

pub fn centered_ordinary_lut() -> GlweCiphertextOwned<u64> {
    let h = A44_DELTA / 2;
    generate_programmable_bootstrap_glwe_lut(
        A44.polynomial_size,
        A44.glwe_dimension.to_glwe_size(),
        4,
        A44.ciphertext_modulus,
        1u64,
        |x| if x == 0 { 0u64.wrapping_sub(h) } else { h },
    )
}

pub fn centered_cm_lut() -> CmGlweCiphertextOwned<u64> {
    let cm = CM_PARAM_4_2_MINUS_64;
    let h = CM_DELTA / 2;
    cm_generate_programmable_bootstrap_glwe_lut(
        cm.polynomial_size,
        cm.glwe_dimension,
        cm.cm_dimension,
        4,
        cm.ciphertext_modulus,
        1u64,
        |x| if x == 0 { 0u64.wrapping_sub(h) } else { h },
    )
}

fn ordinary_call(
    key: &EvaluationKeys,
    input: &Lwe,
    lut: GlweCiphertextOwned<u64>,
    offset: u64,
    counts: &mut Counts,
) -> OrdinaryProbe {
    let raw = ordinary_pbs(key, input, &lut);
    counts.ordinary_pbs += 1;
    let mut output = raw.clone();
    if offset != 0 {
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(offset));
    }
    OrdinaryProbe {
        input: input.clone(),
        raw,
        output,
        lut,
        offset,
    }
}

fn cm_call(
    key: &EvaluationKeys,
    input: &Cm,
    lut: CmGlweCiphertextOwned<u64>,
    offset: u64,
    counts: &mut Counts,
) -> CmProbe {
    let mut events = Vec::new();
    let raw = cm_pbs(
        key,
        input,
        &lut,
        counts,
        Policy::Plain,
        "centered_gate",
        &mut events,
    )
    .expect("Plain policy must execute exactly once");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].zero_additions, 0);
    let mut output = raw.clone();
    if offset != 0 {
        cm_lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(offset));
    }
    CmProbe {
        input: input.clone(),
        raw,
        output,
        lut,
        offset,
    }
}

pub fn prepare(key: &EvaluationKeys, small_flags: &[Lwe], counts: &mut Counts) -> Prepared {
    assert_eq!(small_flags.len(), LANES);
    let ordinary: Vec<_> = small_flags
        .iter()
        .map(|input| ordinary_call(key, input, ordinary_lut(16, |x| x), 0, counts))
        .collect();
    let scaled_flags: Vec<_> = ordinary.iter().map(|p| scaled(&p.output, 4)).collect();
    let packed = pack(key, &scaled_flags, counts);
    let cm = cm_call(key, &packed, cm_lut(|x| x), 0, counts);
    Prepared { ordinary, cm }
}

pub fn bridge_inputs(key: &EvaluationKeys, root: &Cm, counts: &mut Counts) -> BridgeInputs {
    let extracted: Vec<_> = (0..LANES)
        .map(|lane| root.extract_lwe_ciphertext(lane))
        .collect();
    let small = extracted
        .iter()
        .enumerate()
        .map(|(lane, input)| {
            let mut out = ordinary_zero(false);
            keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], input, &mut out);
            counts.extraction += 1;
            counts.ordinary_ks += 1;
            out
        })
        .collect();
    BridgeInputs { extracted, small }
}

fn ordinary_sum(values: &[Lwe]) -> Lwe {
    assert!(!values.is_empty());
    let mut sum = values[0].clone();
    for input in &values[1..] {
        lwe_ciphertext_add_assign(&mut sum, input);
    }
    sum
}

fn cm_sum(values: &[Cm]) -> Cm {
    assert!(!values.is_empty());
    let mut sum = values[0].clone();
    for input in &values[1..] {
        cm_compatible(&sum, input);
        cm_lwe_ciphertext_add_assign(&mut sum, input);
    }
    sum
}

/// Preserved two pair PBS, one ordinary KS, and one final PBS.
pub fn bridge_control(
    key: &EvaluationKeys,
    small: &[Lwe],
    counts: &mut Counts,
) -> Vec<OrdinaryProbe> {
    assert_eq!(small.len(), LANES);
    let mut probes: Vec<_> = small
        .chunks_exact(2)
        .map(|pair| {
            ordinary_call(
                key,
                &ordinary_sum(pair),
                ordinary_lut(4, |x| u64::from(x != 0)),
                0,
                counts,
            )
        })
        .collect();
    let sum = ordinary_sum(&probes.iter().map(|p| p.output.clone()).collect::<Vec<_>>());
    let mut small_sum = ordinary_zero(false);
    keyswitch_lwe_ciphertext(&key.ordinary_ksk, &sum, &mut small_sum);
    counts.ordinary_ks += 1;
    probes.push(ordinary_call(
        key,
        &small_sum,
        ordinary_lut(16, |x| u64::from(x != 0)),
        0,
        counts,
    ));
    probes
}

pub fn bridge_candidate(key: &EvaluationKeys, small: &[Lwe], counts: &mut Counts) -> OrdinaryProbe {
    assert_eq!(small.len(), LANES);
    ordinary_call(
        key,
        &ordinary_sum(small),
        centered_ordinary_lut(),
        A44_DELTA / 2,
        counts,
    )
}

/// Preserved 3+1 then two-input CM reduction, with intermediate refresh.
pub fn reduction_control(key: &EvaluationKeys, groups: &[Cm], counts: &mut Counts) -> Vec<CmProbe> {
    assert_eq!(groups.len(), 4);
    let first_small = cm_ks(key, &cm_sum(&groups[..3]), counts);
    let first = cm_call(key, &first_small, cm_lut(|x| u64::from(x != 0)), 0, counts);
    let final_sum = cm_sum(&[first.output.clone(), groups[3].clone()]);
    let final_small = cm_ks(key, &final_sum, counts);
    let last = cm_call(key, &final_small, cm_lut(|x| u64::from(x != 0)), 0, counts);
    vec![first, last]
}

pub fn reduction_candidate(key: &EvaluationKeys, groups: &[Cm], counts: &mut Counts) -> CmProbe {
    assert_eq!(groups.len(), 4);
    let small = cm_ks(key, &cm_sum(groups), counts);
    cm_call(key, &small, centered_cm_lut(), CM_DELTA / 2, counts)
}

/// Exact retained broadcast and active+zero-any+1 update. Fixture active is a real CM PBS output.
pub fn consume(
    key: &EvaluationKeys,
    active: &Cm,
    zero: &Cm,
    any: &Lwe,
    counts: &mut Counts,
) -> Consumer {
    let broadcast = pack(key, &vec![scaled(any, 4); LANES], counts);
    let sum_big = cm_sum(&[active.clone(), zero.clone()]);
    let mut small = cm_ks(key, &sum_big, counts);
    cm_compatible(&small, &broadcast);
    cm_lwe_ciphertext_sub_assign(&mut small, &broadcast);
    cm_lwe_ciphertext_plaintext_add_assign(&mut small, Plaintext(CM_DELTA));
    let update = cm_call(key, &small, cm_lut(|x| u64::from(x == 2)), 0, counts);
    Consumer {
        broadcast,
        sum_big,
        update,
    }
}

// Append-only integrated N16 child; all passed primitive source bytes above are unchanged.
pub mod integrated {
    include!("integrated.rs");
}
