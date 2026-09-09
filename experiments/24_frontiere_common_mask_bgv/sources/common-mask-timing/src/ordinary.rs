//! Actual U8 A62 low-eight-bit slice: same raw bodies/KS/PBS/signed recurrence.
//! Sequential diagnostic scheduling only; no extraction/A34/scan and no timing comparison.
use super::*;
const A50_SOURCE_MULTIPLIERS: [i64; 8] = [-1, -1, -1, -1, -1, 1, -1, -1];
const A50_REDUCTION_RADIX: usize = 15;
const A38_CHUNK_END_LEVELS: [usize; 2] = [3, 7];
pub struct PbsEvent {
    pub tag: String,
    pub input: Lwe,
    pub small: Lwe,
    pub output: Lwe,
    pub lut: GlweCiphertextOwned<u64>,
}
pub struct State {
    pub tag: String,
    pub values: Vec<Lwe>,
}
pub struct Result {
    pub original_active: Vec<Lwe>,
    pub original_bits: Vec<Vec<Lwe>>,
    pub outputs: Vec<Lwe>,
    pub states: Vec<State>,
    pub events: Vec<PbsEvent>,
    pub ordinary_ks: usize,
    pub ordinary_pbs: usize,
}
fn sum_lwes(values: &[Lwe], zero: &Lwe) -> Lwe {
    let mut sum = zero.clone();
    for value in values {
        lwe_ciphertext_add_assign(&mut sum, value);
    }
    sum
}

fn scale_lwe_signed(input: &Lwe, multiplier: i64) -> Lwe {
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

fn pbs(
    key: &EvaluationKeys,
    input: &Lwe,
    lut: &GlweCiphertextOwned<u64>,
    tag: String,
    events: &mut Vec<PbsEvent>,
) -> Lwe {
    let mut switched = ordinary_zero(false);
    keyswitch_lwe_ciphertext(&key.ordinary_ksk, input, &mut switched);
    let mut output = ordinary_zero(true);
    programmable_bootstrap_lwe_ciphertext(&switched, &mut output, lut, &key.ordinary_fbsk);
    events.push(PbsEvent {
        tag,
        input: input.clone(),
        small: switched,
        output: output.clone(),
        lut: lut.clone(),
    });
    output
}

pub fn run(key: &EvaluationKeys, initial_candidates: &[Lwe], bits_by_level: &[Vec<Lwe>]) -> Result {
    assert_eq!(initial_candidates.len(), 4);
    assert_eq!(bits_by_level.len(), 8);
    let polynomial_size = A44.polynomial_size;
    let glwe_size = A44.glwe_dimension.to_glwe_size();
    let modulus = A44.ciphertext_modulus;
    let bool_delta = A44_DELTA;
    let box_size = polynomial_size.0 / 16;
    let half_box = box_size / 2;
    let raw_accumulator = |body: Vec<u64>| {
        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(body),
            modulus,
        )
    };
    let mut a50_target_one_body = vec![0u64; polynomial_size.0];
    a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);
    let mut a50_radix15_or_body = vec![0u64; polynomial_size.0];
    a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);
    let a50_target_one_accumulator = raw_accumulator(a50_target_one_body);
    let a50_radix15_or_accumulator = raw_accumulator(a50_radix15_or_body);
    let zero = ordinary_zero(true);
    let mut candidates = initial_candidates.to_vec();
    let mut events = Vec::new();
    let mut states = vec![State {
        tag: "initial".into(),
        values: candidates.clone(),
    }];
    for (level, bits) in bits_by_level.iter().enumerate() {
        assert_eq!(bits.len(), candidates.len());
        let weighted_bits: Vec<Lwe> = bits
            .iter()
            .map(|bit| scale_lwe_signed(bit, A50_SOURCE_MULTIPLIERS[level]))
            .collect();
        states.push(State {
            tag: format!("round/{level}/weighted"),
            values: weighted_bits.clone(),
        });
        let zero_candidates: Vec<Lwe> = candidates
            .iter()
            .zip(&weighted_bits)
            .enumerate()
            .map(|(i, (candidate, bit))| {
                let mut encoded = candidate.clone();
                lwe_ciphertext_add_assign(&mut encoded, bit);
                pbs(
                    key,
                    &encoded,
                    &a50_target_one_accumulator,
                    format!("round/{level}/zero/{i}"),
                    &mut events,
                )
            })
            .collect();
        states.push(State {
            tag: format!("round/{level}/zero"),
            values: zero_candidates.clone(),
        });
        let mut reduced = zero_candidates.clone();
        let mut depth = 0;
        while reduced.len() > 1 {
            reduced = reduced
                .chunks(A50_REDUCTION_RADIX)
                .enumerate()
                .map(|(node, chunk)| {
                    if chunk.len() == 1 {
                        chunk[0].clone()
                    } else {
                        pbs(
                            key,
                            &sum_lwes(chunk, &zero),
                            &a50_radix15_or_accumulator,
                            format!("round/{level}/or/{depth}/{node}"),
                            &mut events,
                        )
                    }
                })
                .collect();
            depth += 1;
        }
        let any_zero = reduced.pop().expect("nonempty A50 OR");
        states.push(State {
            tag: format!("round/{level}/any"),
            values: vec![any_zero.clone()],
        });
        let linear_candidates: Vec<Lwe> = candidates
            .iter()
            .zip(&zero_candidates)
            .map(|(candidate, zero_candidate)| {
                let mut next = candidate.clone();
                lwe_ciphertext_add_assign(&mut next, zero_candidate);
                lwe_ciphertext_sub_assign(&mut next, &any_zero);
                next
            })
            .collect();
        states.push(State {
            tag: format!("round/{level}/linear"),
            values: linear_candidates.clone(),
        });
        candidates = if A38_CHUNK_END_LEVELS.contains(&level) {
            linear_candidates
                .iter()
                .enumerate()
                .map(|(i, candidate)| {
                    pbs(
                        key,
                        candidate,
                        &a50_target_one_accumulator,
                        format!("round/{level}/refresh/{i}"),
                        &mut events,
                    )
                })
                .collect()
        } else {
            linear_candidates
        };
        states.push(State {
            tag: format!("round/{level}/output"),
            values: candidates.clone(),
        });
    }
    let count = events.len();
    Result {
        original_active: initial_candidates.to_vec(),
        original_bits: bits_by_level.to_vec(),
        outputs: candidates,
        states,
        events,
        ordinary_ks: count,
        ordinary_pbs: count,
    }
}
