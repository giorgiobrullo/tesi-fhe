//! Plain-policy N16 arithmetic from frozen persistent.rs, without diagnostic captures.
use super::*;

fn plain_pbs(
    key: &EvaluationKeys,
    input: &Cm,
    lut: &CmGlweCiphertextOwned<u64>,
    counts: &mut Counts,
) -> Cm {
    // Preserve the Plain branch's input/pool contract; it performs no correction.
    let cm = CM_PARAM_4_2_MINUS_64;
    assert_eq!(input.lwe_dimension(), cm.lwe_dimension);
    assert_eq!(input.cm_dimension(), cm.cm_dimension);
    assert_eq!(input.ciphertext_modulus(), cm.ciphertext_modulus);
    assert_eq!(input.ciphertext_modulus(), CiphertextModulus::new_native());
    assert_eq!(key.cm_zero_pool.lwe_dimension(), cm.lwe_dimension);
    assert_eq!(key.cm_zero_pool.cm_dimension(), cm.cm_dimension);
    assert_eq!(key.cm_zero_pool.ciphertext_modulus(), cm.ciphertext_modulus);
    assert_eq!(key.cm_zero_pool.cm_lwe_ciphertext_count(), cm.max_nb_zeros_n);
    let mut output = cm_zero(true);
    programmable_bootstrap_cm_lwe_ciphertext(input, &mut output, lut, &key.cm_fbsk);
    counts.cm_pbs += 1;
    output
}

fn ingress(key: &EvaluationKeys, active: &[Lwe], counts: &mut Counts) -> Vec<Cm> {
    assert_eq!(active.len(), 16);
    let identity = cm_lut(|x| x);
    active.chunks_exact(4).map(|inputs| {
        let scaled_inputs: Vec<_> = inputs.iter().map(|x| scaled(x, 4)).collect();
        let small = pack(key, &scaled_inputs, counts);
        plain_pbs(key, &small, &identity, counts)
    }).collect()
}

fn round(
    key: &EvaluationKeys,
    active: &[Cm],
    bits: &[Lwe],
    layout: Layout,
    counts: &mut Counts,
) -> Vec<Cm> {
    assert_eq!(active.len(), 4);
    assert_eq!(bits.len(), 16);
    let zero_cm = cm_lut(|x| u64::from(x == layout.alpha));
    let nonzero_cm = cm_lut(|x| u64::from(x != 0));
    let update_cm = cm_lut(|x| u64::from(x == 2));
    let nonzero_cm_to_a44 = ordinary_lut(4, |x| u64::from(x != 0));
    let nonzero_a44 = ordinary_lut(16, |x| u64::from(x != 0));
    let mut zeros_big = Vec::new();
    for group in 0..4 {
        assert_eq!(active[group].lwe_dimension(), LweDimension(1536));
        assert_eq!(active[group].cm_dimension().0, 4);
        let weighted: Vec<_> = bits[4 * group..4 * group + 4]
            .iter().map(|x| scaled(x, layout.rescale)).collect();
        let b_small = pack(key, &weighted, counts);
        let mut z_small = cm_ks(key, &active[group], counts);
        cm_lwe_ciphertext_cleartext_mul_assign(&mut z_small, Cleartext(layout.alpha));
        cm_compatible(&z_small, &b_small);
        cm_lwe_ciphertext_add_assign(&mut z_small, &b_small);
        zeros_big.push(plain_pbs(key, &z_small, &zero_cm, counts));
    }
    // Retain the actual three-plus-singleton, then two-root reduction.
    let mut roots = zeros_big.clone();
    while roots.len() > 1 {
        let mut next = Vec::new();
        for chunk in roots.chunks(3) {
            if chunk.len() == 1 {
                next.push(chunk[0].clone());
                continue;
            }
            let mut sum = chunk[0].clone();
            for item in &chunk[1..] {
                cm_compatible(&sum, item);
                cm_lwe_ciphertext_add_assign(&mut sum, item);
            }
            let small = cm_ks(key, &sum, counts);
            next.push(plain_pbs(key, &small, &nonzero_cm, counts));
        }
        roots = next;
    }
    let mut bridge = Vec::new();
    for lane in 0..LANES {
        let extracted = roots[0].extract_lwe_ciphertext(lane);
        counts.extraction += 1;
        let mut small = ordinary_zero(false);
        keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], &extracted, &mut small);
        counts.ordinary_ks += 1;
        bridge.push(small);
    }
    let mut pair_flags = Vec::new();
    for pair in 0..2 {
        let mut sum = bridge[2 * pair].clone();
        lwe_ciphertext_add_assign(&mut sum, &bridge[2 * pair + 1]);
        pair_flags.push(ordinary_pbs(key, &sum, &nonzero_cm_to_a44));
        counts.ordinary_pbs += 1;
    }
    let mut pair_sum = pair_flags[0].clone();
    lwe_ciphertext_add_assign(&mut pair_sum, &pair_flags[1]);
    let mut pair_small = ordinary_zero(false);
    keyswitch_lwe_ciphertext(&key.ordinary_ksk, &pair_sum, &mut pair_small);
    counts.ordinary_ks += 1;
    let any = ordinary_pbs(key, &pair_small, &nonzero_a44);
    counts.ordinary_pbs += 1;
    let broadcast = pack(key, &vec![scaled(&any, 4); LANES], counts);
    let mut next = Vec::new();
    for group in 0..4 {
        let mut sum = active[group].clone();
        cm_compatible(&sum, &zeros_big[group]);
        cm_lwe_ciphertext_add_assign(&mut sum, &zeros_big[group]);
        let mut small = cm_ks(key, &sum, counts);
        cm_compatible(&small, &broadcast);
        cm_lwe_ciphertext_sub_assign(&mut small, &broadcast);
        cm_lwe_ciphertext_plaintext_add_assign(&mut small, Plaintext(CM_DELTA));
        next.push(plain_pbs(key, &small, &update_cm, counts));
    }
    next
}

fn egress(key: &EvaluationKeys, states: &[Cm], counts: &mut Counts) -> Vec<Lwe> {
    assert_eq!(states.len(), 4);
    let identity = ordinary_lut(4, |x| x);
    (0..16).map(|i| {
        let lane = i % 4;
        let extracted = states[i / 4].extract_lwe_ciphertext(lane);
        counts.extraction += 1;
        let mut small = ordinary_zero(false);
        keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], &extracted, &mut small);
        counts.ordinary_ks += 1;
        let output = ordinary_pbs(key, &small, &identity);
        counts.ordinary_pbs += 1;
        output
    }).collect()
}

pub fn run(key: &EvaluationKeys, active: &[Lwe], bits: &[Vec<Lwe>]) -> (Vec<Lwe>, Counts) {
    assert_eq!(bits.len(), 8);
    let mut counts = Counts::default();
    let mut state = ingress(key, active, &mut counts);
    for (level, layout) in crate::model::LAYOUTS.iter().copied().enumerate() {
        state = round(key, &state, &bits[level], layout, &mut counts);
    }
    let outputs = egress(key, &state, &mut counts);
    (outputs, counts)
}
