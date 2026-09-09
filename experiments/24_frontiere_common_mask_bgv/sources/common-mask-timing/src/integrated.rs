// Server-only eight-round N16 integration, consuming actual packed-prefix outputs.
use super::*;

pub const SELECTOR_COUNTS: Counts = Counts {
    packing: 44,
    cm_ks: 72,
    cm_pbs: 76,
    ordinary_ks: 48,
    ordinary_pbs: 24,
    extraction: 48,
};

pub struct GroupZero {
    pub weighted: Vec<Lwe>,
    pub bit_pack: Cm,
    pub active_small: Cm,
    pub zero: CmProbe,
}

pub struct GroupUpdate {
    pub sum_big: Cm,
    pub sum_small: Cm,
    pub update: CmProbe,
}

pub struct Round {
    pub input: Vec<Cm>,
    pub zeros: Vec<GroupZero>,
    pub reduction_sum: Cm,
    pub reduction: CmProbe,
    pub bridge: BridgeInputs,
    pub any: OrdinaryProbe,
    pub broadcast_input: Lwe,
    pub broadcast: Cm,
    pub updates: Vec<GroupUpdate>,
    pub counts: Counts,
}

pub struct Egress {
    pub extracted: Lwe,
    pub output: OrdinaryProbe,
}

pub struct Chain {
    pub ingress_inputs: Vec<Vec<Lwe>>,
    pub ingress: Vec<CmProbe>,
    pub rounds: Vec<Round>,
    pub egress: Vec<Egress>,
    pub outputs: Vec<Lwe>,
    pub counts: Counts,
}

fn round(
    key: &EvaluationKeys,
    active: &[Cm],
    bits: &[Lwe],
    layout: Layout,
    counts: &mut Counts,
) -> Round {
    assert_eq!(active.len(), 4);
    assert_eq!(bits.len(), 16);
    let zeros: Vec<_> = (0..4)
        .map(|group| {
            let weighted: Vec<_> = bits[4 * group..4 * group + 4]
                .iter()
                .map(|x| scaled(x, layout.rescale))
                .collect();
            let bit_pack = pack(key, &weighted, counts);
            let active_small = cm_ks(key, &active[group], counts);
            let mut input = active_small.clone();
            cm_lwe_ciphertext_cleartext_mul_assign(&mut input, Cleartext(layout.alpha));
            cm_compatible(&input, &bit_pack);
            cm_lwe_ciphertext_add_assign(&mut input, &bit_pack);
            let zero = cm_call(
                key,
                &input,
                cm_lut(|x| u64::from(x == layout.alpha)),
                0,
                counts,
            );
            GroupZero {
                weighted,
                bit_pack,
                active_small,
                zero,
            }
        })
        .collect();
    let groups: Vec<_> = zeros.iter().map(|z| z.zero.output.clone()).collect();
    // Diagnostic copy of the exact public sum. reduction_candidate performs the one charged CM KS/PBS.
    let reduction_sum = cm_sum(&groups);
    let reduction = reduction_candidate(key, &groups, counts);
    let bridge = bridge_inputs(key, &reduction.output, counts);
    let any = bridge_candidate(key, &bridge.small, counts);
    let broadcast_input = scaled(&any.output, 4);
    // One packing call per round; all four update groups consume these same bytes.
    let broadcast = pack(key, &vec![broadcast_input.clone(); LANES], counts);
    let updates = (0..4)
        .map(|group| {
            let sum_big = cm_sum(&[active[group].clone(), groups[group].clone()]);
            let sum_small = cm_ks(key, &sum_big, counts);
            let mut input = sum_small.clone();
            cm_compatible(&input, &broadcast);
            cm_lwe_ciphertext_sub_assign(&mut input, &broadcast);
            cm_lwe_ciphertext_plaintext_add_assign(&mut input, Plaintext(CM_DELTA));
            let update = cm_call(key, &input, cm_lut(|x| u64::from(x == 2)), 0, counts);
            GroupUpdate {
                sum_big,
                sum_small,
                update,
            }
        })
        .collect();
    Round {
        input: active.to_vec(),
        zeros,
        reduction_sum,
        reduction,
        bridge,
        any,
        broadcast_input,
        broadcast,
        updates,
        counts: *counts,
    }
}

pub fn run(key: &EvaluationKeys, active: &[Lwe], bits: &[Vec<Lwe>]) -> Chain {
    assert_eq!(active.len(), 16);
    assert_eq!(bits.len(), 8);
    assert!(bits.iter().all(|b| b.len() == 16));
    let mut counts = Counts::default();
    let ingress_inputs: Vec<Vec<_>> = active
        .chunks_exact(4)
        .map(|row| row.iter().map(|x| scaled(x, 4)).collect())
        .collect();
    let ingress: Vec<_> = ingress_inputs
        .iter()
        .map(|row| {
            let input = pack(key, row, &mut counts);
            cm_call(key, &input, cm_lut(|x| x), 0, &mut counts)
        })
        .collect();
    let mut state: Vec<_> = ingress.iter().map(|p| p.output.clone()).collect();
    let mut rounds = Vec::with_capacity(8);
    for (level, layout) in crate::model::LAYOUTS.iter().copied().enumerate() {
        let result = round(key, &state, &bits[level], layout, &mut counts);
        state = result
            .updates
            .iter()
            .map(|p| p.update.output.clone())
            .collect();
        rounds.push(result);
    }
    let egress: Vec<_> = (0..16)
        .map(|i| {
            let lane = i % 4;
            let extracted = state[i / 4].extract_lwe_ciphertext(lane);
            counts.extraction += 1;
            let mut small = ordinary_zero(false);
            keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], &extracted, &mut small);
            counts.ordinary_ks += 1;
            let output = ordinary_call(key, &small, ordinary_lut(4, |x| x), 0, &mut counts);
            Egress { extracted, output }
        })
        .collect();
    let outputs = egress.iter().map(|e| e.output.output.clone()).collect();
    assert_eq!(counts, SELECTOR_COUNTS);
    Chain {
        ingress_inputs,
        ingress,
        rounds,
        egress,
        outputs,
        counts,
    }
}
