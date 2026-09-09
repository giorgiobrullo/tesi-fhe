//! N16 successor of A190 server-only persistent interface. No client keys/oracle values enter these functions.
use super::*;

pub struct CmResult {
    pub states: Vec<Cm>,
    pub traces: Vec<Trace>,
    pub counts: Counts,
    pub reductions: Vec<ReductionEvent>,
    pub completed: bool,
}

/// Exactly 9N actual ordinary PBS: one active vector and eight original weighted-bit vectors.
pub fn prepare(
    key: &EvaluationKeys,
    active: &[Lwe],
    bits: &[Vec<Lwe>],
) -> (Vec<Lwe>, Vec<Vec<Lwe>>, Vec<Trace>, usize) {
    assert_eq!(active.len(), 16);
    assert_eq!(bits.len(), 8);
    let mut count = 0;
    let mut traces = Vec::new();
    let identity = ordinary_lut(16, |x| x);
    let aa = active
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let out = ordinary_pbs(key, x, &identity);
            count += 1;
            trace_lwe(
                &mut traces,
                format!("prepare/active/{i}"),
                Domain::A44Big,
                &out,
            );
            out
        })
        .collect();
    let bb = bits
        .iter()
        .zip(crate::model::LAYOUTS)
        .enumerate()
        .map(|(level, (row, layout))| {
            assert_eq!(row.len(), active.len());
            let lut = ordinary_lut(16, |x| (x & 1) * layout.weight);
            row.iter()
                .enumerate()
                .map(|(i, x)| {
                    let out = ordinary_pbs(key, x, &lut);
                    count += 1;
                    trace_lwe(
                        &mut traces,
                        format!("prepare/bit/{level}/{i}"),
                        Domain::A44Big,
                        &out,
                    );
                    out
                })
                .collect()
        })
        .collect();
    (aa, bb, traces, count)
}

pub fn ingress(key: &EvaluationKeys, active: &[Lwe], policy: Policy) -> CmResult {
    assert_eq!(active.len(), 16);
    let mut counts = Counts::default();
    let mut traces = Vec::new();
    let mut reductions = Vec::new();

    macro_rules! accepted {
        ($call:expr) => {
            match $call {
                Some(value) => value,
                None => {
                    return CmResult {
                        states: Vec::new(),
                        traces,
                        counts,
                        reductions,
                        completed: false,
                    };
                }
            }
        };
    }

    let identity_cm = cm_lut(|x| x);
    let mut states = Vec::with_capacity(4);
    for (group, inputs) in active.chunks_exact(4).enumerate() {
        let aa: Vec<_> = inputs.iter().map(|x| scaled(x, 4)).collect();
        let small = pack(key, &aa, &mut counts);
        trace_cm(
            &mut traces,
            format!("ingress/active_pack/{group}"),
            Domain::CmSmall,
            &small,
        );
        let big = accepted!(cm_pbs(
            key,
            &small,
            &identity_cm,
            &mut counts,
            policy,
            &format!("ingress/active_pack/{group}"),
            &mut reductions
        ));
        trace_cm(
            &mut traces,
            format!("ingress/active_big/{group}"),
            Domain::CmBig,
            &big,
        );
        states.push(big);
    }
    CmResult {
        states,
        traces,
        counts,
        reductions,
        completed: true,
    }
}

pub fn round_cm(
    key: &EvaluationKeys,
    active: &[Cm],
    bits: &[Lwe],
    layout: Layout,
    policy: Policy,
) -> CmResult {
    assert_eq!(active.len(), 4);
    assert_eq!(bits.len(), 16);
    let groups = active.len();
    let mut counts = Counts::default();
    let mut traces = Vec::new();
    let mut reductions = Vec::new();

    macro_rules! accepted {
        ($call:expr) => {
            match $call {
                Some(value) => value,
                None => {
                    return CmResult {
                        states: Vec::new(),
                        traces,
                        counts,
                        reductions,
                        completed: false,
                    };
                }
            }
        };
    }

    let zero_cm = cm_lut(|x| u64::from(x == layout.alpha));
    let nonzero_cm = cm_lut(|x| u64::from(x != 0));
    let update_cm = cm_lut(|x| u64::from(x == 2));
    let nonzero_cm_to_a44 = ordinary_lut(4, |x| u64::from(x != 0));
    let nonzero_a44 = ordinary_lut(16, |x| u64::from(x != 0));
    let mutation = Mutation::None;
    let mut zeros_big = Vec::new();
    for group in 0..groups {
        assert_eq!(active[group].lwe_dimension(), LweDimension(1536));
        assert_eq!(active[group].cm_dimension().0, 4);
        let bb: Vec<_> = bits[4 * group..4 * group + 4]
            .iter()
            .map(|x| scaled(x, layout.rescale))
            .collect();
        let b_small = pack(key, &bb, &mut counts);
        trace_cm(
            &mut traces,
            format!("bit_pack/{group}"),
            Domain::CmSmall,
            &b_small,
        );
        let mut z_small = cm_ks(key, &active[group], &mut counts);
        trace_cm(
            &mut traces,
            format!("z_ks/{group}"),
            Domain::CmSmall,
            &z_small,
        );
        cm_lwe_ciphertext_cleartext_mul_assign(&mut z_small, Cleartext(layout.alpha));
        cm_compatible(&z_small, &b_small);
        cm_lwe_ciphertext_add_assign(&mut z_small, &b_small);
        trace_cm(
            &mut traces,
            format!("z_input/{group}"),
            Domain::CmSmall,
            &z_small,
        );
        let z_big = accepted!(cm_pbs(
            key,
            &z_small,
            &zero_cm,
            &mut counts,
            policy,
            &format!("z_input/{group}"),
            &mut reductions
        ));
        trace_cm(&mut traces, format!("z/{group}"), Domain::CmBig, &z_big);
        zeros_big.push(z_big);
    }
    // Reduce across groups, preserving four independent secret lanes. Singletons are forwarded.
    let mut roots = zeros_big.clone();
    let mut level = 0;
    while roots.len() > 1 {
        let mut next = Vec::new();
        for (node, chunk) in roots.chunks(3).enumerate() {
            if chunk.len() == 1 {
                next.push(chunk[0].clone());
                continue;
            }
            let mut sum = chunk[0].clone();
            for item in &chunk[1..] {
                cm_compatible(&sum, item);
                cm_lwe_ciphertext_add_assign(&mut sum, item);
            }
            let small = cm_ks(key, &sum, &mut counts);
            trace_cm(
                &mut traces,
                format!("reduce_input/{level}/{node}"),
                Domain::CmSmall,
                &small,
            );
            let big = accepted!(cm_pbs(
                key,
                &small,
                &nonzero_cm,
                &mut counts,
                policy,
                &format!("reduce_input/{level}/{node}"),
                &mut reductions
            ));
            trace_cm(
                &mut traces,
                format!("reduce/{level}/{node}"),
                Domain::CmBig,
                &big,
            );
            next.push(big);
        }
        roots = next;
        level += 1;
    }

    let mut bridge = Vec::new();
    for lane in 0..LANES {
        let extracted = roots[0].extract_lwe_ciphertext(lane);
        counts.extraction += 1;
        traces.push(Trace {
            tag: format!("root_extracted/{lane}"),
            domain: Domain::CmBig,
            lane,
            ct: extracted.clone(),
        });
        let mut small = ordinary_zero(false);
        keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], &extracted, &mut small);
        counts.ordinary_ks += 1;
        trace_lwe(
            &mut traces,
            format!("root_bridge/{lane}"),
            Domain::A44Small,
            &small,
        );
        bridge.push(small);
    }
    let mut pair_flags = Vec::new();
    for pair in 0..2 {
        let mut sum = bridge[2 * pair].clone();
        lwe_ciphertext_add_assign(&mut sum, &bridge[2 * pair + 1]);
        trace_lwe(
            &mut traces,
            format!("pair_input/{pair}"),
            Domain::A44Small,
            &sum,
        );
        let flag = ordinary_pbs(key, &sum, &nonzero_cm_to_a44);
        counts.ordinary_pbs += 1;
        trace_lwe(&mut traces, format!("pair/{pair}"), Domain::A44Big, &flag);
        pair_flags.push(flag);
    }
    let mut pair_sum = pair_flags[0].clone();
    lwe_ciphertext_add_assign(&mut pair_sum, &pair_flags[1]);
    trace_lwe(&mut traces, "any_big_sum".into(), Domain::A44Big, &pair_sum);
    let mut pair_small = ordinary_zero(false);
    keyswitch_lwe_ciphertext(&key.ordinary_ksk, &pair_sum, &mut pair_small);
    counts.ordinary_ks += 1;
    trace_lwe(
        &mut traces,
        "any_input".into(),
        Domain::A44Small,
        &pair_small,
    );
    let any = ordinary_pbs(key, &pair_small, &nonzero_a44);
    counts.ordinary_pbs += 1;
    trace_lwe(&mut traces, "any".into(), Domain::A44Big, &any);
    let broadcast = pack(key, &vec![scaled(&any, 4); LANES], &mut counts);
    trace_cm(&mut traces, "broadcast".into(), Domain::CmSmall, &broadcast);

    let mut next_big = Vec::new();
    for group in 0..groups {
        let mut sum = active[group].clone();
        cm_compatible(&sum, &zeros_big[group]);
        cm_lwe_ciphertext_add_assign(&mut sum, &zeros_big[group]);
        trace_cm(
            &mut traces,
            format!("update_big_sum/{group}"),
            Domain::CmBig,
            &sum,
        );
        let mut small = cm_ks(key, &sum, &mut counts);
        trace_cm(
            &mut traces,
            format!("update_sum/{group}"),
            Domain::CmSmall,
            &small,
        );
        cm_compatible(&small, &broadcast);
        cm_lwe_ciphertext_sub_assign(&mut small, &broadcast);
        if mutation != Mutation::OmitOffset {
            cm_lwe_ciphertext_plaintext_add_assign(&mut small, Plaintext(CM_DELTA));
        }
        trace_cm(
            &mut traces,
            format!("update_input/{group}"),
            Domain::CmSmall,
            &small,
        );
        let next = accepted!(cm_pbs(
            key,
            &small,
            &update_cm,
            &mut counts,
            policy,
            &format!("update_input/{group}"),
            &mut reductions
        ));
        trace_cm(&mut traces, format!("next/{group}"), Domain::CmBig, &next);
        next_big.push(next);
    }
    CmResult {
        states: next_big,
        traces,
        counts,
        reductions,
        completed: true,
    }
}

pub fn egress(key: &EvaluationKeys, states: &[Cm]) -> (Vec<Lwe>, Vec<Trace>, Counts) {
    assert_eq!(states.len(), 4);
    let mut counts = Counts::default();
    let mut traces = Vec::new();
    let mut outputs = Vec::new();
    let identity = ordinary_lut(4, |x| x);
    for i in 0..16 {
        let lane = i % 4;
        let extracted = states[i / 4].extract_lwe_ciphertext(lane);
        counts.extraction += 1;
        traces.push(Trace {
            tag: format!("egress/extracted/{i}"),
            domain: Domain::CmBig,
            lane,
            ct: extracted.clone(),
        });
        let mut small = ordinary_zero(false);
        keyswitch_lwe_ciphertext(&key.lane_to_a44[lane], &extracted, &mut small);
        counts.ordinary_ks += 1;
        trace_lwe(
            &mut traces,
            format!("egress/small/{i}"),
            Domain::A44Small,
            &small,
        );
        let out = ordinary_pbs(key, &small, &identity);
        counts.ordinary_pbs += 1;
        trace_lwe(
            &mut traces,
            format!("egress/output/{i}"),
            Domain::A44Big,
            &out,
        );
        outputs.push(out);
    }
    (outputs, traces, counts)
}

fn add(a: &mut Counts, b: Counts) {
    a.packing += b.packing;
    a.cm_ks += b.cm_ks;
    a.cm_pbs += b.cm_pbs;
    a.ordinary_ks += b.ordinary_ks;
    a.ordinary_pbs += b.ordinary_pbs;
    a.extraction += b.extraction;
}

pub struct Checkpoint {
    pub tag: String,
    pub states: Vec<Cm>,
    pub counts: Counts,
}
pub struct Chain {
    pub original_active: Vec<Lwe>,
    pub original_bits: Vec<Vec<Lwe>>,
    pub outputs: Vec<Lwe>,
    pub checkpoints: Vec<Checkpoint>,
    pub traces: Vec<Trace>,
    pub reductions: Vec<ReductionEvent>,
    pub counts: Counts,
    pub completed: bool,
}

pub fn run(
    key: &EvaluationKeys,
    active: &[Lwe],
    bits: &[Vec<Lwe>],
    policy: Policy,
    reset_negative: bool,
) -> Chain {
    let ingress = ingress(key, active, policy);
    let mut result = Chain {
        original_active: active.to_vec(),
        original_bits: bits.to_vec(),
        outputs: Vec::new(),
        checkpoints: Vec::new(),
        traces: ingress.traces,
        reductions: ingress.reductions,
        counts: ingress.counts,
        completed: false,
    };
    if !ingress.completed {
        return result;
    }
    let initial = ingress.states.clone();
    let mut state = ingress.states;
    result.checkpoints.push(Checkpoint {
        tag: "ingress".into(),
        states: state.clone(),
        counts: result.counts,
    });
    for (level, layout) in crate::model::LAYOUTS.iter().copied().enumerate() {
        // The negative deliberately restores these exact initial bytes, never oracle/re-encryption.
        if reset_negative {
            state = initial.clone();
        }
        result.checkpoints.push(Checkpoint {
            tag: format!("round/{level}/input"),
            states: state.clone(),
            counts: result.counts,
        });
        let mut next = round_cm(key, &state, &bits[level], layout, policy);
        add(&mut result.counts, next.counts);
        for t in &mut next.traces {
            t.tag = format!("round/{level}/{}", t.tag);
        }
        for e in &mut next.reductions {
            e.stage = format!("round/{level}/{}", e.stage);
        }
        result.traces.extend(next.traces);
        result.reductions.extend(next.reductions);
        if !next.completed {
            return result;
        }
        state = next.states;
        result.checkpoints.push(Checkpoint {
            tag: format!("round/{level}/output"),
            states: state.clone(),
            counts: result.counts,
        });
    }
    let (outputs, traces, counts) = egress(key, &state);
    add(&mut result.counts, counts);
    result.outputs = outputs;
    result.traces.extend(traces);
    result.completed = true;
    result
}

/// Public key containers are streamed into hashes; no secret key is serialized.
pub fn key_bindings(key: &EvaluationKeys) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let mut ordinary = Sha256::new();
    for x in key.ordinary_fbsk.as_view().data() {
        ordinary.update(x.re.to_bits().to_le_bytes());
        ordinary.update(x.im.to_bits().to_le_bytes());
    }
    let mut common = Sha256::new();
    for x in key.cm_fbsk.as_view().data() {
        common.update(x.re.to_bits().to_le_bytes());
        common.update(x.im.to_bits().to_le_bytes());
    }
    let result = serde_json::json!({"ordinary_fourier_sha256":format!("{:x}",ordinary.finalize()),"cm_fourier_sha256":format!("{:x}",common.finalize()),
      "ordinary_ksk_sha256":crate::observe::words_hash(key.ordinary_ksk.as_ref()),"cm_ksk_sha256":crate::observe::words_hash(key.cm_ksk.as_ref()),
      "packing_key_sha256":crate::observe::words_hash(key.cm_packing.as_ref()),"lane_ksk_sha256":key.lane_to_a44.iter().map(|x|crate::observe::words_hash(x.as_ref())).collect::<Vec<_>>(),
      "zero_pool_sha256":crate::observe::words_hash(key.cm_zero_pool.as_ref())});
    result
}
