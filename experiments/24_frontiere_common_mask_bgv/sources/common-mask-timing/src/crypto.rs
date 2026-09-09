//! Diagnostic C1 circuit. This module contains no plaintext circuit oracle.
use crate::model::{Counts, Layout, A44_DELTA, CM_DELTA, LANES};
use crate::zero_pool::{apply, Policy, ReductionEvent};
use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    cm_fft64::programmable_bootstrap_cm_lwe_ciphertext,
    cm_generate_programmable_bootstrap_glwe_lut,
    cm_lwe_keyswitch_key_generation::allocate_and_generate_new_cm_lwe_keyswitch_key,
    par_generate_cm_lwe_bootstrap_key, CM_PARAM_4_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::parameters::ClassicPBSParameters;

pub const A44: ClassicPBSParameters = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
pub type Lwe = LweCiphertextOwned<u64>;
pub type Cm = CmLweCiphertextOwned<u64>;

pub struct ClientKeys {
    pub ordinary_small: LweSecretKeyOwned<u64>,
    pub ordinary_big: LweSecretKeyOwned<u64>,
    pub cm_small: Vec<LweSecretKeyOwned<u64>>,
    pub cm_big: Vec<LweSecretKeyOwned<u64>>,
}

/// Deliberately contains no secret keys or references to the client.
pub struct EvaluationKeys {
    ordinary_fbsk: FourierLweBootstrapKeyOwned,
    ordinary_ksk: LweKeyswitchKeyOwned<u64>,
    cm_fbsk: FourierCmLweBootstrapKeyOwned,
    cm_ksk: CmLweKeyswitchKeyOwned<u64>,
    cm_packing: CmLwePackingKeyOwned<u64>,
    lane_to_a44: Vec<LweKeyswitchKeyOwned<u64>>,
    pub added_payload_bytes: [usize; 4],
    cm_zero_pool: CmLweCiphertextListOwned<u64>,
    pub zero_pool_payload_bytes: usize,
}

pub fn generate_keys_with_ordinary(
    ordinary_glwe: GlweSecretKeyOwned<u64>,
    ordinary_small: LweSecretKeyOwned<u64>,
    ordinary_fbsk: FourierLweBootstrapKeyOwned,
    ordinary_ksk: LweKeyswitchKeyOwned<u64>,
) -> (ClientKeys, EvaluationKeys) {
    let cm = CM_PARAM_4_2_MINUS_64;
    assert_eq!(cm.cm_dimension.0, LANES);
    assert_eq!(cm.precision, 2);
    assert_eq!(cm.lwe_dimension.0, 772);
    assert_eq!(cm.glwe_dimension.0 * cm.polynomial_size.0, 1536);
    assert_eq!(A44.lwe_dimension.0, 859);
    assert_eq!(A44.polynomial_size.0, 2048);
    assert_eq!(A44.glwe_dimension.0, 1);
    assert_eq!(A44.message_modulus.0 * A44.carry_modulus.0, 16);
    assert_eq!((A44.pbs_base_log.0, A44.pbs_level.0), (23, 1));
    assert_eq!((A44.ks_base_log.0, A44.ks_level.0), (3, 5));
    assert_eq!(A44.ciphertext_modulus, cm.ciphertext_modulus);
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut secret = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut enc = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    // Reuse the caller's actual baseline key family. No replacement ordinary keygen.
    let ordinary_big = ordinary_glwe.into_lwe_secret_key();
    assert_eq!(ordinary_big.lwe_dimension(), LweDimension(2048));
    assert_eq!(ordinary_small.lwe_dimension(), A44.lwe_dimension);
    assert_eq!(ordinary_ksk.input_key_lwe_dimension(), ordinary_big.lwe_dimension());
    assert_eq!(ordinary_ksk.output_key_lwe_dimension(), ordinary_small.lwe_dimension());
    assert_eq!(ordinary_fbsk.input_lwe_dimension(), ordinary_small.lwe_dimension());
    assert_eq!(ordinary_fbsk.output_lwe_dimension(), ordinary_big.lwe_dimension());

    // Independent draws per lane at BOTH key sizes. Repeating one lane secret is forbidden.
    let cm_small: Vec<_> = (0..LANES)
        .map(|_| allocate_and_generate_new_binary_lwe_secret_key(cm.lwe_dimension, &mut secret))
        .collect();
    let cm_glwe: Vec<_> = (0..LANES)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                cm.glwe_dimension,
                cm.polynomial_size,
                &mut secret,
            )
        })
        .collect();
    let cm_big: Vec<_> = cm_glwe
        .iter()
        .cloned()
        .map(GlweSecretKey::into_lwe_secret_key)
        .collect();
    for i in 0..LANES {
        for j in i + 1..LANES {
            assert!(
                cm_small[i].as_ref() != cm_small[j].as_ref(),
                "repeated small lane key"
            );
            assert!(
                cm_big[i].as_ref() != cm_big[j].as_ref(),
                "repeated big lane key"
            );
        }
    }
    let mut cm_bsk = CmLweBootstrapKey::new(
        0u64,
        cm.glwe_dimension,
        cm.cm_dimension,
        cm.polynomial_size,
        cm.base_log_bs,
        cm.level_bs,
        cm.lwe_dimension,
        cm.ciphertext_modulus,
    );
    par_generate_cm_lwe_bootstrap_key(
        &cm_small,
        &cm_glwe,
        &mut cm_bsk,
        cm.glwe_noise_distribution,
        &mut enc,
    );
    let mut cm_fbsk = FourierCmLweBootstrapKey::new(
        cm.lwe_dimension,
        cm.glwe_dimension,
        cm.cm_dimension,
        cm.polynomial_size,
        cm.base_log_bs,
        cm.level_bs,
    );
    par_convert_standard_cm_lwe_bootstrap_key_to_fourier(&cm_bsk, &mut cm_fbsk);
    drop(cm_bsk);
    let cm_ksk = allocate_and_generate_new_cm_lwe_keyswitch_key(
        &cm_big,
        &cm_small,
        cm.cm_dimension,
        cm.base_log_ks,
        cm.level_ks,
        cm.lwe_noise_distribution,
        cm.ciphertext_modulus,
        &mut enc,
    );
    let cm_packing = allocate_and_generate_new_cm_lwe_packing_key(
        &ordinary_big,
        &cm_small,
        cm.base_log_ks,
        cm.level_ks,
        cm.lwe_noise_distribution,
        cm.ciphertext_modulus,
        &mut enc,
    );
    // This is CM-BIG -> A44-SMALL; A78's old CM-small -> ordinary-big bridge is not used.
    let lane_to_a44: Vec<_> = cm_big
        .iter()
        .map(|lane| {
            allocate_and_generate_new_lwe_keyswitch_key(
                lane,
                &ordinary_small,
                A44.ks_base_log,
                A44.ks_level,
                A44.lwe_noise_distribution,
                A44.ciphertext_modulus,
                &mut enc,
            )
        })
        .collect();
    // One complete shared-mask zero per pool row, with four independent lane bodies.
    let mut cm_zero_pool = CmLweCiphertextList::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.max_nb_zeros_n,
        cm.ciphertext_modulus,
    );
    let zero = PlaintextList::new(0u64, PlaintextCount(LANES));
    let zero_messages: Vec<_> = (0..cm.max_nb_zeros_n.0).map(|_| zero.clone()).collect();
    encrypt_cm_lwe_ciphertext_list(
        &cm_small,
        &mut cm_zero_pool,
        &zero_messages,
        cm.lwe_noise_distribution,
        &mut enc,
    );
    let zero_pool_payload_bytes = std::mem::size_of_val(cm_zero_pool.as_ref());
    assert_eq!(zero_pool_payload_bytes, 9_405_120);
    let added_payload_bytes = [
        cm_fbsk.as_view().data().len() * 16,
        std::mem::size_of_val(cm_ksk.as_ref()),
        std::mem::size_of_val(cm_packing.as_ref()),
        lane_to_a44
            .iter()
            .map(|k| std::mem::size_of_val(k.as_ref()))
            .sum(),
    ];
    assert_eq!(
        added_payload_bytes,
        [154943488, 47677440, 254279680, 211353600]
    );
    (
        ClientKeys {
            ordinary_small,
            ordinary_big,
            cm_small,
            cm_big,
        },
        EvaluationKeys {
            ordinary_fbsk,
            ordinary_ksk,
            cm_fbsk,
            cm_ksk,
            cm_packing,
            lane_to_a44,
            added_payload_bytes,
            cm_zero_pool,
            zero_pool_payload_bytes,
        },
    )
}

#[derive(Clone, Copy, Debug)]
pub enum Domain {
    A44Small,
    A44Big,
    CmSmall,
    CmBig,
}

pub struct Trace {
    pub tag: String,
    pub domain: Domain,
    pub lane: usize,
    pub ct: Lwe,
}

fn trace_lwe(trace: &mut Vec<Trace>, tag: String, domain: Domain, ct: &Lwe) {
    trace.push(Trace {
        tag,
        domain,
        lane: 0,
        ct: ct.clone(),
    });
}

fn trace_cm(trace: &mut Vec<Trace>, tag: String, domain: Domain, ct: &Cm) {
    // Diagnostic copies only; these are NOT extractions on the server's functional data path.
    for lane in 0..LANES {
        trace.push(Trace {
            tag: tag.clone(),
            domain,
            lane,
            ct: ct.extract_lwe_ciphertext(lane),
        });
    }
}

pub fn decrypt_trace(client: &ClientKeys, trace: &Trace) -> u64 {
    let sk = match trace.domain {
        Domain::A44Small => &client.ordinary_small,
        Domain::A44Big => &client.ordinary_big,
        Domain::CmSmall => &client.cm_small[trace.lane],
        Domain::CmBig => &client.cm_big[trace.lane],
    };
    decrypt_lwe_ciphertext(sk, &trace.ct).0
}

/// Client-only observer: the actual kernel switches each coefficient BEFORE subtracting masks.
/// Rounding the decrypted torus phase is recorded separately and never substitutes for this.
pub fn coefficientwise_degree(client: &ClientKeys, trace: &Trace, polynomial_size: usize) -> usize {
    let sk = match trace.domain {
        Domain::A44Small => &client.ordinary_small,
        Domain::CmSmall => &client.cm_small[trace.lane],
        _ => panic!("BR input observer requires a small-domain ciphertext"),
    };
    let modulus = 2 * polynomial_size;
    let mut degree = modulus_switch_word(*trace.ct.get_body().data, polynomial_size) as i64;
    for (&a, &s) in trace.ct.get_mask().as_ref().iter().zip(sk.as_ref()) {
        degree -= modulus_switch_word(a, polynomial_size) as i64 * s as i64;
    }
    degree.rem_euclid(modulus as i64) as usize
}

pub fn modulus_switch_word(word: u64, polynomial_size: usize) -> usize {
    assert!(polynomial_size.is_power_of_two());
    let shift = 64 - (2 * polynomial_size).ilog2();
    (word.wrapping_add(1u64 << (shift - 1)) >> shift) as usize
}

fn ordinary_zero(big: bool) -> Lwe {
    let dim = if big {
        LweDimension(A44.glwe_dimension.0 * A44.polynomial_size.0)
    } else {
        A44.lwe_dimension
    };
    LweCiphertext::new(0u64, dim.to_lwe_size(), A44.ciphertext_modulus)
}

fn cm_zero(big: bool) -> Cm {
    let cm = CM_PARAM_4_2_MINUS_64;
    let dim = if big {
        LweDimension(cm.glwe_dimension.0 * cm.polynomial_size.0)
    } else {
        cm.lwe_dimension
    };
    CmLweCiphertext::new(0u64, dim, cm.cm_dimension, cm.ciphertext_modulus)
}

fn ordinary_lut<F: Fn(u64) -> u64>(input_modulus: usize, f: F) -> GlweCiphertextOwned<u64> {
    generate_programmable_bootstrap_glwe_lut(
        A44.polynomial_size,
        A44.glwe_dimension.to_glwe_size(),
        input_modulus,
        A44.ciphertext_modulus,
        A44_DELTA,
        f,
    )
}

fn cm_lut<F: Fn(u64) -> u64>(f: F) -> CmGlweCiphertextOwned<u64> {
    let cm = CM_PARAM_4_2_MINUS_64;
    // One function shared by all lanes, as required by the current public helper.
    cm_generate_programmable_bootstrap_glwe_lut(
        cm.polynomial_size,
        cm.glwe_dimension,
        cm.cm_dimension,
        4,
        cm.ciphertext_modulus,
        CM_DELTA,
        f,
    )
}

fn ordinary_pbs(key: &EvaluationKeys, input: &Lwe, lut: &GlweCiphertextOwned<u64>) -> Lwe {
    let mut output = ordinary_zero(true);
    programmable_bootstrap_lwe_ciphertext(input, &mut output, lut, &key.ordinary_fbsk);
    output
}

fn cm_pbs(
    key: &EvaluationKeys,
    input: &Cm,
    lut: &CmGlweCiphertextOwned<u64>,
    counts: &mut Counts,
    policy: Policy,
    stage: &str,
    events: &mut Vec<ReductionEvent>,
) -> Option<Cm> {
    let mut event = apply(input, &key.cm_zero_pool, policy, stage);
    if !event.allowed {
        // Retain both inputs and the best candidate, without executing this PBS.
        events.push(event);
        return None;
    }
    let mut output = cm_zero(true);
    programmable_bootstrap_cm_lwe_ciphertext(&event.corrected, &mut output, lut, &key.cm_fbsk);
    counts.cm_pbs += 1;
    event.pbs_executed = true;
    events.push(event);
    Some(output)
}

fn cm_ks(key: &EvaluationKeys, input: &Cm, counts: &mut Counts) -> Cm {
    let mut output = cm_zero(false);
    cm_keyswitch_lwe_ciphertext(&key.cm_ksk, input, &mut output);
    counts.cm_ks += 1;
    output
}

fn pack(key: &EvaluationKeys, inputs: &[Lwe], counts: &mut Counts) -> Cm {
    assert_eq!(inputs.len(), LANES);
    let mut output = cm_zero(false);
    pack_lwe_ciphertexts_into_cm(&key.cm_packing, inputs, &mut output);
    counts.packing += 1;
    output
}

fn scaled(input: &Lwe, factor: u64) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut out, Cleartext(factor));
    out
}

fn cm_compatible(a: &Cm, b: &Cm) {
    assert_eq!(a.lwe_dimension(), b.lwe_dimension());
    assert_eq!(a.cm_dimension(), b.cm_dimension());
    assert_eq!(a.ciphertext_modulus(), b.ciphertext_modulus());
}

/// Fresh nontrivial A44-small ciphertexts; no zero-noise or trivial-mask real inputs.
pub fn client_encrypt(client: &ClientKeys, values: &[u64]) -> Vec<Lwe> {
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut enc = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    values
        .iter()
        .map(|&v| {
            assert!(v <= 1);
            allocate_and_encrypt_new_lwe_ciphertext(
                &client.ordinary_small,
                Plaintext(v * A44_DELTA),
                A44.lwe_noise_distribution,
                A44.ciphertext_modulus,
                &mut enc,
            )
        })
        .collect()
}

/// Public preprocessing emits real noisy PBS outputs in the same scale/domain as the A66 interface.
/// These 2*N PBS are fixture preparation, separately recorded from the C1 circuit ledger.
pub fn prepare_inputs(
    key: &EvaluationKeys,
    active: &[Lwe],
    bits: &[Lwe],
    layout: Layout,
) -> (Vec<Lwe>, Vec<Lwe>, Vec<Trace>) {
    assert_eq!(active.len(), bits.len());
    let identity = ordinary_lut(16, |x| x);
    let weighted = ordinary_lut(16, |x| (x & 1) * layout.weight);
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut trace = Vec::new();
    for i in 0..active.len() {
        a.push(ordinary_pbs(key, &active[i], &identity));
        b.push(ordinary_pbs(key, &bits[i], &weighted));
        trace_lwe(
            &mut trace,
            format!("input_active/{i}"),
            Domain::A44Big,
            &a[i],
        );
        trace_lwe(&mut trace, format!("input_bit/{i}"), Domain::A44Big, &b[i]);
    }
    (a, b, trace)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    None,
    OmitOffset,
    OmitBitRescale,
    WrongLaneKsk,
}

pub struct RoundResult {
    pub outputs: Vec<Lwe>,
    pub traces: Vec<Trace>,
    pub counts: Counts,
    pub reductions: Vec<ReductionEvent>,
    pub completed: bool,
}

/// SERVER BOUNDARY: only public keys, ciphertexts, shape/layout, and negative-control selector.
/// No decryption, secret keys, or plaintext active/bit values may enter this function.
pub fn run_round(
    key: &EvaluationKeys,
    active: &[Lwe],
    bits: &[Lwe],
    layout: Layout,
    mutation: Mutation,
    policy: Policy,
) -> RoundResult {
    assert!(!active.is_empty());
    assert_eq!(active.len(), bits.len());
    let n = active.len();
    let groups = n.div_ceil(LANES);
    let mut counts = Counts::default();
    let mut traces = Vec::new();
    let mut reductions = Vec::new();
    // Stop before the refused BR. Preserve the partial primitive ledger and traces.
    macro_rules! accepted {
        ($call:expr) => {
            match $call {
                Some(value) => value,
                None => {
                    return RoundResult {
                        outputs: Vec::new(),
                        traces,
                        counts,
                        reductions,
                        completed: false,
                    }
                }
            }
        };
    }
    let identity_cm = cm_lut(|x| x);
    let zero_cm = cm_lut(|x| u64::from(x == layout.alpha));
    let nonzero_cm = cm_lut(|x| u64::from(x != 0));
    let update_cm = cm_lut(|x| u64::from(x == 2));
    // The first bridge/egress LUTs accept Delta_CM input and emit Delta_A44 output.
    let nonzero_cm_to_a44 = ordinary_lut(4, |x| u64::from(x != 0));
    let identity_cm_to_a44 = ordinary_lut(4, |x| x);
    let nonzero_a44 = ordinary_lut(16, |x| u64::from(x != 0));
    let mut active_big = Vec::new();
    let mut zeros_big = Vec::new();
    for group in 0..groups {
        let mut aa = Vec::new();
        let mut bb = Vec::new();
        for lane in 0..LANES {
            let i = group * LANES + lane;
            if i < n {
                aa.push(scaled(&active[i], 4));
                let factor = if mutation == Mutation::OmitBitRescale {
                    1
                } else {
                    layout.rescale
                };
                bb.push(scaled(&bits[i], factor));
            } else {
                // Only missing tail slots use public trivial zero; real inputs are all encrypted.
                aa.push(ordinary_zero(true));
                bb.push(ordinary_zero(true));
            }
        }
        let a_small = pack(key, &aa, &mut counts);
        trace_cm(
            &mut traces,
            format!("active_pack/{group}"),
            Domain::CmSmall,
            &a_small,
        );
        let a_big = accepted!(cm_pbs(
            key,
            &a_small,
            &identity_cm,
            &mut counts,
            policy,
            &format!("active_pack/{group}"),
            &mut reductions
        ));
        trace_cm(
            &mut traces,
            format!("active_big/{group}"),
            Domain::CmBig,
            &a_big,
        );
        let b_small = pack(key, &bb, &mut counts);
        trace_cm(
            &mut traces,
            format!("bit_pack/{group}"),
            Domain::CmSmall,
            &b_small,
        );
        let mut z_small = cm_ks(key, &a_big, &mut counts);
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
        active_big.push(a_big);
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
        let mut sum = active_big[group].clone();
        cm_compatible(&sum, &zeros_big[group]);
        cm_lwe_ciphertext_add_assign(&mut sum, &zeros_big[group]);
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
    let mut outputs = Vec::new();
    for i in 0..n {
        let lane = i % LANES;
        let extracted = next_big[i / LANES].extract_lwe_ciphertext(lane);
        counts.extraction += 1;
        let selected_lane = if mutation == Mutation::WrongLaneKsk {
            (lane + 1) % LANES
        } else {
            lane
        };
        let mut small = ordinary_zero(false);
        keyswitch_lwe_ciphertext(&key.lane_to_a44[selected_lane], &extracted, &mut small);
        counts.ordinary_ks += 1;
        trace_lwe(
            &mut traces,
            format!("egress_small/{i}"),
            Domain::A44Small,
            &small,
        );
        let out = ordinary_pbs(key, &small, &identity_cm_to_a44);
        counts.ordinary_pbs += 1;
        trace_lwe(&mut traces, format!("output/{i}"), Domain::A44Big, &out);
        outputs.push(out);
    }
    RoundResult {
        outputs,
        traces,
        counts,
        reductions,
        completed: true,
    }
}

/// One step of the cached stock-flow shape, using this gate's actual four-lane keys.
/// The cached concrete test uses two lanes and three steps; this is a bounded four-lane adaptation.
pub fn stock_input(client: &ClientKeys, key: &EvaluationKeys) -> (Cm, Vec<Trace>, Counts) {
    let cm = CM_PARAM_4_2_MINUS_64;
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut enc = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let messages = PlaintextList::new(0u64, PlaintextCount(LANES));
    let mut big = allocate_and_encrypt_new_cm_lwe_ciphertext(
        &client.cm_big,
        &messages,
        cm.glwe_noise_distribution,
        cm.ciphertext_modulus,
        &mut enc,
    );
    let mut traces = Vec::new();
    trace_cm(&mut traces, "stock_encrypted".into(), Domain::CmBig, &big);
    cm_lwe_ciphertext_cleartext_mul_assign(&mut big, Cleartext(cm.nu as u64));
    trace_cm(&mut traces, "stock_nu3".into(), Domain::CmBig, &big);
    let mut counts = Counts::default();
    let small = cm_ks(key, &big, &mut counts);
    trace_cm(&mut traces, "stock_input".into(), Domain::CmSmall, &small);
    (small, traces, counts)
}

pub fn stock_arm(key: &EvaluationKeys, input: &Cm, policy: Policy) -> RoundResult {
    let mut counts = Counts::default();
    let mut reductions = Vec::new();
    let mut traces = Vec::new();
    let output = cm_pbs(
        key,
        input,
        &cm_lut(|x| x),
        &mut counts,
        policy,
        "stock_input",
        &mut reductions,
    );
    let completed = output.is_some();
    let outputs = if let Some(output) = output {
        trace_cm(&mut traces, "stock_output".into(), Domain::CmBig, &output);
        (0..LANES)
            .map(|lane| output.extract_lwe_ciphertext(lane))
            .collect()
    } else {
        Vec::new()
    };
    RoundResult {
        outputs,
        traces,
        counts,
        reductions,
        completed,
    }
}

// A155_APPEND_ONLY_EGRESS_MARGIN: original A150 crypto module above is byte-identical.
pub struct EgressMarginProbe {
    pub shifted_input: Lwe,
    pub output: Lwe,
    pub body_additions: usize,
    pub ordinary_pbs: usize,
    pub ordinary_ks: usize,
}

/// Separate server diagnostic: one fixed public body addition and the unchanged egress LUT/PBS.
/// No key switch, decryption, secret key, feedback or retry is used.
pub fn egress_margin_probe(key: &EvaluationKeys, input: &Lwe, offset: i64) -> EgressMarginProbe {
    assert!(offset == -(1i64 << 59) || offset == 1i64 << 59);
    assert_eq!(input.lwe_size(), A44.lwe_dimension.to_lwe_size());
    assert_eq!(input.ciphertext_modulus(), A44.ciphertext_modulus);
    let mut shifted = input.clone();
    lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(offset as u64));
    let body_additions = 1;
    let lut = ordinary_lut(4, |x| x);
    let output = ordinary_pbs(key, &shifted, &lut);
    let ordinary_pbs = 1;
    EgressMarginProbe {
        shifted_input: shifted,
        output,
        body_additions,
        ordinary_pbs,
        ordinary_ks: 0,
    }
}

// A190 additions; the complete A176 module prefix remains unchanged.
#[path = "ordinary.rs"]
pub mod ordinary;
#[path = "persistent.rs"]
pub mod persistent;

#[path = "untraced.rs"]
pub mod untraced;

#[path = "parallel.rs"]
pub mod parallel;

// Append-only centered-output gate; every preceding source byte is preserved.
#[path = "centered.rs"]
pub mod centered;

// Append-only untraced parallel centered selector; prior primitive bytes remain unchanged.
#[path = "centered_parallel.rs"]
pub mod centered_parallel;
