//! Complete production-shaped endpoints. No client observation, caching or clocks.
use crate::{
    crypto::{self, EvaluationKeys, Lwe},
    joint_untraced,
    model::Counts,
    scan_bridge,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::{
    atomic_pattern::AtomicPatternServerKey, server_key::ShortintBootstrappingKey, ServerKey,
};

pub struct Output {
    pub low: Lwe,
    pub high: Lwe,
    pub ordinary_br: u64,
    pub ordinary_ks: u64,
    pub ordinary_marginals: u64,
    pub cm: Counts,
}
pub struct JointEndpoint {
    pub output: Output,
    pub full: Vec<Lwe>,
    pub low: Vec<Lwe>,
    pub producer: joint_untraced::Prefix,
    pub flags: Vec<Lwe>,
}
pub struct CmEndpoint {
    pub output: Output,
    pub producer: prefix::IntegrationPrefixOutput,
    pub flags: Vec<Lwe>,
}
fn finish(
    server: &ServerKey,
    key: &EvaluationKeys,
    initial: &[Lwe],
    bits: &[Vec<Lwe>],
    prefix: (u64, u64, u64),
) -> (Output, Vec<Lwe>) {
    let (flags, cm) = crypto::centered_parallel::run(key, initial, bits);
    assert_eq!(cm, crypto::centered::integrated::SELECTOR_COUNTS);
    let (low, high, scan) = scan_bridge::scan(server, &flags).unwrap();
    assert_eq!(
        (
            scan.blind_rotations,
            scan.key_switches,
            scan.output_marginals
        ),
        (16, 16, 20)
    );
    (
        Output {
            low,
            high,
            ordinary_br: prefix.0 + cm.ordinary_pbs as u64 + scan.blind_rotations,
            ordinary_ks: prefix.1 + cm.ordinary_ks as u64 + scan.key_switches,
            ordinary_marginals: prefix.2 + cm.ordinary_pbs as u64 + scan.output_marginals,
            cm,
        },
        flags,
    )
}
pub fn joint_materialize(
    server: &ServerKey,
    key: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[prefix::TemplateView<'_>],
) -> JointEndpoint {
    let plan = prefix::plan_private_argmin_execution(templates).unwrap();
    assert!(plan.aligned_fast_path);
    let pairs = prefix::integration_score_pairs(
        prefix::A44_PARAMETER_BINDING,
        server,
        packed,
        templates,
        plan.execution_domain,
    )
    .unwrap();
    let (full, low): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let ordinary = match &server.atomic_pattern {
        AtomicPatternServerKey::Standard(k) => k,
        _ => panic!("Standard required"),
    };
    let bsk = match &ordinary.bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => bsk,
        _ => panic!("Classic required"),
    };
    let keys = joint_untraced::Keys {
        ksk: &ordinary.key_switching_key,
        bsk,
    };
    let producer = joint_untraced::prefix(&full, &low, joint_untraced::Mode::Joint4, &keys, true);
    assert_eq!(
        (
            producer.counts.br,
            producer.counts.ks,
            producer.counts.samples
        ),
        (127, 127, 255)
    );
    let (output, flags) = finish(
        server,
        key,
        &producer.initial_candidates,
        &producer.bits_by_level,
        (127, 127, 255),
    );
    JointEndpoint {
        output,
        full,
        low,
        producer,
        flags,
    }
}
pub fn cm_materialize(
    server: &ServerKey,
    key: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[prefix::TemplateView<'_>],
) -> CmEndpoint {
    let plan = prefix::plan_private_argmin_execution(templates).unwrap();
    assert!(plan.aligned_fast_path);
    let producer = prefix::integration_extraction_a34_prefix(
        prefix::A44_PARAMETER_BINDING,
        server,
        packed,
        templates,
        plan.execution_domain,
    )
    .unwrap();
    assert_eq!(
        (
            producer.ordinary_br,
            producer.structural_ks,
            producer.output_marginals
        ),
        (239, 191, 303)
    );
    let (output, flags) = finish(
        server,
        key,
        &producer.initial_candidates,
        &producer.bits_by_level,
        (239, 191, 303),
    );
    CmEndpoint {
        output,
        producer,
        flags,
    }
}
pub fn joint_id(
    server: &ServerKey,
    key: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[prefix::TemplateView<'_>],
) -> Output {
    // Required intermediates are destroyed before this call returns and before clock stop.
    joint_materialize(server, key, packed, templates).output
}
pub fn cm_id(
    server: &ServerKey,
    key: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[prefix::TemplateView<'_>],
) -> Output {
    cm_materialize(server, key, packed, templates).output
}
pub fn r3_output(out: r3::nibble::IntegratedOutput) -> Output {
    assert_eq!((out.br, out.ks, out.pbs_samples), (303, 303, 307));
    Output {
        low: out.low_digit,
        high: out.high_digit,
        ordinary_br: out.br as u64,
        ordinary_ks: out.ks as u64,
        ordinary_marginals: out.pbs_samples as u64,
        cm: Counts::default(),
    }
}
pub fn r3_id(
    server: &ServerKey,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[r3::TemplateView<'_>],
) -> Output {
    r3_output(r3::nibble::parallel_nibble_id(server, packed, templates).unwrap())
}
