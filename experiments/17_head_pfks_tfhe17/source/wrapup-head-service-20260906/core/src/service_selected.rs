//! The root-selected M arithmetic, with public uniform-domain admission only.
use super::*;
use service::{Counts, ScoreDomain, TemplateView};

pub const PFKS_BASE_LOG: usize = 22;
pub const N127_COUNTS: Counts = Counts {
    br: 1397, ks: 1016, marginals: 1778, pfks: 635, initial_samples: 127,
};

pub fn window_function() -> Poly { d1::window() }

pub fn evaluate(
    server: &ServerKey, head: &FourierLweBootstrapKeyOwned,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    packed: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain,
) -> Result<(Lwe, Lwe, Counts), String> {
    // The outer service also checks this contract; this exported adapter keeps
    // the same exact domain check before borrowing keys for its first FHE call.
    service::request::validate(packed, templates, domain)?;
    let ShortintBootstrappingKey::Classic(ordinary_bsk) = &server.bootstrapping_key;
    let head_keys = wide::Keys { ksk: &server.key_switching_key, bsk: head };
    let normalizer = wide::Keys { ksk: &server.key_switching_key, bsk: ordinary_bsk };
    let output = m_untraced::endpoint(server, window, packed, templates, &head_keys, &normalizer);
    let counts = Counts { br: output.counts.br, ks: output.counts.ks,
        marginals: output.counts.samples, pfks: output.counts.pfks,
        initial_samples: output.counts.score_samples };
    if counts != N127_COUNTS { return Err("selected M endpoint operation ledger differs".into()); }
    let [low, high] = output.digits;
    Ok((low, high, counts))
}
