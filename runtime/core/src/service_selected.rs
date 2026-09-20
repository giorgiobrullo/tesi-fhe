//! Six-payload M with uniform terminal modes and three encrypted ID digits.
use super::*;
use service::{Counts, ScoreDomain, TemplateView, ThresholdMode};

pub const PFKS_BASE_LOG: usize = 22;
pub const N127_COUNTS: Counts = Counts {
    br: 1524, ks: 1143, marginals: 2032, pfks: 762, initial_samples: 127,
};

pub const fn operation_counts(n: usize, mode: ThresholdMode) -> Option<Counts> {
    if n == 0 || n > crate::general::MAX_GALLERY_SIZE {
        return None;
    }
    let n = n as u64;
    let merges = match mode {
        ThresholdMode::AllReject => {
            return Some(Counts { br: 0, ks: 0, marginals: 0, pfks: 0, initial_samples: 0 });
        }
        ThresholdMode::CompareSentinel { score } if score >= 1 && score <= 4095 => n,
        ThresholdMode::CompareSentinel { .. } => return None,
        ThresholdMode::AllAccept => n - 1,
    };
    Some(Counts {
        br: 6 * n + 6 * merges,
        ks: 4 * n + 5 * merges,
        marginals: 6 * n + 10 * merges,
        pfks: 6 * merges,
        initial_samples: n,
    })
}

pub fn window_function() -> Poly { selector_refresh::window_function() }

pub fn evaluate(
    server: &ServerKey, head: &FourierLweBootstrapKeyOwned,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    packed: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain, parallel: bool,
) -> Result<(Lwe, Lwe, Lwe, Counts), String> {
    // The outer service also checks this contract; this exported adapter keeps
    // the same exact domain check before borrowing keys for its first FHE call.
    service::request::validate(packed, templates, domain)?;
    let plan = crate::general::plan(templates)?;
    let expected = service::operation_counts(templates.len(), service::ExecutionMode::Uniform(plan.mode))
        .ok_or("Head uniform operation plan is invalid")?;
    let expected = if public_digits::mode() != public_digits::Mode::Off {
        public_digits::savings(templates)?.adjust_public_counts(expected)
    } else { expected };
    let ShortintBootstrappingKey::Classic(ordinary_bsk) = &server.bootstrapping_key;
    let head_keys = wide::Keys { ksk: &server.key_switching_key, bsk: head };
    let normalizer = wide::Keys { ksk: &server.key_switching_key, bsk: ordinary_bsk };
    let output = wide_id::endpoint(server, window, packed, templates, &head_keys, &normalizer, parallel, plan.mode);
    let counts = Counts { br: output.counts.br, ks: output.counts.ks,
        marginals: output.counts.samples, pfks: output.counts.pfks,
        initial_samples: output.counts.score_samples };
    if counts != expected { return Err("selected M endpoint operation ledger differs".into()); }
    let [low, middle, high] = output.digits;
    Ok((low, middle, high, counts))
}
