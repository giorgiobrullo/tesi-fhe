//! Public threshold homogeneity through the unchanged adjacent binary tree.
//!
//! This plan depends only on admitted public templates. A known threshold is
//! retained only when both child subtrees have the same normalized payload.
//! It never compares scores or suppresses an identity, including below-domain
//! thresholds whose leaf identity has already been set to zero by the parent.
use crate::{h_untraced, mixed, mixed_plan, service, smallcuts};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// One entry for each real merge, in indexed tree order; carried tails have
    /// no entry. True means the full threshold triple is public and identical.
    pub levels: Vec<Vec<bool>>,
    pub omitted_threshold_selections: usize,
}

impl Plan {
    pub(super) fn from_payloads(payloads: Vec<[u64; 3]>) -> Self {
        assert!(!payloads.is_empty());
        let mut current: Vec<_> = payloads.into_iter().map(Some).collect();
        let mut levels = Vec::new();
        let mut omitted_threshold_selections = 0;
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut level = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                let shared = match (pair[0], pair[1]) {
                    (Some(left), Some(right)) if left == right => Some(left),
                    _ => None,
                };
                level.push(shared.is_some());
                omitted_threshold_selections += usize::from(shared.is_some());
                next.push(shared);
            }
            if current.len() % 2 == 1 {
                next.push(*current.last().unwrap());
            }
            current = next;
            levels.push(level);
        }
        Self {
            levels,
            omitted_threshold_selections,
        }
    }
}

/// The uniform route returns None and retains its exact original ciphertexts.
pub fn plan(templates: &[service::TemplateView<'_>]) -> Result<Option<Plan>, String> {
    let execution = service::plan(templates)?;
    if execution.mode != service::ExecutionMode::MixedWinnerThreshold {
        return Ok(None);
    }
    Ok(Some(plan_in_domain(templates, execution.execution_domain)?))
}

pub(super) fn plan_in_domain(
    templates: &[service::TemplateView<'_>],
    domain: service::ScoreDomain,
) -> Result<Plan, String> {
    let payloads = templates
        .iter()
        .map(|entry| {
            mixed_plan::threshold_payload(entry.threshold, domain).map(|payload| payload.digits)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Plan::from_payloads(payloads))
}

/// Counts refer to the actual template order, public domain and selected ID cuts.
/// Public preplanning is part of the candidate evaluation and therefore its time.
pub fn operation_counts(
    templates: &[service::TemplateView<'_>],
) -> Result<service::Counts, String> {
    let execution = service::plan(templates)?;
    let counts = service::operation_counts(templates.len(), execution.mode)
        .ok_or("invalid public-threshold operation-count request")?;
    if execution.mode == service::ExecutionMode::MixedWinnerThreshold {
        let plan = plan_in_domain(templates, execution.execution_domain)?;
        Ok(adjust_public_counts(
            counts,
            plan.omitted_threshold_selections,
        ))
    } else {
        Ok(counts)
    }
}

pub(super) fn adjust_public_counts(mut counts: service::Counts, omitted: usize) -> service::Counts {
    let omitted = omitted as u64;
    counts.br -= omitted;
    counts.pfks -= 3 * omitted;
    counts.marginals -= 3 * omitted;
    counts
}

/// The shared KS, comparison outputs and all score/ID selector work are retained.
pub(super) fn adjust_counts(mut counts: h_untraced::Counts, omitted: usize) -> h_untraced::Counts {
    let k = omitted as u64;
    counts.br -= k;
    counts.levels -= k;
    counts.pfks -= 3 * k;
    counts.samples -= 3 * k;
    counts.rotations -= 3 * k;
    counts.polynomial_permutations -= 6 * k;
    counts.glwe_additions -= 2 * k;
    counts.lwe_subtractions -= 3 * k;
    counts.lwe_addbacks -= 3 * k;
    counts
}

pub(super) fn expected_internal_counts(
    n: usize,
    final_predicate: bool,
    omitted: usize,
) -> h_untraced::Counts {
    adjust_counts(
        smallcuts::adjust_counts(
            mixed::reached(n, n - 1, final_predicate),
            n,
            n - 1,
            final_predicate,
            smallcuts::mode(),
        ),
        omitted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(value: u64) -> [u64; 3] {
        [value >> 8, (value >> 4) & 15, value & 15]
    }

    #[test]
    fn same_threshold_except_last_tracks_real_tree_and_carried_tail() {
        for (n, expected) in [
            (3, 1),
            (4, 1),
            (16, 11),
            (128, 120),
            (129, 127),
            (224, 216),
            (225, 221),
        ] {
            let mut values = vec![payload(272); n];
            values[n - 1] = payload(273);
            let plan = Plan::from_payloads(values);
            assert_eq!(plan.levels.iter().map(Vec::len).sum::<usize>(), n - 1);
            assert_eq!(plan.omitted_threshold_selections, expected, "N={n}");
        }
    }

    #[test]
    fn alternating_thresholds_preserve_every_threshold_selector() {
        for n in [3, 4, 16, 128, 129, 224, 225] {
            let plan = Plan::from_payloads((0..n).map(|i| payload(272 + (i % 2) as u64)).collect());
            assert_eq!(plan.omitted_threshold_selections, 0);
        }
    }

    #[test]
    fn complete_nibble_payload_equality_is_required() {
        for (left, right) in [(15, 16), (255, 256), (0, 4095), (272, 273)] {
            assert_eq!(
                Plan::from_payloads(vec![payload(left), payload(right)])
                    .omitted_threshold_selections,
                0
            );
        }
        assert_eq!(
            Plan::from_payloads(vec![payload(4095); 225]).omitted_threshold_selections,
            224
        );
    }

    #[test]
    fn retained_full_counts_match_actual_skipped_group_work() {
        let before = mixed::reached(128, 127, true);
        let after = adjust_counts(before, 120);
        assert_eq!(
            (
                before.br - after.br,
                before.ks - after.ks,
                before.pfks - after.pfks,
                before.samples - after.samples
            ),
            (120, 0, 360, 360)
        );
        assert_eq!(before.centering_calls, after.centering_calls);
        assert_eq!(before.score_samples, after.score_samples);
    }
}
