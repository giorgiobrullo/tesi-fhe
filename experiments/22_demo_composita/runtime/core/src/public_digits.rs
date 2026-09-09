//! Public digit constants through the original adjacent binary tournament.
//! The benchmark changes this mode only between synchronous evaluations.
use crate::{h_untraced, service, wide_id, Lwe, SCORE_DELTA};
use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};
use tfhe::core_crypto::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Mode {
    Off,
    Omit,
    Repack,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Omit => "omit",
            Self::Repack => "repack",
        }
    }
}

static MODE: AtomicU8 = AtomicU8::new(Mode::Off as u8);

pub fn set_mode(mode: Mode) {
    MODE.store(mode as u8, Ordering::Relaxed);
}

pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        0 => Mode::Off,
        1 => Mode::Omit,
        2 => Mode::Repack,
        _ => unreachable!("only Mode values are stored"),
    }
}

#[derive(Clone, Debug)]
pub(super) struct Merge<const N: usize> {
    pub constants: [Option<u64>; N],
    pub groups: Vec<Vec<usize>>,
}

impl<const N: usize> Merge<N> {
    pub fn payloads(&self) -> usize {
        self.groups.iter().map(Vec::len).sum()
    }

    /// Retained constants remain literal public ciphertexts, including zero IDs.
    /// This changes noise relative to selecting an equal plaintext, so candidate
    /// and reference outputs require semantic checks rather than word equality.
    pub fn restore_constants(&self, left: &[Lwe; N], right: &[Lwe; N], out: &mut [Lwe; N]) {
        for (lane, known) in self.constants.iter().enumerate().skip(3) {
            if let Some(value) = known {
                for input in [&left[lane], &right[lane]] {
                    assert!(input.get_mask().as_ref().iter().all(|word| *word == 0));
                    assert_eq!(*input.get_body().data, value * SCORE_DELTA);
                }
                out[lane] = left[lane].clone();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Savings {
    pub pfks: u64,
    pub dynamic_br: u64,
    pub merges: usize,
}

impl Savings {
    pub(super) fn adjust_counts(self, mut counts: h_untraced::Counts) -> h_untraced::Counts {
        counts.br -= self.dynamic_br;
        counts.levels -= self.dynamic_br;
        counts.pfks -= self.pfks;
        counts.samples -= self.pfks;
        counts.rotations -= self.pfks;
        counts.polynomial_permutations -= 2 * self.pfks;
        counts.glwe_additions -= self.pfks - self.dynamic_br;
        counts.lwe_subtractions -= self.pfks;
        counts.lwe_addbacks -= self.pfks;
        counts
    }

    pub fn adjust_public_counts(self, mut counts: service::Counts) -> service::Counts {
        counts.br -= self.dynamic_br;
        counts.pfks -= self.pfks;
        counts.marginals -= self.pfks;
        counts
    }
}

#[derive(Clone, Debug)]
pub(super) struct Plan<const N: usize> {
    pub levels: Vec<Vec<Merge<N>>>,
    pub savings: Savings,
}

impl<const N: usize> Plan<N> {
    fn from_leaves(mut current: Vec<[Option<u64>; N]>, selected_mode: Mode) -> Self {
        assert!(matches!(N, 6 | 9));
        assert!(!current.is_empty() && selected_mode != Mode::Off);
        let id_width = if current.len() <= 224 { 2 } else { 3 };
        let mut levels = Vec::new();
        let mut savings = Savings::default();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut level = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                let constants = std::array::from_fn(|lane| match (pair[0][lane], pair[1][lane]) {
                    (Some(left), Some(right)) if left == right => Some(left),
                    _ => None,
                });
                let threshold_is_public = N == 9 && constants[6..9].iter().all(Option::is_some);
                let baseline_groups = 2 + usize::from(N == 9 && !threshold_is_public);
                let baseline_payloads = 3 + id_width + 3 * usize::from(N == 9 && !threshold_is_public);
                let mut groups = vec![vec![0, 1, 2]];
                if selected_mode == Mode::Repack {
                    let variable: Vec<_> = (3..N).filter(|&lane| constants[lane].is_none()).collect();
                    groups.extend(variable.chunks(3).map(<[usize]>::to_vec));
                } else {
                    for range in [(3, 6), (6, N)] {
                        let variable: Vec<_> = (range.0..range.1)
                            .filter(|&lane| constants[lane].is_none()).collect();
                        if !variable.is_empty() {
                            groups.push(variable);
                        }
                    }
                }
                let planned = Merge { constants, groups };
                // All score/ID/threshold lanes use Delta59. The score group stays
                // unchanged; other groups reuse exactly the original offsets0/41/82.
                assert!(planned.groups.iter().all(|group| (1..=3).contains(&group.len())));
                assert!(planned.payloads() <= baseline_payloads);
                assert!(planned.groups.len() <= baseline_groups);
                savings.pfks += (baseline_payloads - planned.payloads()) as u64;
                savings.dynamic_br += (baseline_groups - planned.groups.len()) as u64;
                savings.merges += 1;
                next.push(constants);
                level.push(planned);
            }
            if current.len() % 2 == 1 {
                next.push(*current.last().unwrap());
            }
            current = next;
            levels.push(level);
        }
        Self { levels, savings }
    }
}

pub(super) fn uniform(n: usize, selected_mode: Mode) -> Plan<6> {
    let leaves = (1..=n).map(|identity| {
        let ids = wide_id::identity_digits(identity).expect("admitted identity");
        [None, None, None, Some(ids[0]), Some(ids[1]), Some(ids[2])]
    }).collect();
    Plan::from_leaves(leaves, selected_mode)
}

pub(super) fn mixed(
    templates: &[service::TemplateView<'_>], domain: service::ScoreDomain, selected_mode: Mode,
) -> Result<Plan<9>, String> {
    let leaves = templates.iter().enumerate().map(|(index, template)| {
        // Reuse the existing normalized/clamped threshold and below-domain ID0 rule.
        crate::mixed::leaf_public_payloads(index, template.threshold, domain).map(|payload| {
            [None, None, None, Some(payload[0]), Some(payload[1]), Some(payload[2]),
                Some(payload[3]), Some(payload[4]), Some(payload[5])]
        })
    }).collect::<Result<Vec<_>, _>>()?;
    Ok(Plan::from_leaves(leaves, selected_mode))
}

pub fn savings(templates: &[service::TemplateView<'_>]) -> Result<Savings, String> {
    let selected_mode = mode();
    let plan = service::plan(templates)?;
    if selected_mode == Mode::Off {
        return Ok(Savings::default());
    }
    Ok(match plan.mode {
        service::ExecutionMode::Uniform(service::ThresholdMode::AllReject) => Savings::default(),
        service::ExecutionMode::Uniform(_) => uniform(templates.len(), selected_mode).savings,
        service::ExecutionMode::MixedWinnerThreshold => mixed(templates, plan.execution_domain, selected_mode)?.savings,
    })
}

pub fn operation_counts(templates: &[service::TemplateView<'_>]) -> Result<service::Counts, String> {
    let baseline = crate::public_thresholds::operation_counts(templates)?;
    Ok(savings(templates)?.adjust_public_counts(baseline))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_carries_remain_variable_and_odd_tails_keep_order() {
        for n in [1, 3, 15, 16, 127, 128, 129, 224, 225, 226, 1024, 3374] {
            for mode in [Mode::Omit, Mode::Repack] {
                let plan = uniform(n, mode);
                assert_eq!(plan.savings.merges, n - 1);
                let mut ranges: Vec<_> = (1..=n).map(|i| vec![i]).collect();
                for level in &plan.levels {
                    let mut next = Vec::new();
                    for (node, pair) in level.iter().zip(ranges.chunks_exact(2)) {
                        let descendants: Vec<_> = pair.iter().flatten().copied().collect();
                        for lane in 3..6 {
                            if let Some(value) = node.constants[lane] {
                                assert!(descendants.iter().all(|id| wide_id::identity_digits(*id).unwrap()[lane - 3] == value));
                            }
                        }
                        next.push(descendants);
                    }
                    if ranges.len() % 2 == 1 { next.push(ranges.last().unwrap().clone()); }
                    ranges = next;
                }
                assert_eq!(ranges[0], (1..=n).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn partial_threshold_constants_allow_compatible_repacking() {
        let leaves = vec![
            [None, None, None, Some(1), Some(0), Some(0), Some(1), Some(1), Some(0)],
            [None, None, None, Some(2), Some(0), Some(0), Some(1), Some(1), Some(1)],
        ];
        let omit = Plan::from_leaves(leaves.clone(), Mode::Omit);
        let repack = Plan::from_leaves(leaves, Mode::Repack);
        assert_eq!(omit.levels[0][0].groups, vec![vec![0, 1, 2], vec![3], vec![8]]);
        assert_eq!(repack.levels[0][0].groups, vec![vec![0, 1, 2], vec![3, 8]]);
        assert_eq!(omit.savings.pfks, 3);
        assert_eq!(repack.savings.dynamic_br, 1);
    }

    #[test]
    fn below_domain_ids_use_existing_zero_rule() {
        let domain = service::ScoreDomain { lower: 0, upper: 4095 };
        let payload = crate::mixed::leaf_public_payloads(224, i64::MIN, domain).unwrap();
        assert_eq!(&payload[..3], &[0, 0, 0]);
        assert_eq!(&payload[3..], &[0, 0, 0]);
        let accept = crate::mixed::leaf_public_payloads(224, i64::MAX, domain).unwrap();
        assert_eq!(&accept[..3], &[0, 0, 1]);
        assert_eq!(&accept[3..], &[15, 15, 15]);
    }
}
