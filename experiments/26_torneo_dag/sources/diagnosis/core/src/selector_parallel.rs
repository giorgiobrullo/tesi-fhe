//! Parallel selector work only while at most four merges are ready.
//! Configuration changes between joined query/level boundaries, as in classic_batch.
use super::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static REQUESTED_PARALLEL: AtomicBool = AtomicBool::new(false);
static READY: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static PFKS_TASKS: AtomicUsize = AtomicUsize::new(0);
static GROUP_TASKS: AtomicUsize = AtomicUsize::new(0);
static G4_CALLS: AtomicUsize = AtomicUsize::new(0);
static G4_PFKS_TASKS: AtomicUsize = AtomicUsize::new(0);
static READY_CALLS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

pub fn begin_query(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    REQUESTED_PARALLEL.store(false, Ordering::Relaxed);
    for counter in [
        &READY,
        &CALLS,
        &PFKS_TASKS,
        &GROUP_TASKS,
        &G4_CALLS,
        &G4_PFKS_TASKS,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in &READY_CALLS {
        counter.store(0, Ordering::Relaxed);
    }
}

pub(super) fn configure_level(ready_merges: usize, requested_parallel: bool) {
    READY.store(ready_merges, Ordering::Relaxed);
    REQUESTED_PARALLEL.store(requested_parallel, Ordering::Relaxed);
}

fn eligible(enabled: bool, parallel: bool, ready: usize) -> bool {
    enabled && parallel && (1..=4).contains(&ready)
}

pub fn report() -> Value {
    json!({
        "enabled": ENABLED.load(Ordering::Relaxed),
        "max_ready_merges": 4,
        "selectors": CALLS.load(Ordering::Relaxed),
        "pfks_tasks": PFKS_TASKS.load(Ordering::Relaxed),
        "group_br_tasks": GROUP_TASKS.load(Ordering::Relaxed),
        "g4_selectors_with_parallel_pfks": G4_CALLS.load(Ordering::Relaxed),
        "g4_pfks_tasks": G4_PFKS_TASKS.load(Ordering::Relaxed),
        "g4_rotation_parallelism": "serial synthesis shared across groups; no classic group BR tasks",
        "selectors_by_ready_1_to_4": READY_CALLS.iter().map(|x| x.load(Ordering::Relaxed)).collect::<Vec<_>>(),
        "additional_keys": 0,
        "additional_threads": 0
    })
}

pub(super) fn selected_lanes<const N: usize>(groups: &[&[usize]]) -> Vec<usize> {
    assert!(!groups.is_empty());
    let mut seen = [false; N];
    let mut lanes = Vec::new();
    for group in groups {
        assert!(!group.is_empty() && group.len() <= 3);
        for &lane in *group {
            assert!(
                lane < N && !seen[lane],
                "selected payload must appear exactly once"
            );
            seen[lane] = true;
            lanes.push(lane);
        }
    }
    lanes
}

/// Used by G4 before its shared serial rotation traversal. No new pool is created.
pub(super) fn g4_pfks_parallel(payloads: usize) -> bool {
    let ready = READY.load(Ordering::Relaxed);
    let use_parallel = eligible(
        ENABLED.load(Ordering::Relaxed),
        REQUESTED_PARALLEL.load(Ordering::Relaxed),
        ready,
    );
    if use_parallel {
        assert_eq!(
            rayon::current_num_threads(),
            16,
            "use the existing fixed query pool"
        );
        G4_CALLS.fetch_add(1, Ordering::Relaxed);
        G4_PFKS_TASKS.fetch_add(payloads, Ordering::Relaxed);
    }
    use_parallel
}

pub(super) fn construct_pfks(
    left: &[Lwe],
    right: &[Lwe],
    lanes: &[usize],
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    parallel: bool,
) -> Vec<(usize, Glwe)> {
    let construct = |&lane: &usize| {
        let mut difference = right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
        let mut term = Glwe::new(
            0,
            window.output_glwe_size(),
            window.output_polynomial_size(),
            difference.ciphertext_modulus(),
        );
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            window,
            &mut term,
            &difference,
        );
        (lane, term)
    };
    if parallel {
        lanes.par_iter().map(construct).collect()
    } else {
        lanes.iter().map(construct).collect()
    }
}

pub(super) fn maybe_select<const N: usize>(
    left: &[Lwe],
    right: &[Lwe],
    combined: &Lwe,
    groups: &[&[usize]],
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> Option<([Lwe; N], wide_id::Metrics)> {
    maybe_select_impl(
        left,
        right,
        combined,
        groups,
        window_key,
        ksk,
        bsk,
        READY.load(Ordering::Relaxed),
        REQUESTED_PARALLEL.load(Ordering::Relaxed),
    )
}

pub(super) fn maybe_select_with_policy<const N: usize>(
    left: &[Lwe],
    right: &[Lwe],
    combined: &Lwe,
    groups: &[&[usize]],
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
    policy: tournament_dag::NodePolicy,
) -> Option<([Lwe; N], wide_id::Metrics)> {
    maybe_select_impl(
        left,
        right,
        combined,
        groups,
        window_key,
        ksk,
        bsk,
        policy.baseline_ready_merges,
        policy.requested_parallel && policy.allow_inner_parallel,
    )
}

fn maybe_select_impl<const N: usize>(
    left: &[Lwe],
    right: &[Lwe],
    combined: &Lwe,
    groups: &[&[usize]],
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
    ready: usize,
    parallel: bool,
) -> Option<([Lwe; N], wide_id::Metrics)> {
    if !eligible(ENABLED.load(Ordering::Relaxed), parallel, ready) {
        return None;
    }
    assert_eq!(
        rayon::current_num_threads(),
        16,
        "use the existing fixed query pool"
    );
    assert_eq!((left.len(), right.len()), (N, N));
    let lanes = selected_lanes::<N>(groups);
    let modulus = combined.ciphertext_modulus();
    let mut control = Lwe::new(0u64, ksk.output_key_lwe_dimension().to_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, combined, &mut control);
    let centered = mean_center::apply(control);
    let mask_terms = centered.original.get_mask().as_ref().len();
    let mean_center::Centered {
        corrected: control, ..
    } = centered;

    // Every PFKS retains the same scalar decomposition and integer accumulation order.
    let terms = construct_pfks(left, right, &lanes, window_key, true);
    let mut pfks: [Option<Glwe>; N] = std::array::from_fn(|_| None);
    for (lane, term) in terms {
        pfks[lane] = Some(term);
    }
    // Retain the parent's clone/take policy; grouping and copies stay in the query clock.
    let prepared: Vec<Vec<(usize, Glwe)>> = groups
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|&lane| {
                    #[cfg(not(feature = "opt-owned-pfks"))]
                    let term = pfks[lane].as_ref().expect("selected PFKS lane").clone();
                    #[cfg(feature = "opt-owned-pfks")]
                    let term = pfks[lane].take().expect("selected PFKS lane");
                    (lane, term)
                })
                .collect()
        })
        .collect();
    let group_outputs: Vec<Vec<(usize, Lwe)>> = prepared
        .into_par_iter()
        .map(|group| {
            let mut accumulator: Option<Glwe> = None;
            let group_lanes: Vec<_> = group.iter().map(|(lane, _)| *lane).collect();
            for (position, (_, mut term)) in group.into_iter().enumerate() {
                for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign(
                        &mut polynomial,
                        MonomialDegree(position * 41),
                    );
                }
                if let Some(acc) = accumulator.as_mut() {
                    for (word, value) in acc.as_mut().iter_mut().zip(term.as_ref()) {
                        *word = word.wrapping_add(*value);
                    }
                } else {
                    accumulator = Some(term);
                }
            }
            let mut accumulator = accumulator.expect("nonempty group");
            // Independent accumulators borrow one immutable corrected control and BSK.
            blind_rotate_assign(&control, &mut accumulator, bsk);
            group_lanes
                .into_iter()
                .enumerate()
                .map(|(position, lane)| {
                    let mut output =
                        Lwe::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), modulus);
                    extract_lwe_sample_from_glwe_ciphertext(
                        &accumulator,
                        &mut output,
                        MonomialDegree(position * 41),
                    );
                    lwe_ciphertext_add_assign(&mut output, &left[lane]);
                    (lane, output)
                })
                .collect()
        })
        .collect();
    let mut outputs: [Option<Lwe>; N] = std::array::from_fn(|_| None);
    for (lane, output) in group_outputs.into_iter().flatten() {
        outputs[lane] = Some(output);
    }
    let output = std::array::from_fn(|lane| {
        outputs[lane].take().unwrap_or_else(|| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                bsk.output_lwe_dimension().to_lwe_size(),
                Plaintext(0),
                modulus,
            )
        })
    });
    let payloads = lanes.len();
    let group_count = groups.len();
    let metrics = wide_id::Metrics {
        pfks: payloads,
        ks: 1,
        br: group_count,
        samples: payloads,
        monomial_calls: payloads,
        nonidentity_monomial_calls: payloads - group_count,
        polynomial_permutation_calls: 2 * payloads,
        glwe_additions: payloads - group_count,
        lwe_subtractions: payloads,
        lwe_addbacks: payloads,
        grouped_centering: false,
        public_centering_calls: 1,
        public_centering_mask_terms: mask_terms,
        public_centering_body_additions: 1,
    };
    assert!(metrics.pass_for(payloads, group_count));
    CALLS.fetch_add(1, Ordering::Relaxed);
    PFKS_TASKS.fetch_add(payloads, Ordering::Relaxed);
    GROUP_TASKS.fetch_add(group_count, Ordering::Relaxed);
    READY_CALLS[ready - 1].fetch_add(1, Ordering::Relaxed);
    Some((output, metrics))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_tail_requires_enabled_parallel_query() {
        for ready in 0..=16 {
            assert_eq!(eligible(true, true, ready), (1..=4).contains(&ready));
            assert!(!eligible(false, true, ready));
            assert!(!eligible(true, false, ready));
        }
    }

    #[test]
    fn sparse_payload_layout_preserves_original_lanes() {
        assert_eq!(
            selected_lanes::<9>(&[&[0, 1, 2], &[3, 4], &[6, 7, 8]]),
            vec![0, 1, 2, 3, 4, 6, 7, 8]
        );
        assert_eq!(selected_lanes::<6>(&[&[3, 4]]), vec![3, 4]);
    }

    #[test]
    #[should_panic(expected = "selected payload must appear exactly once")]
    fn repeated_payload_is_rejected_before_ciphertext_work() {
        selected_lanes::<6>(&[&[0, 1], &[1, 2]]);
    }
}
