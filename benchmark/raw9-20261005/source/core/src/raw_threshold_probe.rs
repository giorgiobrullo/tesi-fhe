//! Isolated two-child final-stage probe. This is not a production query endpoint.
use super::*;
use rayon::prelude::*;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Score lanes 0..3, ID lanes 3..6, and threshold lanes 6..9.
pub struct Pair {
    pub left: [LweCiphertextOwned<u64>; 9],
    pub right: [LweCiphertextOwned<u64>; 9],
}

#[derive(Clone, Copy)]
pub enum Mode {
    Uniform { sentinel: u16 },
    Mixed,
}

#[derive(Clone, Copy)]
pub enum Arm {
    Baseline,
    Raw,
    RawParallel9,
}

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub br: usize,
    pub ks: usize,
    pub pfks: usize,
    pub marginals: usize,
}

pub struct Output {
    pub digits: [LweCiphertextOwned<u64>; 3],
    pub counts: Counts,
    pub scheduling: Value,
}

/// Three actual ternary PBS calls, followed by the current weighted control.
fn compare(left: &[Lwe], right: &[Lwe], server: &ServerKey, counts: &mut Counts) -> Lwe {
    let calls = AtomicUsize::new(0);
    let stages = classic_batch::stages(left, right, server, |difference| {
        let output = comparator::pbs_untraced(difference, false, server);
        record_fullquery_callback();
        calls.fetch_add(1, Ordering::Relaxed);
        output
    });
    let actual = calls.load(Ordering::Relaxed);
    assert_eq!(actual, 3, "three actual comparator callbacks are required");
    counts.br += actual;
    counts.ks += actual;
    counts.marginals += actual;
    let mut combined = stages[0].clone();
    for (index, word) in combined.as_mut().iter_mut().enumerate() {
        *word = stages[0].as_ref()[index]
            .wrapping_mul(4)
            .wrapping_add(stages[1].as_ref()[index].wrapping_mul(2))
            .wrapping_add(stages[2].as_ref()[index]);
    }
    *combined.get_mut_body().data = combined.get_body().data.wrapping_sub(SCORE_DELTA / 2);
    combined
}

fn select(
    left: &[Lwe; 9],
    right: &[Lwe; 9],
    control: &Lwe,
    groups: &[&[usize]],
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    counts: &mut Counts,
) -> Result<[Lwe; 9], String> {
    let ShortintBootstrappingKey::Classic(bsk) = &server.bootstrapping_key;
    let (output, metrics) = smallcuts::select_lanes::<9>(
        left,
        right,
        control,
        groups,
        window,
        &server.key_switching_key,
        bsk,
    );
    let payloads = groups.iter().map(|group| group.len()).sum();
    if !metrics.pass_for(payloads, groups.len()) {
        return Err("selector metrics differ from the scalar refreshed contract".into());
    }
    counts.br += metrics.br;
    counts.ks += metrics.ks;
    counts.pfks += metrics.pfks;
    counts.marginals += metrics.samples;
    Ok(output)
}

fn public_tuple(template: &Lwe, score: u16) -> [Lwe; 9] {
    let score_digits = [
        u64::from(score >> 8),
        u64::from((score >> 4) & 15),
        u64::from(score & 15),
    ];
    std::array::from_fn(|lane| {
        let digit = if lane < 3 { score_digits[lane] } else { 0 };
        allocate_and_trivially_encrypt_new_lwe_ciphertext(
            template.lwe_size(),
            Plaintext(digit * SCORE_DELTA),
            template.ciphertext_modulus(),
        )
    })
}

pub(super) fn evaluate(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    input: &Pair,
    mode: Mode,
    arm: Arm,
) -> Result<Output, String> {
    if input.left.iter().chain(&input.right).any(|lane| {
        lane.lwe_size().to_lwe_dimension().0 != 2048
            || !lane.ciphertext_modulus().is_native_modulus()
    }) {
        return Err("fixture requires native64 large-LWE2048 lanes".into());
    }
    if matches!(mode, Mode::Uniform { sentinel } if sentinel == 0 || sentinel > 4095) {
        return Err("uniform fixture requires a representable T+1 sentinel".into());
    }
    // Match the current caller; configure once outside all joined tasks.
    composite::begin_query(composite::Mode::PublicParallel, false);
    classic_batch::configure_level(1, true);

    let mut counts = Counts::default();
    let zero = public_tuple(&input.left[0], 0);
    let sentinel = match mode {
        Mode::Uniform { sentinel } => public_tuple(&input.left[0], sentinel),
        Mode::Mixed => zero.clone(),
    };

    let selected = match arm {
        Arm::Baseline => {
            let choice = compare(&input.left[..3], &input.right[..3], server, &mut counts);
            let groups: &[&[usize]] = match mode {
                Mode::Uniform { .. } => &[&[0, 1, 2, 3], &[4]],
                Mode::Mixed => &[&[0, 1, 2, 3], &[4, 6, 7, 8]],
            };
            let winner = select(
                &input.left,
                &input.right,
                &choice,
                groups,
                server,
                window,
                &mut counts,
            )?;
            match mode {
                Mode::Uniform { .. } => {
                    // T+1 > score means acceptance; positive control chooses the right ID.
                    let acceptance = compare(&sentinel[..3], &winner[..3], server, &mut counts);
                    select(
                        &sentinel,
                        &winner,
                        &acceptance,
                        &[&[3, 4]],
                        server,
                        window,
                        &mut counts,
                    )?
                }
                Mode::Mixed => {
                    // score > own tau means rejection; positive control chooses zero.
                    let rejection = compare(&winner[..3], &winner[6..9], server, &mut counts);
                    select(
                        &winner,
                        &zero,
                        &rejection,
                        &[&[3, 4]],
                        server,
                        window,
                        &mut counts,
                    )?
                }
            }
        }
        Arm::Raw | Arm::RawParallel9 => {
            // These three comparisons all read original inputs, before any lane replacement.
            let operands: [(&[Lwe], &[Lwe]); 3] = match mode {
                Mode::Uniform { .. } => [
                    (&input.left[..3], &input.right[..3]),
                    (&sentinel[..3], &input.left[..3]),
                    (&sentinel[..3], &input.right[..3]),
                ],
                Mode::Mixed => [
                    (&input.left[..3], &input.right[..3]),
                    (&input.left[..3], &input.left[6..9]),
                    (&input.right[..3], &input.right[6..9]),
                ],
            };
            let controls: Vec<Lwe> = if matches!(arm, Arm::RawParallel9) {
                // Indexed collection preserves choice/left/right order. Each task owns counts.
                let completed: Vec<_> = operands
                    .into_par_iter()
                    .map(|(left, right)| {
                        let mut local = Counts::default();
                        let control = compare(left, right, server, &mut local);
                        (control, local)
                    })
                    .collect();
                completed
                    .into_iter()
                    .map(|(control, local)| {
                        counts.br += local.br;
                        counts.ks += local.ks;
                        counts.pfks += local.pfks;
                        counts.marginals += local.marginals;
                        control
                    })
                    .collect()
            } else {
                operands
                    .into_iter()
                    .map(|(left, right)| compare(left, right, server, &mut counts))
                    .collect()
            };
            let mut controls = controls.into_iter();
            let choice = controls.next().expect("original choice control");
            let left_raw = controls.next().expect("left threshold control");
            let right_raw = controls.next().expect("right threshold control");
            let mut left = input.left.clone();
            let mut right = input.right.clone();
            left[0] = left_raw;
            right[0] = right_raw;
            // Transport the chosen signed aggregate and its ID in one packed group.
            let winner = select(
                &left,
                &right,
                &choice,
                &[&[0, 3, 4]],
                server,
                window,
                &mut counts,
            )?;
            match mode {
                Mode::Uniform { .. } => select(
                    &zero,
                    &winner,
                    &winner[0],
                    &[&[3, 4]],
                    server,
                    window,
                    &mut counts,
                )?,
                Mode::Mixed => select(
                    &winner,
                    &zero,
                    &winner[0],
                    &[&[3, 4]],
                    server,
                    window,
                    &mut counts,
                )?,
            }
        }
    };
    let expected = match (arm, mode) {
        (Arm::Baseline, Mode::Uniform { .. }) => Counts {
            br: 11,
            ks: 10,
            pfks: 7,
            marginals: 15,
        },
        (Arm::Baseline, Mode::Mixed) => Counts {
            br: 11,
            ks: 10,
            pfks: 10,
            marginals: 18,
        },
        (Arm::Raw | Arm::RawParallel9, _) => Counts {
            br: 13,
            ks: 13,
            pfks: 5,
            marginals: 16,
        },
    };
    if counts != expected {
        return Err("actual callsite counts differ from the preregistered arm".into());
    }
    let comparator_report = classic_batch::report();
    let selector_report = selector_parallel::report();
    let comparisons = if matches!(arm, Arm::Baseline) { 2 } else { 3 };
    let groups = if matches!(arm, Arm::Baseline) { 3 } else { 2 };
    if comparator_report["parallel3_merges"].as_u64() != Some(comparisons)
        || comparator_report["batch3_merges"].as_u64() != Some(0)
        || selector_report["enabled"].as_bool() != Some(true)
        || selector_report["selectors"].as_u64() != Some(2)
        || selector_report["group_br_tasks"].as_u64() != Some(groups)
        || selector_report["pfks_tasks"].as_u64() != Some(counts.pfks as u64)
        || selector_report["selectors_by_ready_1_to_4"] != json!([2, 0, 0, 0])
        || selector_report["g4_selectors_with_parallel_pfks"].as_u64() != Some(0)
    {
        return Err("actual parallel route counters differ from the current configuration".into());
    }
    Ok(Output {
        digits: [
            selected[3].clone(),
            selected[4].clone(),
            selected[5].clone(),
        ],
        counts,
        scheduling: json!({"comparators": comparator_report, "selectors": selector_report}),
    })
}

// Full-query diagnostic additions. No keys, ciphertexts or intermediate phases leave memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FullArm {
    Baseline,
    RawParallel9,
}

static FULL_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static FULL_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

pub(super) struct FullGuard;
impl Drop for FullGuard {
    fn drop(&mut self) {
        FULL_ACTIVE.store(false, Ordering::SeqCst);
    }
}
pub(super) fn begin_fullquery_callbacks() -> Result<FullGuard, String> {
    if FULL_ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("fullquery diagnostic requires serialized requests".into());
    }
    FULL_CALLBACKS.store(0, Ordering::SeqCst);
    Ok(FullGuard)
}
pub(super) fn record_fullquery_callback() {
    if FULL_ACTIVE.load(Ordering::Relaxed) {
        FULL_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
pub struct FullStage {
    pub duration_ns: u64,
    pub work: Value,
    pub scheduling: Value,
}

pub(super) struct Snapshot {
    counts: h_untraced::Counts,
    callbacks: usize,
    comparators: Value,
    selectors: Value,
}
impl Snapshot {
    pub(super) fn new(counts: h_untraced::Counts) -> Self {
        Self {
            counts,
            callbacks: FULL_CALLBACKS.load(Ordering::SeqCst),
            comparators: classic_batch::report(),
            selectors: selector_parallel::report(),
        }
    }
    pub(super) fn finish(
        self,
        arm: FullArm,
        started: std::time::Instant,
        counts: h_untraced::Counts,
    ) -> FullStage {
        let c = subtract_counts(counts, self.counts);
        let expected = terminal_counts(arm);
        assert_eq!(c, expected, "complete terminal work ledger");
        let callbacks = FULL_CALLBACKS
            .load(Ordering::SeqCst)
            .checked_sub(self.callbacks)
            .unwrap();
        assert_eq!(callbacks, if arm == FullArm::Baseline { 6 } else { 9 });
        let after_c = classic_batch::report();
        let after_s = selector_parallel::report();
        let change = |before: &Value, after: &Value, field: &str| {
            after[field]
                .as_u64()
                .unwrap()
                .checked_sub(before[field].as_u64().unwrap())
                .unwrap()
        };
        let comparisons = change(&self.comparators, &after_c, "parallel3_merges");
        let batch3 = change(&self.comparators, &after_c, "batch3_merges");
        let selectors = change(&self.selectors, &after_s, "selectors");
        let groups = change(&self.selectors, &after_s, "group_br_tasks");
        let pfks = change(&self.selectors, &after_s, "pfks_tasks");
        assert_eq!(comparisons, if arm == FullArm::Baseline { 2 } else { 3 });
        assert_eq!(batch3, 0);
        assert_eq!(selectors, 2);
        assert_eq!(groups, if arm == FullArm::Baseline { 3 } else { 2 });
        assert_eq!(pfks, c.pfks);
        assert_eq!(after_s["enabled"].as_bool(), Some(true));
        assert_eq!(
            change(&self.selectors, &after_s, "g4_selectors_with_parallel_pfks"),
            0
        );
        let ready: Vec<u64> = (0..4)
            .map(|i| {
                after_s["selectors_by_ready_1_to_4"][i]
                    .as_u64()
                    .unwrap()
                    .checked_sub(
                        self.selectors["selectors_by_ready_1_to_4"][i]
                            .as_u64()
                            .unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(ready, vec![2, 0, 0, 0]);
        FullStage {
            duration_ns: started.elapsed().as_nanos().try_into().unwrap(),
            work: c.json(),
            scheduling: json!({"comparator_callbacks":callbacks,"parallel3_merges":comparisons,
                "batch3_merges":batch3,"selectors":selectors,"group_br_tasks":groups,
                "pfks_tasks":pfks,"selectors_by_ready_1_to_4":ready}),
        }
    }
}

pub(super) fn terminal_counts(arm: FullArm) -> h_untraced::Counts {
    let raw = arm == FullArm::RawParallel9;
    h_untraced::Counts {
        br: if raw { 13 } else { 11 },
        ks: if raw { 13 } else { 10 },
        pfks: if raw { 5 } else { 7 },
        samples: if raw { 16 } else { 15 },
        levels: if raw { 13 } else { 11 },
        rotations: if raw { 5 } else { 7 },
        polynomial_permutations: if raw { 10 } else { 14 },
        glwe_additions: if raw { 3 } else { 4 },
        lwe_subtractions: if raw { 5 } else { 7 },
        lwe_addbacks: if raw { 5 } else { 7 },
        centering_calls: 4,
        centering_mask_terms: 3436,
        centering_body_additions: 4,
        ..h_untraced::Counts::default()
    }
}

pub(super) fn add_counts(out: &mut h_untraced::Counts, value: h_untraced::Counts) {
    macro_rules! add { ($($f:ident),*) => { $(out.$f += value.$f;)* }; }
    add!(
        br,
        ks,
        pfks,
        samples,
        score_samples,
        levels,
        scales,
        rotations,
        polynomial_permutations,
        glwe_additions,
        lwe_subtractions,
        lwe_addbacks,
        centering_calls,
        centering_mask_terms,
        centering_body_additions
    );
}
fn subtract_counts(a: h_untraced::Counts, b: h_untraced::Counts) -> h_untraced::Counts {
    let mut out = h_untraced::Counts::default();
    macro_rules! sub { ($($f:ident),*) => { $(out.$f = a.$f.checked_sub(b.$f).unwrap();)* }; }
    sub!(
        br,
        ks,
        pfks,
        samples,
        score_samples,
        levels,
        scales,
        rotations,
        polynomial_permutations,
        glwe_additions,
        lwe_subtractions,
        lwe_addbacks,
        centering_calls,
        centering_mask_terms,
        centering_body_additions
    );
    out
}
pub(super) fn replace_terminal(mut baseline: h_untraced::Counts) -> h_untraced::Counts {
    baseline = subtract_counts(baseline, terminal_counts(FullArm::Baseline));
    add_counts(&mut baseline, terminal_counts(FullArm::RawParallel9));
    baseline
}
pub(super) fn replace_public_terminal(mut baseline: service::Counts) -> service::Counts {
    baseline.br += 2;
    baseline.ks += 3;
    baseline.pfks -= 2;
    baseline.marginals += 1;
    baseline
}

// No begin_query or mode reset here: the operands retain the real prefix ancestry.
pub(super) fn fullquery_terminal(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    left: &[Lwe; 6],
    right: &[Lwe; 6],
    sentinel: &[Lwe; 6],
) -> ([Lwe; 6], h_untraced::Counts) {
    for tuple in [left, right] {
        assert!(tuple[5].get_mask().as_ref().iter().all(|v| *v == 0));
        assert_eq!(*tuple[5].get_body().data, 0);
    }
    let operands = [
        (&left[..3], &right[..3]),
        (&sentinel[..3], &left[..3]),
        (&sentinel[..3], &right[..3]),
    ];
    let completed: Vec<_> = operands
        .into_par_iter()
        .map(|(a, b)| {
            let mut local = Counts::default();
            (compare(a, b, server, &mut local), local)
        })
        .collect();
    let actual: usize = completed.iter().map(|(_, c)| c.br).sum();
    assert_eq!(actual, 9);
    assert!(completed
        .iter()
        .all(|(_, c)| (c.br, c.ks, c.marginals, c.pfks) == (3, 3, 3, 0)));
    let mut controls = completed.into_iter().map(|(c, _)| c);
    let choice = controls.next().unwrap();
    let mut a = left.clone();
    let mut b = right.clone();
    a[0] = controls.next().unwrap();
    b[0] = controls.next().unwrap();
    let ShortintBootstrappingKey::Classic(bsk) = &server.bootstrapping_key;
    let (winner, m1) = smallcuts::select_lanes::<6>(
        &a,
        &b,
        &choice,
        &[&[0, 3, 4]],
        window,
        &server.key_switching_key,
        bsk,
    );
    let (output, m2) = smallcuts::select_lanes::<6>(
        sentinel,
        &winner,
        &winner[0],
        &[&[3, 4]],
        window,
        &server.key_switching_key,
        bsk,
    );
    // add_selection accounts for one comparison per selector; one extra comparison is actual work.
    let mut counts = h_untraced::Counts {
        br: (actual - 6) as u64,
        ks: (actual - 6) as u64,
        samples: (actual - 6) as u64,
        levels: (actual - 6) as u64,
        ..h_untraced::Counts::default()
    };
    smallcuts::add_selection(&mut counts, &m1, 3, 1);
    smallcuts::add_selection(&mut counts, &m2, 2, 1);
    assert_eq!(counts, terminal_counts(FullArm::RawParallel9));
    (output, counts)
}
