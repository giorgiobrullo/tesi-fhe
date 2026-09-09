//! Bounded experiment controls. Change them only between synchronous evaluations.
//!
//! This process-wide API is for the sequential benchmark worker, not concurrent service use.
//! Baseline retains the original selector; the other arms omit only selected payload lanes.
use super::*;
use serde::Serialize;
use std::sync::{atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering}, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Baseline,
    FinalIdOnly,
    NarrowId,
    Both,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::FinalIdOnly => "final_id_only",
            Self::NarrowId => "narrow_id",
            Self::Both => "both",
        }
    }

    pub const fn narrow_for(self, n: usize) -> bool {
        matches!(self, Self::NarrowId | Self::Both) && n >= 1 && n <= 224
    }

    pub const fn final_id_only(self) -> bool {
        matches!(self, Self::FinalIdOnly | Self::Both)
    }
}

static MODE: AtomicU8 = AtomicU8::new(Mode::Baseline as u8);
static PROFILING: AtomicBool = AtomicBool::new(false);
static TAIL_CUTOFF: AtomicUsize = AtomicUsize::new(0);
static PROFILE: Mutex<Option<Profile>> = Mutex::new(None);

pub fn set_mode(value: Mode) { MODE.store(value as u8, Ordering::Relaxed); }

pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        0 => Mode::Baseline,
        1 => Mode::FinalIdOnly,
        2 => Mode::NarrowId,
        3 => Mode::Both,
        _ => unreachable!("only Mode values are stored"),
    }
}

/// Zero retains the original scheduling. Other values serialize levels with at most this
/// many ready merges; score formation and digit extraction keep their requested scheduling.
pub fn set_tail_cutoff(value: usize) {
    assert!(matches!(value, 0 | 1 | 2 | 4), "tail cutoff must be 0, 1, 2 or 4");
    TAIL_CUTOFF.store(value, Ordering::Relaxed);
}

pub fn tail_cutoff() -> usize { TAIL_CUTOFF.load(Ordering::Relaxed) }

pub(super) fn parallel_level(requested: bool, ready_merges: usize) -> bool {
    let cutoff = tail_cutoff();
    requested && (cutoff == 0 || ready_merges > cutoff)
}

pub fn set_profiling(enabled: bool) {
    PROFILING.store(enabled, Ordering::Relaxed);
    *PROFILE.lock().expect("profile mutex poisoned") = None;
}

/// All durations are wall-clock nanoseconds on the coordinating thread. The tournament
/// duration contains its level durations, so these must not be added twice. No summed
/// worker durations or per-primitive timings are collected. Work counts are operation totals.
#[derive(Serialize)]
struct Profile {
    schema: &'static str,
    mode: Mode,
    gallery_size: usize,
    narrow_id_active: bool,
    requested_parallel: bool,
    tail_cutoff: usize,
    scoring_wall_ns: u64,
    extraction_wall_ns: u64,
    tournament_wall_ns: u64,
    final_wall_ns: u64,
    evaluate_wall_ns: u64,
    levels: Vec<LevelProfile>,
    primitive_work_counts: Value,
    duration_semantics: &'static str,
}

#[derive(Serialize)]
struct LevelProfile {
    candidates: usize,
    ready_merges: usize,
    carried_candidates: usize,
    scheduled_parallel: bool,
    wall_ns: u64,
}

pub(super) enum Stage { Scoring, Extraction, Tournament, Final }

pub(super) fn start_timer() -> Option<Instant> {
    PROFILING.load(Ordering::Relaxed).then(Instant::now)
}

fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

pub(super) fn begin_profile(n: usize, parallel: bool) -> Option<Instant> {
    let started = start_timer()?;
    let mode = mode();
    *PROFILE.lock().expect("profile mutex poisoned") = Some(Profile {
        schema: "smallcuts-stage-profile.v1", mode, gallery_size: n,
        narrow_id_active: mode.narrow_for(n), requested_parallel: parallel,
        tail_cutoff: tail_cutoff(), scoring_wall_ns: 0, extraction_wall_ns: 0,
        tournament_wall_ns: 0, final_wall_ns: 0, evaluate_wall_ns: 0,
        levels: Vec::new(), primitive_work_counts: Value::Null,
        duration_semantics: "coordinator wall time; levels are included in tournament; no summed worker durations; stage gaps and profiling overhead remain in evaluate",
    });
    Some(started)
}

pub(super) fn record_stage(stage: Stage, started: Option<Instant>) {
    let Some(started) = started else { return; };
    let ns = elapsed_ns(started);
    if let Some(profile) = PROFILE.lock().expect("profile mutex poisoned").as_mut() {
        match stage {
            Stage::Scoring => profile.scoring_wall_ns += ns,
            Stage::Extraction => profile.extraction_wall_ns += ns,
            Stage::Tournament => profile.tournament_wall_ns += ns,
            Stage::Final => profile.final_wall_ns += ns,
        }
    }
}

pub(super) fn record_level(candidates: usize, parallel: bool, started: Option<Instant>) {
    let Some(started) = started else { return; };
    let wall_ns = elapsed_ns(started);
    if let Some(profile) = PROFILE.lock().expect("profile mutex poisoned").as_mut() {
        profile.levels.push(LevelProfile {
            candidates, ready_merges: candidates / 2, carried_candidates: candidates % 2,
            scheduled_parallel: parallel, wall_ns,
        });
    }
}

pub(super) fn finish_profile(started: Option<Instant>, counts: &service::Counts) {
    let Some(started) = started else { return; };
    let ns = elapsed_ns(started);
    if let Some(profile) = PROFILE.lock().expect("profile mutex poisoned").as_mut() {
        profile.evaluate_wall_ns = ns;
        profile.primitive_work_counts = json!({
            "br": counts.br, "ks": counts.ks, "pfks": counts.pfks,
            "marginals": counts.marginals, "initial_samples": counts.initial_samples,
        });
    }
}

/// Consume the last enabled query profile. A failed query can have a partial profile with
/// evaluate_wall_ns=0 and null work counts. Disabled evaluations do not read the clock.
pub fn take_profile() -> Option<Value> {
    PROFILE.lock().expect("profile mutex poisoned").take()
        .map(|profile| serde_json::to_value(profile).expect("profile fields serialize"))
}

const fn removed(n: usize, real_merges: usize, final_predicate: bool, mode: Mode) -> (u64, u64) {
    let final_count = final_predicate as u64;
    let narrow = mode.narrow_for(n) as u64;
    let final_cut = mode.final_id_only() as u64 * final_count;
    ((real_merges as u64 + final_count) * narrow + 3 * final_cut, final_cut)
}

/// Explicit-mode structural ledger, without global state. Public shortcuts still depend
/// on the admitted execution plan; narrow IDs fall back to three digits above 224.
pub const fn operation_counts(n: usize, execution: service::ExecutionMode, mode: Mode) -> Option<service::Counts> {
    let (mut counts, final_predicate) = match execution {
        service::ExecutionMode::Uniform(uniform) => {
            let Some(counts) = service_selected::operation_counts(n, uniform) else { return None; };
            match uniform {
                general::ThresholdMode::AllReject => return Some(counts),
                general::ThresholdMode::AllAccept => (counts, false),
                general::ThresholdMode::CompareSentinel { .. } => (counts, true),
            }
        }
        service::ExecutionMode::MixedWinnerThreshold => {
            let Some(counts) = mixed::operation_counts(n) else { return None; };
            (counts, true)
        }
    };
    let (lanes, groups) = removed(n, n - 1, final_predicate, mode);
    counts.br -= groups;
    counts.pfks -= lanes;
    counts.marginals -= lanes;
    Some(counts)
}

pub(super) fn adjust_counts(mut counts: h_untraced::Counts, n: usize, real_merges: usize,
    final_predicate: bool, mode: Mode) -> h_untraced::Counts {
    let (lanes, groups) = removed(n, real_merges, final_predicate, mode);
    counts.br -= groups;
    counts.levels -= groups;
    counts.pfks -= lanes;
    counts.samples -= lanes;
    counts.rotations -= lanes;
    counts.polynomial_permutations -= 2 * lanes;
    counts.glwe_additions -= lanes - groups;
    counts.lwe_subtractions -= lanes;
    counts.lwe_addbacks -= lanes;
    counts
}

pub(super) const SCORE_GROUP: &[usize] = &[0, 1, 2];
pub(super) const ID_TWO: &[usize] = &[3, 4];
pub(super) const ID_THREE: &[usize] = &[3, 4, 5];
pub(super) const THRESHOLD_GROUP: &[usize] = &[6, 7, 8];

/// Same functional key, correction, offsets, BR and add-back as the original selectors.
/// Unselected slots become public zero placeholders; no PFKS, BR or extraction visits them.
/// Arrays keep the old shape so score/threshold operand positions and the wire stay fixed.
pub(super) fn select_lanes<const N: usize>(
    left: &[Lwe], right: &[Lwe], combined: &Lwe, groups: &[&[usize]],
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>, bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe; N], wide_id::Metrics) {
    if let Some(selected) = g4_query::maybe_select::<N>(left, right, combined, groups, window_key) { return selected; }
    assert_eq!((left.len(), right.len()), (N, N));
    let modulus = combined.ciphertext_modulus();
    let mut metrics = wide_id::Metrics::default();
    let mut control = Lwe::new(0u64, ksk.output_key_lwe_dimension().to_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, combined, &mut control);
    metrics.ks += 1;
    let centered = mean_center::apply(control);
    metrics.public_centering_calls += 1;
    metrics.public_centering_mask_terms += centered.original.get_mask().as_ref().len();
    metrics.public_centering_body_additions += 1;
    let mean_center::Centered { corrected: control, .. } = centered;
    let mut pfks: [Option<Glwe>; N] = std::array::from_fn(|_| None);
    for &lane in groups.iter().flat_map(|group| group.iter()) {
        assert!(pfks[lane].is_none(), "payload lane appears only once");
        let mut difference = right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
        metrics.lwe_subtractions += 1;
        let mut term = Glwe::new(0u64, window_key.output_glwe_size(), window_key.output_polynomial_size(), modulus);
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(window_key, &mut term, &difference);
        metrics.pfks += 1;
        pfks[lane] = Some(term);
    }
    let mut outputs: [Option<Lwe>; N] = std::array::from_fn(|_| None);
    for &group in groups {
        assert!(!group.is_empty() && group.len() <= 3);
        let mut accumulator: Option<Glwe> = None;
        for (position, &lane) in group.iter().enumerate() {
            let offset = position * 41;
            #[cfg(not(feature = "opt-owned-pfks"))]
            let mut term = pfks[lane].as_ref().expect("selected PFKS lane").clone();
            #[cfg(feature = "opt-owned-pfks")]
            let mut term = pfks[lane].take().expect("selected PFKS lane");
            for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial, MonomialDegree(offset));
                metrics.polynomial_permutation_calls += 1;
            }
            metrics.monomial_calls += 1;
            metrics.nonidentity_monomial_calls += usize::from(offset != 0);
            if let Some(acc) = accumulator.as_mut() {
                for (word, value) in acc.as_mut().iter_mut().zip(term.as_ref()) {
                    *word = word.wrapping_add(*value);
                }
                metrics.glwe_additions += 1;
            } else { accumulator = Some(term); }
        }
        let mut accumulator = accumulator.expect("nonempty payload group");
        blind_rotate_assign(&control, &mut accumulator, bsk);
        metrics.br += 1;
        for (position, &lane) in group.iter().enumerate() {
            let mut output = Lwe::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut output, MonomialDegree(position * 41));
            metrics.samples += 1;
            lwe_ciphertext_add_assign(&mut output, &left[lane]);
            metrics.lwe_addbacks += 1;
            outputs[lane] = Some(output);
        }
    }
    let output = std::array::from_fn(|lane| outputs[lane].take().unwrap_or_else(|| {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(bsk.output_lwe_dimension().to_lwe_size(), Plaintext(0), modulus)
    }));
    (output, metrics)
}

pub(super) fn add_selection(counts: &mut h_untraced::Counts, metrics: &wide_id::Metrics,
    payloads: usize, groups: usize) {
    assert!(metrics.pass_for(payloads, groups));
    counts.br += 3 + metrics.br as u64;
    counts.ks += 3 + metrics.ks as u64;
    counts.samples += 3 + metrics.samples as u64;
    counts.levels += 3 + metrics.br as u64;
    counts.pfks += metrics.pfks as u64;
    counts.rotations += metrics.monomial_calls as u64;
    counts.polynomial_permutations += metrics.polynomial_permutation_calls as u64;
    counts.glwe_additions += metrics.glwe_additions as u64;
    counts.lwe_subtractions += metrics.lwe_subtractions as u64;
    counts.lwe_addbacks += metrics.lwe_addbacks as u64;
    counts.centering_calls += metrics.public_centering_calls as u64;
    counts.centering_mask_terms += metrics.public_centering_mask_terms as u64;
    counts.centering_body_additions += metrics.public_centering_body_additions as u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use service::{Counts, ExecutionMode, ThresholdMode};

    #[test]
    fn combined_work_matches_the_preregistered_n128_and_n129_cuts() {
        let uniform = ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score: 1211 });
        for (n, baseline, final_only, narrow, both) in [
            (128, (1408, 1024, 768, 1920), (1407, 1024, 765, 1917), (1408, 1024, 640, 1792), (1407, 1024, 637, 1789)),
            (129, (1419, 1032, 774, 1935), (1418, 1032, 771, 1932), (1419, 1032, 645, 1806), (1418, 1032, 642, 1803)),
        ] {
            for (mode, expected) in [(Mode::Baseline, baseline), (Mode::FinalIdOnly, final_only), (Mode::NarrowId, narrow), (Mode::Both, both)] {
                let counts = operation_counts(n, uniform, mode).unwrap();
                assert_eq!((counts.br, counts.ks, counts.pfks, counts.marginals), expected);
                assert_eq!(counts.initial_samples, n as u64);
            }
        }
        let mixed = operation_counts(128, ExecutionMode::MixedWinnerThreshold, Mode::Both).unwrap();
        assert_eq!((mixed.br, mixed.ks, mixed.pfks, mixed.marginals), (1534, 1024, 1018, 2170));
    }

    #[test]
    fn narrow_dispatch_stops_at_the_first_nonzero_third_identity_digit() {
        assert_eq!(wide_id::identity_digits(224), Some([14, 14, 0]));
        assert_eq!(wide_id::identity_digits(225), Some([0, 0, 1]));
        for execution in [ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score: 1211 }), ExecutionMode::MixedWinnerThreshold] {
            let old = operation_counts(224, execution, Mode::Baseline).unwrap();
            let narrow = operation_counts(224, execution, Mode::NarrowId).unwrap();
            assert_eq!((old.pfks - narrow.pfks, old.br - narrow.br), (224, 0));
            for n in [225, 226, 1024, service::MAX_GALLERY_SIZE] {
                assert_eq!(operation_counts(n, execution, Mode::NarrowId), operation_counts(n, execution, Mode::Baseline));
                assert_eq!(operation_counts(n, execution, Mode::Both), operation_counts(n, execution, Mode::FinalIdOnly));
                assert!(!Mode::Both.narrow_for(n));
            }
        }
    }

    #[test]
    fn public_shortcuts_do_not_create_a_final_selector_or_skip_admission() {
        for mode in [Mode::Baseline, Mode::FinalIdOnly, Mode::NarrowId, Mode::Both] {
            for n in [1, 128, 224, 225] {
                assert_eq!(operation_counts(n, ExecutionMode::Uniform(ThresholdMode::AllReject), mode),
                    Some(Counts { br: 0, ks: 0, pfks: 0, marginals: 0, initial_samples: 0 }));
            }
            assert_eq!(operation_counts(1, ExecutionMode::Uniform(ThresholdMode::AllAccept), mode),
                Some(Counts { br: 6, ks: 4, pfks: 0, marginals: 6, initial_samples: 1 }));
            for n in [0, service::MAX_GALLERY_SIZE + 1, usize::MAX] {
                assert_eq!(operation_counts(n, ExecutionMode::Uniform(ThresholdMode::AllReject), mode), None);
            }
            for score in [0, 4096, u16::MAX] {
                assert_eq!(operation_counts(128, ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score }), mode), None);
            }
        }
        let accept = ExecutionMode::Uniform(ThresholdMode::AllAccept);
        assert_eq!(operation_counts(128, accept, Mode::FinalIdOnly), operation_counts(128, accept, Mode::Baseline));
        assert_eq!(operation_counts(128, accept, Mode::Both), operation_counts(128, accept, Mode::NarrowId));
        assert_eq!(operation_counts(128, accept, Mode::Both).unwrap().pfks, 5 * 127);
    }
}
