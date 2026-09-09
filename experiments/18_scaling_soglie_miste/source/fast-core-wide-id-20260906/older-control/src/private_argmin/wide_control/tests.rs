//! Key-free source, integer-LUT and generic scan graph checks. No key generation or FHE.
use super::*;
use crate::a53_scan::{self, A53StaticError, PrimitiveCounts};
use crate::a53_scan::fhe::wide::materialize_a53_scan_wide;

fn views(template: &[i64], n: usize, threshold: i64) -> Vec<TemplateView<'_>> {
    let norm2 = template.iter().map(|value| value * value).sum();
    (0..n).map(|_| TemplateView { template, norm2, threshold }).collect()
}

fn region<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    &text[text.find(start).unwrap()..text.find(end).unwrap()]
}

#[test]
fn score_extraction_elimination_and_preparations_keep_the_exact_parent_prefix() {
    let parent = include_str!("../../private_argmin.rs");
    let adapted = include_str!("../wide_control.rs");
    let expected = region(parent, "fn private_argmin_aligned_a38_impl(", "    let mut a53_roots = None;")
        .replace("fn private_argmin_aligned_a38_impl(", "fn evaluate_aligned(")
        .replace("Result<AlignedPrivateArgminOutput, PrivateArgminError>", "Result<A126WideOutput, PrivateArgminError>")
        .replace("include_bytes!(\"../artifacts/fused_candidate_zero_body.u64le\")",
                 "include_bytes!(\"../../artifacts/fused_candidate_zero_body.u64le\")")
        .replace("high[state] = identity_code / A38_NIBBLE_RADIX;", "high[state] = unused_high_digit(identity_code);");
    assert_eq!(region(adapted, "fn evaluate_aligned(", "    let backend = A66A53CoreBackend"), expected);
    // This includes all active arithmetic and all otherwise-unused setup allocations.
    let parent_validation = region(parent, "fn validate_inputs(", "/// Calcola il fingerprint");
    let adapted_validation = region(adapted, "fn validate_inputs(", "pub fn cauchy_score_domain(");
    assert_eq!(parent_validation, adapted_validation);
}

#[test]
fn unused_lut_normalization_keeps_every_prior_release_torus_word_without_overflow() {
    for identity in 0..=3374u64 {
        let old_word = (identity / 16).wrapping_mul(1u64 << 59);
        let normalized = unused_high_digit(identity);
        assert!(normalized < 32);
        assert_eq!(normalized * (1u64 << 59), old_word);
    }
    assert_eq!(unused_high_digit(511), 31);
    assert_eq!(unused_high_digit(512), 0);
}

#[test]
fn every_identity_and_last_group_layout_pass_the_actual_negacyclic_coefficients() {
    for identity in 0..=MAX_GALLERY_SIZE {
        let digits = wide_scan::identity_digits(identity).unwrap();
        assert!(digits.iter().all(|digit| *digit < 15));
        assert_eq!(usize::from(digits[0]) + 15*usize::from(digits[1]) + 225*usize::from(digits[2]), identity);
        if identity > 0 {
            let layout = wide_scan::selector_layout((identity - 1) / 4, 1 + (identity - 1) % 4).unwrap();
            wide_scan::validate_selector_layout(&layout).unwrap();
        }
    }
    assert_eq!(wide_scan::identity_digits(224), Ok([14, 14, 0]));
    assert_eq!(wide_scan::identity_digits(225), Ok([0, 0, 1]));
    assert_eq!(wide_scan::identity_digits(3374), Ok([14, 14, 14]));
    assert!(wide_scan::identity_digits(3375).is_err());
}

#[test]
fn all_old_full_group_offsets_remain_exact_and_the_first_new_parity_conflict_is_avoided() {
    for group in 0..32 {
        let layout = wide_scan::selector_layout(group, 4).unwrap();
        assert_eq!(layout.dual_lanes, [0, 1]);
        assert_eq!(layout.single_lane, 2);
        assert_eq!(layout.offsets, a53_scan::FULL_GROUP_SELECTOR_OFFSETS[group]);
        let old = a53_scan::selector_layout(group, 4, false).unwrap();
        assert_eq!(layout.dual_residue_body, old.residue_body);
    }
    let layout = wide_scan::selector_layout(56, 4).unwrap();
    assert_eq!(wide_scan::identity_digits(228), Ok([3, 0, 1]));
    assert_eq!(layout.dual_lanes, [0, 2]);
    assert_eq!(layout.single_lane, 1);
    assert_eq!((layout.offsets.low, layout.offsets.high), (2, 31));
    for length in 1..=3 {
        let short = wide_scan::selector_layout(56, length).unwrap();
        assert_eq!(short.dual_lanes, [0, 1]);
        assert_eq!((short.offsets.low, short.offsets.high), (0, 0));
    }
}

#[test]
fn malformed_geometry_lane_maps_and_coefficients_are_rejected() {
    for (group, length) in [(0, 0), (0, 5), (843, 3), (844, 1), (usize::MAX, 4)] {
        assert!(wide_scan::selector_layout(group, length).is_err());
    }
    let mut layout = wide_scan::selector_layout(56, 4).unwrap();
    layout.single_lane = layout.dual_lanes[0];
    assert!(wide_scan::validate_selector_layout(&layout).is_err());
    let mut layout = wide_scan::selector_layout(56, 4).unwrap();
    layout.dual_residue_body[0] ^= 1;
    assert!(wide_scan::validate_selector_layout(&layout).is_err());
    for n in [0, 3375, usize::MAX] {
        assert!(wide_scan::scan_counts(n).is_err());
        assert!(operation_counts(n).is_none());
    }
}

#[test]
fn counts_extend_the_same_a126_prefix_and_the_explicit_three_root_scan() {
    for n in 1..=MAX_GALLERY_SIZE {
        let counts = operation_counts(n).unwrap();
        let scan = wide_scan::scan_counts(n).unwrap();
        let groups = n.div_ceil(4) as u64;
        assert_eq!((scan.selector_blind_rotations, scan.selector_key_switches, scan.selector_marginals),
                   (2*groups, 2*groups, 3*groups));
        assert_eq!(counts.initial_samples, 2*n as u64);
        assert_eq!(counts.br - counts.ks, 3*n as u64);
        assert_eq!(counts.marginals - counts.br, 5*n as u64 + groups);
        if n <= 128 {
            let old = a126_aligned_operation_counts(n).unwrap();
            let old_scan = a53_scan::scan_counts(n).unwrap().total;
            assert_eq!(counts.br - scan.total.blind_rotations, old.blind_rotations - old_scan.blind_rotations);
            assert_eq!(counts.ks - scan.total.key_switches, old.key_switches - old_scan.key_switches);
            assert_eq!(counts.marginals - scan.total.output_marginals, old.output_marginals - old_scan.output_marginals);
        }
    }
    for (n, expected) in [(127, (3299, 2918, 3966)), (224, (5799, 5127, 6975)),
        (225, (5826, 5151, 7008)), (256, (6643, 5875, 7987)),
        (512, (13275, 11739, 15963)), (1024, (26530, 23458, 31906)),
        (3374, (87366, 77244, 105080))] {
        let counts = operation_counts(n).unwrap();
        assert_eq!((counts.br, counts.ks, counts.marginals), expected);
    }
}

#[test]
fn wider_admission_retains_the_aligned_domain_and_leaves_old128_guards_intact() {
    let template = [1i64; 512];
    for n in [1, 127, 128, 129, 224, 225, 256, 512, 1024, 3374] {
        let entries = views(&template, n, 4);
        let wide = plan(&entries).unwrap();
        assert!(wide.aligned_fast_path);
        assert_eq!(wide.execution_domain.lower, -1019);
        let old = super::super::plan_private_argmin_execution(&entries);
        assert_eq!(old.is_ok(), n <= 128);
        if let Ok(old) = old { assert_eq!(wide, old); }
    }
    assert!(plan(&[]).is_err());
    assert!(plan(&views(&template, 3375, 4)).is_err());
    assert!(plan(&views(&template, 1, 273)).is_err());
    let mut mixed = views(&template, 2, 4);
    mixed[1].threshold = 5;
    assert!(plan(&mixed).is_err());
    let mut bad_norm = views(&template, 1, 4);
    bad_norm[0].norm2 = 0;
    assert!(plan(&bad_norm).is_err());
    assert!(plan(&views(&template[..511], 1, 4)).is_err());
    let mut bad_coordinate = template;
    bad_coordinate[0] = 4;
    assert!(plan(&views(&bad_coordinate, 1, 4)).is_err());
}

#[derive(Default)]
struct ExactBackend {
    br: AtomicU64,
    extra_marginals: AtomicU64,
}

impl ExactBackend {
    fn sample(&self, input: u64, body: &[u64], sample_degree: usize) -> u64 {
        assert_eq!(body.len(), 2048);
        assert_eq!(input % (1u64 << 59), 0);
        let degree = (input >> 59) as usize * 128 + sample_degree;
        let value = body[degree % 2048];
        if (degree / 2048) % 2 == 0 { value } else { value.wrapping_neg() }
    }
}

impl A53FheBackend for ExactBackend {
    type Lwe = u64;
    type Accumulator = Vec<u64>;
    type Error = A53StaticError;

    fn trivial_zero(&self) -> u64 { 0 }
    fn add_assign(&self, target: &mut u64, source: &u64) { *target = target.wrapping_add(*source); }
    fn sub_assign(&self, target: &mut u64, source: &u64) { *target = target.wrapping_sub(*source); }
    fn add_plaintext_assign(&self, target: &mut u64, source: u64) { *target = target.wrapping_add(source); }
    fn prepare_raw_accumulator(&self, body: &[u64]) -> Result<Vec<u64>, A53StaticError> {
        if body.len() != 2048 { return Err(A53StaticError::InvalidBody); }
        Ok(body.to_vec())
    }
    fn pbs_prepared(&self, input: &u64, accumulator: &Vec<u64>) -> Result<u64, A53StaticError> {
        self.br.fetch_add(1, Ordering::Relaxed);
        Ok(self.sample(*input, accumulator, 0))
    }
    fn pbs_dual_prepared(&self, input: &u64, accumulator: Vec<u64>, first: usize, second: usize)
        -> Result<(u64, u64), A53StaticError> {
        self.br.fetch_add(1, Ordering::Relaxed);
        self.extra_marginals.fetch_add(1, Ordering::Relaxed);
        Ok((self.sample(*input, &accumulator, first), self.sample(*input, &accumulator, second)))
    }
    fn counters(&self) -> PrimitiveCounts {
        let count = self.br.load(Ordering::Relaxed);
        PrimitiveCounts { blind_rotations: count, key_switches: count,
            output_marginals: count + self.extra_marginals.load(Ordering::Relaxed) }
    }
}

#[test]
fn actual_generic_scan_graph_preserves_rejection_late_ids_and_ties_at_large_sizes() {
    for n in [1, 2, 3, 4, 5, 15, 16, 127, 128, 129, 224, 225, 228, 256, 512, 1024, 3374] {
        for active in [Vec::new(), vec![n - 1], vec![0, n - 1], vec![n / 2, n - 1]] {
            let mut candidates = vec![0; n];
            for index in active { candidates[index] = 1u64 << 59; }
            let expected = candidates.iter().position(|value| *value != 0).map_or(0, |index| index + 1);
            let backend = ExactBackend::default();
            let output = materialize_a53_scan_wide(&a66_a53_gate(), &backend, &candidates).unwrap();
            let digits = [output.low_digit >> 59, output.middle_digit >> 59, output.high_digit >> 59];
            assert!(digits.iter().all(|digit| *digit < 15));
            assert_eq!(digits[0] + 15*digits[1] + 225*digits[2], expected as u64);
            assert_eq!(output.expected_counts, output.observed_counts);
            assert_eq!(output.observed_counts, wide_scan::scan_counts(n).unwrap().total);
        }
    }
}
