//! Key-free checks of the actual public planner, sentinel words and fixed LUT bodies.
//! No secret key, native FHE endpoint, PBS or noisy-correctness claim.
use super::*;
use service::{ScoreDomain, TemplateView, ThresholdMode};

fn views(template: &[i64], n: usize, threshold: i64) -> Vec<TemplateView<'_>> {
    let norm2 = template.iter().map(|value| value * value).sum();
    (0..n).map(|_| TemplateView { template, norm2, threshold }).collect()
}

fn payload(score: u64, identity: u64) -> [u64; 5] {
    [score >> 8, (score >> 4) & 15, score & 15, identity % 15, identity / 15]
}

fn clear_merge(left: [u64; 5], right: [u64; 5], window: &[u64]) -> [u64; 5] {
    let signs: [i64; 3] = std::array::from_fn(|lane| {
        let address = (128 * (left[lane] as i64 - right[lane] as i64)).rem_euclid(4096);
        comparator::value(false, address as usize)
    });
    let address = 128 * (4 * signs[0] + 2 * signs[1] + signs[2]) - 64;
    let coefficient = window[address.rem_euclid(2048) as usize] as i64;
    let selected = if address.div_euclid(2048).rem_euclid(2) == 0 { coefficient } else { -coefficient };
    assert!(selected == 0 || selected == 1);
    if selected == 1 { right } else { left }
}

fn clear_selected(scores: &[i64], domain: ScoreDomain, mode: ThresholdMode, window: &[u64]) -> u64 {
    if mode == ThresholdMode::AllReject { return 0; }
    let mut current: Vec<_> = scores.iter().enumerate()
        .map(|(i, score)| payload((i128::from(*score) - i128::from(domain.lower)) as u64, i as u64 + 1))
        .collect();
    while current.len() > 1 {
        let mut next: Vec<_> = current.chunks_exact(2)
            .map(|pair| clear_merge(pair[0], pair[1], window)).collect();
        if current.len() % 2 == 1 { next.push(*current.last().unwrap()); }
        current = next;
    }
    let winner = current[0];
    let selected = if let Some(sentinel) = general::sentinel_payload(mode) {
        clear_merge(sentinel, winner, window)
    } else {
        assert_eq!(mode, ThresholdMode::AllAccept);
        winner
    };
    selected[3] + 15 * selected[4]
}

#[test]
fn previously_aligned_plans_keep_exact_domains_and_sentinel_words() {
    let mut template = [1i64; 512];
    template[511] = 0;
    for n in [1, 2, 127, 128, 129, 224] {
        for threshold in [-1113, -1112, -937, -1, 0, 4, 85, 86] {
            let entries = views(&template, n, threshold);
            let old = private_argmin::plan_private_argmin_execution_with_limit(&entries, 224).unwrap();
            assert!(old.aligned_fast_path);
            let plan = service::plan(&entries).unwrap();
            assert_eq!(plan.cauchy_domain, old.cauchy_domain);
            assert_eq!(plan.execution_domain, old.execution_domain);
            assert_eq!(plan.aligned_fast_path, old.aligned_fast_path);
            assert_eq!(plan.threshold, threshold);
            assert_eq!(general::sentinel_payload(plan.mode), Some([4, 0, 0, 0, 0]));
        }
    }
    // Keep the old merge even when a much narrower domain would allow a public accept shortcut.
    let zeros = [0i64; 512];
    let entries = views(&zeros, 1, 4);
    let plan = service::plan(&entries).unwrap();
    assert!(plan.threshold >= plan.execution_domain.upper);
    assert!(plan.aligned_fast_path);
    assert_eq!(plan.mode, ThresholdMode::CompareSentinel { score: 1024 });
}

#[test]
fn every_score_center_and_inclusive_boundary_use_actual_lut_and_sentinel() {
    let domain = ScoreDomain { lower: -1024, upper: 3071 };
    let window = d1::window();
    for score in domain.lower..=domain.upper {
        for threshold in [i64::MIN, domain.lower - 1, domain.lower, score - 1, score,
                          score + 1, domain.upper - 1, domain.upper, domain.upper + 1, i64::MAX] {
            let mode = general::mode_for_domain(threshold, domain).unwrap();
            let identity = clear_selected(&[score], domain, mode, window.as_ref());
            assert_eq!(identity, u64::from(score <= threshold));
        }
    }
    assert_eq!(general::sentinel_payload(ThresholdMode::CompareSentinel { score: 4095 }), Some([15, 15, 15, 0, 0]));
    for score in [0, 4096, u16::MAX] {
        let invalid = ThresholdMode::CompareSentinel { score };
        assert_eq!(general::sentinel_payload(invalid), None);
        assert_eq!(service::operation_counts(1, invalid), None);
    }
}

#[test]
fn signed_extremes_branch_before_arithmetic_and_invalid_domains_still_reject() {
    for domain in [ScoreDomain { lower: i64::MIN, upper: i64::MIN + 4095 },
                   ScoreDomain { lower: i64::MAX - 4095, upper: i64::MAX }] {
        assert_eq!(general::mode_for_domain(domain.lower, domain).unwrap(), ThresholdMode::CompareSentinel { score: 1 });
        assert_eq!(general::mode_for_domain(domain.upper - 1, domain).unwrap(), ThresholdMode::CompareSentinel { score: 4095 });
        assert_eq!(general::mode_for_domain(domain.upper, domain).unwrap(), ThresholdMode::AllAccept);
    }
    let domain = ScoreDomain { lower: -937, upper: 1959 };
    assert_eq!(general::mode_for_domain(i64::MIN, domain).unwrap(), ThresholdMode::AllReject);
    assert_eq!(general::mode_for_domain(i64::MAX, domain).unwrap(), ThresholdMode::AllAccept);
    for invalid in [ScoreDomain { lower: 1, upper: 0 }, ScoreDomain { lower: 0, upper: 4096 },
                    ScoreDomain { lower: i64::MIN, upper: i64::MAX }] {
        assert!(general::mode_for_domain(i64::MIN, invalid).is_err());
        assert!(general::mode_for_domain(i64::MAX, invalid).is_err());
    }
}

#[test]
fn general_uniform_admission_preserves_template_and_geometry_guards() {
    let mut template = [1i64; 512];
    template[511] = 0;
    let packed = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
    for threshold in [i64::MIN, -1114, 273, 1958, 1959, i64::MAX] {
        let entries = views(&template, 224, threshold);
        let plan = service::plan(&entries).unwrap();
        assert!(!plan.aligned_fast_path);
        assert_eq!(plan.execution_domain, ScoreDomain { lower: -937, upper: 1959 });
        assert_eq!(plan.mode, general::mode_for_domain(threshold, plan.execution_domain).unwrap());
        assert!(service::request::validate(&packed, &entries, plan.execution_domain).is_ok());
        let wrong = ScoreDomain { lower: -938, upper: 1959 };
        assert!(service::request::validate(&packed, &entries, wrong).is_err());
        let malformed = Glwe::new(0, GlweSize(1), PolynomialSize(2048), CiphertextModulus::new_native());
        assert!(service::request::validate(&malformed, &entries, plan.execution_domain).is_err());
    }
    let plan = service::plan(&views(&template, 1, 273)).unwrap();
    assert_eq!(plan.mode, ThresholdMode::CompareSentinel { score: 1211 });
    let mut mixed = views(&template, 2, 4);
    mixed[1].threshold = 273;
    assert!(service::plan(&mixed).is_err());
    let mut bad_norm = views(&template, 1, i64::MIN);
    bad_norm[0].norm2 = 512;
    assert!(service::plan(&bad_norm).is_err());
    let mut coordinate = template;
    coordinate[0] = 4;
    assert!(service::plan(&views(&coordinate, 1, i64::MIN)).is_err());
    assert!(service::plan(&views(&template[..511], 1, i64::MIN)).is_err());
    // Norm1023 gives a Cauchy width4097: public rejection does not bypass domain admission.
    let mut too_wide = [0i64; 512];
    too_wide[..255].fill(2);
    too_wide[255..258].fill(1);
    assert!(service::plan(&views(&too_wide, 1, i64::MIN)).is_err());
    assert!(service::plan(&[]).is_err());
    assert!(service::plan(&views(&template, 225, i64::MIN)).is_err());
}

#[test]
fn each_terminal_mode_has_the_complete_actual_work_ledger() {
    let compare = ThresholdMode::CompareSentinel { score: 1211 };
    for n in 1..=224 {
        for mode in [ThresholdMode::AllReject, compare, ThresholdMode::AllAccept] {
            let counts = service::operation_counts(n, mode).unwrap();
            let reached = match mode {
                ThresholdMode::AllReject => h_untraced::Counts::default(),
                ThresholdMode::CompareSentinel { .. } => m_untraced::reached(n, n),
                ThresholdMode::AllAccept => m_untraced::reached(n, n - 1),
            };
            m_untraced::check(&reached, n, mode);
            assert_eq!((counts.br, counts.ks, counts.pfks, counts.marginals, counts.initial_samples),
                       (reached.br, reached.ks, reached.pfks, reached.samples, reached.score_samples));
        }
    }
    for n in [0, 225, usize::MAX] {
        for mode in [ThresholdMode::AllReject, compare, ThresholdMode::AllAccept] {
            assert_eq!(service::operation_counts(n, mode), None);
        }
    }
    assert_eq!(service::operation_counts(127, compare), Some(service::N127_COUNTS));
    let single_accept = service::operation_counts(1, ThresholdMode::AllAccept).unwrap();
    assert_eq!((single_accept.br, single_accept.ks, single_accept.pfks), (6, 4, 0));
}

#[test]
fn public_rejection_produces_the_actual_two_zero_ciphertexts_without_keys() {
    let output = m_untraced::public_rejection(CiphertextModulus::new_native());
    assert_eq!(output.counts, h_untraced::Counts::default());
    for digit in output.digits {
        assert_eq!(digit.as_ref().len(), 2049);
        assert!(digit.ciphertext_modulus().is_native_modulus());
        assert!(digit.as_ref().iter().all(|word| *word == 0));
    }
}

#[test]
fn dynamic_cut_preserves_first_ties_odd_tails_and_late_winning_ids() {
    let domain = ScoreDomain { lower: 0, upper: 4095 };
    let window = d1::window();
    for n in [1, 2, 3, 15, 16, 126, 127, 128, 129, 223, 224] {
        for winner in 0..n {
            let mut scores = vec![4095; n];
            scores[winner] = 1210;
            for threshold in [-1, 0, 1209, 1210, 1211, 4094, 4095, i64::MAX] {
                let mode = general::mode_for_domain(threshold, domain).unwrap();
                let actual = clear_selected(&scores, domain, mode, window.as_ref());
                assert_eq!(actual, if threshold >= 1210 { winner as u64 + 1 } else { 0 });
            }
        }
        for score in [0, 15, 16, 255, 256, 1023, 1024, 4095] {
            for threshold in [score - 1, score, score + 1] {
                let mode = general::mode_for_domain(threshold, domain).unwrap();
                assert_eq!(clear_selected(&vec![score; n], domain, mode, window.as_ref()), u64::from(score <= threshold));
            }
        }
        let mut tie = vec![4095; n];
        tie[0] = 1210;
        tie[n - 1] = 1210;
        let mode = general::mode_for_domain(1210, domain).unwrap();
        assert_eq!(clear_selected(&tie, domain, mode, window.as_ref()), 1);
    }
}
