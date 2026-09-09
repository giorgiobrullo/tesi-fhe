//! Key-free mixed semantics, actual public payloads, selector geometry and operand binding.
use super::*;
use service::{ExecutionMode, ScoreDomain, TemplateView, ThresholdMode};

fn entries<'a>(template: &'a [i64], thresholds: &[i64]) -> Vec<TemplateView<'a>> {
    let norm2 = template.iter().map(|value| value*value).sum();
    thresholds.iter().map(|threshold| TemplateView { template, norm2, threshold: *threshold }).collect()
}

fn score_digits(value: u64) -> [u64; 3] {
    assert!(value <= 4095);
    [value >> 8, (value >> 4) & 15, value & 15]
}

fn control(left: &[u64], right: &[u64]) -> i64 {
    assert_eq!((left.len(), right.len()), (3, 3));
    [4, 2, 1].into_iter().enumerate().map(|(lane, weight)| {
        let degree = (128*(left[lane] as i64-right[lane] as i64)).rem_euclid(4096);
        weight*comparator::value(false, degree as usize)
    }).sum()
}

fn window_at(window: &[u64], degree: i64) -> i64 {
    let coefficient = window[degree.rem_euclid(2048) as usize] as i64;
    if degree.div_euclid(2048).rem_euclid(2) == 0 { coefficient } else { -coefficient }
}

fn selected<const N: usize>(left: [u64; N], right: [u64; N], predicate: i64, window: &[u64]) -> [u64; N] {
    let coefficient = window_at(window, 128*predicate-64);
    assert!(coefficient == 0 || coefficient == 1);
    if coefficient == 1 { right } else { left }
}

fn plaintext_mixed(scores: &[i64], thresholds: &[i64], domain: ScoreDomain, window: &[u64]) -> u64 {
    assert!(!scores.is_empty() && scores.len() == thresholds.len());
    let mut current: Vec<[u64; 9]> = scores.iter().zip(thresholds).enumerate().map(|(i, (score, threshold))| {
        assert!(*score >= domain.lower && *score <= domain.upper);
        let normalized = (i128::from(*score)-i128::from(domain.lower)) as u64;
        let score = score_digits(normalized);
        let public = mixed::leaf_public_payloads(i, *threshold, domain).unwrap();
        [score[0], score[1], score[2], public[0], public[1], public[2], public[3], public[4], public[5]]
    }).collect();
    while current.len() > 1 {
        let mut next: Vec<_> = current.chunks_exact(2).map(|pair| {
            selected(pair[0], pair[1], control(&pair[0][..3], &pair[1][..3]), window)
        }).collect();
        if current.len()%2 == 1 { next.push(*current.last().unwrap()); }
        current = next;
    }
    let winner = current[0];
    let keep: [u64; 6] = winner[..6].try_into().unwrap();
    let result = selected(keep, [0; 6], control(&winner[..3], &winner[6..9]), window);
    result[3]+15*result[4]+225*result[5]
}

fn oracle(scores: &[i64], thresholds: &[i64]) -> u64 {
    let index = (0..scores.len()).min_by_key(|i| (scores[*i], *i)).unwrap();
    if scores[index] <= thresholds[index] { index as u64+1 } else { 0 }
}

fn metrics(payloads: usize) -> wide_id::Metrics {
    let groups = payloads/3;
    wide_id::Metrics {
        pfks: payloads, ks: 1, br: groups, samples: payloads,
        monomial_calls: payloads, nonidentity_monomial_calls: payloads-groups,
        polynomial_permutation_calls: 2*payloads, glwe_additions: payloads-groups,
        lwe_subtractions: payloads, lwe_addbacks: payloads,
        public_centering_calls: 1, public_centering_mask_terms: 859, public_centering_body_additions: 1,
    }
}

#[test]
fn uniform_dispatch_preserves_all_parent_plan_fields_and_work() {
    let mut template = [1i64; 512];
    template[511] = 0;
    for n in [1, 2, 127, 224, 225, 256, 3374] {
        for threshold in [i64::MIN, -1114, -1113, 4, 86, 273, 1959, i64::MAX] {
            let gallery = entries(&template, &vec![threshold; n]);
            let parent = general::plan(&gallery).unwrap();
            let plan = service::plan(&gallery).unwrap();
            assert_eq!(plan.cauchy_domain, parent.cauchy_domain);
            assert_eq!(plan.execution_domain, parent.execution_domain);
            assert_eq!(plan.aligned_fast_path, parent.aligned_fast_path);
            assert_eq!(plan.threshold, Some(parent.threshold));
            assert_eq!(plan.mode, ExecutionMode::Uniform(parent.mode));
            assert_eq!(service::operation_counts(n, plan.mode), service_selected::operation_counts(n, parent.mode));
        }
    }
    let mixed = entries(&template, &[4, 273]);
    assert!(general::plan(&mixed).is_err());
    let plan = service::plan(&mixed).unwrap();
    assert_eq!(plan.mode, ExecutionMode::MixedWinnerThreshold);
    assert_eq!(plan.threshold, None);
    assert!(!plan.aligned_fast_path);
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
}

#[test]
fn mixed_admission_keeps_domain_template_and_packed_guards_before_evaluation() {
    let mut template = [1i64; 512];
    template[511] = 0;
    let packed = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
    for thresholds in [[4, 273], [i64::MIN, i64::MAX], [i64::MIN, i64::MIN+1], [i64::MAX-1, i64::MAX]] {
        let gallery = entries(&template, &thresholds);
        let plan = service::plan(&gallery).unwrap();
        assert_eq!(plan.mode, ExecutionMode::MixedWinnerThreshold);
        assert_eq!(plan.execution_domain, ScoreDomain { lower: -937, upper: 1959 });
        assert!(service::request::validate(&packed, &gallery, plan.execution_domain).is_ok());
        assert!(service::request::validate(&packed, &gallery, ScoreDomain { lower: -1019, upper: 1959 }).is_err());
        let malformed = Glwe::new(0, GlweSize(1), PolynomialSize(2048), CiphertextModulus::new_native());
        assert!(service::request::validate(&malformed, &gallery, plan.execution_domain).is_err());
    }
    let mut wrong_norm = entries(&template, &[i64::MIN, i64::MIN+1]);
    wrong_norm[0].norm2 = 512;
    assert!(service::plan(&wrong_norm).is_err());
    let mut bad_coordinate = template;
    bad_coordinate[0] = 4;
    assert!(service::plan(&entries(&bad_coordinate, &[4, 273])).is_err());
    assert!(service::plan(&entries(&template[..511], &[4, 273])).is_err());
    let mut wide = [0i64; 512];
    wide[..255].fill(2);
    wide[255..258].fill(1);
    assert!(service::plan(&entries(&wide, &[i64::MIN, i64::MIN+1])).is_err());
    assert!(service::plan(&[]).is_err());
    let mut thresholds = vec![4; 3375];
    thresholds[3374] = 273;
    assert!(service::plan(&entries(&template, &thresholds)).is_err());
}

#[test]
fn clamped_threshold_and_public_below_domain_identity_cover_signed_edges() {
    for domain in [ScoreDomain { lower: -937, upper: 1959 },
                   ScoreDomain { lower: i64::MIN, upper: i64::MIN+4095 },
                   ScoreDomain { lower: i64::MAX-4095, upper: i64::MAX }] {
        for threshold in [i64::MIN, domain.lower, domain.upper-1, domain.upper, i64::MAX] {
            let payload = mixed_plan::threshold_payload(threshold, domain).unwrap();
            let expected = i128::from(threshold.clamp(domain.lower, domain.upper))-i128::from(domain.lower);
            assert_eq!(payload.digits[0]*256+payload.digits[1]*16+payload.digits[2], expected as u64);
            assert_eq!(payload.below_domain, threshold < domain.lower);
            let public = mixed::leaf_public_payloads(3373, threshold, domain).unwrap();
            assert_eq!(&public[..3], if payload.below_domain { &[0, 0, 0] } else { &[14, 14, 14] });
            assert_eq!(&public[3..], &payload.digits);
        }
    }
    let domain = ScoreDomain { lower: -937, upper: 1959 };
    assert_eq!(mixed::leaf_public_payloads(224, 273, domain).unwrap(), [0, 0, 1, 4, 11, 10]);
    assert_eq!(mixed::leaf_public_payloads(224, -938, domain).unwrap(), [0, 0, 0, 0, 0, 0]);
    for index in [3374, usize::MAX] {
        assert!(mixed::leaf_public_payloads(index, i64::MIN, domain).is_err());
    }
    for domain in [ScoreDomain { lower: 1, upper: 0 }, ScoreDomain { lower: 0, upper: 4096 },
                   ScoreDomain { lower: i64::MIN, upper: i64::MAX }] {
        assert!(mixed_plan::threshold_payload(i64::MIN, domain).is_err());
        assert!(mixed_plan::threshold_payload(i64::MAX, domain).is_err());
    }
}

#[test]
fn actual_nine_lane_matrix_preserves_scores_ids_and_selected_thresholds() {
    assert_eq!(mixed::OUTPUTS, 9);
    assert_eq!(mixed::GROUPS, [&[0, 1, 2][..], &[3, 4, 5][..], &[6, 7, 8][..]]);
    assert_eq!(mixed::OFFSETS, [&[0, 41, 82][..], &[0, 41, 82][..], &[0, 41, 82][..]]);
    assert_eq!(mixed::OFFSETS[0], wide_id::OFFSETS[0]);
    assert_eq!(mixed::OFFSETS[1], wide_id::OFFSETS[1]);
    let window = d1::window();
    assert_eq!(window.as_ref().iter().sum::<u64>(), 287);
    let mut checked = 0;
    for top in -1..=1 {
        for middle in -1..=1 {
            for low in -1..=1 {
                let predicate = 4*top+2*middle+low;
                for offsets in mixed::OFFSETS {
                    for (out_index, out) in offsets.iter().enumerate() {
                        for (term_index, term) in offsets.iter().enumerate() {
                            for error in -20..=20 {
                                let degree = 128*predicate-64+error+*out as i64-*term as i64;
                                assert_eq!(window_at(window.as_ref(), degree), i64::from(predicate > 0 && out_index == term_index));
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 29_889);
}

#[test]
fn root_operand_views_bind_score_threshold_and_distinct_payload_roles() {
    let winner: [Lwe; 9] = std::array::from_fn(|lane| allocate_and_trivially_encrypt_new_lwe_ciphertext(
        LweSize(2049), Plaintext(100+lane as u64), CiphertextModulus::new_native()));
    let (score, threshold, keep) = mixed::root_parts(&winner);
    assert_eq!((score.len(), threshold.len(), keep.len()), (3, 3, 6));
    assert!(std::ptr::eq(score.as_ptr(), winner.as_ptr()));
    assert!(std::ptr::eq(threshold.as_ptr(), winner[6..].as_ptr()));
    assert!(std::ptr::eq(keep.as_ptr(), winner.as_ptr()));
    for lane in 0..3 {
        assert_eq!(*score[lane].get_body().data, 100+lane as u64);
        assert_eq!(*threshold[lane].get_body().data, 106+lane as u64);
    }
    let window = d1::window();
    let score = score_digits(1210);
    let keep = [score[0], score[1], score[2], 1, 0, 0];
    let correct = selected(keep, [0; 6], control(&score, &score), window.as_ref());
    let wrong = selected(keep, [0; 6], control(&score, &[0; 3]), window.as_ref());
    assert_eq!(correct[3], 1);
    assert_eq!(wrong[3], 0);
}

#[test]
fn mixed_ledger_counts_nine_lane_tree_then_six_lane_final_selection() {
    for n in 1..=3374 {
        let counts = service::operation_counts(n, ExecutionMode::MixedWinnerThreshold).unwrap();
        let complete = mixed::reached(n, n-1, true);
        let n = n as u64;
        assert_eq!((counts.br, counts.ks, counts.pfks, counts.marginals, counts.initial_samples),
            (12*n-1, 8*n, 9*n-3, 18*n-3, n));
        assert_eq!((complete.br, complete.ks, complete.pfks, complete.samples, complete.score_samples),
            (counts.br, counts.ks, counts.pfks, counts.marginals, counts.initial_samples));
        assert_eq!((complete.levels, complete.rotations, complete.polynomial_permutations,
            complete.glwe_additions, complete.lwe_subtractions, complete.lwe_addbacks),
            (14*n-1, 9*n-3, 18*n-6, 6*n-2, 9*n-3, 9*n-3));
        assert_eq!((complete.centering_calls, complete.centering_mask_terms, complete.centering_body_additions),
            (n, 859*n, n));
    }
    for n in [1, 2, 3, 127, 224, 225, 256, 1024, 3374] {
        let mut counts = wide_id::reached(n, 0);
        for _ in 0..n-1 { mixed::add_selection(&mut counts, &metrics(9), 9); }
        assert_eq!(counts, mixed::reached(n, n-1, false));
        let final_metrics = metrics(6);
        assert!(final_metrics.pass());
        mixed::add_selection(&mut counts, &final_metrics, 6);
        assert_eq!(counts, mixed::reached(n, n-1, true));
    }
    for n in [0, 3375, usize::MAX] {
        assert_eq!(service::operation_counts(n, ExecutionMode::MixedWinnerThreshold), None);
    }
}

#[test]
fn nearest_rejection_and_strict_first_tie_do_not_select_a_permissive_alternative() {
    let window = d1::window();
    let domain = ScoreDomain { lower: -100, upper: 3995 };
    for (scores, thresholds, expected) in [
        (vec![0, 1], vec![-1, 2], 0),
        (vec![0, 0], vec![-1, 1], 0),
        (vec![0, 0], vec![0, -1], 1),
        (vec![1, 0], vec![2, 0], 2),
        (vec![-100, -99], vec![-101, i64::MAX], 0),
        (vec![-100, -100], vec![i64::MIN, i64::MAX], 0),
        (vec![3995, 3995], vec![i64::MAX, i64::MIN], 1),
    ] {
        assert_eq!(oracle(&scores, &thresholds), expected);
        assert_eq!(plaintext_mixed(&scores, &thresholds, domain, window.as_ref()), expected);
    }
}

#[test]
fn every_twelve_bit_scalar_center_obeys_its_selected_inclusive_threshold() {
    let window = d1::window();
    let domain = ScoreDomain { lower: -1024, upper: 3071 };
    for score in domain.lower..=domain.upper {
        for threshold in [i64::MIN, domain.lower-1, domain.lower, score-1, score,
                          score+1, domain.upper-1, domain.upper, domain.upper+1, i64::MAX] {
            assert_eq!(plaintext_mixed(&[score], &[threshold], domain, window.as_ref()), u64::from(score <= threshold));
        }
    }
}

#[test]
fn wider_stable_trees_carry_the_actual_winners_threshold_and_three_digit_id() {
    let window = d1::window();
    let domain = ScoreDomain { lower: 0, upper: 4095 };
    for n in [2, 3, 15, 16, 127, 128, 129, 224, 225, 226, 256, 512, 1024, 3374] {
        let mut positions = vec![0, 14, 15, 223, 224, 225, n-1];
        positions.retain(|index| *index < n);
        positions.sort_unstable();
        positions.dedup();
        for index in positions {
            let mut scores = vec![4095; n];
            scores[index] = 1210;
            for selected_threshold in [i64::MIN, -1, 1209, 1210, 1211, 4095, i64::MAX] {
                let mut thresholds = vec![4095; n];
                thresholds[index] = selected_threshold;
                assert_eq!(plaintext_mixed(&scores, &thresholds, domain, window.as_ref()), oracle(&scores, &thresholds));
            }
        }
        let mut scores = vec![4095; n];
        scores[0] = 1210;
        scores[n-1] = 1210;
        let mut thresholds = vec![4095; n];
        thresholds[0] = 1209;
        assert_eq!(plaintext_mixed(&scores, &thresholds, domain, window.as_ref()), 0);
        thresholds[0] = 1210;
        assert_eq!(plaintext_mixed(&scores, &thresholds, domain, window.as_ref()), 1);
    }
    // The mode query is structural; the actual planner can never emit mixed mode for N1.
    let template = [0i64; 512];
    let plan = service::plan(&entries(&template, &[i64::MAX])).unwrap();
    assert_eq!(plan.mode, ExecutionMode::Uniform(ThresholdMode::AllAccept));
}
