//! Key-free admission, actual LUT geometry and integer contract tests.
//! These do not establish noisy correctness or run the encrypted endpoint.
use super::*;

fn views<'a>(template: &'a [i64], n: usize, threshold: i64) -> Vec<service::TemplateView<'a>> {
    let norm2 = template.iter().map(|value| value * value).sum();
    (0..n).map(|_| service::TemplateView { template, norm2, threshold }).collect()
}

fn payload(score: u64, identity: u64) -> [u64; 5] {
    [score >> 8, (score >> 4) & 15, score & 15, identity % 15, identity / 15]
}

fn window_at(window: &[u64], degree: isize) -> i64 {
    let word = window[degree.rem_euclid(2048) as usize] as i64;
    if degree.div_euclid(2048).rem_euclid(2) == 0 { word } else { -word }
}

// Apply the real comparator LUT and real window at the exact message addresses.
fn clear_merge(left: [u64; 5], right: [u64; 5], window: &[u64]) -> [u64; 5] {
    let signs: [i64; 3] = std::array::from_fn(|lane| {
        let difference = left[lane] as i64 - right[lane] as i64;
        let degree = (128 * difference).rem_euclid(4096) as usize;
        comparator::value(false, degree)
    });
    let combined = 4 * signs[0] + 2 * signs[1] + signs[2];
    let choose_right = window_at(window, (128 * combined - 64) as isize);
    assert!(choose_right == 0 || choose_right == 1);
    if choose_right == 1 { right } else { left }
}

fn clear_tree(scores: &[u64], window: &[u64]) -> ([u64; 5], usize) {
    let mut current: Vec<_> = scores.iter().enumerate()
        .map(|(index, score)| payload(*score, index as u64 + 1)).collect();
    let mut merges = 0;
    while current.len() > 1 {
        let mut next: Vec<_> = current.chunks_exact(2)
            .map(|pair| clear_merge(pair[0], pair[1], window)).collect();
        merges += next.len();
        if current.len() % 2 == 1 { next.push(*current.last().unwrap()); }
        current = next;
    }
    (clear_merge(payload(1024, 0), current[0], window), merges + 1)
}

#[test]
fn every_supported_size_has_complete_and_partial_ledgers() {
    assert_eq!(service::MAX_GALLERY_SIZE, 224);
    for n in 1..=224 {
        let expected = service::operation_counts(n).unwrap();
        assert_eq!((expected.br, expected.ks, expected.pfks, expected.marginals, expected.initial_samples),
                   (11*n as u64, 8*n as u64, 5*n as u64, 14*n as u64, n as u64));
        for k in 0..=n {
            let reached = m_untraced::reached(n, k);
            assert_eq!(reached.br, 6*n as u64 + 5*k as u64);
            assert_eq!(reached.ks, 4*n as u64 + 4*k as u64);
            assert_eq!(reached.samples, 6*n as u64 + 8*k as u64);
            assert_eq!(reached.levels, 8*n as u64 + 5*k as u64);
            assert_eq!(reached.pfks, 5*k as u64);
            assert_eq!(reached.centering_calls, k as u64);
            assert_eq!(reached.centering_mask_terms, 859*k as u64);
        }
        m_untraced::check(&m_untraced::reached(n, n), n);
    }
    for n in [0, 225, usize::MAX] { assert_eq!(service::operation_counts(n), None); }
    assert_eq!(service::operation_counts(127), Some(service::N127_COUNTS));
}

#[test]
fn head_admission_extends_only_size_and_preserves_legacy_limit() {
    let template = [1i64; 512];
    for n in 1..=224 {
        let entries = views(&template, n, 4);
        let plan = service::plan(&entries).unwrap();
        assert!(plan.aligned_fast_path);
        assert_eq!(plan.execution_domain.lower, -1019);
        let legacy = private_argmin::plan_private_argmin_execution(&entries);
        assert_eq!(legacy.is_ok(), n <= 128);
        if let Ok(legacy) = legacy { assert_eq!(plan, legacy); }
    }
    assert!(service::plan(&[]).is_err());
    assert!(service::plan(&views(&template, 225, 4)).is_err());
    assert!(service::plan(&views(&template, 1, 273)).is_err());
    assert!(service::plan(&views(&template, 1, i64::MIN)).is_err());
    let mut mixed = views(&template, 2, 4);
    mixed[1].threshold = 5;
    assert!(service::plan(&mixed).is_err());
    let mut incorrect_norm = views(&template, 1, 4);
    incorrect_norm[0].norm2 = 511;
    assert!(service::plan(&incorrect_norm).is_err());
    let mut invalid_coordinate = template;
    invalid_coordinate[0] = 4;
    assert!(service::plan(&views(&invalid_coordinate, 1, 4)).is_err());
    assert!(service::plan(&views(&template[..511], 1, 4)).is_err());
}

#[test]
fn request_rejects_geometry_and_changed_execution_domain_without_keys() {
    let template = [1i64; 512];
    let entries = views(&template, 224, 4);
    let domain = service::plan(&entries).unwrap().execution_domain;
    let packed = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
    assert!(service::request::validate(&packed, &entries, domain).is_ok());
    let changed = service::ScoreDomain { lower: domain.lower + 1, upper: domain.upper };
    assert!(service::request::validate(&packed, &entries, changed).is_err());
    for (glwe, polynomial) in [(1, 2048), (2, 1024), (4, 1024)] {
        let malformed = Glwe::new(0, GlweSize(glwe), PolynomialSize(polynomial), CiphertextModulus::new_native());
        assert!(service::request::validate(&malformed, &entries, domain).is_err());
    }
}

#[test]
fn actual_window_keeps_all_five_payload_coefficients_separate() {
    assert_eq!(OUTPUTS, 5);
    assert_eq!(PAYLOAD_DELTAS, [1u64 << 59; 5]);
    assert_eq!(GROUPS, [&[0, 1, 2][..], &[3, 4][..]]);
    assert_eq!(OFFSETS, [&[0, 41, 82][..], &[0, 41][..]]);
    let window = d1::window();
    assert_eq!(window.as_ref().iter().sum::<u64>(), 287);
    let mut checked = 0;
    for top in -1..=1 {
        for middle in -1..=1 {
            for low in -1..=1 {
                let combined = 4*top + 2*middle + low;
                for error in -20..=20 {
                    let address = 128*combined - 64 + error;
                    for offsets in OFFSETS {
                        for (i, out) in offsets.iter().enumerate() {
                            for (j, term) in offsets.iter().enumerate() {
                                let degree = address + *out as isize - *term as isize;
                                assert_eq!(window_at(window.as_ref(), degree), i64::from(combined > 0 && i == j));
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 14391);
}

#[test]
fn every_size_and_winner_preserve_odd_carries_ids_ties_and_rejection() {
    let window = d1::window();
    for n in 1..=224 {
        for winner in 0..n {
            let mut scores = vec![1025; n];
            scores[winner] = 1023;
            let (selected, merges) = clear_tree(&scores, window.as_ref());
            assert_eq!(selected, payload(1023, winner as u64 + 1));
            assert_eq!(merges, n);
            assert!(selected[3] < 15 && selected[4] < 15);
        }
        for score in [0, 15, 16, 255, 256, 1023, 1024, 4095] {
            let (selected, merges) = clear_tree(&vec![score; n], window.as_ref());
            assert_eq!(selected, if score <= 1023 { payload(score, 1) } else { payload(1024, 0) });
            assert_eq!(merges, n);
        }
        let mut cross_tree_tie = vec![1025; n];
        cross_tree_tie[0] = 1023;
        cross_tree_tie[n - 1] = 1023;
        assert_eq!(clear_tree(&cross_tree_tie, window.as_ref()).0, payload(1023, 1));
    }
    assert_eq!(payload(0, 224)[3..], [14, 14]);
    assert_eq!(payload(0, 225)[4], 15);
    for score in 0..4096 {
        let expected = if score <= 1023 { payload(score, 1) } else { payload(1024, 0) };
        assert_eq!(clear_tree(&[score], window.as_ref()), (expected, 1));
    }
}
