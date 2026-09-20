use super::super::test_support::entry;
use super::*;

#[test]
fn integer_ceil_sqrt_is_exact_without_floating_point() {
    for value in 0u64..=100_000 {
        let root = ceil_sqrt(value);
        assert!(root * root >= value);
        assert!(root == 0 || (root - 1) * (root - 1) < value);
    }
    assert_eq!(ceil_sqrt(u64::MAX), 1u64 << 32);
}

#[test]
fn cauchy_domain_is_checked_and_twelve_bit() {
    let mut first = [0i64; PROBE_DIM];
    first[0] = 1;
    let mut second = [0i64; PROBE_DIM];
    second[0] = 2;
    let templates = [entry(&first, 0), entry(&second, 0)];
    let domain = cauchy_score_domain(&templates).unwrap();
    assert_eq!(
        domain,
        ScoreDomain {
            lower: -124,
            upper: 132
        }
    );
    assert_eq!(domain.checked_width(), Some(257));

    let invalid = ScoreDomain {
        lower: i64::MIN,
        upper: i64::MAX,
    };
    assert!(matches!(
        validate_domain(invalid),
        Err(PrivateArgminError::InvalidDomain { .. })
    ));
}

#[test]
fn execution_planner_aligns_only_when_the_expanded_domain_is_safe() {
    // 74 * 3^2 + 2^2 + 1^2 = 671, che induce esattamente [-987, 2329].
    let mut digiface_shape = [0i64; PROBE_DIM];
    digiface_shape[..74].fill(3);
    digiface_shape[74] = 2;
    digiface_shape[75] = 1;

    let current = [entry(&digiface_shape, 4)];
    let plan = plan_private_argmin_execution(&current).unwrap();
    assert_eq!(
        plan,
        PrivateArgminExecutionPlan {
            cauchy_domain: ScoreDomain {
                lower: -987,
                upper: 2329,
            },
            execution_domain: ScoreDomain {
                lower: -1019,
                upper: 2329,
            },
            aligned_fast_path: true,
        }
    );
    assert!(aligned_uniform_fast_path_for_thresholds(
        &[4],
        plan.execution_domain
    ));

    let mixed = [entry(&digiface_shape, 4), entry(&digiface_shape, 5)];
    let plan = plan_private_argmin_execution(&mixed).unwrap();
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(!plan.aligned_fast_path);

    // T=37 darebbe lower=-986 e restringerebbe di uno il bound inferiore: fallback.
    let non_covering = [entry(&digiface_shape, 37)];
    let plan = plan_private_argmin_execution(&non_covering).unwrap();
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(!plan.aligned_fast_path);

    // Con upper=2329, T=-743 produce [-1766,2329] (4096 valori); uno in meno eccede.
    let boundary = [entry(&digiface_shape, -743)];
    let plan = plan_private_argmin_execution(&boundary).unwrap();
    assert_eq!(
        plan.execution_domain,
        ScoreDomain {
            lower: -1766,
            upper: 2329,
        }
    );
    assert_eq!(plan.execution_domain.checked_width(), Some(4096));
    assert!(plan.aligned_fast_path);

    let too_wide = [entry(&digiface_shape, -744)];
    let plan = plan_private_argmin_execution(&too_wide).unwrap();
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(!plan.aligned_fast_path);

    let overflowing_threshold = [entry(&digiface_shape, i64::MIN)];
    let plan = plan_private_argmin_execution(&overflowing_threshold).unwrap();
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(!plan.aligned_fast_path);

    // T=36 allinea senza cambiare il dominio stretto.
    let identical = [entry(&digiface_shape, 36)];
    let plan = plan_private_argmin_execution(&identical).unwrap();
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(plan.aligned_fast_path);
}

#[test]
fn execution_planner_preserves_single_score_extremes_and_validation_errors() {
    let zero = [0i64; PROBE_DIM];

    let accept_all = [entry(&zero, 1023)];
    let plan = plan_private_argmin_execution(&accept_all).unwrap();
    assert_eq!(plan.cauchy_domain, ScoreDomain { lower: 0, upper: 0 });
    assert_eq!(plan.execution_domain, plan.cauchy_domain);
    assert!(plan.aligned_fast_path);
    assert_eq!(clear_private_argmin(&[0], &accept_all).unwrap().code, 1);

    let reject_all = [entry(&zero, -1)];
    let plan = plan_private_argmin_execution(&reject_all).unwrap();
    assert_eq!(
        plan.execution_domain,
        ScoreDomain {
            lower: -1024,
            upper: 0,
        }
    );
    assert!(plan.aligned_fast_path);
    assert_eq!(clear_private_argmin(&[0], &reject_all).unwrap().code, 0);

    let wide = [entry(&[3i64; PROBE_DIM], 0)];
    assert!(matches!(
        plan_private_argmin_execution(&wide),
        Err(PrivateArgminError::DomainTooWide {
            width: 8693,
            maximum: MAX_DOMAIN_WIDTH,
        })
    ));
    assert_eq!(
        plan_private_argmin_execution(&[]),
        Err(PrivateArgminError::EmptyGallery)
    );
}

#[test]
fn public_template_validation_is_panic_free() {
    let mut invalid = [0i64; PROBE_DIM];
    invalid[19] = 4;
    let view = TemplateView {
        template: &invalid,
        norm2: 16,
        threshold: 0,
    };
    assert_eq!(
        cauchy_score_domain(&[view]),
        Err(PrivateArgminError::InvalidTemplateCoordinate {
            index: 0,
            coordinate: 19,
            value: 4,
        })
    );
    let valid = [0i64; PROBE_DIM];
    let mismatch = TemplateView {
        template: &valid,
        norm2: 1,
        threshold: 0,
    };
    assert!(matches!(
        cauchy_score_domain(&[mismatch]),
        Err(PrivateArgminError::IncorrectTemplateNorm { .. })
    ));
}

#[test]
fn tie_and_per_template_threshold_use_only_first_winner() {
    let first = [0i64; PROBE_DIM];
    let second = [0i64; PROBE_DIM];
    let strict_then_permissive = [entry(&first, 9), entry(&second, 100)];

    let nearest_strict = clear_private_argmin(&[10, 11], &strict_then_permissive).unwrap();
    assert_eq!(nearest_strict.winner_index, 0);
    assert!(!nearest_strict.matched);
    assert_eq!(nearest_strict.code, 0);

    let tied = clear_private_argmin(&[10, 10], &strict_then_permissive).unwrap();
    assert_eq!(tied.winner_index, 0);
    assert!(!tied.matched);
    assert_eq!(tied.code, 0);

    let permissive_first = [entry(&first, 10), entry(&second, -100)];
    let accepted = clear_private_argmin(&[10, 10], &permissive_first).unwrap();
    assert_eq!(accepted.winner_index, 0);
    assert!(accepted.matched);
    assert_eq!(accepted.code, 1);
}

#[test]
fn aligned_fast_path_guard_is_exact_and_fail_closed() {
    let aligned = ScoreDomain {
        lower: -1019,
        upper: 2329,
    };
    assert!(aligned_uniform_fast_path_for_thresholds(
        &[4, 4, 4],
        aligned
    ));
    assert!(!aligned_uniform_fast_path_for_thresholds(&[], aligned));
    assert!(!aligned_uniform_fast_path_for_thresholds(
        &[4, 5, 4],
        aligned
    ));
    assert!(!aligned_uniform_fast_path_for_thresholds(
        &[4, 4],
        ScoreDomain {
            lower: -987,
            upper: 2329,
        }
    ));
    assert!(!aligned_uniform_fast_path_for_thresholds(
        &[i64::MAX],
        ScoreDomain {
            lower: i64::MIN,
            upper: i64::MIN + 4095,
        }
    ));
}
