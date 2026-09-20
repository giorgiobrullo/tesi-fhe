use crate::gallery::*;
use crate::metadata;
use crate::protocol::*;
use pfks_core::service::{ExecutionMode, ScoreDomain, ThresholdMode};

fn gallery() -> Galleria {
    crate::tests::initialize_runtime();
    Galleria {
        dim: PROBE_DIM,
        t_default: 4,
        iscritti: Vec::new(),
        chiave: None,
        chiave_sha256: None,
        g4_sha256: None,
        epoch: 123,
        revision: 0,
    }
}

fn template_671() -> Vec<i64> {
    let mut template = vec![0; PROBE_DIM];
    template[..74].fill(3);
    template[74] = 2;
    template[75] = 1;
    template
}

#[test]
fn source_cauchy_bounds_remain_checked_and_match_the_core() {
    let first = Entry::new("public_a".into(), vec![1, 0], 4).unwrap();
    let second = Entry::new("public_b".into(), vec![0, 2], 273).unwrap();
    assert_eq!(first.norm2, 1);
    assert_eq!(first.l1, 1);
    assert_eq!(
        first.score_domain().unwrap(),
        ScoreDomain {
            lower: -63,
            upper: 65
        }
    );
    assert_eq!(
        second.score_domain().unwrap(),
        ScoreDomain {
            lower: -124,
            upper: 132
        }
    );
    assert_eq!(
        gallery_domain(&[first, second]).unwrap(),
        Some(ScoreDomain {
            lower: -124,
            upper: 132
        })
    );
    for (value, expected) in [(0, 0), (1, 1), (2, 2), (1024, 32), (1025, 33)] {
        assert_eq!(ceil_sqrt_nonnegative(value).unwrap(), expected);
    }
    assert!(ceil_sqrt_nonnegative(-1).is_err());
    assert_eq!(gallery_execution_metadata(&[]).unwrap(), None);
    let mut gallery = gallery();
    let (_, metadata) = upsert_entry(&mut gallery, "public_a".into(), template_671(), 4).unwrap();
    assert_eq!(
        metadata.plan.cauchy_domain,
        ScoreDomain {
            lower: -987,
            upper: 2329
        }
    );
    assert_eq!(
        metadata.plan.execution_domain,
        ScoreDomain {
            lower: -1019,
            upper: 2329
        }
    );
    assert_eq!(
        metadata.plan.mode,
        ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score: 1024 })
    );
    assert_eq!(domain_width(metadata.plan.cauchy_domain).unwrap(), 3317);
}

#[test]
fn recorded_synthetic_domains_admit_127_uniform_then_128_mixed() {
    let mut gallery = gallery();
    for i in 0..127 {
        upsert_entry(&mut gallery, format!("public_{i}"), template_671(), 4).unwrap();
    }
    // A crafted public vector with the same norm/domain as the recorded synthetic camera fixture.
    let mut camera_domain_template = vec![0; PROBE_DIM];
    camera_domain_template[..68].fill(3);
    camera_domain_template[68] = 2; // norm 616, Cauchy [-974,2206]
    let (index, metadata) = upsert_entry(
        &mut gallery,
        "public_mixed".into(),
        camera_domain_template,
        273,
    )
    .unwrap();
    assert_eq!(index, 127);
    assert_eq!(gallery.iscritti.len(), 128);
    assert_eq!(gallery.revision, 128);
    assert_eq!(metadata.plan.mode, ExecutionMode::MixedWinnerThreshold);
    assert_eq!(metadata.plan.threshold, None);
    assert!(!metadata.plan.aligned_fast_path);
    assert_eq!(
        metadata.plan.cauchy_domain,
        ScoreDomain {
            lower: -987,
            upper: 2329
        }
    );
    assert_eq!(metadata.plan.execution_domain, metadata.plan.cauchy_domain);
    assert_eq!(metadata.counts.ks, 1152);
    assert_eq!(metadata.counts.initial_samples, 128);
    assert!(metadata.counts.br < 1663);
    assert!(metadata.counts.marginals < 2429);
    assert!(metadata.counts.pfks < 1149);
    // Composite operation counts are cross-checked against the independent
    // Python planner during plan-json and service validation.
}

#[test]
fn signed_threshold_extremes_and_dynamic_uniform_plans_are_admitted() {
    for (threshold, expected) in [
        (i64::MIN, ThresholdMode::AllReject),
        (i64::MAX, ThresholdMode::AllAccept),
        (273, ThresholdMode::CompareSentinel { score: 1261 }),
    ] {
        let mut gallery = gallery();
        let (_, metadata) =
            upsert_entry(&mut gallery, "public_a".into(), template_671(), threshold).unwrap();
        assert_eq!(metadata.plan.mode, ExecutionMode::Uniform(expected));
        assert_eq!(metadata.plan.threshold, Some(threshold));
        assert!(!metadata.plan.aligned_fast_path);
        assert_eq!(gallery.iscritti[0].threshold, threshold);
        let other = if threshold == i64::MAX {
            i64::MIN
        } else {
            i64::MAX
        };
        let (_, mixed) =
            upsert_entry(&mut gallery, "public_b".into(), template_671(), other).unwrap();
        assert_eq!(mixed.plan.mode, ExecutionMode::MixedWinnerThreshold);
        assert_eq!(mixed.plan.threshold, None);
    }
}

#[test]
fn rejected_enrollment_and_replacement_preserve_complete_public_state() {
    let mut gallery = gallery();
    upsert_entry(&mut gallery, "public_a".into(), template_671(), 4).unwrap();
    upsert_entry(&mut gallery, "public_b".into(), vec![1; PROBE_DIM], 273).unwrap();
    let before = metadata::status_json(&gallery).unwrap();
    let entries = gallery.iscritti.clone();
    for (name, vector, threshold) in [
        ("", vec![0; PROBE_DIM], 4),
        ("public_a", vec![0; PROBE_DIM - 1], 4),
        ("public_c", vec![0; PROBE_DIM + 1], 4),
        ("public_a", vec![4; PROBE_DIM], i64::MIN),
        ("public_c", vec![i64::MIN; PROBE_DIM], i64::MAX),
        ("public_a", vec![3; PROBE_DIM], 4),
        ("public_c", vec![3; PROBE_DIM], i64::MIN),
    ] {
        assert!(upsert_entry(&mut gallery, name.into(), vector, threshold).is_err());
        assert_eq!(gallery.iscritti, entries);
        assert_eq!(metadata::status_json(&gallery).unwrap(), before);
    }
    gallery.revision = u64::MAX;
    assert!(upsert_entry(&mut gallery, "public_a".into(), vec![0; PROBE_DIM], 4).is_err());
    assert_eq!(gallery.iscritti, entries);
    assert!(reset_gallery(&mut gallery).is_err());
    assert_eq!(gallery.iscritti, entries);
    assert_eq!(gallery.revision, u64::MAX);
}

#[test]
fn capacity_and_replacement_keep_the_stable_positional_identity() {
    let mut gallery = gallery();
    // Construct the valid public prefix directly, then exercise the real admission boundary.
    gallery.iscritti = (0..MAX_GALLERY)
        .map(|i| Entry::new(format!("public_{i}"), vec![0; PROBE_DIM], 4).unwrap())
        .collect();
    let before = gallery.iscritti.clone();
    assert!(upsert_entry(
        &mut gallery,
        "public_overflow".into(),
        vec![0; PROBE_DIM],
        273
    )
    .is_err());
    assert_eq!(gallery.iscritti, before);
    assert_eq!(gallery.revision, 0);
    let (index, metadata) =
        upsert_entry(&mut gallery, "public_224".into(), vec![0; PROBE_DIM], 273).unwrap();
    assert_eq!(index, 224);
    assert_eq!(gallery.iscritti.len(), 3374);
    assert_eq!(gallery.iscritti[224].name, "public_224");
    assert_eq!(gallery.iscritti[224].threshold, 273);
    assert_eq!(metadata.plan.mode, ExecutionMode::MixedWinnerThreshold);
    assert_eq!(gallery.revision, 1);
    reset_gallery(&mut gallery).unwrap();
    assert!(gallery.iscritti.is_empty());
    assert_eq!(gallery.revision, 2);
    assert_eq!(gallery.epoch, 123);
}

#[test]
fn metadata_rechecks_actual_norms_before_public_shortcuts() {
    for threshold in [i64::MIN, i64::MAX] {
        let mut entry = Entry::new("public_a".into(), vec![1; PROBE_DIM], threshold).unwrap();
        entry.norm2 -= 1;
        assert!(gallery_execution_metadata(&[entry])
            .unwrap_err()
            .contains("IncorrectTemplateNorm"));
    }
    let too_wide = Entry::new(
        "public_a".into(),
        vec![2; 256].into_iter().chain(vec![0; 256]).collect(),
        4,
    )
    .unwrap();
    assert_eq!(too_wide.norm2, 1024);
    assert_eq!(
        domain_width(too_wide.score_domain().unwrap()).unwrap(),
        4097
    );
    assert!(gallery_execution_metadata(&[too_wide]).is_err());
}
