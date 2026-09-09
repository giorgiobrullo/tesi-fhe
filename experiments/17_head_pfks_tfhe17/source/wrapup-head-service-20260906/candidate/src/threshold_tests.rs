use super::*;

fn gallery() -> Galleria {
    Galleria { dim: PROBE_DIM, t_default: -1, iscritti: Vec::new(), chiave: None,
        chiave_sha256: None, epoch: 123, revision: 0 }
}

fn norm_template(norm: usize) -> Vec<i64> {
    (0..PROBE_DIM).map(|i| if i < norm { 1 } else { 0 }).collect()
}

#[test]
fn all_four_invalid_127th_entries_preserve_complete_state() {
    for (threshold, prefix_norm, last_norm) in [(-1114, 510, 511), (87, 508, 511), (-1111, 511, 512), (86, 511, 512)] {
        let mut g = gallery();
        for i in 0..126 {
            upsert_entry(&mut g, format!("id_{}", i+1), norm_template(prefix_norm), threshold).unwrap();
        }
        let before = g.iscritti.clone();
        let revision = g.revision;
        assert!(upsert_entry(&mut g, "id_127".into(), norm_template(last_norm), threshold).is_err());
        assert_eq!(g.iscritti, before);
        assert_eq!(g.revision, revision);
        assert_eq!(g.epoch, 123);
    }
}

#[test]
fn overflow_thresholds_reject_atomically_from_empty_state() {
    for threshold in [i64::MIN, i64::MAX] {
        let mut g = gallery();
        assert!(upsert_entry(&mut g, "invalid".into(), norm_template(511), threshold).is_err());
        assert!(g.iscritti.is_empty());
        assert_eq!(g.revision, 0);
        assert_eq!(g.epoch, 123);
    }
}

#[test]
fn n127_positive_and_negative_thresholds_report_supported() {
    for threshold in [-1110, -513, -512, -1, 0, 4, 85] {
        let entries: Vec<_> = (0..127).map(|i| Entry::new(format!("id_{}", i+1), norm_template(512), threshold).unwrap()).collect();
        let metadata = gallery_execution_metadata(&entries).unwrap().unwrap();
        assert!(metadata.endpoint_domain_supported);
        assert_eq!(metadata.endpoint_fhe, "head_mean_parallel");
        assert_eq!(metadata.execution_domain.lower, threshold - 1023);
        assert!(metadata.execution_domain.lower <= metadata.enrollment_domain.lower);
        assert!(metadata.execution_domain.upper >= metadata.enrollment_domain.upper);
        assert!(domain_width(metadata.execution_domain).unwrap() <= 4096);
    }
}
