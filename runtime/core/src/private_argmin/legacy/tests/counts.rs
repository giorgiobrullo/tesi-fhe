use super::*;

#[test]
fn deterministic_pbs_counts_include_odd_tail_and_n_one() {
    assert_eq!(expected_pbs_count(0), None);
    assert_eq!(expected_pbs_count(1), Some(48));
    assert_eq!(expected_pbs_count(3), Some(141));
    assert_eq!(expected_pbs_count(64), Some(2767));
    assert_eq!(expected_pbs_count(127), Some(5524));
    assert_eq!(expected_pbs_count(128), Some(5559));
    assert_eq!(expected_pbs_count(129), None);

    let aligned = ScoreDomain {
        lower: -1019,
        upper: 2329,
    };
    for (n, pbs, ks, marginals) in [
        (1, 29, 26, 33),
        (2, 67, 61, 75),
        (3, 95, 86, 107),
        (64, 2076, 1884, 2332),
        (127, 4144, 3763, 4652),
        (128, 4174, 3790, 4686),
    ] {
        assert_eq!(aligned_a34_top_pbs_count(n), Some(pbs));
        assert_eq!(
            a34_aligned_operation_counts(n),
            Some(A34OperationCounts {
                blind_rotations: pbs,
                key_switches: ks,
                output_marginals: marginals,
            })
        );
    }
    let a44_n127 = a44_aligned_operation_counts(127).unwrap();
    let a50_n127 = a50_aligned_operation_counts(127).unwrap();
    let removed_scan_n127 = a38_scan_output_counts(127);
    let inserted_scan_n127 = a53_scan_counts(127).unwrap().total;
    assert_eq!(a44_n127.blind_rotations, 3655);
    assert_eq!(a50_n127.blind_rotations, 3455);
    assert_eq!(removed_scan_n127.blind_rotations, 201);
    assert_eq!(inserted_scan_n127.blind_rotations, 136);
    assert_eq!(3455 - 201 + 136, 3390);
    for (n, pbs, ks, marginals) in [
        (1, 25, 22, 30),
        (2, 60, 54, 69),
        (3, 85, 76, 98),
        (4, 110, 98, 127),
        (64, 1713, 1521, 1985),
        (127, 3390, 3009, 3930),
        (128, 3415, 3031, 3959),
    ] {
        assert_eq!(
            a62_aligned_operation_counts(n),
            Some(A62OperationCounts {
                blind_rotations: pbs,
                key_switches: ks,
                output_marginals: marginals,
            })
        );
    }
    for (n, pbs, ks, marginals) in [
        (1, 25, 22, 30),
        (2, 60, 54, 69),
        (3, 85, 76, 98),
        (64, 1835, 1643, 2113),
        (127, 3655, 3274, 4206),
        (128, 3682, 3298, 4237),
    ] {
        assert_eq!(aligned_a38_pbs_count(n), Some(pbs));
        assert_eq!(
            a38_aligned_operation_counts(n),
            Some(A38OperationCounts {
                blind_rotations: pbs,
                key_switches: ks,
                output_marginals: marginals,
            })
        );
        assert_eq!(
            expected_pbs_count_for_thresholds(n, &vec![4; n], aligned),
            Some(pbs)
        );
    }
    assert_eq!(aligned_a34_top_pbs_count(0), None);
    assert_eq!(aligned_a34_top_pbs_count(129), None);
    assert_eq!(a34_aligned_operation_counts(0), None);
    assert_eq!(a34_aligned_operation_counts(129), None);
    assert_eq!(aligned_a38_pbs_count(0), None);
    assert_eq!(aligned_a38_pbs_count(129), None);
    assert_eq!(a38_aligned_operation_counts(0), None);
    assert_eq!(a38_aligned_operation_counts(129), None);
    assert_eq!(a62_aligned_operation_counts(0), None);
    assert_eq!(a62_aligned_operation_counts(129), None);
    assert_eq!(
        expected_pbs_count_for_thresholds(
            127,
            &[4; 127],
            ScoreDomain {
                lower: -987,
                upper: 2329,
            },
        ),
        Some(4965)
    );

    let domain = ScoreDomain {
        lower: -10,
        upper: 10,
    };
    assert_eq!(
        expected_pbs_count_for_thresholds(3, &[0, 0, 0], domain),
        Some(128)
    );
    assert_eq!(
        expected_pbs_count_for_thresholds(64, &[0; 64], domain),
        Some(2494)
    );
    assert_eq!(
        expected_pbs_count_for_thresholds(127, &[0; 127], domain),
        Some(4965)
    );
    assert_eq!(
        expected_pbs_count_for_thresholds(128, &[0; 128], domain),
        Some(5000)
    );
    assert_eq!(4965 - 3 * 127, 4584);
    assert_eq!(expected_pbs_count_for_thresholds(3, &[0, 1], domain), None);
}
