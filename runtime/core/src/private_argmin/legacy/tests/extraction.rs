use super::*;

#[test]
fn fused_accumulator_layout_is_exact_through_the_safe_rotation_interval() {
    let polynomial_size = PolynomialSize(2048);
    let beta = 1u64 << (BOOL_DELTA_LOG - 1);
    let quarter = polynomial_size.0 / 4;

    for bit_index in 3..=6 {
        let alpha = 1u64 << (FULL_DELTA_LOG + bit_index - 1);
        let body = fused_correction_accumulator_body(polynomial_size, alpha, beta);
        assert!(body[..polynomial_size.0 / 2]
            .iter()
            .all(|&value| value == alpha.wrapping_neg()));
        assert!(body[polynomial_size.0 / 2..]
            .iter()
            .all(|&value| value == beta.wrapping_neg()));

        for bit in [0u64, 1] {
            let base_rotation = quarter + bit as usize * polynomial_size.0;
            for error in -(quarter as isize - 1)..=(quarter as isize - 1) {
                let rotation = (base_rotation as isize + error)
                    .rem_euclid((2 * polynomial_size.0) as isize)
                    as usize;
                let correction = negacyclic_division_sample(&body, rotation, 0).wrapping_add(alpha);
                let boolean = negacyclic_division_sample(&body, rotation, polynomial_size.0 / 2)
                    .wrapping_add(beta);
                assert_eq!(correction, bit << (FULL_DELTA_LOG + bit_index));
                assert_eq!(boolean, bit << BOOL_DELTA_LOG);
            }

            // Il lookup usa intervalli semiaperti: il bordo negativo appartiene ancora al
            // plateau corretto, mentre +N/4 e -N/4-1 sono le prime rotazioni non sicure.
            let negative_boundary = (base_rotation as isize - quarter as isize)
                .rem_euclid((2 * polynomial_size.0) as isize)
                as usize;
            let negative_outside = (base_rotation as isize - quarter as isize - 1)
                .rem_euclid((2 * polynomial_size.0) as isize)
                as usize;
            let positive_boundary = (base_rotation + quarter) % (2 * polynomial_size.0);
            let expected_raw_correction = if bit == 0 {
                alpha.wrapping_neg()
            } else {
                alpha
            };
            let expected_raw_boolean = if bit == 0 { beta.wrapping_neg() } else { beta };
            assert_eq!(
                negacyclic_division_sample(&body, negative_boundary, 0),
                expected_raw_correction
            );
            assert_eq!(
                negacyclic_division_sample(&body, negative_boundary, polynomial_size.0 / 2),
                expected_raw_boolean
            );
            assert_ne!(
                negacyclic_division_sample(&body, negative_outside, 0),
                expected_raw_correction
            );
            assert_ne!(
                negacyclic_division_sample(&body, negative_outside, polynomial_size.0 / 2),
                expected_raw_boolean
            );
            assert_ne!(
                negacyclic_division_sample(&body, positive_boundary, 0),
                expected_raw_correction
            );
            assert_ne!(
                negacyclic_division_sample(&body, positive_boundary, polynomial_size.0 / 2),
                expected_raw_boolean
            );
        }
    }

    assert!(std::panic::catch_unwind(|| {
        fused_correction_accumulator_body(PolynomialSize(6), 1, 2)
    })
    .is_err());
}

#[test]
fn fused_and_reused_bits_are_canonical_boolean_inputs() {
    for bit_index in 3..=7 {
        assert!(is_canonical_boolean_bit(bit_index));
        assert_eq!(extracted_bit_weight(bit_index), 1);
    }
    assert!(recodes_bit(HIGH_SCORE_BIT));
    assert_eq!(extracted_bit_weight(HIGH_SCORE_BIT), 1);
    assert!(!(0..=10).any(recodes_bit));
}
