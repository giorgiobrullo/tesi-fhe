use super::*;

#[test]
fn comparison_state_luts_are_exhaustive() {
    for left in 0u64..=1 {
        for right in 0u64..=1 {
            assert_eq!(boolean_and_lut(left + right), left & right);
        }
    }
    for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
        for any_zero in [false, true] {
            for threshold_bit in [false, true] {
                let code = state
                    .wrapping_sub(u64::from(any_zero))
                    .wrapping_sub(u64::from(threshold_bit))
                    & 15;
                let minimum_bit = !any_zero;
                let expected = if state != COMPARISON_EQUAL {
                    state
                } else {
                    match (minimum_bit, threshold_bit) {
                        (false, true) => COMPARISON_LESS,
                        (true, false) => COMPARISON_GREATER,
                        _ => COMPARISON_EQUAL,
                    }
                };
                assert_eq!(comparison_state_lut(code), expected);
            }
        }
        for below in [false, true] {
            assert_eq!(
                comparison_accept_tag_lut(state + u64::from(below)),
                8 * u64::from(state != COMPARISON_GREATER && !below)
            );
        }
    }
}

#[test]
fn boolean_threshold_recurrence_matches_all_twelve_bit_comparisons() {
    for minimum in 0u64..MAX_DOMAIN_WIDTH as u64 {
        for threshold in 0u64..MAX_DOMAIN_WIDTH as u64 {
            let mut state = COMPARISON_EQUAL;
            for bit_position in (0..SCORE_BITS).rev() {
                let any_zero = ((minimum >> bit_position) & 1) == 0;
                let threshold_bit = ((threshold >> bit_position) & 1) == 1;
                let code = state
                    .wrapping_sub(u64::from(any_zero))
                    .wrapping_sub(u64::from(threshold_bit))
                    & 15;
                state = comparison_state_lut(code);
            }
            assert_eq!(
                comparison_accept_tag_lut(state),
                8 * u64::from(minimum <= threshold)
            );
            assert_eq!(comparison_accept_tag_lut(state + 1), 0);
        }
    }
}

#[test]
fn bounded_selection_luts_are_exhaustive() {
    for bit_weight in [2, 4, 8] {
        let (candidate_weight, zero_bit_weight) = zero_layout(bit_weight);
        for candidate in 0u64..=1 {
            for bit in 0u64..=1 {
                let zero_code = candidate * candidate_weight + bit * zero_bit_weight;
                assert_eq!(
                    zero_candidate_lut(zero_code, candidate_weight, zero_bit_weight),
                    u64::from(candidate == 1 && bit == 0)
                );
            }
        }
    }
    for candidate in [false, true] {
        for bit in [false, true] {
            let zero_candidate = candidate && !bit;
            for any_zero in [false, true] {
                if zero_candidate && !any_zero {
                    continue;
                }
                let code = u64::from(candidate)
                    .wrapping_add(u64::from(zero_candidate))
                    .wrapping_sub(u64::from(any_zero))
                    & 15;
                assert_eq!(
                    update_candidate_from_zero_lut(code),
                    u64::from(candidate && (bit != any_zero))
                );
            }
        }
    }
    for candidate in [false, true] {
        for even_bit in [false, true] {
            let even_zero = candidate && !even_bit;
            for even_any_zero in [false, true] {
                if even_zero && !even_any_zero {
                    continue;
                }
                let encoded = 0u64
                    .wrapping_sub(u64::from(candidate))
                    .wrapping_sub(u64::from(even_zero))
                    .wrapping_add(u64::from(even_any_zero))
                    & 15;
                let logically_active = candidate && (even_bit != even_any_zero);
                assert!(
                    (logically_active && encoded == 15)
                        || (!logically_active && matches!(encoded, 0 | 1))
                );
                for bit_weight in [1u64, 2, 4, 8] {
                    for odd_bit in [false, true] {
                        let odd_zero = logically_active && !odd_bit;
                        for odd_any_zero in [false, true] {
                            if odd_zero && !odd_any_zero {
                                continue;
                            }
                            let zero_code = (encoded + bit_weight * u64::from(odd_bit)) & 15;
                            assert_eq!(
                                encoded_zero_candidate_lut(zero_code),
                                if odd_zero { u64::MAX } else { 0 }
                            );
                            let normalize_code = 0u64
                                .wrapping_sub(encoded)
                                .wrapping_add(u64::from(odd_zero))
                                .wrapping_sub(u64::from(odd_any_zero))
                                & 15;
                            assert_eq!(
                                update_candidate_from_zero_lut(normalize_code),
                                u64::from(logically_active && (odd_bit != odd_any_zero))
                            );
                        }
                    }
                }
            }
        }
    }
    for weight in [1, 2, 4] {
        for code in 0..16 {
            assert_eq!(
                weighted_or_lut(code, weight),
                if (1..=4).contains(&code) { weight } else { 0 }
            );
        }
    }
    for bit_offset in [0, 3, 6] {
        for group_len in 1..=3 {
            let payload_mask = (1u64 << group_len) - 1;
            for accept in [false, true] {
                for payload in 0..8 {
                    assert_eq!(
                        output_group_lut(payload + 8 * u64::from(accept), bit_offset, group_len,),
                        if accept {
                            (payload & payload_mask) << bit_offset
                        } else {
                            0
                        }
                    );
                }
            }
        }
    }
    for candidate in [false, true] {
        for prefix in [false, true] {
            for previous_count in 0u64..=2 {
                let code = u64::from(candidate)
                    .wrapping_sub(u64::from(prefix))
                    .wrapping_sub(previous_count)
                    & 15;
                assert_eq!(
                    update_candidate_from_zero_lut(code),
                    u64::from(candidate && !prefix && previous_count == 0)
                );
            }
        }
    }
}

#[test]
fn output_bit_masks_reconstruct_every_supported_code() {
    for gallery_size in 1..=MAX_GALLERY_SIZE {
        let bit_positions = output_bit_positions(gallery_size);
        assert_eq!(
            bit_positions.len() as u32,
            usize::BITS - gallery_size.leading_zeros()
        );
        for winner_index in 0..gallery_size {
            let reconstructed: usize = bit_positions
                .iter()
                .filter(|&&bit_position| output_code_has_bit(winner_index, bit_position))
                .map(|&bit_position| 1usize << bit_position)
                .sum();
            assert_eq!(reconstructed, winner_index + 1);
        }
    }
}

#[test]
fn output_group_luts_fit_the_code_scale_for_every_gallery_size() {
    let code_delta = 1u64 << CODE_DELTA_LOG;
    for gallery_size in 1..=MAX_GALLERY_SIZE {
        for positions in output_bit_positions(gallery_size).chunks(3) {
            let bit_offset = positions[0];
            for code in 0..PBS_MESSAGE_MODULUS as u64 {
                assert!(output_group_lut(code, bit_offset, positions.len())
                    .checked_mul(code_delta)
                    .is_some());
                assert!(aligned_output_group_lut(code, bit_offset, positions.len())
                    .checked_mul(code_delta)
                    .is_some());
                let payload_modulus = 1u64 << positions.len();
                assert_eq!(
                    aligned_output_group_lut(code, bit_offset, positions.len()),
                    if code < payload_modulus {
                        code << bit_offset
                    } else {
                        0
                    }
                );
            }
        }
    }
}

fn clear_a34_top_code(h: u64) -> u64 {
    assert!(h < 16);
    let base = a34_top_classifier_slot_lut(2 * (h % 8));
    if h < 8 {
        base & 31
    } else {
        base.wrapping_neg() & 31
    }
}

#[test]
fn a34_top_classifier_and_reducers_are_exhaustive_on_reachable_states() {
    for slot in (1..A34_TOP_CLASSIFIER_MODULUS as u64).step_by(2) {
        assert_eq!(a34_top_classifier_slot_lut(slot), 0);
    }
    for h in 0..16u64 {
        let code = clear_a34_top_code(h);
        assert_eq!(code, A34_TOP_CLASSIFIER_CODES[h as usize]);
        assert_eq!(
            code,
            if h < 8 {
                A34_TOP_CLASSIFIER_CODES[h as usize]
            } else {
                A34_TOP_CLASSIFIER_CODES[(h - 8) as usize].wrapping_neg() & 31
            }
        );
        let canonical_input = code.wrapping_add(4) & 31;
        assert!(canonical_input < A34_TOP_CLASSIFIER_MODULUS as u64);
        assert_eq!(
            a34_canonical_category_lut(canonical_input),
            match h {
                0 => 1,
                1 => 3,
                2 => 7,
                _ => 0,
            }
        );
    }

    let categories = [1u64, 3, 7, 0];
    for (left_rank, &left) in categories.iter().enumerate() {
        for (right_rank, &right) in categories.iter().enumerate() {
            let phase = left + right;
            assert!(phase < A34_TOP_CLASSIFIER_MODULUS as u64);
            assert_eq!(
                a34_pair_category_lut(phase),
                categories[left_rank.min(right_rank)]
            );
        }
    }

    for (minimum_h, &global_category) in categories.iter().enumerate() {
        for h in 0..16u64 {
            let phase = clear_a34_top_code(h)
                .wrapping_add(global_category)
                .wrapping_add(4)
                & 31;
            assert!(phase < A34_TOP_CLASSIFIER_MODULUS as u64);
            assert_eq!(
                a34_top_candidate_lut(phase),
                u64::from(h == minimum_h as u64)
            );
        }
    }
}

fn clear_sparse_classifier(h: u64, weight: u64) -> (u64, u64) {
    assert!(h < 8);
    let base = h % 4;
    let mut code = aligned_classifier_slot_lut(2 * base, weight);
    let mut flag = aligned_classifier_slot_lut(2 * base + 1, weight);
    if h >= 4 {
        code = code.wrapping_neg() & 31;
        flag = flag.wrapping_neg() & 31;
    }
    (code, flag)
}

fn clear_aligned_sparse_code(values: &[u64]) -> u64 {
    assert!(!values.is_empty() && values.len() <= MAX_GALLERY_SIZE);
    assert!(values.iter().all(|&value| value < MAX_DOMAIN_WIDTH as u64));
    let classified: Vec<(u64, u64)> = values
        .iter()
        .enumerate()
        .map(|(index, &value)| clear_sparse_classifier(value >> 9, [1, 3][index % 2]))
        .collect();
    let pair_flags: Vec<u64> = classified
        .chunks(2)
        .map(|pair| {
            let code = (4 + pair.iter().map(|(_, flag)| *flag).sum::<u64>()) & 31;
            aligned_pair_flag_lut(code)
        })
        .collect();
    let any_b9_zero = u64::from(pair_flags.contains(&1));
    let codes: Vec<u64> = classified
        .iter()
        .map(|(code, _)| (code + any_b9_zero) & 31)
        .collect();
    let b8_zero: Vec<u64> = codes
        .iter()
        .zip(values)
        .map(|(&code, &value)| aligned_candidate_lut((code + 2 * ((value >> 8) & 1)) & 31))
        .collect();
    let any_b8_zero = u64::from(b8_zero.contains(&1));
    let mut candidates: Vec<bool> = codes
        .iter()
        .zip(&b8_zero)
        .map(|(&code, &zero)| {
            aligned_candidate_lut(code.wrapping_sub(zero).wrapping_add(any_b8_zero) & 31) == 1
        })
        .collect();
    for bit in (0..=ALIGNED_SELECTION_HIGH_BIT).rev() {
        let any_zero = values
            .iter()
            .zip(&candidates)
            .any(|(&value, &candidate)| candidate && ((value >> bit) & 1) == 0);
        for (&value, candidate) in values.iter().zip(&mut candidates) {
            if *candidate {
                *candidate = ((value >> bit) & 1) == u64::from(!any_zero);
            }
        }
    }
    candidates
        .iter()
        .position(|candidate| *candidate)
        .map_or(0, |index| index as u64 + 1)
}

#[test]
fn aligned_sparse_classifier_and_pair_lut_are_exhaustive() {
    let expected_codes = [2, 3, 4, 4, 30, 29, 28, 28];
    for weight in [1u64, 3] {
        for h in 0..8u64 {
            let (code, flag) = clear_sparse_classifier(h, weight);
            assert_eq!(code, expected_codes[h as usize]);
            assert_eq!(
                flag,
                match h {
                    0 => weight,
                    4 => 32 - weight,
                    _ => 0,
                }
            );
        }
    }
    for left_h in 0..8u64 {
        for right_h in 0..8u64 {
            let (_, left) = clear_sparse_classifier(left_h, 1);
            let (_, right) = clear_sparse_classifier(right_h, 3);
            let packed = (left + right + 4) & 31;
            assert!(packed <= 8);
            assert_eq!(
                aligned_pair_flag_lut(packed),
                u64::from(left_h == 0 || right_h == 0)
            );
        }
        let (_, singleton) = clear_sparse_classifier(left_h, 1);
        let packed = (singleton + 4) & 31;
        assert_eq!(aligned_pair_flag_lut(packed), u64::from(left_h == 0));
    }
}

#[test]
fn aligned_sparse_clear_model_preserves_exact_id_and_first_tie() {
    for value in 0..MAX_DOMAIN_WIDTH as u64 {
        assert_eq!(
            clear_aligned_sparse_code(&[value]),
            u64::from(value <= ALIGNED_UNIFORM_THRESHOLD as u64),
            "single value={value}"
        );
    }
    let cases = [
        (vec![0], 1),
        (vec![1023], 1),
        (vec![1024], 0),
        (vec![4095], 0),
        (vec![1024, 1023], 2),
        (vec![512, 0, 768], 2),
        (vec![77, 77, 78], 1),
        (vec![1024, 1536, 4095], 0),
    ];
    for (values, expected) in cases {
        assert_eq!(clear_aligned_sparse_code(&values), expected, "{values:?}");
    }
    let mut last_wins = vec![1000u64; MAX_GALLERY_SIZE];
    last_wins[MAX_GALLERY_SIZE - 1] = 0;
    assert_eq!(clear_aligned_sparse_code(&last_wins), 128);

    let mut state = 0xA33A_11C3_D5E7_F901u64;
    for case_index in 0..10_000usize {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let n = 1 + case_index % MAX_GALLERY_SIZE;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            values.push((state >> 32) & 4095);
        }
        if case_index % 17 == 0 && n > 1 {
            values[1] = values[0];
        }
        let winner = values
            .iter()
            .enumerate()
            .min_by_key(|(index, value)| (**value, *index))
            .unwrap();
        let expected = if *winner.1 <= ALIGNED_UNIFORM_THRESHOLD as u64 {
            winner.0 as u64 + 1
        } else {
            0
        };
        assert_eq!(
            clear_aligned_sparse_code(&values),
            expected,
            "case={case_index}, values={values:?}"
        );
    }
}
