//! Source-only primitive: one public g4 synthesis per group, reused over2/3 GLWEs.
//! This diagnostic is not a tournament or a runtime optimization claim.
use super::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::lwe_multi_bit_programmable_bootstrapping::{
    modulus_switch_multi_bit, modulus_switch_multi_bit_blind_rotate_assign,
    prepare_multi_bit_ggsw_mem_optimized,
};
use tfhe::core_crypto::algorithms::polynomial_algorithms::
    polynomial_wrapping_monic_monomial_div_assign;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign, add_external_product_assign_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::Fft;

const GROUPING: usize = 4;
const GROUP_COUNT: usize = 226;
const DEGREE_TORUS: u64 = 1 << 52;
const TWO: [&[usize]; 2] = [&[0, 1, 2], &[3, 4]];
const THREE: [&[usize]; 3] = [&[0, 1, 2], &[3, 4], &[6, 7, 8]];

type SwitchTable = [[usize; 16]; GROUP_COUNT];

fn switched_degree(word: u64) -> usize {
    pbs_modulus_switch(word, PolynomialSize(2048))
}

fn subset_sum(mask: &[u64], subset: usize) -> u64 {
    assert_eq!(mask.len(), GROUPING);
    mask.iter().enumerate().fold(0u64, |sum, (index, &word)| {
        sum.wrapping_add(word.wrapping_mul(((subset >> (3 - index)) & 1) as u64))
    })
}

fn signed_round_div16(value: i128) -> i128 {
    if value >= 0 { (value + 8) / 16 } else { -((-value + 8) / 16) }
}

pub(super) struct Centered {
    pub(super) corrected: Lwe,
    pub(super) degree_table: SwitchTable,
    pub(super) correction: i128,
    pub(super) sum_all_subset_rounding_errors: i128,
}

/// Uniform-subset public mean. Secret bits are not accepted by this function.
pub(super) fn grouped_mean(input: &Lwe) -> Centered {
    assert_eq!(input.lwe_size().0, 905);
    let mut degree_table = [[0; 16]; GROUP_COUNT];
    let mut total = 0i128;
    for (group, mask) in input.get_mask().as_ref().chunks_exact(4).enumerate() {
        for subset in 0..16 {
            let sum = subset_sum(mask, subset);
            let degree = switched_degree(sum);
            degree_table[group][subset] = degree;
            total += (degree as u64).wrapping_mul(DEGREE_TORUS).wrapping_sub(sum) as i64 as i128;
        }
    }
    let correction = signed_round_div16(total);
    assert!((16 * correction - total).abs() <= 8);
    let mut corrected = input.clone();
    *corrected.get_mut_body().data = corrected.get_body().data.wrapping_add(correction as u64);
    Centered { corrected, degree_table, correction, sum_all_subset_rounding_errors: total }
}

/// Minimal serial-synthesis batch. Each accumulator sees exactly the stock
/// deterministic g4 group order. Public low-level helpers are unchanged.
pub(super) fn batch_same_control(
    control: &Lwe,
    accumulators: &mut [Glwe],
    key: &FourierLweMultiBitBootstrapKeyOwned,
) -> usize {
    assert!((1..=3).contains(&accumulators.len()));
    assert_eq!(key.input_lwe_dimension().0, 904);
    assert_eq!(key.grouping_factor().0, GROUPING);
    assert_eq!(control.lwe_size().0, 905);
    let fft = Fft::new(PolynomialSize(2048));
    let fft = fft.as_view();
    let body_degree = switched_degree(*control.get_body().data);
    let mut alternates: Vec<Glwe> = accumulators.iter_mut().map(|accumulator| {
        assert_eq!(accumulator.glwe_size().0, 2);
        assert_eq!(accumulator.polynomial_size().0, 2048);
        assert!(accumulator.ciphertext_modulus().is_native_modulus());
        for mut polynomial in accumulator.as_mut_polynomial_list().iter_mut() {
            polynomial_wrapping_monic_monomial_div_assign(&mut polynomial, MonomialDegree(body_degree));
        }
        Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native())
    }).collect();
    let ggsws: Vec<_> = key.ggsw_iter().collect();
    assert_eq!(ggsws.len(), GROUP_COUNT * 16);
    let mut combined = FourierGgswCiphertext::new(
        key.glwe_size(), key.polynomial_size(), key.decomposition_base_log(), key.decomposition_level_count(),
    );
    let mut monomial = FourierPolynomial::new(key.polynomial_size());
    let mut scratch = ComputationBuffers::new();
    scratch.resize(add_external_product_assign_scratch::<u64>(key.glwe_size(), key.polynomial_size(), fft).unaligned_bytes_required());
    for group in 0..GROUP_COUNT {
        let mask = &control.as_ref()[4 * group..4 * group + 4];
        let degrees = modulus_switch_multi_bit(CiphertextModulusLog(12), LweBskGroupingFactor(4), mask);
        prepare_multi_bit_ggsw_mem_optimized(&mut combined, &ggsws[group * 16..(group + 1) * 16], degrees, &mut monomial, fft);
        for (accumulator, alternate) in accumulators.iter_mut().zip(&mut alternates) {
            alternate.as_mut().fill(0);
            add_external_product_assign(alternate.as_mut_view(), combined.as_view(), accumulator.as_view(), fft, scratch.stack());
            std::mem::swap(accumulator, alternate);
        }
    }
    GROUP_COUNT
}

pub(super) fn lwe_observation(ciphertext: &Lwe, secret: &LweSecretKeyView<'_, u64>) -> Value {
    json!({"words":ciphertext.as_ref(), "sha256":observer::hash_words(ciphertext.as_ref()),
           "phase":decrypt_lwe_ciphertext(secret, ciphertext).0})
}

fn glwe_observation(ciphertext: &Glwe, secret: &GlweSecretKeyOwned<u64>) -> Value {
    let mut phases = PlaintextList::new(0u64, PlaintextCount(2048));
    decrypt_glwe_ciphertext(secret, ciphertext, &mut phases);
    json!({"words":ciphertext.as_ref(), "sha256":observer::hash_words(ciphertext.as_ref()),
           "phases":phases.as_ref()})
}

fn standard_address(input: &Lwe, secret: &LweSecretKeyOwned<u64>) -> usize {
    let mask_sum: i128 = input.get_mask().as_ref().iter().zip(secret.as_ref())
        .map(|(&word, &bit)| switched_degree(word) as i128 * bit as i128).sum();
    (switched_degree(*input.get_body().data) as i128 - mask_sum).rem_euclid(4096) as usize
}

pub(super) fn grouped_observation(original: &Lwe, centered: &Centered, secret: &LweSecretKeyOwned<u64>) -> (Value, usize) {
    assert_eq!(secret.lwe_dimension().0, 904);
    let mut selected = Vec::new();
    let mut sum_degrees = 0i128;
    let mut actual_errors = 0i128;
    for (group, (mask, bits)) in original.get_mask().as_ref().chunks_exact(4).zip(secret.as_ref().chunks_exact(4)).enumerate() {
        assert!(bits.iter().all(|&bit| bit <= 1));
        let subset = bits.iter().fold(0usize, |value, &bit| 2 * value + bit as usize);
        let actual_sum = subset_sum(mask, subset);
        let degree = centered.degree_table[group][subset];
        selected.push(subset);
        sum_degrees += degree as i128;
        actual_errors += (degree as u64).wrapping_mul(DEGREE_TORUS).wrapping_sub(actual_sum) as i64 as i128;
        let stock: Vec<_> = modulus_switch_multi_bit(CiphertextModulusLog(12), LweBskGroupingFactor(4), mask).collect();
        assert_eq!(stock, centered.degree_table[group][1..]);
    }
    let body = *centered.corrected.get_body().data;
    let body_degree = switched_degree(body);
    let body_error = (body_degree as u64).wrapping_mul(DEGREE_TORUS).wrapping_sub(body) as i64;
    let address = (body_degree as i128 - sum_degrees).rem_euclid(4096) as usize;
    let original_phase = decrypt_lwe_ciphertext(&secret.as_view(), original).0;
    let corrected_phase = decrypt_lwe_ciphertext(&secret.as_view(), &centered.corrected).0;
    assert_eq!(corrected_phase, original_phase.wrapping_add(centered.correction as u64));
    let reconstructed = original_phase.wrapping_add(centered.correction as u64)
        .wrapping_add(body_error as u64).wrapping_sub(actual_errors as u64);
    assert_eq!(reconstructed, (address as u64).wrapping_mul(DEGREE_TORUS));
    (json!({"original":lwe_observation(original, &secret.as_view()),
        "corrected":lwe_observation(&centered.corrected, &secret.as_view()),
        "degree_table":centered.degree_table.iter().map(|row|row.as_slice()).collect::<Vec<_>>(),
        "selected_subset_indices":selected, "mean_correction_decimal":centered.correction.to_string(),
        "sum_all_subset_rounding_errors_decimal":centered.sum_all_subset_rounding_errors.to_string(),
        "rounding_rule":"nearest signed integer of aggregate sum/16; half ties away from zero",
        "mean_rounding_error_times16_decimal":(16*centered.correction-centered.sum_all_subset_rounding_errors).to_string(),
        "body_degree":body_degree,"body_rounding_error_torus":body_error,
        "selected_rounding_error_sum_decimal":actual_errors.to_string(),"actual_grouped_address":address,
        "exact_grouped_phase_identity":true,"stock_subset_switch_vectors_equal":true,
        "statistical_scope":"Uniform-subset mean premise only; no conditional mask distribution or tail bound."}), address)
}

fn pack_pfks(left: &[Lwe; 9], right: &[Lwe; 9], groups: &[&[usize]], window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>) -> Vec<Glwe> {
    groups.iter().map(|group| {
        let mut accumulator = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
        for (position, &lane) in group.iter().enumerate() {
            let mut difference = right[lane].clone();
            lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
            let mut term = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
            private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(window, &mut term, &difference);
            for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial, MonomialDegree(position * 41));
            }
            for (word, addend) in accumulator.as_mut().iter_mut().zip(term.as_ref()) {
                *word = word.wrapping_add(*addend);
            }
        }
        accumulator
    }).collect()
}

fn extract_add_back(accumulators: &[Glwe], left: &[Lwe; 9], groups: &[&[usize]]) -> [Lwe; 9] {
    let mut outputs: [Lwe; 9] = std::array::from_fn(|_| allocate_and_trivially_encrypt_new_lwe_ciphertext(LweSize(2049), Plaintext(0), CiphertextModulus::new_native()));
    for (accumulator, group) in accumulators.iter().zip(groups) {
        for (position, &lane) in group.iter().enumerate() {
            extract_lwe_sample_from_glwe_ciphertext(accumulator, &mut outputs[lane], MonomialDegree(position * 41));
            lwe_ciphertext_add_assign(&mut outputs[lane], &left[lane]);
        }
    }
    outputs
}

fn window_at(window: &[u64], degree: isize) -> u64 {
    let word = window[degree.rem_euclid(2048) as usize];
    if degree.div_euclid(2048).rem_euclid(2) == 0 { word } else { word.wrapping_neg() }
}

pub(crate) fn run(
    server: &ServerKey, window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    bridge: &multibit::BridgeKeys, secret: &GlweSecretKeyOwned<u64>,
    small904: &LweSecretKeyOwned<u64>, small859: &LweSecretKeyOwned<u64>,
    mut emit: impl FnMut(Value),
) -> Value {
    let (g4_ksk, g4_bsk) = bridge.primitive_keys();
    assert_eq!((g4_ksk.input_key_lwe_dimension().0, g4_ksk.output_key_lwe_dimension().0), (2048, 904));
    assert_eq!((g4_ksk.decomposition_base_log().0, g4_ksk.decomposition_level_count().0), (4, 4));
    assert_eq!((g4_bsk.decomposition_base_log().0, g4_bsk.decomposition_level_count().0), (22, 1));
    assert_eq!((window.decomposition_base_log().0, window.decomposition_level_count().0), (22, 1));
    let ShortintBootstrappingKey::Classic(classic_bsk) = &server.bootstrapping_key;
    let big = secret.as_lwe_secret_key();
    let mut seeder = new_seeder();
    let mut random = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());
    let window_function = service_selected::window_function();
    multibit::begin_query(0, false);
    let mut cases = 0usize;
    let mut primitive_outputs = 0usize;
    let mut checked_glwes = 0usize;
    let mut selected_payloads = 0usize;
    for top in -1i64..=1 {
        for middle in -1i64..=1 {
            for low in -1i64..=1 {
                let signs = [top, middle, low];
                let left_values = [(8+top) as u64, (8+middle) as u64, (8+low) as u64,
                    (cases as u64+1)%15, (cases as u64+1)/15, 0,
                    cases as u64%16, cases as u64*3%16, cases as u64*7%16];
                let right_values = [8u64, 8, 8, (cases as u64+2)%15, (cases as u64+2)/15, 0,
                    (cases as u64+3)%16, (cases as u64*3+5)%16, (cases as u64*7+9)%16];
                let mut encrypt = |value: u64| allocate_and_encrypt_new_lwe_ciphertext(&big, Plaintext(value*SCORE_DELTA),
                    V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64.glwe_noise_distribution,
                    CiphertextModulus::new_native(), &mut random);
                let left: [Lwe; 9] = std::array::from_fn(|i|encrypt(left_values[i]));
                let right: [Lwe; 9] = std::array::from_fn(|i|encrypt(right_values[i]));
                let (stages, combined) = comparator::prefix(&left[..4], &right[..4], server);
                let expected_combined = 4*top+2*middle+low;
                let expected_phase = ((2*expected_combined-1) as u64).wrapping_mul(SCORE_DELTA/2);
                let choose_right = left_values[..3] > right_values[..3];
                assert_eq!(choose_right, expected_combined > 0);
                let prefix: Vec<Value> = stages.iter().zip(signs).map(|(stage, sign)| {
                    let phase = decrypt_lwe_ciphertext(&big, &stage.output).0;
                    let error = phase.wrapping_sub((sign as u64).wrapping_mul(SCORE_DELTA)) as i64;
                    let address = standard_address(&stage.small, small859);
                    let pass = comparator::value(false, address) == sign && error.unsigned_abs() < SCORE_DELTA/2;
                    json!({"name":stage.name,"intended_sign":sign,"input":lwe_observation(&stage.input,&big),
                        "small859":lwe_observation(&stage.small,&small859.as_view()),"output":lwe_observation(&stage.output,&big),
                        "actual_standard_address":address,"output_error_torus":error,"pass":pass})
                }).collect();
                let mut raw904 = Lwe::new(0, LweSize(905), CiphertextModulus::new_native());
                keyswitch_lwe_ciphertext(g4_ksk, &combined, &mut raw904);
                let centered = grouped_mean(&raw904);
                let (mean_observation, address) = grouped_observation(&raw904, &centered, small904);
                let combined_error = decrypt_lwe_ciphertext(&big, &combined).0.wrapping_sub(expected_phase) as i64;
                emit(json!({"record":"g4_dynamic_control","case":cases,"intended_signs":signs,
                    "left_values":left_values,"right_values":right_values,"choose_right":choose_right,
                    "left":left.iter().map(|ct|lwe_observation(ct,&big)).collect::<Vec<_>>(),
                    "right":right.iter().map(|ct|lwe_observation(ct,&big)).collect::<Vec<_>>(),
                    "prefix":prefix,"combined":lwe_observation(&combined,&big),"intended_combined_phase":expected_phase,
                    "combined_error_torus":combined_error,"grouped_control":mean_observation,
                    "pass":prefix.iter().all(|row|row["pass"]==true) && combined_error.unsigned_abs()<SCORE_DELTA/2}));
                assert!(prefix.iter().all(|row|row["pass"]==true) && combined_error.unsigned_abs()<SCORE_DELTA/2);
                for groups in [&TWO[..], &THREE[..]] {
                    let active: Vec<usize> = groups.iter().flat_map(|group|group.iter().copied()).collect();
                    let accumulators = pack_pfks(&left, &right, groups, window);
                    let mut classic_control = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
                    keyswitch_lwe_ciphertext(&server.key_switching_key, &combined, &mut classic_control);
                    let classic_control = mean_center::apply(classic_control).corrected;
                    let mut classic_accumulators = accumulators.clone();
                    for accumulator in &mut classic_accumulators {
                        blind_rotate_assign(&classic_control, accumulator, classic_bsk);
                    }
                    let manual_classic = extract_add_back(&classic_accumulators, &left, groups);
                    let (unchanged_classic, _) = smallcuts::select_lanes::<9>(&left, &right, &combined, groups, window, &server.key_switching_key, classic_bsk);
                    assert_eq!(manual_classic, unchanged_classic, "packed PFKS bridge differs from the unchanged selector");
                    let mut stock = accumulators.clone();
                    let start = Instant::now();
                    for accumulator in &mut stock {
                        modulus_switch_multi_bit_blind_rotate_assign(&centered.corrected, accumulator, g4_bsk, ThreadCount(1), true);
                    }
                    let stock_ns = start.elapsed().as_nanos() as u64;
                    let mut batched = accumulators.clone();
                    let start = Instant::now();
                    let synthesized = batch_same_control(&centered.corrected, &mut batched, g4_bsk);
                    let batch_ns = start.elapsed().as_nanos() as u64;
                    let equal = stock == batched;
                    let stock_output = extract_add_back(&stock, &left, groups);
                    let batch_output = extract_add_back(&batched, &left, groups);
                    let matrix: Vec<Vec<Vec<u64>>> = groups.iter().map(|group| (0..group.len()).map(|destination| (0..group.len())
                        .map(|source|window_at(window_function.as_ref(), address as isize+41*(destination as isize-source as isize))).collect()).collect()).collect();
                    let matrix_pass = matrix.iter().all(|rows| rows.iter().enumerate().all(|(i,row)|row.iter().enumerate()
                        .all(|(j,&value)|value==u64::from(choose_right && i==j))));
                    let expected = if choose_right { &right_values } else { &left_values };
                    let output_phases: Vec<_> = batch_output.iter().map(|ct|decrypt_lwe_ciphertext(&big,ct).0).collect();
                    let expected_digits: Vec<_> = (0..9).map(|lane|if active.contains(&lane){expected[lane]}else{0}).collect();
                    let errors: Vec<_> = output_phases.iter().zip(&expected_digits).map(|(&phase,&digit)|phase.wrapping_sub(digit*SCORE_DELTA) as i64).collect();
                    let native_pass = errors.iter().all(|error|error.unsigned_abs()<SCORE_DELTA/2);
                    let classic_pass = unchanged_classic.iter().zip(&expected_digits).all(|(ct,&digit)|
                        (decrypt_lwe_ciphertext(&big,ct).0.wrapping_sub(digit*SCORE_DELTA) as i64).unsigned_abs()<SCORE_DELTA/2);
                    let pass = equal && stock_output==batch_output && matrix_pass && native_pass && classic_pass;
                    emit(json!({"record":"g4_dynamic_primitive","case":cases,"groups":groups,"group_count":groups.len(),
                        "active_lanes":active,"actual_grouped_address":address,"window_matrix":matrix,"window_matrix_pass":matrix_pass,
                        "accumulators":accumulators.iter().map(|ct|glwe_observation(ct,secret)).collect::<Vec<_>>(),
                        "stock_g4":stock.iter().map(|ct|glwe_observation(ct,secret)).collect::<Vec<_>>(),
                        "batched_g4":batched.iter().map(|ct|glwe_observation(ct,secret)).collect::<Vec<_>>(),
                        "full_glwe_words_equal":equal,"classic_manual_matches_unchanged_selector":true,
                        "classic_outputs":unchanged_classic.iter().map(|ct|lwe_observation(ct,&big)).collect::<Vec<_>>(),
                        "stock_outputs":stock_output.iter().map(|ct|lwe_observation(ct,&big)).collect::<Vec<_>>(),
                        "batch_outputs":batch_output.iter().map(|ct|lwe_observation(ct,&big)).collect::<Vec<_>>(),
                        "expected_digits":expected_digits,"output_errors_torus":errors,
                        "stock_synthesized_groups":GROUP_COUNT*groups.len(),"batch_synthesized_groups":synthesized,
                        "external_products_each_arm":GROUP_COUNT*groups.len(),
                        "stock_producers":1,"batch_producers":0,"batch_serial_synthesis":true,
                        "stock_br_only_diagnostic_ns":stock_ns,"batch_br_only_diagnostic_ns":batch_ns,
                        "timing_scope":"Single diagnostic BR calls with unequal thread policy and warm-state order; not paired performance evidence.",
                        "pass":pass}));
                    assert!(pass,"g4 dynamic primitive or actual payload gate failed");
                    primitive_outputs += 1;
                    checked_glwes += stock.len();
                    selected_payloads += active.len();
                }
                cases += 1;
            }
        }
    }
    assert_eq!((cases,primitive_outputs,checked_glwes,selected_payloads),(27,54,135,351));
    json!({"record":"g4_dynamic_complete","pass":true,"control_cases":cases,"primitive_outputs":primitive_outputs,
        "stock_batch_full_glwe_equalities":checked_glwes,"equal_u64_words":checked_glwes*4096,
        "live_payloads_per_arm":selected_payloads,"independent_secret_replay_pending":true,
        "not_a_full_query_or_performance_result":true})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_bit_order_and_half_ties_match_stock_switch_on_wrap_vectors() {
        let vectors = [[0,1,DEGREE_TORUS/2-1,DEGREE_TORUS/2],
            [u64::MAX,DEGREE_TORUS/2+1,u64::MAX-DEGREE_TORUS/2,7*DEGREE_TORUS],
            [1<<63,1<<63,1<<63,1<<63]];
        for mask in vectors {
            let library: Vec<_> = modulus_switch_multi_bit(CiphertextModulusLog(12),LweBskGroupingFactor(4),&mask).collect();
            for subset in 1..16 { assert_eq!(switched_degree(subset_sum(&mask,subset)),library[subset-1]); }
            assert_eq!(subset_sum(&mask,1),mask[3]);
            assert_eq!(subset_sum(&mask,8),mask[0]);
        }
    }

    #[test]
    fn signed_mean_rounding_and_exact_window_matrix_cover_all_control_centers() {
        for total in -1024i128..=1024 {
            let rounded=signed_round_div16(total);
            assert!((16*rounded-total).abs()<=8);
            assert_eq!(signed_round_div16(-total),-rounded);
        }
        let window=service_selected::window_function();
        for combined in -7isize..=7 {
            for radius in -20isize..=20 {
                let address=128*combined-64+radius;
                for group in THREE {
                    for i in 0..group.len() { for j in 0..group.len() {
                        assert_eq!(window_at(window.as_ref(),address+41*(i as isize-j as isize)),u64::from(combined>0&&i==j));
                    }}
                }
            }
        }
    }
}
