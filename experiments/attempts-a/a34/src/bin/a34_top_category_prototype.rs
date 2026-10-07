//! Harness FHE isolato per la sola sostituzione A34 top-category.
//!
//! Il core deriva dalla fotografia A33 congelata, ma conserva scan, output e selezione esatta
//! b7..b0. A34-top trattiene quei bit, classifica `h=x>>8`, riduce la categoria minima e produce i
//! candidati iniziali. Questo binario non contiene lo scan/output A34 ne' il candidato A36.
//!
//! Senza `--run` esegue soltanto le asserzioni clear/strutturali. Con `--run` genera una chiave
//! effimera in memoria e valida i checkpoint cifrati; non serializza chiavi o ciphertext.

use a34_top_category_prototype::{
    a34_aligned_operation_counts, clear_private_argmin, expected_pbs_count_for_thresholds,
    plan_private_argmin_execution, private_argmin_with_trace, A34OperationCounts,
    PrivateArgminMetrics, PrivateArgminTrace, ScoreDomain, TemplateView, BOOL_DELTA_LOG,
    CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET,
    MAX_GALLERY_SIZE, PROBE_DIM, PROBE_NORM2_MAX,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const SCORE_MASK: u64 = (1 << 12) - 1;
const PHASE_MASK: u64 = 31;
const OR_BLOCK: usize = 4;
const FIRST_ONE_GROUP: usize = 3;
const EXPECTED_BIT_POSITIONS: [u32; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const EXPECTED_BIT_WEIGHTS: [u64; 8] = [1, 1, 1, 1, 1, 8, 4, 2];
const TOP_CODES: [u64; 16] = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0];
const COUNT_FIXTURES: [(usize, A34OperationCounts); 6] = [
    (
        1,
        A34OperationCounts {
            blind_rotations: 29,
            key_switches: 26,
            output_marginals: 33,
        },
    ),
    (
        2,
        A34OperationCounts {
            blind_rotations: 67,
            key_switches: 61,
            output_marginals: 75,
        },
    ),
    (
        3,
        A34OperationCounts {
            blind_rotations: 95,
            key_switches: 86,
            output_marginals: 107,
        },
    ),
    (
        64,
        A34OperationCounts {
            blind_rotations: 2076,
            key_switches: 1884,
            output_marginals: 2332,
        },
    ),
    (
        127,
        A34OperationCounts {
            blind_rotations: 4144,
            key_switches: 3763,
            output_marginals: 4652,
        },
    ),
    (
        128,
        A34OperationCounts {
            blind_rotations: 4174,
            key_switches: 3790,
            output_marginals: 4686,
        },
    ),
];

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone)]
struct CaseSpec {
    name: String,
    threshold: i64,
    translated_scores: Vec<u64>,
    expected_code: u64,
    replay: bool,
    full_only: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct DecodedTrace {
    score_full: Vec<u64>,
    score_low_mod16: Vec<u64>,
    aligned_residuals: Vec<u64>,
    top_codes: Vec<u64>,
    canonical_categories: Vec<u64>,
    category_reduction_levels: Vec<Vec<u64>>,
    global_category: u64,
    initial_candidates: Vec<u64>,
    bridged_bits_by_level: Vec<Vec<u64>>,
    zero_candidates_by_level: Vec<Vec<u64>>,
    any_zero_by_level: Vec<u64>,
    candidates_by_level: Vec<Vec<u64>>,
    winners: Vec<u64>,
    coded_digits_lsb_first: Vec<u64>,
    code_groups: Vec<u64>,
    final_code: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayRecord {
    output_ciphertext: Vec<u64>,
    output_code: u64,
    total_pbs_count: u64,
    stage_pbs_counts: [u64; 7],
    trace: DecodedTrace,
}

fn cases() -> Vec<CaseSpec> {
    let mut result: Vec<CaseSpec> = (0..16u64)
        .map(|h| {
            let translated = h << 8;
            CaseSpec {
                name: format!("n1_classifier_h{h}"),
                threshold: 1023 - translated as i64,
                translated_scores: vec![translated],
                expected_code: u64::from(h <= 3),
                replay: false,
                full_only: false,
            }
        })
        .collect();

    result.extend([
        CaseSpec {
            name: "n1_accept_boundary_1023".into(),
            threshold: 0,
            translated_scores: vec![1023],
            expected_code: 1,
            replay: false,
            full_only: false,
        },
        CaseSpec {
            name: "n1_reject_boundary_1024".into(),
            threshold: -1,
            translated_scores: vec![1024],
            expected_code: 0,
            replay: false,
            full_only: false,
        },
        CaseSpec {
            name: "n2_boundary_second_identity".into(),
            threshold: 0,
            translated_scores: vec![1024, 1023],
            expected_code: 2,
            replay: false,
            full_only: false,
        },
        CaseSpec {
            name: "n3_first_tie_replay".into(),
            threshold: 946,
            translated_scores: vec![77, 77, 78],
            expected_code: 1,
            replay: true,
            full_only: false,
        },
        CaseSpec {
            name: "n3_all_reject".into(),
            threshold: -1,
            translated_scores: vec![1024; 3],
            expected_code: 0,
            replay: false,
            full_only: false,
        },
        last_identity_case(64),
        last_identity_case(127),
        last_identity_case(128),
    ]);
    result
}

fn last_identity_case(gallery_size: usize) -> CaseSpec {
    let mut translated_scores = vec![1020; gallery_size];
    translated_scores[gallery_size - 1] = 1019;
    CaseSpec {
        name: format!("n{gallery_size}_last_identity"),
        threshold: 4,
        translated_scores,
        expected_code: gallery_size as u64,
        replay: false,
        full_only: true,
    }
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn clear_score(template: &[i64], probe: &[i64]) -> i64 {
    squared_norm(template)
        - 2 * template
            .iter()
            .zip(probe)
            .map(|(gallery, query)| gallery * query)
            .sum::<i64>()
}

fn template_for_raw_score(score: i64) -> Vec<i64> {
    let mut template = vec![0i64; PROBE_DIM];
    match score {
        0 => {}
        1 => template[0] = 1,
        _ => panic!("lo schema isolato rappresenta soltanto score raw 0/1, ricevuto {score}"),
    }
    template
}

fn make_gallery(case: &CaseSpec, execution_lower: i64, probe: &[i64]) -> Vec<Vec<i64>> {
    case.translated_scores
        .iter()
        .map(|&translated| {
            let raw_score = i64::try_from(translated).unwrap() + execution_lower;
            let template = template_for_raw_score(raw_score);
            assert_eq!(clear_score(&template, probe), raw_score);
            template
        })
        .collect()
}

fn encrypt_packed_probe(
    probe: &[i64],
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    polynomial_size: PolynomialSize,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= PROBE_NORM2_MAX);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM <= polynomial_size.0);

    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOW_MOD16_DELTA_LOG);
    }
    let mut encrypted = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
        modulus,
    );
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    encrypted
}

fn decode_symbol(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe, delta_log: u32) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (delta_log - 1))
        >> delta_log
}

fn decode_many(
    secret_key: &LweSecretKeyView<'_, u64>,
    ciphertexts: &[Lwe],
    delta_log: u32,
    mask: u64,
) -> Vec<u64> {
    ciphertexts
        .iter()
        .map(|ciphertext| decode_symbol(secret_key, ciphertext, delta_log) & mask)
        .collect()
}

fn decode_nested(
    secret_key: &LweSecretKeyView<'_, u64>,
    ciphertexts: &[Vec<Lwe>],
    delta_log: u32,
    mask: u64,
) -> Vec<Vec<u64>> {
    ciphertexts
        .iter()
        .map(|row| decode_many(secret_key, row, delta_log, mask))
        .collect()
}

fn require_option<'a>(value: &'a Option<Lwe>, stage: &str) -> &'a Lwe {
    value
        .as_ref()
        .unwrap_or_else(|| panic!("checkpoint A34-top assente: {stage}"))
}

fn decode_trace(
    secret_key: &LweSecretKeyView<'_, u64>,
    trace: &PrivateArgminTrace,
) -> DecodedTrace {
    DecodedTrace {
        score_full: decode_many(secret_key, &trace.score_full, FULL_DELTA_LOG, SCORE_MASK),
        score_low_mod16: decode_many(secret_key, &trace.score_low_mod16, LOW_MOD16_DELTA_LOG, 15),
        aligned_residuals: decode_many(
            secret_key,
            &trace.aligned_residuals,
            FULL_DELTA_LOG + 8,
            15,
        ),
        top_codes: decode_many(secret_key, &trace.a34_top_codes, BOOL_DELTA_LOG, PHASE_MASK),
        canonical_categories: decode_many(
            secret_key,
            &trace.a34_canonical_categories,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        category_reduction_levels: decode_nested(
            secret_key,
            &trace.a34_category_reduction_levels,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        global_category: decode_symbol(
            secret_key,
            require_option(&trace.a34_global_category, "a34_global_category"),
            BOOL_DELTA_LOG,
        ) & PHASE_MASK,
        initial_candidates: decode_many(
            secret_key,
            &trace.aligned_initial_candidates,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        bridged_bits_by_level: decode_nested(
            secret_key,
            &trace.bridged_bits_by_level,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        zero_candidates_by_level: decode_nested(
            secret_key,
            &trace.zero_candidates_by_level,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        any_zero_by_level: decode_many(
            secret_key,
            &trace.any_zero_by_level,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        candidates_by_level: decode_nested(
            secret_key,
            &trace.candidates_by_level,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        winners: decode_many(secret_key, &trace.winners, BOOL_DELTA_LOG, PHASE_MASK),
        coded_digits_lsb_first: decode_many(
            secret_key,
            &trace.coded_digits_lsb_first,
            BOOL_DELTA_LOG,
            PHASE_MASK,
        ),
        code_groups: decode_many(secret_key, &trace.code_groups, CODE_DELTA_LOG, 255),
        final_code: decode_symbol(
            secret_key,
            require_option(&trace.final_code, "final_code"),
            CODE_DELTA_LOG,
        ) & 255,
    }
}

fn category_code(h: u64) -> u64 {
    match h {
        0 => 1,
        1 => 3,
        2 => 7,
        _ => 0,
    }
}

fn category_rank(code: u64) -> usize {
    [1, 3, 7, 0]
        .iter()
        .position(|&candidate| candidate == code)
        .unwrap_or_else(|| panic!("categoria non canonica: {code}"))
}

fn reduce_category_pair(left: u64, right: u64) -> u64 {
    [1, 3, 7, 0][category_rank(left).min(category_rank(right))]
}

fn expected_category_levels(scores: &[u64]) -> Vec<Vec<u64>> {
    let mut level: Vec<u64> = scores
        .iter()
        .map(|score| category_code(score >> 8))
        .collect();
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                pair.get(1)
                    .map_or(pair[0], |&right| reduce_category_pair(pair[0], right))
            })
            .collect();
        levels.push(level.clone());
    }
    levels
}

fn expected_top_candidates(scores: &[u64]) -> Vec<bool> {
    let minimum_h = scores.iter().map(|score| score >> 8).min().unwrap();
    if minimum_h >= 4 {
        return vec![false; scores.len()];
    }
    scores
        .iter()
        .map(|score| (score >> 8) == minimum_h)
        .collect()
}

type SelectionTrace = (Vec<u64>, Vec<Vec<u64>>, Vec<u64>, Vec<Vec<u64>>);

fn expected_selection_trace(translated_scores: &[u64]) -> SelectionTrace {
    let mut candidates = expected_top_candidates(translated_scores);
    let initial = candidates.iter().map(|&value| u64::from(value)).collect();
    let mut zero_by_level = Vec::with_capacity(EXPECTED_BIT_POSITIONS.len());
    let mut any_zero_by_level = Vec::with_capacity(EXPECTED_BIT_POSITIONS.len());
    let mut candidates_by_level = Vec::with_capacity(EXPECTED_BIT_POSITIONS.len());

    for &bit in &EXPECTED_BIT_POSITIONS {
        let zero_candidates: Vec<bool> = candidates
            .iter()
            .zip(translated_scores)
            .map(|(&candidate, &score)| candidate && ((score >> bit) & 1) == 0)
            .collect();
        let any_zero = zero_candidates.contains(&true);
        candidates = candidates
            .iter()
            .zip(&zero_candidates)
            .map(|(&candidate, &zero)| candidate && (zero == any_zero))
            .collect();
        zero_by_level.push(
            zero_candidates
                .iter()
                .map(|&value| u64::from(value))
                .collect(),
        );
        any_zero_by_level.push(u64::from(any_zero));
        candidates_by_level.push(candidates.iter().map(|&value| u64::from(value)).collect());
    }
    (
        initial,
        zero_by_level,
        any_zero_by_level,
        candidates_by_level,
    )
}

fn expected_output_positions(gallery_size: usize) -> Vec<u32> {
    (0..usize::BITS)
        .filter(|&bit| (1..=gallery_size).any(|code| ((code >> bit) & 1) == 1))
        .collect()
}

fn validate_trace(case: &CaseSpec, trace: &PrivateArgminTrace, decoded: &DecodedTrace) {
    let gallery_size = case.translated_scores.len();
    assert!(
        trace.aligned_fast_path,
        "{}: dispatch non A34-top",
        case.name
    );
    assert_eq!(trace.bit_positions_msb_first, EXPECTED_BIT_POSITIONS);
    assert_eq!(trace.bit_weights_msb_first, EXPECTED_BIT_WEIGHTS);
    assert!(trace.selected_threshold_bits_msb_first.is_empty());
    assert!(trace.selected_below.is_none());
    assert!(trace.comparison_state_by_level.is_empty());
    assert!(trace.accept_tag.is_none());
    assert!(trace.sparse_codes.is_empty());
    assert!(trace.sparse_signed_flags.is_empty());
    assert!(trace.sparse_pair_flags.is_empty());
    assert!(trace.sparse_any_b9_zero.is_none());
    assert!(trace.aligned_b8_zero_candidates.is_empty());
    assert!(trace.aligned_any_b8_zero.is_none());
    assert!(trace
        .full_small_bits_lsb_first
        .iter()
        .all(|bits| bits.len() == 8));
    assert!(trace
        .full_corrections_lsb_first
        .iter()
        .all(|bits| bits.len() == 8));

    assert_eq!(decoded.score_full, case.translated_scores);
    assert_eq!(
        decoded.score_low_mod16,
        case.translated_scores
            .iter()
            .map(|score| score & 15)
            .collect::<Vec<_>>()
    );
    let high_categories: Vec<u64> = case
        .translated_scores
        .iter()
        .map(|score| score >> 8)
        .collect();
    assert_eq!(decoded.aligned_residuals, high_categories);
    assert_eq!(
        decoded.top_codes,
        high_categories
            .iter()
            .map(|&h| TOP_CODES[h as usize])
            .collect::<Vec<_>>()
    );
    assert_eq!(
        decoded.canonical_categories,
        high_categories
            .iter()
            .map(|&h| category_code(h))
            .collect::<Vec<_>>()
    );
    let expected_levels = expected_category_levels(&case.translated_scores);
    assert_eq!(decoded.category_reduction_levels, expected_levels);
    assert_eq!(decoded.global_category, expected_levels.last().unwrap()[0]);

    let (initial, zero_by_level, any_zero_by_level, candidates_by_level) =
        expected_selection_trace(&case.translated_scores);
    assert_eq!(decoded.initial_candidates, initial);
    assert_eq!(decoded.bridged_bits_by_level.len(), 8);
    for (level, (&bit, &weight)) in EXPECTED_BIT_POSITIONS
        .iter()
        .zip(&EXPECTED_BIT_WEIGHTS)
        .enumerate()
    {
        let expected_bits: Vec<u64> = case
            .translated_scores
            .iter()
            .map(|score| ((score >> bit) & 1) * weight)
            .collect();
        assert_eq!(decoded.bridged_bits_by_level[level], expected_bits);
        assert_eq!(
            decoded.zero_candidates_by_level[level],
            zero_by_level[level]
        );
        assert_eq!(decoded.any_zero_by_level[level], any_zero_by_level[level]);
        if level % 2 == 1 {
            assert_eq!(
                decoded.candidates_by_level[level],
                candidates_by_level[level]
            );
        }
    }

    let final_candidates = candidates_by_level.last().unwrap();
    let first = final_candidates.iter().position(|&value| value == 1);
    let expected_winners: Vec<u64> = (0..gallery_size)
        .map(|index| u64::from(first == Some(index)))
        .collect();
    assert_eq!(decoded.winners, expected_winners);
    if initial.iter().all(|&value| value == 0) {
        assert!(decoded
            .candidates_by_level
            .iter()
            .skip(1)
            .step_by(2)
            .all(|level| level.iter().all(|&value| value == 0)));
        assert!(decoded.winners.iter().all(|&value| value == 0));
    }

    let output_positions = expected_output_positions(gallery_size);
    let expected_digits: Vec<u64> = output_positions
        .iter()
        .map(|&bit| ((case.expected_code >> bit) & 1) << (bit % 3))
        .collect();
    assert_eq!(decoded.coded_digits_lsb_first, expected_digits);
    let expected_groups: Vec<u64> = output_positions
        .chunks(3)
        .map(|bits| {
            let offset = bits[0];
            let mask = ((1u64 << bits.len()) - 1) << offset;
            case.expected_code & mask
        })
        .collect();
    assert_eq!(decoded.code_groups, expected_groups);
    assert_eq!(decoded.final_code, case.expected_code);
}

fn fixture_counts(gallery_size: usize) -> Option<A34OperationCounts> {
    COUNT_FIXTURES
        .iter()
        .find_map(|&(size, counts)| (size == gallery_size).then_some(counts))
}

fn assert_count_fixtures() {
    for (gallery_size, expected) in COUNT_FIXTURES {
        assert_eq!(independent_operation_counts(gallery_size), Some(expected));
        assert_eq!(a34_aligned_operation_counts(gallery_size), Some(expected));
        assert_eq!(
            expected.key_switches,
            expected.blind_rotations - 3 * gallery_size as u64
        );
        assert_eq!(
            expected.output_marginals,
            expected.blind_rotations + 4 * gallery_size as u64
        );
    }
    assert_eq!(a34_aligned_operation_counts(0), None);
    assert_eq!(a34_aligned_operation_counts(MAX_GALLERY_SIZE + 1), None);
}

fn independent_or_reduction_pbs(mut items: usize) -> u64 {
    let mut count = 0;
    while items > 1 {
        items = items.div_ceil(OR_BLOCK);
        count += items as u64;
    }
    count
}

fn independent_radix4_exclusive_prefix_pbs(items: usize) -> u64 {
    if items <= 2 {
        return 0;
    }
    if items <= OR_BLOCK {
        return (items - 2) as u64;
    }

    let mut totals = 0;
    let mut expansion = 0;
    let mut groups = 0;
    for start in (0..items).step_by(OR_BLOCK) {
        let group_len = (items - start).min(OR_BLOCK);
        groups += 1;
        totals += u64::from(group_len > 1);
        expansion += if start == 0 {
            group_len.saturating_sub(2) as u64
        } else {
            (group_len - 1) as u64
        };
    }
    totals + expansion + independent_radix4_exclusive_prefix_pbs(groups)
}

fn independent_first_one_scan_pbs(items: usize) -> u64 {
    let groups = items.div_ceil(FIRST_ONE_GROUP);
    let group_totals = (0..items)
        .step_by(FIRST_ONE_GROUP)
        .filter(|&start| (items - start).min(FIRST_ONE_GROUP) > 1)
        .count() as u64;
    group_totals + independent_radix4_exclusive_prefix_pbs(groups) + items as u64
}

fn independent_output_pbs(gallery_size: usize) -> u64 {
    let positions = expected_output_positions(gallery_size);
    let bit_pbs: u64 = positions
        .iter()
        .map(|&bit| {
            (1..=gallery_size)
                .filter(|&code| ((code >> bit) & 1) == 1)
                .count()
        })
        .map(|items| independent_or_reduction_pbs(items).max(1))
        .sum();
    bit_pbs + positions.len().div_ceil(3) as u64
}

fn independent_operation_counts(gallery_size: usize) -> Option<A34OperationCounts> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    let extraction = 13 * n;
    let selection = 14 * n + 8 * independent_or_reduction_pbs(gallery_size) - 1;
    let scan = independent_first_one_scan_pbs(gallery_size);
    let output = independent_output_pbs(gallery_size);
    let blind_rotations = extraction + selection + scan + output;
    Some(A34OperationCounts {
        blind_rotations,
        key_switches: blind_rotations - 3 * n,
        output_marginals: blind_rotations + 4 * n,
    })
}

fn stage_pbs_counts(metrics: &PrivateArgminMetrics) -> [u64; 7] {
    [
        metrics.setup.pbs_count,
        metrics.score.pbs_count,
        metrics.extract.pbs_count,
        metrics.select.pbs_count,
        metrics.scan.pbs_count,
        metrics.threshold.pbs_count,
        metrics.output.pbs_count,
    ]
}

fn evaluate(
    case: &CaseSpec,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    secret_key: &LweSecretKeyView<'_, u64>,
) -> ReplayRecord {
    let raw_scores: Vec<i64> = case
        .translated_scores
        .iter()
        .map(|&score| i64::try_from(score).unwrap() + domain.lower)
        .collect();
    let clear = clear_private_argmin(&raw_scores, templates).expect("oracolo clear fallito");
    assert_eq!(
        clear.code, case.expected_code,
        "{}: oracolo clear",
        case.name
    );

    let (output, trace) = private_argmin_with_trace(server_key, packed_probe, templates, domain)
        .expect("core A34-top ha rifiutato un caso valido");
    let expected_counts = a34_aligned_operation_counts(templates.len()).unwrap();
    if let Some(fixture) = fixture_counts(templates.len()) {
        assert_eq!(expected_counts, fixture);
    }
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    assert_eq!(
        expected_pbs_count_for_thresholds(templates.len(), &thresholds, domain),
        Some(expected_counts.blind_rotations)
    );
    assert_eq!(
        output.metrics.total_pbs_count,
        expected_counts.blind_rotations
    );
    let stage_counts = stage_pbs_counts(&output.metrics);
    assert_eq!(
        stage_counts.iter().sum::<u64>(),
        expected_counts.blind_rotations
    );
    let gallery_size = templates.len();
    assert_eq!(output.metrics.setup.pbs_count, 0);
    assert_eq!(output.metrics.score.pbs_count, 0);
    assert_eq!(output.metrics.extract.pbs_count, 13 * gallery_size as u64);
    assert_eq!(
        output.metrics.select.pbs_count,
        14 * gallery_size as u64 + 8 * independent_or_reduction_pbs(gallery_size) - 1
    );
    assert_eq!(
        output.metrics.scan.pbs_count,
        independent_first_one_scan_pbs(gallery_size)
    );
    assert_eq!(output.metrics.threshold.pbs_count, 0);
    assert_eq!(
        output.metrics.output.pbs_count,
        independent_output_pbs(gallery_size)
    );

    let output_code = decode_symbol(secret_key, &output.code, CODE_DELTA_LOG) & 255;
    assert_eq!(output_code, case.expected_code, "{}: output FHE", case.name);
    let decoded = decode_trace(secret_key, &trace);
    validate_trace(case, &trace, &decoded);

    ReplayRecord {
        output_ciphertext: output.code.as_ref().to_vec(),
        output_code,
        total_pbs_count: output.metrics.total_pbs_count,
        stage_pbs_counts: stage_counts,
        trace: decoded,
    }
}

fn main() {
    assert_count_fixtures();
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|argument| argument == "--run") {
        println!(
            "usage: a34_top_category_prototype --run [--small-only]\n\
             PLAN,variant=a34_top_only,cases={},h_classes=16,count_fixtures=6,\
             scan_output=a33,contains_a36=false,keys=ephemeral_in_memory,\
             secret_material_persisted=false",
            cases().len()
        );
        return;
    }
    let small_only = args.iter().any(|argument| argument == "--small-only");
    let selected: Vec<CaseSpec> = cases()
        .into_iter()
        .filter(|case| !small_only || !case.full_only)
        .collect();
    let probe = vec![0i64; PROBE_DIM];

    let key_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!(
        "KEY,generation_s={:.6},ephemeral=true,secret_material_persisted=false",
        key_started.elapsed().as_secs_f64()
    );

    let validation_started = Instant::now();
    let mut evaluations = 0usize;
    for case in &selected {
        let execution_lower = case.threshold - 1023;
        let gallery = make_gallery(case, execution_lower, &probe);
        let templates: Vec<TemplateView<'_>> = gallery
            .iter()
            .map(|template| TemplateView {
                template,
                norm2: squared_norm(template),
                threshold: case.threshold,
            })
            .collect();
        let plan = plan_private_argmin_execution(&templates).expect("planning A34-top fallito");
        assert!(
            plan.aligned_fast_path,
            "{}: planner non allineato",
            case.name
        );
        assert_eq!(plan.execution_domain.lower, execution_lower);
        assert!(plan.execution_domain.lower <= plan.cauchy_domain.lower);
        assert!(plan.execution_domain.upper >= plan.cauchy_domain.upper);
        let packed_probe = encrypt_packed_probe(
            &probe,
            &glwe_secret_key,
            client_params.glwe_noise_distribution(),
            polynomial_size,
            modulus,
            &mut generator,
        );

        let run_started = Instant::now();
        let first = evaluate(
            case,
            &server_key,
            &packed_probe,
            &templates,
            plan.execution_domain,
            &big_secret_key,
        );
        evaluations += 1;
        let mut replay_verified = false;
        if case.replay {
            let replay = evaluate(
                case,
                &server_key,
                &packed_probe,
                &templates,
                plan.execution_domain,
                &big_secret_key,
            );
            evaluations += 1;
            assert_eq!(first, replay, "{}: replay divergente", case.name);
            replay_verified = true;
        }
        let counts = a34_aligned_operation_counts(templates.len()).unwrap();
        println!(
            "RESULT,case={},n={},code={},br={},ks={},marginals={},replay_verified={},\
             seconds={:.6},correct=true",
            case.name,
            templates.len(),
            first.output_code,
            counts.blind_rotations,
            counts.key_switches,
            counts.output_marginals,
            replay_verified,
            run_started.elapsed().as_secs_f64()
        );
    }

    println!(
        "SUMMARY,variant=a34_top_only,cases={},evaluations={evaluations},\
         small_only={small_only},scan_output=a33,contains_a36=false,ephemeral_key=true,\
         secret_material_persisted=false,seconds={:.6},correct=true",
        selected.len(),
        validation_started.elapsed().as_secs_f64()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_categories_and_pair_reducer_are_exhaustive() {
        for h in 0..8 {
            assert_eq!(TOP_CODES[h + 8], (32 - TOP_CODES[h]) & PHASE_MASK);
        }
        assert_eq!(
            (0..16).map(category_code).collect::<Vec<_>>(),
            [1, 3, 7]
                .into_iter()
                .chain(std::iter::repeat(0).take(13))
                .collect::<Vec<_>>()
        );
        for &left in &[1, 3, 7, 0] {
            for &right in &[1, 3, 7, 0] {
                let expected = [1, 3, 7, 0][category_rank(left).min(category_rank(right))];
                assert_eq!(reduce_category_pair(left, right), expected);
            }
        }
    }

    #[test]
    fn hardcoded_counts_cover_every_required_gallery_size() {
        assert_count_fixtures();
        assert_eq!(
            COUNT_FIXTURES.map(|(gallery_size, _)| gallery_size),
            [1, 2, 3, 64, 127, 128]
        );
    }

    #[test]
    fn case_matrix_covers_h_boundaries_ties_reject_and_tail_ids() {
        let cases = cases();
        for h in 0..16 {
            let name = format!("n1_classifier_h{h}");
            let case = cases.iter().find(|case| case.name == name).unwrap();
            assert_eq!(case.translated_scores, [h << 8]);
            assert_eq!(case.expected_code, u64::from(h <= 3));
        }
        assert!(cases.iter().any(|case| case.translated_scores == [1023]));
        assert!(cases.iter().any(|case| case.translated_scores == [1024]));
        assert!(cases.iter().any(|case| case.name.contains("tie")));
        assert!(cases.iter().any(|case| case.name.contains("all_reject")));
        assert!(cases
            .iter()
            .any(|case| case.translated_scores.len() == 127 && case.expected_code == 127));
        assert!(cases
            .iter()
            .any(|case| case.translated_scores.len() == 128 && case.expected_code == 128));
    }

    #[test]
    fn every_case_is_realizable_and_matches_the_independent_clear_oracle() {
        let probe = vec![0i64; PROBE_DIM];
        for case in cases() {
            let execution_lower = case.threshold - 1023;
            let gallery = make_gallery(&case, execution_lower, &probe);
            let templates: Vec<TemplateView<'_>> = gallery
                .iter()
                .map(|template| TemplateView {
                    template,
                    norm2: squared_norm(template),
                    threshold: case.threshold,
                })
                .collect();
            let plan = plan_private_argmin_execution(&templates).unwrap();
            assert!(plan.aligned_fast_path, "{}", case.name);
            assert_eq!(
                plan.execution_domain.lower, execution_lower,
                "{}",
                case.name
            );
            let raw_scores: Vec<i64> = case
                .translated_scores
                .iter()
                .map(|&score| i64::try_from(score).unwrap() + execution_lower)
                .collect();
            assert_eq!(
                clear_private_argmin(&raw_scores, &templates).unwrap().code,
                case.expected_code,
                "{}",
                case.name
            );
            let minimum = case
                .translated_scores
                .iter()
                .enumerate()
                .min_by_key(|(index, score)| (**score, *index))
                .unwrap();
            let top_candidates = expected_top_candidates(&case.translated_scores);
            let minimum_h = *minimum.1 >> 8;
            assert_eq!(
                top_candidates,
                case.translated_scores
                    .iter()
                    .map(|score| minimum_h < 4 && (score >> 8) == minimum_h)
                    .collect::<Vec<_>>(),
                "{}: candidati dopo la sola riduzione top",
                case.name
            );
            let (_, _, _, candidates_by_level) = expected_selection_trace(&case.translated_scores);
            let final_candidates = candidates_by_level
                .last()
                .expect("la selezione sugli otto bit bassi deve avere un livello finale");
            assert_eq!(
                final_candidates
                    .iter()
                    .position(|&candidate| candidate == 1),
                (*minimum.1 <= 1023).then_some(minimum.0),
                "{}",
                case.name
            );
        }
    }
}
