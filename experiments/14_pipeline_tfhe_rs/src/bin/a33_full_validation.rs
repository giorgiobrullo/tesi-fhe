//! Validazione FHE end-to-end mirata del percorso uniforme allineato A33.
//!
//! Il harness genera una chiave effimera, mai serializzata, e verifica i checkpoint cifrati del
//! core reale su confini di ammissione, tie-first, tail dispari, rifiuto fail-closed e identita'
//! massima a N=127. Il replay rivaluta lo stesso ciphertext con la stessa chiave effimera e
//! confronta sia l'output cifrato sia tutti i checkpoint decifrati, senza stampare materiale
//! segreto o ciphertext.

use pipeline_tfhe_rs::{
    clear_private_argmin, expected_pbs_count_for_thresholds, plan_private_argmin_execution,
    private_argmin_with_trace, PrivateArgminMetrics, PrivateArgminTrace, ScoreDomain, TemplateView,
    BOOL_DELTA_LOG, CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG,
    LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM, PROBE_NORM2_MAX,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const THRESHOLD: i64 = 4;
const EXECUTION_LOWER: i64 = THRESHOLD - 1023;
const SCORE_MASK: u64 = (1 << 12) - 1;
const SPARSE_MASK: u64 = 31;
const EXPECTED_BIT_POSITIONS: [u32; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const EXPECTED_BIT_WEIGHTS: [u64; 8] = [1, 1, 1, 1, 1, 8, 4, 2];

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone)]
struct CaseSpec {
    name: &'static str,
    translated_scores: Vec<u64>,
    expected_code: u64,
    replay: bool,
    no_resurrection: bool,
}

#[derive(PartialEq, Eq)]
struct DecodedTrace {
    score_full: Vec<u64>,
    score_low_mod16: Vec<u64>,
    aligned_residuals: Vec<u64>,
    sparse_codes: Vec<u64>,
    sparse_signed_flags: Vec<u64>,
    sparse_pair_flags: Vec<u64>,
    any_b9_zero: u64,
    b8_zero_candidates: Vec<u64>,
    any_b8_zero: u64,
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

#[derive(PartialEq, Eq)]
struct ReplayRecord {
    output_ciphertext: Vec<u64>,
    output_code: u64,
    total_pbs_count: u64,
    stage_pbs_counts: [u64; 7],
    trace: DecodedTrace,
}

fn cases() -> Vec<CaseSpec> {
    let mut n127 = vec![1025; 127];
    n127[0] = 512;
    n127[1] = 1023;
    n127[2] = 1024;
    n127[3] = 2047;
    n127[4] = 2048;
    n127[126] = 511;

    vec![
        CaseSpec {
            name: "n1_accept_1023",
            translated_scores: vec![1023],
            expected_code: 1,
            replay: false,
            no_resurrection: false,
        },
        CaseSpec {
            name: "n1_reject_1024",
            translated_scores: vec![1024],
            expected_code: 0,
            replay: false,
            no_resurrection: true,
        },
        CaseSpec {
            name: "n3_odd_tail_last_identity",
            translated_scores: vec![1025, 1024, 1023],
            expected_code: 3,
            replay: false,
            no_resurrection: false,
        },
        CaseSpec {
            name: "n3_tie_first_replay",
            translated_scores: vec![1023, 1023, 1025],
            expected_code: 1,
            replay: true,
            no_resurrection: false,
        },
        CaseSpec {
            name: "n3_all_reject_no_resurrection",
            translated_scores: vec![2047, 2048, 1024],
            expected_code: 0,
            replay: false,
            no_resurrection: true,
        },
        CaseSpec {
            name: "n127_boundary_tail_identity",
            translated_scores: n127,
            expected_code: 127,
            replay: false,
            no_resurrection: false,
        },
    ]
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

fn remainder_terms(remainder: usize) -> &'static [i64] {
    match remainder {
        0 => &[],
        1 => &[-1, 1, 1],
        2 => &[-1, 1],
        3 => &[-1],
        4 => &[-1, -1, 1, 1],
        5 => &[-1, -1, 1],
        6 => &[-1, -1],
        7 => &[-2, 1],
        8 => &[-2],
        9 => &[-1, -1, -1],
        10 => &[-2, -1, 1],
        11 => &[-2, -1],
        12 => &[-1, -1, -1, -1],
        13 => &[-3, 1, 1],
        14 => &[-3, 1],
        _ => unreachable!("resto modulo 15 fuori intervallo"),
    }
}

/// Costruisce un template in [-3,3] il cui score contro il probe tutto-uno e' esattamente `score`.
fn template_for_score(score: i64) -> Vec<i64> {
    let mut template = vec![0i64; PROBE_DIM];
    let used = if score < 0 {
        let count = usize::try_from(-score).expect("score negativo non rappresentabile");
        template[..count].fill(1);
        count
    } else {
        let quotient = usize::try_from(score / 15).expect("quoziente non rappresentabile");
        let tail = remainder_terms((score % 15) as usize);
        template[..quotient].fill(-3);
        template[quotient..quotient + tail.len()].copy_from_slice(tail);
        quotient + tail.len()
    };
    assert!(
        used <= PROBE_DIM,
        "score non rappresentabile in 512 coordinate"
    );
    template
}

fn make_gallery(translated_scores: &[u64], probe: &[i64]) -> Vec<Vec<i64>> {
    translated_scores
        .iter()
        .map(|&translated| {
            let score = i64::try_from(translated).unwrap() + EXECUTION_LOWER;
            let template = template_for_score(score);
            assert_eq!(clear_score(&template, probe), score);
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
        .unwrap_or_else(|| panic!("checkpoint A33 assente: {stage}"))
}

fn decode_trace(
    secret_key: &LweSecretKeyView<'_, u64>,
    trace: &PrivateArgminTrace,
) -> DecodedTrace {
    DecodedTrace {
        score_full: decode_many(secret_key, &trace.score_full, FULL_DELTA_LOG, SCORE_MASK),
        score_low_mod16: decode_many(secret_key, &trace.score_low_mod16, LOW_MOD16_DELTA_LOG, 15),
        aligned_residuals: decode_many(secret_key, &trace.aligned_residuals, FULL_DELTA_LOG + 9, 7),
        sparse_codes: decode_many(secret_key, &trace.sparse_codes, BOOL_DELTA_LOG, SPARSE_MASK),
        sparse_signed_flags: decode_many(
            secret_key,
            &trace.sparse_signed_flags,
            BOOL_DELTA_LOG,
            SPARSE_MASK,
        ),
        sparse_pair_flags: decode_many(secret_key, &trace.sparse_pair_flags, BOOL_DELTA_LOG, 15),
        any_b9_zero: decode_symbol(
            secret_key,
            require_option(&trace.sparse_any_b9_zero, "sparse_any_b9_zero"),
            BOOL_DELTA_LOG,
        ) & 15,
        b8_zero_candidates: decode_many(
            secret_key,
            &trace.aligned_b8_zero_candidates,
            BOOL_DELTA_LOG,
            15,
        ),
        any_b8_zero: decode_symbol(
            secret_key,
            require_option(&trace.aligned_any_b8_zero, "aligned_any_b8_zero"),
            BOOL_DELTA_LOG,
        ) & 15,
        initial_candidates: decode_many(
            secret_key,
            &trace.aligned_initial_candidates,
            BOOL_DELTA_LOG,
            15,
        ),
        bridged_bits_by_level: decode_nested(
            secret_key,
            &trace.bridged_bits_by_level,
            BOOL_DELTA_LOG,
            15,
        ),
        zero_candidates_by_level: decode_nested(
            secret_key,
            &trace.zero_candidates_by_level,
            BOOL_DELTA_LOG,
            15,
        ),
        any_zero_by_level: decode_many(secret_key, &trace.any_zero_by_level, BOOL_DELTA_LOG, 15),
        candidates_by_level: decode_nested(
            secret_key,
            &trace.candidates_by_level,
            BOOL_DELTA_LOG,
            15,
        ),
        winners: decode_many(secret_key, &trace.winners, BOOL_DELTA_LOG, 15),
        coded_digits_lsb_first: decode_many(
            secret_key,
            &trace.coded_digits_lsb_first,
            BOOL_DELTA_LOG,
            15,
        ),
        code_groups: decode_many(secret_key, &trace.code_groups, CODE_DELTA_LOG, 255),
        final_code: decode_symbol(
            secret_key,
            require_option(&trace.final_code, "final_code"),
            CODE_DELTA_LOG,
        ) & 255,
    }
}

fn expected_sparse_code(high: u64) -> u64 {
    [2, 3, 4, 4, 30, 29, 28, 28][high as usize]
}

fn expected_output_positions(n: usize) -> Vec<u32> {
    (0..usize::BITS)
        .filter(|&bit| (1..=n).any(|code| ((code >> bit) & 1) == 1))
        .collect()
}

fn expected_selection_trace(
    translated_scores: &[u64],
) -> (Vec<u64>, Vec<Vec<u64>>, Vec<u64>, Vec<Vec<u64>>) {
    let highs: Vec<u64> = translated_scores.iter().map(|score| score >> 9).collect();
    let any_high_zero = highs.contains(&0);
    let class_candidates: Vec<bool> = highs
        .iter()
        .map(|&high| high == u64::from(!any_high_zero))
        .collect();
    let b8_zero: Vec<bool> = class_candidates
        .iter()
        .zip(translated_scores)
        .map(|(&candidate, &score)| candidate && ((score >> 8) & 1) == 0)
        .collect();
    let any_b8_zero = b8_zero.contains(&true);
    let mut candidates: Vec<bool> = class_candidates
        .iter()
        .zip(&b8_zero)
        .map(|(&candidate, &zero)| candidate && (zero == any_b8_zero))
        .collect();
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

fn validate_trace(case: &CaseSpec, trace: &PrivateArgminTrace, decoded: &DecodedTrace) {
    let n = case.translated_scores.len();
    assert!(trace.aligned_fast_path, "{}: dispatch non A33", case.name);
    assert_eq!(trace.bit_positions_msb_first, EXPECTED_BIT_POSITIONS);
    assert_eq!(trace.bit_weights_msb_first, EXPECTED_BIT_WEIGHTS);
    assert!(trace.selected_threshold_bits_msb_first.is_empty());
    assert!(trace.selected_below.is_none());
    assert!(trace.comparison_state_by_level.is_empty());
    assert!(trace.accept_tag.is_none());

    assert_eq!(decoded.score_full, case.translated_scores);
    assert_eq!(
        decoded.score_low_mod16,
        case.translated_scores
            .iter()
            .map(|score| score & 15)
            .collect::<Vec<_>>()
    );
    let highs: Vec<u64> = case
        .translated_scores
        .iter()
        .map(|score| score >> 9)
        .collect();
    assert_eq!(decoded.aligned_residuals, highs);
    assert_eq!(
        decoded.sparse_codes,
        highs
            .iter()
            .map(|&high| expected_sparse_code(high))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        decoded.sparse_signed_flags,
        highs
            .iter()
            .enumerate()
            .map(|(index, &high)| {
                let weight = if index % 2 == 0 { 1 } else { 3 };
                match high {
                    0 => weight,
                    4 => (32 - weight) & SPARSE_MASK,
                    _ => 0,
                }
            })
            .collect::<Vec<_>>()
    );
    let expected_pair_flags: Vec<u64> = highs
        .chunks(2)
        .map(|pair| u64::from(pair.contains(&0)))
        .collect();
    assert_eq!(decoded.sparse_pair_flags, expected_pair_flags);
    let any_high_zero = highs.contains(&0);
    assert_eq!(decoded.any_b9_zero, u64::from(any_high_zero));

    let class_candidates: Vec<bool> = highs
        .iter()
        .map(|&high| high == u64::from(!any_high_zero))
        .collect();
    let b8_zero_candidates: Vec<u64> = class_candidates
        .iter()
        .zip(&case.translated_scores)
        .map(|(&candidate, &score)| u64::from(candidate && ((score >> 8) & 1) == 0))
        .collect();
    assert_eq!(decoded.b8_zero_candidates, b8_zero_candidates);
    assert_eq!(
        decoded.any_b8_zero,
        u64::from(b8_zero_candidates.contains(&1))
    );

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
        // Dopo i livelli pari A33 conserva intenzionalmente una codifica signed non Booleana.
        // Ogni secondo livello la canonicalizza: questi sono i checkpoint confrontabili a 0/1.
        if level % 2 == 1 {
            assert_eq!(
                decoded.candidates_by_level[level],
                candidates_by_level[level]
            );
        }
    }

    let final_candidates = candidates_by_level.last().unwrap();
    let first = final_candidates.iter().position(|&value| value == 1);
    let expected_winners: Vec<u64> = (0..n)
        .map(|index| u64::from(first == Some(index)))
        .collect();
    assert_eq!(decoded.winners, expected_winners);
    if case.no_resurrection {
        assert!(initial.iter().all(|&value| value == 0));
        assert!(decoded
            .candidates_by_level
            .iter()
            .skip(1)
            .step_by(2)
            .all(|level| level.iter().all(|&value| value == 0)));
        assert!(decoded.winners.iter().all(|&value| value == 0));
    }

    let output_positions = expected_output_positions(n);
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

fn hardcoded_expected_pbs(n: usize) -> u64 {
    match n {
        1 => 31,
        3 => 100,
        127 => 4273,
        _ => panic!("dimensione non prevista dal harness: {n}"),
    }
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
    let clear_scores: Vec<i64> = case
        .translated_scores
        .iter()
        .map(|&score| i64::try_from(score).unwrap() + domain.lower)
        .collect();
    let clear = clear_private_argmin(&clear_scores, templates).expect("oracolo clear fallito");
    assert_eq!(
        clear.code, case.expected_code,
        "{}: oracolo clear",
        case.name
    );

    let (output, trace) = private_argmin_with_trace(server_key, packed_probe, templates, domain)
        .expect("core A33 ha rifiutato un caso valido");
    let expected_pbs = hardcoded_expected_pbs(templates.len());
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    assert_eq!(
        expected_pbs_count_for_thresholds(templates.len(), &thresholds, domain),
        Some(expected_pbs)
    );
    assert_eq!(output.metrics.total_pbs_count, expected_pbs);
    let stage_counts = stage_pbs_counts(&output.metrics);
    assert_eq!(stage_counts.iter().sum::<u64>(), expected_pbs);
    assert_eq!(output.metrics.threshold.pbs_count, 0);

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
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|argument| argument == "--run") {
        println!(
            "usage: a33_full_validation --run [--small-only]\n\
             PLAN,cases=6,n127_evaluations=1,replay_case=n3_tie_first_replay,\
             keys=ephemeral_in_memory,secret_material_persisted=false"
        );
        return;
    }
    let small_only = args.iter().any(|argument| argument == "--small-only");
    let selected: Vec<CaseSpec> = cases()
        .into_iter()
        .filter(|case| !small_only || case.translated_scores.len() < 127)
        .collect();
    let probe = vec![1i64; PROBE_DIM];
    assert!(squared_norm(&probe) <= PROBE_NORM2_MAX);

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
        let gallery = make_gallery(&case.translated_scores, &probe);
        let templates: Vec<TemplateView<'_>> = gallery
            .iter()
            .map(|template| TemplateView {
                template,
                norm2: squared_norm(template),
                threshold: THRESHOLD,
            })
            .collect();
        let plan = plan_private_argmin_execution(&templates).expect("planning A33 fallito");
        assert!(plan.aligned_fast_path, "{}: planner non A33", case.name);
        assert_eq!(plan.execution_domain.lower, EXECUTION_LOWER);
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
            assert!(
                first == replay,
                "{}: il replay dello stesso ciphertext diverge",
                case.name
            );
            replay_verified = true;
        }
        println!(
            "RESULT,case={},n={},code={},pbs={},replay_verified={},seconds={:.6},correct=true",
            case.name,
            templates.len(),
            first.output_code,
            first.total_pbs_count,
            replay_verified,
            run_started.elapsed().as_secs_f64()
        );
    }

    println!(
        "SUMMARY,cases={},evaluations={evaluations},small_only={small_only},\
         ephemeral_key=true,secret_material_persisted=false,seconds={:.6},correct=true",
        selected.len(),
        validation_started.elapsed().as_secs_f64()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_templates_realize_every_boundary_exactly() {
        let probe = vec![1i64; PROBE_DIM];
        for translated in [511u64, 512, 1023, 1024, 1025, 2047, 2048] {
            let expected = i64::try_from(translated).unwrap() + EXECUTION_LOWER;
            let template = template_for_score(expected);
            assert_eq!(clear_score(&template, &probe), expected);
            assert!(template.iter().all(|value| (-3..=3).contains(value)));
        }
    }

    #[test]
    fn case_matrix_has_expected_clear_identity_and_costs() {
        let probe = vec![1i64; PROBE_DIM];
        for case in cases() {
            let gallery = make_gallery(&case.translated_scores, &probe);
            let templates: Vec<TemplateView<'_>> = gallery
                .iter()
                .map(|template| TemplateView {
                    template,
                    norm2: squared_norm(template),
                    threshold: THRESHOLD,
                })
                .collect();
            let plan = plan_private_argmin_execution(&templates).unwrap();
            assert!(plan.aligned_fast_path);
            assert_eq!(plan.execution_domain.lower, EXECUTION_LOWER);
            let scores: Vec<i64> = case
                .translated_scores
                .iter()
                .map(|&score| i64::try_from(score).unwrap() + EXECUTION_LOWER)
                .collect();
            assert_eq!(
                clear_private_argmin(&scores, &templates).unwrap().code,
                case.expected_code
            );
            let thresholds = vec![THRESHOLD; templates.len()];
            assert_eq!(
                expected_pbs_count_for_thresholds(
                    templates.len(),
                    &thresholds,
                    plan.execution_domain
                ),
                Some(hardcoded_expected_pbs(templates.len()))
            );
        }
    }
}
