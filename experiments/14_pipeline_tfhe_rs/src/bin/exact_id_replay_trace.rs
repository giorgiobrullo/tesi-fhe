//! Replay locale di un probe exact-ID preservato con checkpoint cifrati interni.
//!
//! Questo binario diagnostico richiede esplicitamente la chiave client e non e' collegato al
//! servizio HTTP. Il core di produzione continua a restituire soltanto il codice finale.

use pipeline_tfhe_rs::{
    cauchy_score_domain, private_argmin_with_trace, TemplateView, BOOL_DELTA_LOG, CODE_DELTA_LOG,
    FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, PROBE_DIM,
};
use std::path::Path;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::{ClientKey, ServerKey};

const PROBE_MAGIC: u64 = u64::from_le_bytes(*b"VRCOPRB2");
const PROBE_HEADER_WORDS: usize = 8;
const LOW_NIBBLE_BITS: u32 = u64::BITS - LOW_MOD16_DELTA_LOG;
const HIGH_DELTA_LOG: u32 = FULL_DELTA_LOG + LOW_NIBBLE_BITS;

fn read_words(path: &Path) -> (Vec<u64>, Vec<u64>) {
    let bytes = std::fs::read(path).expect("probe ciphertext mancante");
    assert!(bytes.len().is_multiple_of(8), "ciphertext troncato");
    let words: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    let header_len = words[0] as usize;
    assert_eq!(header_len, PROBE_HEADER_WORDS, "header inatteso");
    assert!(words.len() > header_len);
    (
        words[1..=header_len].to_vec(),
        words[header_len + 1..].to_vec(),
    )
}

fn read_vector(path: &Path) -> Vec<i64> {
    std::fs::read_to_string(path)
        .expect("vettore mancante")
        .split_whitespace()
        .map(|value| value.parse().expect("vettore non numerico"))
        .collect()
}

fn read_gallery(path: &Path) -> Vec<Vec<i64>> {
    let text = std::fs::read_to_string(path).expect("galleria diagnostica mancante");
    let mut lines = text.lines();
    let header: Vec<usize> = lines
        .next()
        .expect("galleria vuota")
        .split_whitespace()
        .map(|value| value.parse().expect("header galleria non numerico"))
        .collect();
    assert_eq!(header.len(), 2);
    let (count, dimension) = (header[0], header[1]);
    let gallery: Vec<Vec<i64>> = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .map(|value| value.parse().expect("template non numerico"))
                .collect()
        })
        .collect();
    assert_eq!(gallery.len(), count);
    assert!(gallery.iter().all(|row| row.len() == dimension));
    gallery
}

fn decode_symbol(phase: u64, delta_log: u32) -> u64 {
    phase.wrapping_add(1u64 << (delta_log - 1)) >> delta_log
}

fn phase_error_delta(phase: u64, expected: u64, delta_log: u32) -> f64 {
    let target = expected.wrapping_mul(1u64 << delta_log);
    let signed = phase.wrapping_sub(target) as i64;
    signed as f64 / (1u64 << delta_log) as f64
}

fn report_symbols(stage: &str, phases: &[u64], expected: &[u64], delta_log: u32) -> usize {
    assert_eq!(phases.len(), expected.len(), "{stage}: lunghezze diverse");
    let mut mismatches = Vec::new();
    let mut max_abs_error = 0.0f64;
    for (index, (&phase, &wanted)) in phases.iter().zip(expected).enumerate() {
        let actual = decode_symbol(phase, delta_log);
        let error = phase_error_delta(phase, wanted, delta_log);
        max_abs_error = max_abs_error.max(error.abs());
        if actual != wanted && mismatches.len() < 8 {
            mismatches.push((index, wanted, actual, error));
        }
    }
    let mismatch_count = phases
        .iter()
        .zip(expected)
        .filter(|(phase, wanted)| decode_symbol(**phase, delta_log) != **wanted)
        .count();
    println!(
        "STAGE,{stage},items={},mismatches={mismatch_count},max_abs_phase_error_delta={max_abs_error:.6}",
        phases.len()
    );
    for (index, wanted, actual, error) in mismatches {
        println!(
            "MISMATCH,{stage},index={index},expected={wanted},actual={actual},phase_error_delta={error:.6}"
        );
    }
    mismatch_count
}

fn report_torus_noise(stage: &str, phases: &[u64], expected: &[u64], delta_log: u32) {
    assert_eq!(phases.len(), expected.len(), "{stage}: lunghezze diverse");
    let errors: Vec<f64> = phases
        .iter()
        .zip(expected)
        .map(|(&phase, &wanted)| {
            let target = wanted.wrapping_mul(1u64 << delta_log);
            let signed = phase.wrapping_sub(target) as i64;
            signed as f64 / 2f64.powi(64)
        })
        .collect();
    let count = errors.len() as f64;
    let mean = errors.iter().sum::<f64>() / count;
    let rms = (errors.iter().map(|error| error * error).sum::<f64>() / count).sqrt();
    let standard_deviation = (errors
        .iter()
        .map(|error| (error - mean) * (error - mean))
        .sum::<f64>()
        / count)
        .sqrt();
    let max_abs = errors
        .iter()
        .map(|error| error.abs())
        .fold(0.0f64, f64::max);
    println!(
        "NOISE,{stage},items={},mean_torus={mean:.9e},rms_torus={rms:.9e},stddev_torus={standard_deviation:.9e},max_abs_torus={max_abs:.9e}",
        errors.len()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "usage: exact_id_replay_trace <key-dir> <probe.ct> <probe.txt> <gallery.txt> <threshold>"
    );
    let key_dir = Path::new(&args[1]);
    let probe_ct_path = Path::new(&args[2]);
    let probe = read_vector(Path::new(&args[3]));
    let gallery = read_gallery(Path::new(&args[4]));
    let threshold: i64 = args[5].parse().expect("soglia non numerica");
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(gallery.iter().all(|template| template.len() == PROBE_DIM));

    let client_key: ClientKey = bincode::deserialize(
        &std::fs::read(key_dir.join("client.key")).expect("client.key mancante"),
    )
    .expect("client.key incompatibile");
    let server_key: ServerKey = bincode::deserialize(
        &std::fs::read(key_dir.join("server.key")).expect("server.key mancante"),
    )
    .expect("server.key incompatibile");
    let (glwe_secret_key, small_secret_key, _) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();

    let (header, body) = read_words(probe_ct_path);
    assert_eq!(header[0], PROBE_MAGIC);
    assert_eq!(header[3] as usize, glwe_secret_key.polynomial_size().0);
    assert_eq!(header[4] as usize, glwe_secret_key.glwe_dimension().0);
    assert_eq!(header[5] as usize, PROBE_DIM);
    assert_eq!(header[6] as u32, FULL_DELTA_LOG);
    assert_eq!(header[7] as u32, LOW_MOD16_DELTA_LOG);
    let packed_probe =
        GlweCiphertext::from_container(body, glwe_secret_key.polynomial_size(), modulus);

    let norm2: Vec<i64> = gallery
        .iter()
        .map(|template| template.iter().map(|value| value * value).sum())
        .collect();
    let templates: Vec<_> = gallery
        .iter()
        .zip(&norm2)
        .map(|(template, &norm2)| TemplateView {
            template,
            norm2,
            threshold,
        })
        .collect();
    let domain = cauchy_score_domain(&templates).expect("dominio galleria non valido");
    let scores: Vec<i64> = gallery
        .iter()
        .zip(&norm2)
        .map(|(template, &norm2)| {
            norm2
                - 2 * template
                    .iter()
                    .zip(&probe)
                    .map(|(gallery, query)| gallery * query)
                    .sum::<i64>()
        })
        .collect();
    let winner = scores
        .iter()
        .enumerate()
        .min_by_key(|(index, score)| (**score, *index))
        .map(|(index, _)| index)
        .unwrap();
    let translated: Vec<u64> = scores
        .iter()
        .map(|score| u64::try_from(score - domain.lower).unwrap())
        .collect();
    println!(
        "CONFIG,N={},domain_lower={},domain_upper={},winner={},min_score={},threshold={},expected_code={}",
        gallery.len(),
        domain.lower,
        domain.upper,
        winner,
        scores[winner],
        threshold,
        if scores[winner] <= threshold { winner + 1 } else { 0 }
    );

    let (output, trace) = private_argmin_with_trace(&server_key, &packed_probe, &templates, domain)
        .expect("replay private_argmin fallito");
    let decrypt_big = |ciphertext: &LweCiphertextOwned<u64>| {
        decrypt_lwe_ciphertext(&big_secret_key, ciphertext).0
    };
    let _decrypt_small = |ciphertext: &LweCiphertextOwned<u64>| {
        decrypt_lwe_ciphertext(&small_secret_key, ciphertext).0
    };
    let mut total_mismatches = 0usize;
    let mut diagnostic_correction_mismatches = 0usize;

    let phases: Vec<u64> = trace.score_full.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols("score_full", &phases, &translated, FULL_DELTA_LOG);
    let low_mask = (1u64 << LOW_NIBBLE_BITS) - 1;
    let expected_low: Vec<u64> = translated.iter().map(|value| value & low_mask).collect();
    let phases: Vec<u64> = trace.score_low_mod16.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols(
        "score_low_mod16",
        &phases,
        &expected_low,
        LOW_MOD16_DELTA_LOG,
    );

    let expected_high: Vec<u64> = translated
        .iter()
        .map(|value| value >> LOW_NIBBLE_BITS)
        .collect();
    let phases: Vec<u64> = trace.high_residuals.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols(
        "high_residual_after_low_subtraction",
        &phases,
        &expected_high,
        HIGH_DELTA_LOG,
    );
    report_torus_noise(
        "high_residual_after_low_subtraction",
        &phases,
        &expected_high,
        HIGH_DELTA_LOG,
    );

    for bit_index in 0..12usize {
        let expected_bits: Vec<u64> = translated
            .iter()
            .map(|value| (value >> bit_index) & 1)
            .collect();
        let phases: Vec<u64> = trace
            .full_small_bits_lsb_first
            .iter()
            .map(|bits| _decrypt_small(&bits[bit_index]))
            .collect();
        total_mismatches += report_symbols(
            &format!("full_small_bit_{bit_index}"),
            &phases,
            &expected_bits,
            63,
        );
        report_torus_noise(
            &format!("full_small_bit_{bit_index}"),
            &phases,
            &expected_bits,
            63,
        );
    }
    // Le correzioni sono termini analogici sottratti al residuo, non simboli decodificati in modo
    // autonomo dal circuito. Conserviamo il loro rounding come diagnostica di rumore; il gate
    // fatale resta sul residuo high risultante, sui bit estratti e su tutti gli stati downstream.
    for bit_index in 0..11usize {
        let expected_bits: Vec<u64> = translated
            .iter()
            .map(|value| (value >> bit_index) & 1)
            .collect();
        let phases: Vec<u64> = trace
            .full_corrections_lsb_first
            .iter()
            .map(|bits| decrypt_big(&bits[bit_index]))
            .collect();
        diagnostic_correction_mismatches += report_symbols(
            &format!("full_correction_bit_{bit_index}"),
            &phases,
            &expected_bits,
            FULL_DELTA_LOG + bit_index as u32,
        );
        report_torus_noise(
            &format!("full_correction_bit_{bit_index}"),
            &phases,
            &expected_bits,
            FULL_DELTA_LOG + bit_index as u32,
        );
    }
    for bit_index in 0..LOW_NIBBLE_BITS as usize {
        let expected_bits: Vec<u64> = translated
            .iter()
            .map(|value| (value >> bit_index) & 1)
            .collect();
        let phases: Vec<u64> = trace
            .low_small_bits_lsb_first
            .iter()
            .map(|bits| _decrypt_small(&bits[bit_index]))
            .collect();
        total_mismatches += report_symbols(
            &format!("low_small_bit_{bit_index}"),
            &phases,
            &expected_bits,
            63,
        );
        report_torus_noise(
            &format!("low_small_bit_{bit_index}"),
            &phases,
            &expected_bits,
            63,
        );
    }
    for bit_index in 0..LOW_NIBBLE_BITS as usize - 1 {
        let expected_bits: Vec<u64> = translated
            .iter()
            .map(|value| (value >> bit_index) & 1)
            .collect();
        let phases: Vec<u64> = trace
            .low_corrections_lsb_first
            .iter()
            .map(|bits| decrypt_big(&bits[bit_index]))
            .collect();
        diagnostic_correction_mismatches += report_symbols(
            &format!("low_correction_bit_{bit_index}"),
            &phases,
            &expected_bits,
            LOW_MOD16_DELTA_LOG + bit_index as u32,
        );
        report_torus_noise(
            &format!("low_correction_bit_{bit_index}"),
            &phases,
            &expected_bits,
            LOW_MOD16_DELTA_LOG + bit_index as u32,
        );
    }

    let mut expected_candidates = vec![1u64; gallery.len()];
    let mut expected_any_zero = Vec::new();
    for (level, (&bit_position, &bit_weight)) in trace
        .bit_positions_msb_first
        .iter()
        .zip(&trace.bit_weights_msb_first)
        .enumerate()
    {
        let expected_bits: Vec<u64> = translated
            .iter()
            .map(|value| ((value >> bit_position) & 1) * bit_weight)
            .collect();
        let phases: Vec<u64> = trace.bridged_bits_by_level[level]
            .iter()
            .map(&decrypt_big)
            .collect();
        total_mismatches += report_symbols(
            &format!("bridge_bit_{bit_position}"),
            &phases,
            &expected_bits,
            BOOL_DELTA_LOG,
        );

        let per_template_zero: Vec<u64> = translated
            .iter()
            .zip(&expected_candidates)
            .map(|(value, candidate)| candidate * u64::from(((value >> bit_position) & 1) == 0))
            .collect();
        let expected_zero = if trace.zero_candidates_by_level[level].len() == gallery.len() {
            per_template_zero.clone()
        } else {
            per_template_zero
                .chunks(2)
                .map(|pair| u64::from(pair.contains(&1)))
                .collect()
        };
        let phases: Vec<u64> = trace.zero_candidates_by_level[level]
            .iter()
            .map(&decrypt_big)
            .collect();
        total_mismatches += report_symbols(
            &format!("zero_candidates_bit_{bit_position}"),
            &phases,
            &expected_zero,
            BOOL_DELTA_LOG,
        );

        let any_zero = u64::from(per_template_zero.contains(&1));
        expected_any_zero.push(any_zero);
        let phase = decrypt_big(&trace.any_zero_by_level[level]);
        total_mismatches += report_symbols(
            &format!("any_zero_bit_{bit_position}"),
            &[phase],
            &[any_zero],
            BOOL_DELTA_LOG,
        );
        let prior_candidates = expected_candidates.clone();
        expected_candidates = prior_candidates
            .iter()
            .zip(&translated)
            .map(|(candidate, value)| {
                candidate * u64::from(((value >> bit_position) & 1) == 1 - any_zero)
            })
            .collect();
        let expected_candidate_symbols: Vec<u64> = if level % 2 == 0 {
            prior_candidates
                .iter()
                .zip(&per_template_zero)
                .map(|(candidate, zero)| {
                    0u64.wrapping_sub(*candidate)
                        .wrapping_sub(*zero)
                        .wrapping_add(any_zero)
                        & 31
                })
                .collect()
        } else {
            expected_candidates.clone()
        };
        let phases: Vec<u64> = trace.candidates_by_level[level]
            .iter()
            .map(&decrypt_big)
            .collect();
        total_mismatches += report_symbols(
            &format!("candidates_bit_{bit_position}"),
            &phases,
            &expected_candidate_symbols,
            BOOL_DELTA_LOG,
        );
    }

    let expected_group_flags: Vec<u64> = expected_candidates
        .chunks(3)
        .map(|group| u64::from(group.contains(&1)))
        .collect();
    let expected_group_prefixes: Vec<u64> = (0..expected_group_flags.len())
        .map(|index| u64::from(expected_group_flags[..index].contains(&1)))
        .collect();
    let expected_winners: Vec<u64> = expected_candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| candidate * u64::from(!expected_candidates[..index].contains(&1)))
        .collect();
    let phases: Vec<u64> = trace.group_prefixes.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols(
        "group_prefixes",
        &phases,
        &expected_group_prefixes,
        BOOL_DELTA_LOG,
    );
    let phases: Vec<u64> = trace.winners.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols("winners", &phases, &expected_winners, BOOL_DELTA_LOG);

    let selected_threshold = threshold.clamp(domain.lower, domain.upper) - domain.lower;
    let expected_threshold_bits: Vec<u64> = trace
        .bit_positions_msb_first
        .iter()
        .map(|position| (selected_threshold as u64 >> position) & 1)
        .collect();
    let phases: Vec<u64> = trace
        .selected_threshold_bits_msb_first
        .iter()
        .map(&decrypt_big)
        .collect();
    total_mismatches += report_symbols(
        "selected_threshold_bits",
        &phases,
        &expected_threshold_bits,
        BOOL_DELTA_LOG,
    );
    let below = u64::from(threshold < domain.lower);
    total_mismatches += report_symbols(
        "selected_below",
        &[decrypt_big(trace.selected_below.as_ref().unwrap())],
        &[below],
        BOOL_DELTA_LOG,
    );
    let mut comparison_state = 2u64;
    let mut expected_states = Vec::new();
    for (&any_zero, &threshold_bit) in expected_any_zero.iter().zip(&expected_threshold_bits) {
        if comparison_state == 2 {
            comparison_state = match (any_zero, threshold_bit) {
                (1, 1) => 0,
                (0, 0) => 4,
                _ => 2,
            };
        }
        expected_states.push(comparison_state);
    }
    let phases: Vec<u64> = trace
        .comparison_state_by_level
        .iter()
        .map(&decrypt_big)
        .collect();
    total_mismatches += report_symbols(
        "comparison_state",
        &phases,
        &expected_states,
        BOOL_DELTA_LOG,
    );
    let expected_accept = u64::from(scores[winner] <= threshold);
    total_mismatches += report_symbols(
        "accept_tag",
        &[decrypt_big(trace.accept_tag.as_ref().unwrap())],
        &[8 * expected_accept],
        BOOL_DELTA_LOG,
    );

    let output_positions: Vec<u32> = (0..usize::BITS)
        .filter(|position| (1..=gallery.len()).any(|code| ((code >> position) & 1) == 1))
        .collect();
    let winner_code = winner + 1;
    let expected_code = if expected_accept == 1 { winner_code } else { 0 };
    let expected_coded_digits: Vec<u64> = output_positions
        .iter()
        .map(|position| {
            if ((winner_code >> position) & 1) == 1 {
                1u64 << (position % 3)
            } else {
                0
            }
        })
        .collect();
    let coded_digit_phases: Vec<u64> = trace
        .coded_digits_lsb_first
        .iter()
        .map(&decrypt_big)
        .collect();
    total_mismatches += report_symbols(
        "coded_digits",
        &coded_digit_phases,
        &expected_coded_digits,
        BOOL_DELTA_LOG,
    );
    let expected_groups: Vec<u64> = output_positions
        .chunks(3)
        .map(|positions| {
            let mask = 7usize << positions[0];
            (expected_code & mask) as u64
        })
        .collect();
    let phases: Vec<u64> = trace.code_groups.iter().map(&decrypt_big).collect();
    total_mismatches += report_symbols("code_groups", &phases, &expected_groups, CODE_DELTA_LOG);
    total_mismatches += report_symbols(
        "final_code",
        &[decrypt_big(&output.code)],
        &[expected_code as u64],
        CODE_DELTA_LOG,
    );
    println!(
        "SUMMARY,total_checkpoint_mismatches={total_mismatches},diagnostic_correction_rounding_mismatches={diagnostic_correction_mismatches},pbs={},final_phase={}",
        output.metrics.total_pbs_count,
        decrypt_big(&output.code)
    );
    assert_eq!(
        total_mismatches, 0,
        "il replay contiene checkpoint divergenti"
    );
}
