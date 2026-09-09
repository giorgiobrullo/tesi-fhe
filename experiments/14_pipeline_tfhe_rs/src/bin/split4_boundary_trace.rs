//! Validazione FHE mirata dei confini dell'estrattore split4 con le uscite fuse A29.
//!
//! Nel baseline il probe e il solo template sono nulli, quindi il punteggio reale e' zero.
//! Scenari aggiuntivi usano probe e template validi non nulli per conservare il rumore del canale
//! score. In entrambi i casi il limite inferiore del dominio viene scelto come `score-x`, cosi' il
//! core di produzione vede il punteggio tradotto `x`. Questo attraversa residui e confini binari
//! senza introdurre un secondo estrattore diagnostico che potrebbe divergere dal core reale.

use pipeline_tfhe_rs::{
    expected_pbs_count, private_argmin_with_trace, ScoreDomain, TemplateView, BOOL_DELTA_LOG,
    CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM,
    PROBE_NORM2_MAX,
};
use std::collections::BTreeSet;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const SCORE_BITS: usize = 12;
const CORRECTION_BITS: usize = SCORE_BITS - 1;
const EXPECTED_PBS: u64 = 48;

struct BoundaryScene {
    name: &'static str,
    template: Vec<i64>,
    probe: Vec<i64>,
    targets: BTreeSet<u64>,
}

fn decode_symbol(phase: u64, delta_log: u32) -> u64 {
    phase.wrapping_add(1u64 << (delta_log - 1)) >> delta_log
}

fn phase_error_delta(phase: u64, expected: u64, delta_log: u32) -> f64 {
    let target = expected.wrapping_mul(1u64 << delta_log);
    let signed = phase.wrapping_sub(target) as i64;
    signed as f64 / (1u64 << delta_log) as f64
}

fn pearson_correlation(pairs: &[(f64, f64)]) -> Option<f64> {
    if pairs.len() < 2 {
        return None;
    }
    let n = pairs.len() as f64;
    let sum_x: f64 = pairs.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = pairs.iter().map(|(_, y)| y).sum();
    let sum_xx: f64 = pairs.iter().map(|(x, _)| x * x).sum();
    let sum_yy: f64 = pairs.iter().map(|(_, y)| y * y).sum();
    let sum_xy: f64 = pairs.iter().map(|(x, y)| x * y).sum();
    let covariance = n * sum_xy - sum_x * sum_y;
    let variance_product = (n * sum_xx - sum_x * sum_x) * (n * sum_yy - sum_y * sum_y);
    if variance_product <= f64::EPSILON {
        None
    } else {
        Some((covariance / variance_product.sqrt()).clamp(-1.0, 1.0))
    }
}

fn check_symbol(
    scene: &str,
    x: u64,
    stage: &str,
    phase: u64,
    expected: u64,
    delta_log: u32,
) -> (usize, f64) {
    let actual = decode_symbol(phase, delta_log);
    let error = phase_error_delta(phase, expected, delta_log);
    if actual == expected {
        (0, error.abs())
    } else {
        eprintln!(
            "MISMATCH,scene={scene},x={x},stage={stage},expected={expected},actual={actual},phase_error_delta={error:.6}"
        );
        (1, error.abs())
    }
}

fn boundary_targets() -> BTreeSet<u64> {
    let mut targets: BTreeSet<u64> = (0..16).collect();
    for bit_index in 4..=11 {
        let boundary = 1u64 << bit_index;
        targets.extend([boundary - 1, boundary, boundary + 1]);
    }
    targets.insert((1u64 << SCORE_BITS) - 1);
    targets
}

fn sparse_vector(three_count: usize, tail: &[i64]) -> Vec<i64> {
    assert!(three_count + tail.len() <= PROBE_DIM);
    let mut vector = vec![0i64; PROBE_DIM];
    vector[..three_count].fill(3);
    vector[three_count..three_count + tail.len()].copy_from_slice(tail);
    vector
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

fn boundary_scenes() -> Vec<BoundaryScene> {
    let all_targets = boundary_targets();
    let norm_1018 = sparse_vector(113, &[1]);
    let norm_1012 = sparse_vector(112, &[2]);
    let norm_1002 = sparse_vector(111, &[1, 1, 1]);
    let unit_template = sparse_vector(0, &[1]);
    let unit_targets = all_targets
        .iter()
        .copied()
        // A width-4096 domain centered this way covers the unit template's full Cauchy
        // interval only up to x=4031. The x=4095 endpoint remains covered by the zero scene.
        .filter(|x| (64..=4031).contains(x))
        .collect();
    vec![
        BoundaryScene {
            name: "zero_baseline",
            template: vec![0; PROBE_DIM],
            probe: vec![0; PROBE_DIM],
            targets: all_targets,
        },
        BoundaryScene {
            name: "noisy_boundary_16",
            template: norm_1018.clone(),
            probe: norm_1018,
            targets: [15, 16, 17].into_iter().collect(),
        },
        BoundaryScene {
            name: "noisy_boundary_32",
            template: norm_1012.clone(),
            probe: norm_1012,
            targets: [31, 32, 33].into_iter().collect(),
        },
        BoundaryScene {
            name: "noisy_boundary_64",
            template: norm_1002.clone(),
            probe: norm_1002,
            targets: [63, 64, 65].into_iter().collect(),
        },
        BoundaryScene {
            name: "noisy_high_boundaries",
            template: unit_template,
            probe: vec![0; PROBE_DIM],
            targets: unit_targets,
        },
    ]
}

fn encode_probe(probe: &[i64], polynomial_size: usize) -> Vec<u64> {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM <= polynomial_size);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= PROBE_NORM2_MAX);
    let mut plaintext = vec![0u64; polynomial_size];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOW_MOD16_DELTA_LOG);
    }
    plaintext
}

fn main() {
    assert_eq!(
        expected_pbs_count(1),
        Some(EXPECTED_PBS),
        "il modello di costo N=1 non coincide con il test"
    );
    let scenes = boundary_scenes();
    let unique_targets = boundary_targets().len();
    let total_cases: usize = scenes.iter().map(|scene| scene.targets.len()).sum();
    println!(
        "CONFIG,scenes={},unique_targets={unique_targets},cases={total_cases},score_bits={SCORE_BITS},expected_pbs={EXPECTED_PBS}",
        scenes.len()
    );

    let key_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!(
        "KEY,generation_s={:.6},polynomial_size={},secret_material_persisted=false",
        key_started.elapsed().as_secs_f64(),
        polynomial_size.0
    );

    let mut total_mismatches = 0usize;
    let mut completed_cases = 0usize;
    let mut fused_error_pairs = Vec::with_capacity(total_cases * 4);
    let mut fused_error_pairs_by_bit: [Vec<(f64, f64)>; 4] =
        std::array::from_fn(|_| Vec::with_capacity(total_cases));
    let validation_started = Instant::now();

    for scene in &scenes {
        let template_norm2 = squared_norm(&scene.template);
        let probe_norm2 = squared_norm(&scene.probe);
        let score = clear_score(&scene.template, &scene.probe);
        assert!(scene.template.iter().all(|value| (-3..=3).contains(value)));
        assert!(probe_norm2 <= PROBE_NORM2_MAX);
        let mut packed_probe = GlweCiphertextOwned::new(
            0u64,
            glwe_secret_key.glwe_dimension().to_glwe_size(),
            polynomial_size,
            modulus,
        );
        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut packed_probe,
            &PlaintextList::from_container(encode_probe(&scene.probe, polynomial_size.0)),
            client_params.glwe_noise_distribution(),
            &mut generator,
        );
        println!(
            "SCENE,name={},targets={},score={score},template_norm2={template_norm2},probe_norm2={probe_norm2}",
            scene.name,
            scene.targets.len()
        );
        let template = TemplateView {
            template: &scene.template,
            norm2: template_norm2,
            threshold: score,
        };

        for x in scene.targets.iter().copied() {
            let domain = ScoreDomain {
                lower: score - x as i64,
                upper: score - x as i64 + (1i64 << SCORE_BITS) - 1,
            };
            let run_started = Instant::now();
            let (output, trace) =
                private_argmin_with_trace(&server_key, &packed_probe, &[template], domain)
                    .expect("private_argmin_with_trace ha rifiutato il caso di confine");
            let decrypt_big = |ciphertext: &LweCiphertextOwned<u64>| {
                decrypt_lwe_ciphertext(&big_secret_key, ciphertext).0
            };
            let decrypt_small = |ciphertext: &LweCiphertextOwned<u64>| {
                decrypt_lwe_ciphertext(&small_secret_key, ciphertext).0
            };

            assert_eq!(trace.score_full.len(), 1);
            assert_eq!(trace.score_low_mod16.len(), 1);
            assert_eq!(trace.high_residuals.len(), 1);
            assert_eq!(trace.full_small_bits_lsb_first.len(), 1);
            assert_eq!(trace.full_small_bits_lsb_first[0].len(), SCORE_BITS);
            assert_eq!(trace.full_corrections_lsb_first.len(), 1);
            assert_eq!(trace.full_corrections_lsb_first[0].len(), CORRECTION_BITS);
            assert_eq!(trace.low_small_bits_lsb_first.len(), 1);
            assert_eq!(trace.low_small_bits_lsb_first[0].len(), 4);
            assert_eq!(trace.low_corrections_lsb_first.len(), 1);
            assert_eq!(trace.low_corrections_lsb_first[0].len(), 3);
            assert_eq!(trace.fused_boolean_bits_3_to_6.len(), 1);
            assert_eq!(trace.fused_boolean_bits_3_to_6[0].len(), 4);
            assert_eq!(trace.reused_bit7.len(), 1);

            let mut mismatches = 0usize;
            let mut small_mismatches = 0usize;
            let mut correction_mismatches = 0usize;
            let mut fused_boolean_mismatches = 0usize;
            let mut reused_bit7_mismatches = 0usize;
            let mut max_score_error = 0.0f64;
            let mut max_small_error = 0.0f64;
            let mut max_correction_error = 0.0f64;
            let mut max_fused_boolean_error = 0.0f64;
            let mut max_fused_pair_error_gap = 0.0f64;
            let mut fused_correction_errors = [0.0f64; 4];
            let mut fused_boolean_errors = [0.0f64; 4];
            let (count, error) = check_symbol(
                scene.name,
                x,
                "score_full",
                decrypt_big(&trace.score_full[0]),
                x,
                FULL_DELTA_LOG,
            );
            mismatches += count;
            max_score_error = max_score_error.max(error);
            let (count, error) = check_symbol(
                scene.name,
                x,
                "score_low_mod16",
                decrypt_big(&trace.score_low_mod16[0]),
                x & 15,
                LOW_MOD16_DELTA_LOG,
            );
            mismatches += count;
            max_score_error = max_score_error.max(error);
            let (count, error) = check_symbol(
                scene.name,
                x,
                "high_residual",
                decrypt_big(&trace.high_residuals[0]),
                x >> 4,
                FULL_DELTA_LOG + 4,
            );
            mismatches += count;
            max_score_error = max_score_error.max(error);

            for bit_index in 0..SCORE_BITS {
                let expected = (x >> bit_index) & 1;
                let (count, error) = check_symbol(
                    scene.name,
                    x,
                    &format!("full_small_bit_{bit_index}"),
                    decrypt_small(&trace.full_small_bits_lsb_first[0][bit_index]),
                    expected,
                    63,
                );
                mismatches += count;
                small_mismatches += count;
                max_small_error = max_small_error.max(error);
            }
            for bit_index in 0..CORRECTION_BITS {
                let expected = (x >> bit_index) & 1;
                let (count, error) = check_symbol(
                    scene.name,
                    x,
                    &format!("full_correction_bit_{bit_index}"),
                    decrypt_big(&trace.full_corrections_lsb_first[0][bit_index]),
                    expected,
                    FULL_DELTA_LOG + bit_index as u32,
                );
                mismatches += count;
                correction_mismatches += count;
                max_correction_error = max_correction_error.max(error);
            }

            for bit_index in 0..4usize {
                let expected = (x >> bit_index) & 1;
                let (count, _) = check_symbol(
                    scene.name,
                    x,
                    &format!("low_small_bit_{bit_index}"),
                    decrypt_small(&trace.low_small_bits_lsb_first[0][bit_index]),
                    expected,
                    63,
                );
                mismatches += count;
            }
            for bit_index in 0..3usize {
                let expected = (x >> bit_index) & 1;
                let (count, _) = check_symbol(
                    scene.name,
                    x,
                    &format!("low_correction_bit_{bit_index}"),
                    decrypt_big(&trace.low_corrections_lsb_first[0][bit_index]),
                    expected,
                    LOW_MOD16_DELTA_LOG + bit_index as u32,
                );
                mismatches += count;
            }

            // I bit 3..=6 sono le seconde estrazioni LWE delle stesse blind rotation che
            // producono le correzioni. Verifichiamo sia il messaggio Booleano sia la coppia di
            // errori di fase: la correlazione aggregata e' diagnostica, non un criterio di pass.
            for (offset, fused_bit) in trace.fused_boolean_bits_3_to_6[0].iter().enumerate() {
                let bit_index = offset + 3;
                let expected = (x >> bit_index) & 1;
                let correction_phase = decrypt_big(&trace.full_corrections_lsb_first[0][bit_index]);
                let fused_phase = decrypt_big(fused_bit);
                let (count, error) = check_symbol(
                    scene.name,
                    x,
                    &format!("fused_boolean_bit_{bit_index}"),
                    fused_phase,
                    expected,
                    BOOL_DELTA_LOG,
                );
                mismatches += count;
                fused_boolean_mismatches += count;
                max_fused_boolean_error = max_fused_boolean_error.max(error);

                let correction_error = phase_error_delta(
                    correction_phase,
                    expected,
                    FULL_DELTA_LOG + bit_index as u32,
                );
                let fused_error = phase_error_delta(fused_phase, expected, BOOL_DELTA_LOG);
                fused_correction_errors[offset] = correction_error;
                fused_boolean_errors[offset] = fused_error;
                max_fused_pair_error_gap =
                    max_fused_pair_error_gap.max((correction_error - fused_error).abs());
                fused_error_pairs.push((correction_error, fused_error));
                fused_error_pairs_by_bit[offset].push((correction_error, fused_error));
            }

            // Il bit 7 non richiede una nuova estrazione: la sua correzione nasce gia' alla
            // scala Booleana. Oltre al plaintext, imponiamo quindi l'identita' del ciphertext.
            let expected_bit7 = (x >> 7) & 1;
            let reused_bit7_phase = decrypt_big(&trace.reused_bit7[0]);
            let (count, reused_bit7_error) = check_symbol(
                scene.name,
                x,
                "reused_bit_7",
                reused_bit7_phase,
                expected_bit7,
                BOOL_DELTA_LOG,
            );
            mismatches += count;
            reused_bit7_mismatches += count;
            let bit7_ciphertext_identical =
                trace.reused_bit7[0].as_ref() == trace.full_corrections_lsb_first[0][7].as_ref();
            if !bit7_ciphertext_identical {
                eprintln!(
                    "MISMATCH,scene={},x={x},stage=reused_bit_7_ciphertext_identity",
                    scene.name
                );
                mismatches += 1;
                reused_bit7_mismatches += 1;
            }

            let paired_errors = (0..4)
                .map(|offset| {
                    format!(
                        "{}:{:.6}/{:.6}",
                        offset + 3,
                        fused_correction_errors[offset],
                        fused_boolean_errors[offset]
                    )
                })
                .collect::<Vec<_>>()
                .join("|");
            println!(
                "FUSED,scene={},x={x},paired_phase_errors_delta={paired_errors},max_pair_error_gap_delta={max_fused_pair_error_gap:.6},abs_bit7_phase_error_delta={:.6},bit7_ciphertext_identical={bit7_ciphertext_identical}",
                scene.name, reused_bit7_error
            );

            let final_phase = decrypt_big(&output.code);
            let (count, _) =
                check_symbol(scene.name, x, "final_code", final_phase, 1, CODE_DELTA_LOG);
            mismatches += count;
            let trace_final = trace
                .final_code
                .as_ref()
                .expect("checkpoint final_code assente");
            let (count, _) = check_symbol(
                scene.name,
                x,
                "trace_final_code",
                decrypt_big(trace_final),
                1,
                CODE_DELTA_LOG,
            );
            mismatches += count;
            if output.metrics.total_pbs_count != EXPECTED_PBS {
                eprintln!(
                    "MISMATCH,scene={},x={x},stage=pbs_count,expected={EXPECTED_PBS},actual={}",
                    scene.name, output.metrics.total_pbs_count
                );
                mismatches += 1;
            }

            total_mismatches += mismatches;
            completed_cases += 1;
            println!(
                "RESULT,scene={},x={x},residue={},small_mismatches={small_mismatches},correction_mismatches={correction_mismatches},fused_boolean_mismatches={fused_boolean_mismatches},reused_bit7_mismatches={reused_bit7_mismatches},total_mismatches={mismatches},max_score_phase_error_delta={max_score_error:.6},max_small_phase_error_delta={max_small_error:.6},max_correction_phase_error_delta={max_correction_error:.6},max_fused_boolean_phase_error_delta={max_fused_boolean_error:.6},max_fused_pair_error_gap_delta={max_fused_pair_error_gap:.6},abs_reused_bit7_phase_error_delta={:.6},code={},pbs={},seconds={:.6},correct={}",
                scene.name,
                x & 15,
                reused_bit7_error,
                decode_symbol(final_phase, CODE_DELTA_LOG),
                output.metrics.total_pbs_count,
                run_started.elapsed().as_secs_f64(),
                mismatches == 0
            );
        }
    }

    let fused_pair_count = fused_error_pairs.len();
    assert_eq!(
        fused_pair_count,
        completed_cases * 4,
        "ogni caso deve produrre quattro coppie fuse"
    );
    assert!(
        fused_error_pairs_by_bit
            .iter()
            .all(|pairs| pairs.len() == completed_cases),
        "ogni bit fuso deve contribuire una coppia per caso"
    );
    let mean_abs_fused_correction_error = fused_error_pairs
        .iter()
        .map(|(correction, _)| correction.abs())
        .sum::<f64>()
        / fused_pair_count as f64;
    let mean_abs_fused_boolean_error = fused_error_pairs
        .iter()
        .map(|(_, boolean)| boolean.abs())
        .sum::<f64>()
        / fused_pair_count as f64;
    let fused_error_pearson = pearson_correlation(&fused_error_pairs)
        .map(|value| format!("{value:.6}"))
        .unwrap_or_else(|| "undefined".to_owned());
    let fused_error_pearson_by_bit = fused_error_pairs_by_bit
        .iter()
        .enumerate()
        .map(|(offset, pairs)| {
            let value = pearson_correlation(pairs)
                .map(|correlation| format!("{correlation:.6}"))
                .unwrap_or_else(|| "undefined".to_owned());
            format!("{}:{value}", offset + 3)
        })
        .collect::<Vec<_>>()
        .join("|");
    println!(
        "SUMMARY,scenes={},unique_targets={unique_targets},cases={completed_cases},fused_pair_count={fused_pair_count},mean_abs_fused_correction_phase_error_delta={mean_abs_fused_correction_error:.6},mean_abs_fused_boolean_phase_error_delta={mean_abs_fused_boolean_error:.6},fused_correction_boolean_error_pearson={fused_error_pearson},fused_error_pearson_by_bit={fused_error_pearson_by_bit},total_mismatches={total_mismatches},validation_s={:.6},correct={}",
        scenes.len(),
        validation_started.elapsed().as_secs_f64(),
        total_mismatches == 0
    );
    assert_eq!(
        total_mismatches, 0,
        "la validazione split4 contiene checkpoint divergenti"
    );
}
