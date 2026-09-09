//! Argmin sperimentale: torneo con indice cifrato e comparatore periodic-fold.
//!
//! Questa variante non modifica `argmin_torneo.rs` o `varco_demo.rs`. Mantiene il candidato
//! `(score, indice)` in un GLWE, sostituisce sia il segno a ogni nodo sia la soglia finale con il
//! comparatore periodic-fold a tre PBS e usa il circuit bootstrapping soltanto per trasformare il
//! bit di selezione in una GGSW per il CMUX. L'output applicativo e' `(indice, match/no-match)`;
//! la distanza non viene decifrata o stampata.
//!
//! Il binario e' un harness costoso e non parte senza `--run`:
//! `cargo run --release --bin argmin_torneo_periodic_fold -- --run --keys 2 --real-probes 1`

use dyn_stack::{GlobalPodBuffer, PodStack, StackReq};
use rayon::prelude::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{cmux, cmux_scratch, FourierGgswCiphertext};
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS as WOPBS_PARAMS;

const PERIODS: [u64; 2] = [32, 512];
const LOG_INDEX_DELTA: u32 = 56;
const MATCH_COEFFICIENT_FROM_END: usize = 2;
const MIN_LOG_DELTA: u32 = 50;
const MAX_LOG_DELTA: u32 = 54;
const SCORE_DIM: usize = 512;

#[derive(Clone)]
struct Scene {
    dim: usize,
    gallery: Vec<Vec<i64>>,
    squared_norms: Vec<i64>,
    probes: Vec<Vec<i64>>,
    threshold: i64,
}

#[derive(Clone)]
struct SyntheticCase {
    name: &'static str,
    scores: Vec<i64>,
    threshold: i64,
}

struct BenchmarkCase {
    source: &'static str,
    name: String,
    scores: Vec<i64>,
    threshold: i64,
    bound: i64,
    probe_index: Option<usize>,
}

struct Observation {
    key_run: usize,
    source: &'static str,
    name: String,
    n: usize,
    bound: i64,
    log_delta: u32,
    expected_index: usize,
    actual_index: usize,
    expected_match: bool,
    actual_match: bool,
    score_seconds: f64,
    predicate_seconds: f64,
    tournament_seconds: f64,
    threshold_seconds: f64,
    selected_score_error_abs: Option<f64>,
}

impl Observation {
    fn total_seconds(&self) -> f64 {
        self.score_seconds
            + self.predicate_seconds
            + self.tournament_seconds
            + self.threshold_seconds
    }

    fn correct(&self) -> bool {
        self.expected_index == self.actual_index && self.expected_match == self.actual_match
    }
}

fn load_scene(path: &str) -> Scene {
    let text = std::fs::read_to_string(path).expect("manca la scena (esporta_dati.py)");
    let mut rows = text.lines();
    let header: Vec<i64> = rows
        .next()
        .expect("scena vuota")
        .split_whitespace()
        .map(|value| value.parse().expect("header della scena non numerico"))
        .collect();
    assert!(header.len() >= 4, "header della scena incompleto");
    let (dim, gallery_size, probe_count, threshold) = (
        header[0] as usize,
        header[1] as usize,
        header[2] as usize,
        header[3],
    );
    let gallery: Vec<Vec<i64>> = (0..gallery_size)
        .map(|_| {
            rows.next()
                .expect("galleria troncata")
                .split_whitespace()
                .map(|value| value.parse().expect("template non numerico"))
                .collect()
        })
        .collect();
    let probes = (0..probe_count)
        .map(|_| {
            let row: Vec<i64> = rows
                .next()
                .expect("probe troncati")
                .split_whitespace()
                .map(|value| value.parse().expect("probe non numerico"))
                .collect();
            assert_eq!(row.len(), dim + 1, "riga probe di dimensione errata");
            row[1..].to_vec()
        })
        .collect();
    assert!(gallery.iter().all(|template| template.len() == dim));
    let squared_norms = gallery
        .iter()
        .map(|template| template.iter().map(|value| value * value).sum())
        .collect();
    Scene {
        dim,
        gallery,
        squared_norms,
        probes,
        threshold,
    }
}

fn clear_scores(scene: &Scene, n: usize, probe: &[i64]) -> Vec<i64> {
    (0..n)
        .map(|index| {
            scene.squared_norms[index]
                - 2 * scene.gallery[index]
                    .iter()
                    .zip(probe)
                    .map(|(gallery, query)| gallery * query)
                    .sum::<i64>()
        })
        .collect()
}

fn expected_result(scores: &[i64], threshold: i64) -> (usize, bool) {
    let mut best = 0usize;
    for index in 1..scores.len() {
        if scores[index] < scores[best] {
            best = index;
        }
    }
    (best, scores[best] <= threshold)
}

fn score_radius(log_delta: u32) -> i64 {
    ((1u64 << (63 - log_delta)) - 1) as i64
}

fn choose_log_delta(bound: i64) -> u32 {
    assert!(bound >= 0, "il bound deve essere non negativo");
    (MIN_LOG_DELTA..=MAX_LOG_DELTA)
        .rev()
        .find(|&log_delta| bound <= score_radius(log_delta))
        .unwrap_or_else(|| {
            panic!(
                "bound {bound} oltre il dominio periodic-fold massimo {}",
                score_radius(MIN_LOG_DELTA)
            )
        })
}

fn exact_bound(scores: &[i64], threshold: i64) -> i64 {
    let threshold_bound = scores
        .iter()
        .map(|score| (score - threshold).abs())
        .max()
        .unwrap_or(0);
    let min_score = *scores.iter().min().unwrap();
    let max_score = *scores.iter().max().unwrap();
    threshold_bound.max(max_score - min_score)
}

fn analytic_scene_bound(scene: &Scene, n: usize, q_probe: i64) -> i64 {
    let threshold_bound = (0..n)
        .map(|index| {
            let l1: i64 = scene.gallery[index].iter().map(|value| value.abs()).sum();
            2 * q_probe * l1 + scene.squared_norms[index] + scene.threshold.abs()
        })
        .max()
        .unwrap_or(0);
    let pairwise_bound = (0..n)
        .into_par_iter()
        .map(|left| {
            ((left + 1)..n)
                .map(|right| {
                    let l1_difference: i64 = scene.gallery[left]
                        .iter()
                        .zip(&scene.gallery[right])
                        .map(|(a, b)| (a - b).abs())
                        .sum();
                    (scene.squared_norms[left] - scene.squared_norms[right]).abs()
                        + 2 * q_probe * l1_difference
                })
                .max()
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0);
    threshold_bound.max(pairwise_bound)
}

#[cfg(test)]
fn folded_clear_doubled(difference: i64) -> i64 {
    let mut value = 2 * difference - 1;
    for period in PERIODS {
        let period = period as i64;
        let residue = value.rem_euclid(2 * period);
        value += if residue < period {
            period / 2
        } else {
            -(period / 2)
        };
    }
    value
}

fn synthetic_cases(n: usize) -> Vec<SyntheticCase> {
    let mut boundary_accept = (0..n).map(|index| 64 + index as i64).collect::<Vec<_>>();
    boundary_accept[0] = 0;
    boundary_accept[1] = 1;

    let mut boundary_reject = (0..n)
        .map(|index| 128 + (n - index) as i64)
        .collect::<Vec<_>>();
    boundary_reject[n - 1] = 1;
    boundary_reject[n - 2] = 2;

    let mut tie_across_mid = (0..n).map(|index| 300 + index as i64).collect::<Vec<_>>();
    tie_across_mid[n / 2 - 1] = 0;
    tie_across_mid[n / 2] = 0;

    let mut fold_boundaries = (0..n).map(|index| 700 + index as i64).collect::<Vec<_>>();
    let special = [
        -257, -256, -255, -17, -16, -15, -1, 0, 1, 15, 16, 17, 255, 256, 257,
    ];
    fold_boundaries[..special.len()].copy_from_slice(&special);

    let all_equal = vec![0; n];

    let mut near_reject_internal = (0..n).map(|index| 500 + index as i64).collect::<Vec<_>>();
    near_reject_internal[n / 2] = 1;
    near_reject_internal[n / 2 + 1] = 2;

    let mut domain_edges = vec![4095; n];
    domain_edges[n - 1] = -4095;

    vec![
        SyntheticCase {
            name: "boundary_accept_first",
            scores: boundary_accept,
            threshold: 0,
        },
        SyntheticCase {
            name: "boundary_reject_last",
            scores: boundary_reject,
            threshold: 0,
        },
        SyntheticCase {
            name: "tie_across_mid",
            scores: tie_across_mid,
            threshold: 0,
        },
        SyntheticCase {
            name: "fold_discontinuities",
            scores: fold_boundaries,
            threshold: -257,
        },
        SyntheticCase {
            name: "all_equal_at_threshold",
            scores: all_equal,
            threshold: 0,
        },
        SyntheticCase {
            name: "near_reject_internal",
            scores: near_reject_internal,
            threshold: 0,
        },
        SyntheticCase {
            name: "domain_edges_last",
            scores: domain_edges,
            threshold: -4095,
        },
    ]
}

fn percentile(values: &[f64], quantile: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() as f64 * quantile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|arg| arg == "--run") {
        eprintln!(
            "usage: argmin_torneo_periodic_fold --run [--keys N] [--real-probes N] \
             [--q-probe Q] [--scene FILE] [--cbs-base B] [--cbs-levels L]"
        );
        return;
    }
    let key_runs: usize = args
        .iter()
        .position(|arg| arg == "--keys")
        .map(|index| args[index + 1].parse().unwrap())
        .unwrap_or(2);
    let real_probe_count: usize = args
        .iter()
        .position(|arg| arg == "--real-probes")
        .map(|index| args[index + 1].parse().unwrap())
        .unwrap_or(1);
    let q_probe: i64 = args
        .iter()
        .position(|arg| arg == "--q-probe")
        .map(|index| args[index + 1].parse().unwrap())
        .unwrap_or(3);
    let cbs_base: usize = args
        .iter()
        .position(|arg| arg == "--cbs-base")
        .map(|index| args[index + 1].parse().unwrap())
        .unwrap_or(WOPBS_PARAMS.cbs_base_log.0);
    let cbs_level_count: usize = args
        .iter()
        .position(|arg| arg == "--cbs-levels")
        .map(|index| args[index + 1].parse().unwrap())
        .unwrap_or(WOPBS_PARAMS.cbs_level.0);
    let precompute_match = args.iter().any(|arg| arg == "--precompute-match");
    let scene_path = args
        .iter()
        .position(|arg| arg == "--scene")
        .map(|index| args[index + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    assert!(key_runs > 0, "--keys deve essere positivo");
    assert!(real_probe_count > 0, "--real-probes deve essere positivo");
    assert!(q_probe >= 0, "--q-probe deve essere non negativo");
    assert!(cbs_base > 0, "--cbs-base deve essere positivo");
    assert!(cbs_level_count > 0, "--cbs-levels deve essere positivo");

    let scene = load_scene(&scene_path);
    assert_eq!(
        scene.dim, SCORE_DIM,
        "la scena deve avere embedding a 512 dimensioni"
    );
    assert!(
        scene.gallery.len() >= 128,
        "la scena deve contenere almeno 128 template"
    );
    assert!(
        scene.probes.len() >= real_probe_count,
        "la scena non contiene abbastanza probe"
    );
    let observed_q = scene
        .probes
        .iter()
        .take(real_probe_count)
        .flat_map(|probe| probe.iter())
        .map(|value| value.abs())
        .max()
        .unwrap_or(0);
    assert!(
        observed_q <= q_probe,
        "la scena contiene |probe|={observed_q}, oltre q_probe={q_probe}"
    );

    println!(
        "CONFIG,keys={key_runs},real_probes={real_probe_count},q_probe={q_probe},params=LEGACY_WOPBS_MESSAGE_2_CARRY_2,periods=32|512,cbs=2^{}x{},pfpksk=2^{}x{},predicate={},security=legacy_wopbs_documented_123_to_128_bits",
        cbs_base,
        cbs_level_count,
        WOPBS_PARAMS.pfks_base_log.0,
        WOPBS_PARAMS.pfks_level.0,
        if precompute_match {
            "precomputed_selected"
        } else {
            "final_fold"
        },
    );
    println!(
        "RESULT,key,source,case,N,bound,log_delta,expected_index,actual_index,expected_match,actual_match,score_s,predicate_s,tournament_s,threshold_s,total_s,correct,under_5s,under_10s"
    );

    let mut observations = Vec::new();
    for key_run in 1..=key_runs {
        let key_started = Instant::now();
        let polynomial_size = WOPBS_PARAMS.polynomial_size;
        let glwe_size = WOPBS_PARAMS.glwe_dimension.to_glwe_size();
        let modulus = WOPBS_PARAMS.ciphertext_modulus;
        let fft_owned = Fft::new(polynomial_size);
        let fft = fft_owned.as_view();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            WOPBS_PARAMS.glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let small_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            WOPBS_PARAMS.lwe_dimension,
            &mut secret_generator,
        );
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let bootstrap_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_secret_key,
            &glwe_secret_key,
            WOPBS_PARAMS.pbs_base_log,
            WOPBS_PARAMS.pbs_level,
            WOPBS_PARAMS.glwe_noise_distribution,
            modulus,
            &mut generator,
        );
        let mut fourier_bootstrap_key = FourierLweBootstrapKey::new(
            bootstrap_key.input_lwe_dimension(),
            bootstrap_key.glwe_size(),
            bootstrap_key.polynomial_size(),
            bootstrap_key.decomposition_base_log(),
            bootstrap_key.decomposition_level_count(),
        );
        fourier_bootstrap_key
            .as_mut_view()
            .par_fill_with_forward_fourier(bootstrap_key.as_view(), fft);
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &big_secret_key,
            &small_secret_key,
            WOPBS_PARAMS.ks_base_log,
            WOPBS_PARAMS.ks_level,
            WOPBS_PARAMS.lwe_noise_distribution,
            modulus,
            &mut generator,
        );
        let big_size = glwe_secret_key
            .glwe_dimension()
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();
        let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
        let pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &big_secret_key,
            &glwe_secret_key,
            WOPBS_PARAMS.pfks_base_log,
            WOPBS_PARAMS.pfks_level,
            WOPBS_PARAMS.pfks_noise_distribution,
            modulus,
            &mut generator,
        );
        println!(
            "KEY,key={key_run},generation_s={:.3},poly={},small_n={},pfpksk_bytes={}",
            key_started.elapsed().as_secs_f64(),
            polynomial_size.0,
            small_size.to_lwe_dimension().0,
            std::mem::size_of_val(pfpksk.as_ref())
        );

        let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::new(
                (1u64 << 62).wrapping_neg(),
                PlaintextCount(polynomial_size.0),
            ),
            modulus,
        );
        let index_delta = 1u64 << LOG_INDEX_DELTA;
        let cbs_base_log = DecompositionBaseLog(cbs_base);
        let cbs_levels = DecompositionLevelCount(cbs_level_count);

        for &n in &[64usize, 128] {
            let mut cases: Vec<BenchmarkCase> = synthetic_cases(n)
                .into_iter()
                .map(|case| BenchmarkCase {
                    source: "synthetic",
                    name: case.name.to_string(),
                    bound: exact_bound(&case.scores, case.threshold),
                    scores: case.scores,
                    threshold: case.threshold,
                    probe_index: None,
                })
                .collect();
            let real_bound = analytic_scene_bound(&scene, n, q_probe);
            for probe_index in 0..real_probe_count {
                cases.push(BenchmarkCase {
                    source: "scene",
                    name: format!("real_probe_{probe_index}"),
                    scores: clear_scores(&scene, n, &scene.probes[probe_index]),
                    threshold: scene.threshold,
                    bound: real_bound,
                    probe_index: Some(probe_index),
                });
            }

            for case in cases {
                let BenchmarkCase {
                    source,
                    name,
                    scores,
                    threshold,
                    bound,
                    probe_index,
                } = case;
                let log_delta = choose_log_delta(bound);
                let delta = 1u64 << log_delta;
                let fold_accumulators: Vec<_> = PERIODS
                    .iter()
                    .map(|period| {
                        allocate_and_trivially_encrypt_new_glwe_ciphertext(
                            glwe_size,
                            &PlaintextList::new(
                                (period / 4) * delta,
                                PlaintextCount(polynomial_size.0),
                            ),
                            modulus,
                        )
                    })
                    .collect();

                let periodic_compare =
                    |mut state: LweCiphertextOwned<u64>| -> LweCiphertextOwned<u64> {
                        for (period, accumulator) in PERIODS.iter().zip(&fold_accumulators) {
                            let shift = u64::BITS - log_delta - period.ilog2();
                            let mut periodic_phase = state.clone();
                            lwe_ciphertext_cleartext_mul_assign(
                                &mut periodic_phase,
                                Cleartext(1u64 << shift),
                            );
                            let mut switched = LweCiphertext::new(0u64, small_size, modulus);
                            keyswitch_lwe_ciphertext(
                                &key_switching_key,
                                &periodic_phase,
                                &mut switched,
                            );
                            let mut correction = LweCiphertext::new(0u64, big_size, modulus);
                            programmable_bootstrap_lwe_ciphertext(
                                &switched,
                                &mut correction,
                                accumulator,
                                &fourier_bootstrap_key,
                            );
                            lwe_ciphertext_add_assign(&mut state, &correction);
                        }
                        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
                        keyswitch_lwe_ciphertext(&key_switching_key, &state, &mut switched);
                        let mut bit = LweCiphertext::new(0u64, big_size, modulus);
                        programmable_bootstrap_lwe_ciphertext(
                            &switched,
                            &mut bit,
                            &sign_accumulator,
                            &fourier_bootstrap_key,
                        );
                        lwe_ciphertext_plaintext_add_assign(&mut bit, Plaintext(1u64 << 62));
                        bit
                    };

                let score_started = Instant::now();
                let mut candidates: Vec<GlweCiphertextOwned<u64>> = if let Some(probe_index) =
                    probe_index
                {
                    let probe = &scene.probes[probe_index];
                    let mut probe_plaintext = vec![0u64; polynomial_size.0];
                    for (index, value) in probe.iter().enumerate() {
                        probe_plaintext[index] = (*value as u64).wrapping_mul(delta);
                    }
                    let mut encrypted_probe =
                        GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                    encrypt_glwe_ciphertext(
                        &glwe_secret_key,
                        &mut encrypted_probe,
                        &PlaintextList::from_container(probe_plaintext),
                        WOPBS_PARAMS.glwe_noise_distribution,
                        &mut generator,
                    );
                    (0..n)
                        .into_par_iter()
                        .map(|gallery_index| {
                            let mut polynomial = vec![0u64; polynomial_size.0];
                            for coordinate in 0..scene.dim {
                                polynomial[scene.dim - 1 - coordinate] =
                                    (-2 * scene.gallery[gallery_index][coordinate]) as u64;
                            }
                            let polynomial = Polynomial::from_container(polynomial);
                            let mut candidate =
                                GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                            for (mut output, input) in candidate
                                .as_mut_polynomial_list()
                                .iter_mut()
                                .zip(encrypted_probe.as_polynomial_list().iter())
                            {
                                polynomial_wrapping_add_mul_assign(
                                    &mut output,
                                    &input,
                                    &polynomial,
                                );
                            }
                            let mut body = candidate.get_mut_body();
                            body.as_mut()[scene.dim - 1] = body.as_mut()[scene.dim - 1]
                                .wrapping_add(
                                    (scene.squared_norms[gallery_index] as u64).wrapping_mul(delta),
                                );
                            body.as_mut()[polynomial_size.0 - 1] = body.as_mut()
                                [polynomial_size.0 - 1]
                                .wrapping_add((gallery_index as u64).wrapping_mul(index_delta));
                            candidate
                        })
                        .collect()
                } else {
                    scores
                        .iter()
                        .enumerate()
                        .map(|(index, score)| {
                            let mut plaintext = vec![0u64; polynomial_size.0];
                            plaintext[scene.dim - 1] = (*score as u64).wrapping_mul(delta);
                            plaintext[polynomial_size.0 - 1] =
                                (index as u64).wrapping_mul(index_delta);
                            let mut candidate =
                                GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                            encrypt_glwe_ciphertext(
                                &glwe_secret_key,
                                &mut candidate,
                                &PlaintextList::from_container(plaintext),
                                WOPBS_PARAMS.glwe_noise_distribution,
                                &mut generator,
                            );
                            candidate
                        })
                        .collect()
                };
                let score_seconds = score_started.elapsed().as_secs_f64();

                // Variante `--precompute-match`: ogni candidato riceve, in un coefficiente non
                // usato dal prodotto polinomiale, il proprio bit di soglia gia' ripulito. Il bit
                // LWE viene convertito in GGSW e usato per scegliere fra GLWE(0) e GLWE(2^63), poi
                // il normale torneo porta con se' score, indice e bit. Soltanto il bit del vincitore
                // viene estratto alla fine; gli N bit intermedi non sono un output del protocollo.
                let predicate_started = Instant::now();
                if precompute_match {
                    let match_coefficient = polynomial_size.0 - MATCH_COEFFICIENT_FROM_END;
                    let zero_match = GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                    let mut one_plaintext = vec![0u64; polynomial_size.0];
                    one_plaintext[match_coefficient] = 1u64 << 63;
                    let one_match = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                        glwe_size,
                        &PlaintextList::from_container(one_plaintext),
                        modulus,
                    );
                    candidates = candidates
                        .into_par_iter()
                        .map(|mut candidate| {
                            let mut threshold_difference =
                                LweCiphertext::new(0u64, big_size, modulus);
                            extract_lwe_sample_from_glwe_ciphertext(
                                &candidate,
                                &mut threshold_difference,
                                MonomialDegree(scene.dim - 1),
                            );
                            lwe_ciphertext_plaintext_sub_assign(
                                &mut threshold_difference,
                                Plaintext(
                                    (threshold as u64)
                                        .wrapping_mul(delta)
                                        .wrapping_add(delta >> 1),
                                ),
                            );
                            let match_bit = periodic_compare(threshold_difference);
                            let mut match_bit_small =
                                LweCiphertext::new(0u64, small_size, modulus);
                            keyswitch_lwe_ciphertext(
                                &key_switching_key,
                                &match_bit,
                                &mut match_bit_small,
                            );
                            let mut scratch = GlobalPodBuffer::new(
                                StackReq::try_any_of([
                                    circuit_bootstrap_boolean_scratch::<u64>(
                                        small_size,
                                        big_size,
                                        glwe_size,
                                        polynomial_size,
                                        fft,
                                    )
                                    .unwrap(),
                                    tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch(fft)
                                        .unwrap(),
                                    cmux_scratch::<u64>(glwe_size, polynomial_size, fft).unwrap(),
                                ])
                                .unwrap(),
                            );
                            let stack = PodStack::new(&mut scratch);
                            let mut match_ggsw = GgswCiphertext::new(
                                0u64,
                                glwe_size,
                                polynomial_size,
                                cbs_base_log,
                                cbs_levels,
                                modulus,
                            );
                            circuit_bootstrap_boolean(
                                fourier_bootstrap_key.as_view(),
                                match_bit_small.as_view(),
                                match_ggsw.as_mut_view(),
                                DeltaLog(63),
                                pfpksk.as_view(),
                                fft,
                                stack,
                            );
                            let mut match_fourier = FourierGgswCiphertext::new(
                                glwe_size,
                                polynomial_size,
                                cbs_base_log,
                                cbs_levels,
                            );
                            match_fourier.as_mut_view().fill_with_forward_fourier(
                                match_ggsw.as_view(),
                                fft,
                                stack,
                            );
                            let mut selected_match = zero_match.clone();
                            let mut match_one = one_match.clone();
                            cmux(
                                selected_match.as_mut_view(),
                                match_one.as_mut_view(),
                                match_fourier.as_view(),
                                fft,
                                stack,
                            );
                            glwe_ciphertext_add_assign(&mut candidate, &selected_match);
                            candidate
                        })
                        .collect();
                }
                let predicate_seconds = predicate_started.elapsed().as_secs_f64();

                let tournament_started = Instant::now();
                while candidates.len() > 1 {
                    candidates = candidates
                        .par_chunks(2)
                        .map(|pair| {
                            if pair.len() == 1 {
                                return pair[0].clone();
                            }
                            let (left, right) = (&pair[0], &pair[1]);
                            let mut difference = LweCiphertext::new(0u64, big_size, modulus);
                            let mut right_score = LweCiphertext::new(0u64, big_size, modulus);
                            extract_lwe_sample_from_glwe_ciphertext(
                                left,
                                &mut difference,
                                MonomialDegree(scene.dim - 1),
                            );
                            extract_lwe_sample_from_glwe_ciphertext(
                                right,
                                &mut right_score,
                                MonomialDegree(scene.dim - 1),
                            );
                            lwe_ciphertext_sub_assign(&mut difference, &right_score);
                            lwe_ciphertext_plaintext_sub_assign(
                                &mut difference,
                                Plaintext(delta >> 1),
                            );
                            let selector = periodic_compare(difference);
                            let mut selector_small =
                                LweCiphertext::new(0u64, small_size, modulus);
                            keyswitch_lwe_ciphertext(
                                &key_switching_key,
                                &selector,
                                &mut selector_small,
                            );

                            let mut scratch = GlobalPodBuffer::new(
                                StackReq::try_any_of([
                                    circuit_bootstrap_boolean_scratch::<u64>(
                                        small_size,
                                        big_size,
                                        glwe_size,
                                        polynomial_size,
                                        fft,
                                    )
                                    .unwrap(),
                                    tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch(fft)
                                        .unwrap(),
                                    cmux_scratch::<u64>(glwe_size, polynomial_size, fft).unwrap(),
                                ])
                                .unwrap(),
                            );
                            let stack = PodStack::new(&mut scratch);
                            let mut selector_ggsw = GgswCiphertext::new(
                                0u64,
                                glwe_size,
                                polynomial_size,
                                cbs_base_log,
                                cbs_levels,
                                modulus,
                            );
                            circuit_bootstrap_boolean(
                                fourier_bootstrap_key.as_view(),
                                selector_small.as_view(),
                                selector_ggsw.as_mut_view(),
                                DeltaLog(63),
                                pfpksk.as_view(),
                                fft,
                                stack,
                            );
                            let mut selector_fourier = FourierGgswCiphertext::new(
                                glwe_size,
                                polynomial_size,
                                cbs_base_log,
                                cbs_levels,
                            );
                            selector_fourier.as_mut_view().fill_with_forward_fourier(
                                selector_ggsw.as_view(),
                                fft,
                                stack,
                            );

                            let mut selected = right.clone();
                            let mut left_branch = left.clone();
                            cmux(
                                selected.as_mut_view(),
                                left_branch.as_mut_view(),
                                selector_fourier.as_view(),
                                fft,
                                stack,
                            );
                            selected
                        })
                        .collect();
                }
                let tournament_seconds = tournament_started.elapsed().as_secs_f64();
                let winner = candidates.pop().unwrap();

                let mut encrypted_index = LweCiphertext::new(0u64, big_size, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &winner,
                    &mut encrypted_index,
                    MonomialDegree(polynomial_size.0 - 1),
                );
                let actual_index = (decrypt_lwe_ciphertext(&big_secret_key, &encrypted_index)
                    .0
                    .wrapping_add(index_delta >> 1)
                    >> LOG_INDEX_DELTA) as usize;

                let mut threshold_difference = LweCiphertext::new(0u64, big_size, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &winner,
                    &mut threshold_difference,
                    MonomialDegree(scene.dim - 1),
                );
                let selected_score_error_abs = scores.get(actual_index).map(|score| {
                    let clear_phase = (*score as u64).wrapping_mul(delta);
                    let decrypted_phase =
                        decrypt_lwe_ciphertext(&big_secret_key, &threshold_difference).0;
                    (decrypted_phase.wrapping_sub(clear_phase) as i64 as f64 / delta as f64).abs()
                });
                let threshold_started = Instant::now();
                let actual_match = if precompute_match {
                    let mut encrypted_match = LweCiphertext::new(0u64, big_size, modulus);
                    extract_lwe_sample_from_glwe_ciphertext(
                        &winner,
                        &mut encrypted_match,
                        MonomialDegree(polynomial_size.0 - MATCH_COEFFICIENT_FROM_END),
                    );
                    (decrypt_lwe_ciphertext(&big_secret_key, &encrypted_match).0 >> 63) & 1 == 1
                } else {
                    lwe_ciphertext_plaintext_sub_assign(
                        &mut threshold_difference,
                        Plaintext(
                            (threshold as u64)
                                .wrapping_mul(delta)
                                .wrapping_add(delta >> 1),
                        ),
                    );
                    let encrypted_match = periodic_compare(threshold_difference);
                    (decrypt_lwe_ciphertext(&big_secret_key, &encrypted_match).0 >> 63) & 1 == 1
                };
                let threshold_seconds = threshold_started.elapsed().as_secs_f64();
                let (expected_index, expected_match) = expected_result(&scores, threshold);
                let observation = Observation {
                    key_run,
                    source,
                    name,
                    n,
                    bound,
                    log_delta,
                    expected_index,
                    actual_index,
                    expected_match,
                    actual_match,
                    score_seconds,
                    predicate_seconds,
                    tournament_seconds,
                    threshold_seconds,
                    selected_score_error_abs,
                };
                println!(
                    "RESULT,{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{}",
                    observation.key_run,
                    observation.source,
                    observation.name,
                    observation.n,
                    observation.bound,
                    observation.log_delta,
                    observation.expected_index,
                    observation.actual_index,
                    observation.expected_match,
                    observation.actual_match,
                    observation.score_seconds,
                    observation.predicate_seconds,
                    observation.tournament_seconds,
                    observation.threshold_seconds,
                    observation.total_seconds(),
                    observation.correct(),
                    observation.total_seconds() < 5.0,
                    observation.total_seconds() < 10.0,
                );
                println!(
                    "DIAG_SCORE_NOISE,key={},case={},N={},abs_score_units={}",
                    observation.key_run,
                    observation.name,
                    observation.n,
                    observation
                        .selected_score_error_abs
                        .map(|value| format!("{value:.6}"))
                        .unwrap_or_else(|| "index_out_of_range".to_string()),
                );
                observations.push(observation);
            }
        }
    }

    let totals: Vec<f64> = observations
        .iter()
        .map(Observation::total_seconds)
        .collect();
    let correct = observations
        .iter()
        .filter(|result| result.correct())
        .count();
    let under_five = observations
        .iter()
        .filter(|result| result.total_seconds() < 5.0)
        .count();
    let under_ten = observations
        .iter()
        .filter(|result| result.total_seconds() < 10.0)
        .count();
    let score_errors: Vec<f64> = observations
        .iter()
        .filter_map(|result| result.selected_score_error_abs)
        .collect();
    println!(
        "SUMMARY,total={},correct={},under_5s={},under_10s={},median_s={:.6},p95_s={:.6},max_s={:.6}",
        observations.len(),
        correct,
        under_five,
        under_ten,
        percentile(&totals, 0.5),
        percentile(&totals, 0.95),
        totals.iter().copied().fold(0.0, f64::max),
    );
    println!(
        "DIAG_SUMMARY,selected_score_samples={},median_abs_score_units={:.6},p95_abs_score_units={:.6},max_abs_score_units={:.6}",
        score_errors.len(),
        percentile(&score_errors, 0.5),
        percentile(&score_errors, 0.95),
        score_errors.iter().copied().fold(0.0, f64::max),
    );
    if correct != observations.len() || under_ten != observations.len() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_fold_preserves_inclusive_sign_for_every_supported_delta() {
        for log_delta in MIN_LOG_DELTA..=MAX_LOG_DELTA {
            let radius = score_radius(log_delta);
            let doubled_half_torus = 1i64 << (64 - log_delta);
            for difference in -radius..=radius {
                let folded = folded_clear_doubled(difference);
                assert_eq!(folded < 0, difference <= 0, "d={difference}");
                assert!(folded.abs() < doubled_half_torus, "d={difference}");
            }
        }
    }

    #[test]
    fn delta_selection_covers_pairwise_safe_scene_bound() {
        assert_eq!(choose_log_delta(4095), 51);
        assert_eq!(choose_log_delta(4262), 50);
        assert_eq!(score_radius(50), 8191);
    }

    #[test]
    fn adversarial_cases_cover_both_decisions_and_positions() {
        for n in [64usize, 128] {
            let cases = synthetic_cases(n);
            assert!(cases
                .iter()
                .any(|case| expected_result(&case.scores, case.threshold).1));
            assert!(cases
                .iter()
                .any(|case| !expected_result(&case.scores, case.threshold).1));
            assert!(cases
                .iter()
                .any(|case| expected_result(&case.scores, case.threshold).0 == 0));
            assert!(cases
                .iter()
                .any(|case| expected_result(&case.scores, case.threshold).0 == n - 1));
            assert!(cases.iter().any(|case| {
                let (index, _) = expected_result(&case.scores, case.threshold);
                index > 0 && index < n - 1
            }));
        }
    }
}
