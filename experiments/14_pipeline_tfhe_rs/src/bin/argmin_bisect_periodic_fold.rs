//! Argmin quantizzato senza CMUX del punteggio: ricerca binaria cifrata + scan OR.
//!
//! Il server conosce soltanto il dominio pubblico `[L,U]`, derivato dalla galleria in chiaro e
//! dal vincolo `|probe_j| <= q`. Cerca il minimo del punteggio quantizzato in bin di ampiezza
//! configurabile. Ogni round valuta in parallelo `exists_i(score_i <= mid)` con il comparatore
//! periodic-fold a tre PBS; un PBS converte poi il bit cifrato nell'incremento del limite basso.
//! Nessun CMUX seleziona o trasporta un punteggio.
//!
//! Trovato il bin minimo, una scan OR esclusiva di Blelloch seleziona deterministicamente il
//! primo template nel bin. L'unico output applicativo e' un codice cifrato: zero significa
//! rifiuto, `i+1` significa match con l'indice `i`. La distanza non fa parte dell'output.
//!
//! Punto operativo sperimentale: 10 round, bin di ampiezza 6. Il percorso intero esatto si ottiene
//! con `--rounds 13 --bin-width 1`, entro lo stesso dominio padded di 8192 valori.
//!
//! ```text
//! cargo run --release --bin argmin_bisect_periodic_fold -- \
//!   --run --keys 1 --cases adversarial --rounds 10 --bin-width 6
//! ```

use rayon::prelude::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const SCORE_DIM: usize = 512;
const Q_PROBE_DEFAULT: i64 = 3;
const LOG_SCORE_DELTA: u32 = 50;
const LOG_BOOL_DELTA: u32 = 60;
const LOG_CODE_DELTA: u32 = 55;
const PERIODS: [u64; 2] = [32, 512];
const OR_BLOCK: usize = 8;
const MAX_PERIODIC_RADIUS: i64 = 8191;

type Lwe = LweCiphertextOwned<u64>;

#[derive(Clone)]
struct Scene {
    dim: usize,
    gallery: Vec<Vec<i64>>,
    squared_norms: Vec<i64>,
    probes: Vec<Vec<i64>>,
    threshold: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScoreDomain {
    lower: i64,
    upper: i64,
}

impl ScoreDomain {
    fn width(self) -> usize {
        usize::try_from(self.upper - self.lower + 1).expect("dominio non rappresentabile")
    }

    fn bucket(self, score: i64, bin_width: i64) -> usize {
        assert!(self.contains(score));
        usize::try_from((score - self.lower) / bin_width).unwrap()
    }

    fn contains(self, score: i64) -> bool {
        (self.lower..=self.upper).contains(&score)
    }

    fn bucket_upper(self, bucket: usize, bin_width: i64) -> i64 {
        self.lower + (bucket as i64 + 1) * bin_width - 1
    }
}

#[derive(Clone)]
struct BenchmarkCase {
    source: &'static str,
    name: String,
    scores: Vec<i64>,
    threshold: i64,
    probe_index: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
struct ClearResult {
    bucket: usize,
    index: usize,
    matched: bool,
}

#[derive(Default)]
struct Timing {
    score: f64,
    search: f64,
    equality: f64,
    scan: f64,
    threshold: f64,
    output: f64,
}

impl Timing {
    fn total(&self) -> f64 {
        self.score + self.search + self.equality + self.scan + self.threshold + self.output
    }
}

fn load_scene(path: &str) -> Scene {
    let text = std::fs::read_to_string(path).expect("manca la scena (esporta_dati.py)");
    let mut rows = text.lines();
    let header: Vec<i64> = rows
        .next()
        .expect("scena vuota")
        .split_whitespace()
        .map(|value| value.parse().expect("header non numerico"))
        .collect();
    assert!(header.len() >= 4, "header incompleto");
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
    assert!(gallery.iter().all(|template| template.len() == dim));
    let probes = (0..probe_count)
        .map(|_| {
            let row: Vec<i64> = rows
                .next()
                .expect("probe troncati")
                .split_whitespace()
                .map(|value| value.parse().expect("probe non numerico"))
                .collect();
            assert_eq!(row.len(), dim + 1, "probe di dimensione errata");
            row[1..].to_vec()
        })
        .collect();
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

fn analytic_domain(scene: &Scene, n: usize, q_probe: i64) -> ScoreDomain {
    assert!(n > 0 && n <= scene.gallery.len());
    assert!(q_probe >= 0);
    let bounds = (0..n).map(|index| {
        let l1: i64 = scene.gallery[index].iter().map(|value| value.abs()).sum();
        let radius = 2 * q_probe * l1;
        (
            scene.squared_norms[index] - radius,
            scene.squared_norms[index] + radius,
        )
    });
    let (lower, upper) = bounds.fold((i64::MAX, i64::MIN), |(lower, upper), (lo, hi)| {
        (lower.min(lo), upper.max(hi))
    });
    ScoreDomain { lower, upper }
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

fn quantized_threshold_upper(domain: ScoreDomain, threshold: i64, bin_width: i64) -> Option<i64> {
    if threshold < domain.lower {
        None
    } else {
        let bucket = usize::try_from((threshold - domain.lower) / bin_width).unwrap();
        Some(domain.bucket_upper(bucket, bin_width))
    }
}

fn clear_result(
    scores: &[i64],
    threshold: i64,
    domain: ScoreDomain,
    bin_width: i64,
) -> ClearResult {
    assert!(!scores.is_empty());
    assert!(scores.iter().all(|score| domain.contains(*score)));
    let min_bucket = scores
        .iter()
        .map(|score| domain.bucket(*score, bin_width))
        .min()
        .unwrap();
    let index = scores
        .iter()
        .position(|score| domain.bucket(*score, bin_width) == min_bucket)
        .unwrap();
    let matched = quantized_threshold_upper(domain, threshold, bin_width)
        .is_some_and(|upper| scores[index] <= upper);
    ClearResult {
        bucket: min_bucket,
        index,
        matched,
    }
}

fn clear_binary_search_bucket(
    scores: &[i64],
    domain: ScoreDomain,
    bin_width: i64,
    rounds: u32,
) -> usize {
    let mut low_bucket = 0usize;
    for bit in (0..rounds).rev() {
        let step = 1usize << bit;
        let mid_bucket = low_bucket + step - 1;
        let upper = domain.bucket_upper(mid_bucket, bin_width);
        if !scores.iter().any(|score| *score <= upper) {
            low_bucket += step;
        }
    }
    low_bucket
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

fn code_lut_value(lut_value: u64, index: usize) -> u64 {
    // Con message_modulus=16, un bit a 2^60 occupa due caselle della LUT: i due bit veri
    // sommano quindi al valore LUT 4 (non 2).
    if lut_value == 4 {
        (index + 1) as u64
    } else {
        0
    }
}

fn compact_or<F>(mut bits: Vec<Lwe>, or_gate: &F) -> Lwe
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!bits.is_empty());
    while bits.len() > 1 {
        bits = bits.par_chunks(OR_BLOCK).map(or_gate).collect();
    }
    bits.pop().unwrap()
}

fn exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(flags.len().is_power_of_two());
    let mut work = flags.to_vec();

    let mut stride = 2usize;
    while stride <= work.len() {
        let updates: Vec<_> = (0..work.len() / stride)
            .into_par_iter()
            .map(|block| {
                let right = (block + 1) * stride - 1;
                let left = right - stride / 2;
                (right, or_gate(&[work[left].clone(), work[right].clone()]))
            })
            .collect();
        for (index, value) in updates {
            work[index] = value;
        }
        stride *= 2;
    }

    let last = work.len() - 1;
    work[last] = zero.clone();
    let mut stride = work.len();
    while stride >= 2 {
        let updates: Vec<_> = (0..work.len() / stride)
            .into_par_iter()
            .map(|block| {
                let right = (block + 1) * stride - 1;
                let left = right - stride / 2;
                let old_left = work[left].clone();
                let old_right = work[right].clone();
                let new_right = or_gate(&[old_right.clone(), old_left]);
                (left, right, old_right, new_right)
            })
            .collect();
        for (left, right, new_left, new_right) in updates {
            work[left] = new_left;
            work[right] = new_right;
        }
        stride /= 2;
    }
    work
}

fn adversarial_case(n: usize, domain: ScoreDomain, bin_width: i64, rounds: u32) -> BenchmarkCase {
    let available_buckets = domain.width().div_ceil(bin_width as usize);
    let target_bucket = ((1usize << rounds) / 3).min(available_buckets.saturating_sub(2));
    let bucket_lower = domain.lower + target_bucket as i64 * bin_width;
    let bucket_upper = domain
        .bucket_upper(target_bucket, bin_width)
        .min(domain.upper);
    let mut scores = (0..n)
        .map(|index| {
            let later_bucket = target_bucket + 1 + index % (available_buckets - target_bucket - 1);
            (domain.lower + later_bucket as i64 * bin_width + index as i64 % bin_width)
                .min(domain.upper)
        })
        .collect::<Vec<_>>();
    // Il primo minimo quantizzato ha un punteggio esatto peggiore del secondo: l'indice atteso
    // deve seguire la semantica "primo bin minimo", non l'argmin del punteggio non troncato.
    scores[n / 2] = bucket_upper;
    scores[n / 2 + 1] = bucket_lower;
    scores[n - 1] = domain.upper;
    let threshold = if n == 64 {
        bucket_lower // stesso bin: caso inclusivo accettato
    } else {
        bucket_lower - 1 // bin precedente: caso respinto
    };
    BenchmarkCase {
        source: "synthetic",
        name: "bucket_boundary_first_tie".to_string(),
        scores,
        threshold,
        probe_index: None,
    }
}

fn argument<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|arg| arg == name)
        .map(|index| {
            args[index + 1]
                .parse()
                .unwrap_or_else(|_| panic!("valore non valido per {name}"))
        })
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|arg| arg == "--run") {
        eprintln!(
            "usage: argmin_bisect_periodic_fold --run [--keys N] [--cases adversarial|real|both] \
             [--rounds B] [--bin-width W] [--q-probe Q] [--real-probes N] [--scene FILE]"
        );
        return;
    }
    let key_runs: usize = argument(&args, "--keys", 1);
    let rounds: u32 = argument(&args, "--rounds", 10);
    let bin_width: i64 = argument(&args, "--bin-width", 6);
    let q_probe: i64 = argument(&args, "--q-probe", Q_PROBE_DEFAULT);
    let real_probe_count: usize = argument(&args, "--real-probes", 1);
    let case_mode = args
        .iter()
        .position(|arg| arg == "--cases")
        .map(|index| args[index + 1].as_str())
        .unwrap_or("adversarial");
    let scene_path = args
        .iter()
        .position(|arg| arg == "--scene")
        .map(|index| args[index + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    assert!(key_runs > 0);
    assert!((1..=13).contains(&rounds));
    assert!(bin_width > 0);
    assert!(q_probe >= 0);
    assert!(real_probe_count > 0);
    assert!(matches!(case_mode, "adversarial" | "real" | "both"));

    let scene = load_scene(&scene_path);
    assert_eq!(scene.dim, SCORE_DIM);
    assert!(scene.gallery.len() >= 128);
    assert!(scene.probes.len() >= real_probe_count);
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
        "|probe|={observed_q} oltre q={q_probe}"
    );

    println!(
        "CONFIG,params=V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64,log2_p_fail={},periods=32|512,log_score_delta={},log_bool_delta={},rounds={},bin_width={},q_probe={},output=encrypted_reject_sentinel_or_index_plus_one",
        PARAMS.log2_p_fail,
        LOG_SCORE_DELTA,
        LOG_BOOL_DELTA,
        rounds,
        bin_width,
        q_probe,
    );
    println!(
        "RESULT,key,source,case,N,expected_index,actual_index,expected_match,actual_match,score_s,search_s,equality_s,scan_s,threshold_s,output_s,total_s,max_update_error_units,correct,under_10s"
    );

    let modulus = CiphertextModulus::<u64>::new_native();
    let score_delta = 1u64 << LOG_SCORE_DELTA;
    let bool_delta = 1u64 << LOG_BOOL_DELTA;
    let code_delta = 1u64 << LOG_CODE_DELTA;
    let mut all_correct = true;
    let mut all_under_ten = true;

    for key_run in 1..=key_runs {
        for &n in &[64usize, 128] {
            let domain = analytic_domain(&scene, n, q_probe);
            let bucket_capacity = 1usize << rounds;
            let buckets_required = domain.width().div_ceil(bin_width as usize);
            assert!(
                buckets_required <= bucket_capacity,
                "{buckets_required} bin non entrano in {rounds} round"
            );
            let padded_width = i64::try_from(bucket_capacity).unwrap() * bin_width;
            assert!(
                padded_width - 1 <= MAX_PERIODIC_RADIUS,
                "il dominio padded richiede differenze fino a {}, oltre {}",
                padded_width - 1,
                MAX_PERIODIC_RADIUS
            );

            let key_started = Instant::now();
            let client_key = ClientKey::new(PARAMS);
            let server_key = ServerKey::new(&client_key);
            let (glwe_secret_key, _, client_params) = client_key.into_raw_parts();
            let big_secret_key = glwe_secret_key.as_lwe_secret_key();
            let key_switching_key = &server_key.key_switching_key;
            let fourier_bootstrap_key = match &server_key.bootstrapping_key {
                ShortintBootstrappingKey::Classic(key) => key,
                _ => panic!("attesa bootstrapping key classica"),
            };
            let polynomial_size = fourier_bootstrap_key.polynomial_size();
            let glwe_size = fourier_bootstrap_key.glwe_size();
            let big_size = glwe_secret_key
                .glwe_dimension()
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size();
            let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
            let mut seeder_box = new_seeder();
            let seeder = seeder_box.as_mut();
            let mut generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

            let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &PlaintextList::new(
                    (bool_delta >> 1).wrapping_neg(),
                    PlaintextCount(polynomial_size.0),
                ),
                modulus,
            );
            let fold_accumulators: Vec<_> = PERIODS
                .iter()
                .map(|period| {
                    allocate_and_trivially_encrypt_new_glwe_ciphertext(
                        glwe_size,
                        &PlaintextList::new(
                            (period / 4) * score_delta,
                            PlaintextCount(polynomial_size.0),
                        ),
                        modulus,
                    )
                })
                .collect();
            let code_accumulators: Vec<_> = (0..n)
                .map(|index| {
                    generate_programmable_bootstrap_glwe_lut(
                        polynomial_size,
                        glwe_size,
                        16,
                        modulus,
                        code_delta,
                        move |value| code_lut_value(value, index),
                    )
                })
                .collect();

            let apply_pbs = |input: &Lwe, accumulator: &GlweCiphertextOwned<u64>| -> Lwe {
                let mut switched = LweCiphertext::new(0u64, small_size, modulus);
                keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
                let mut output = LweCiphertext::new(0u64, big_size, modulus);
                programmable_bootstrap_lwe_ciphertext(
                    &switched,
                    &mut output,
                    accumulator,
                    fourier_bootstrap_key,
                );
                output
            };
            let periodic_compare = |mut state: Lwe| -> Lwe {
                for (period, accumulator) in PERIODS.iter().zip(&fold_accumulators) {
                    let shift = u64::BITS - LOG_SCORE_DELTA - period.ilog2();
                    let mut phase = state.clone();
                    lwe_ciphertext_cleartext_mul_assign(&mut phase, Cleartext(1u64 << shift));
                    let correction = apply_pbs(&phase, accumulator);
                    lwe_ciphertext_add_assign(&mut state, &correction);
                }
                let mut bit = apply_pbs(&state, &sign_accumulator);
                lwe_ciphertext_plaintext_add_assign(&mut bit, Plaintext(bool_delta >> 1));
                bit
            };
            let or_gate = |bits: &[Lwe]| -> Lwe {
                assert!(!bits.is_empty() && bits.len() <= OR_BLOCK);
                let mut count = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    big_size,
                    Plaintext(0u64),
                    modulus,
                );
                for bit in bits {
                    lwe_ciphertext_add_assign(&mut count, bit);
                }
                lwe_ciphertext_opposite_assign(&mut count);
                lwe_ciphertext_plaintext_add_assign(&mut count, Plaintext(bool_delta >> 1));
                let mut any = apply_pbs(&count, &sign_accumulator);
                lwe_ciphertext_plaintext_add_assign(&mut any, Plaintext(bool_delta >> 1));
                any
            };
            let decode_bool = |ciphertext: &Lwe| -> bool {
                ((decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
                    .0
                    .wrapping_add(bool_delta >> 1)
                    >> LOG_BOOL_DELTA)
                    & 1)
                    == 1
            };

            println!(
                "KEY,key={},N={},generation_s={:.6},domain_L={},domain_U={},domain_width={},buckets_required={},bucket_capacity={},padded_difference_bound={}",
                key_run,
                n,
                key_started.elapsed().as_secs_f64(),
                domain.lower,
                domain.upper,
                domain.width(),
                buckets_required,
                bucket_capacity,
                padded_width - 1,
            );

            let mut cases = Vec::new();
            if matches!(case_mode, "adversarial" | "both") {
                cases.push(adversarial_case(n, domain, bin_width, rounds));
            }
            if matches!(case_mode, "real" | "both") {
                for probe_index in 0..real_probe_count {
                    cases.push(BenchmarkCase {
                        source: "scene",
                        name: format!("real_probe_{probe_index}"),
                        scores: clear_scores(&scene, n, &scene.probes[probe_index]),
                        threshold: scene.threshold,
                        probe_index: Some(probe_index),
                    });
                }
            }

            for case in cases {
                assert!(case.scores.iter().all(|score| domain.contains(*score)));
                let expected = clear_result(&case.scores, case.threshold, domain, bin_width);
                assert_eq!(
                    clear_binary_search_bucket(&case.scores, domain, bin_width, rounds),
                    expected.bucket
                );
                let mut timing = Timing::default();

                let score_started = Instant::now();
                let encrypted_scores: Vec<Lwe> = if let Some(probe_index) = case.probe_index {
                    let mut probe_plaintext = vec![0u64; polynomial_size.0];
                    for (index, value) in scene.probes[probe_index].iter().enumerate() {
                        probe_plaintext[index] = (*value as u64).wrapping_mul(score_delta);
                    }
                    let mut encrypted_probe =
                        GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                    encrypt_glwe_ciphertext(
                        &glwe_secret_key,
                        &mut encrypted_probe,
                        &PlaintextList::from_container(probe_plaintext),
                        client_params.glwe_noise_distribution(),
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
                            let mut product =
                                GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
                            for (mut output, input) in product
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
                            let mut score = LweCiphertext::new(0u64, big_size, modulus);
                            extract_lwe_sample_from_glwe_ciphertext(
                                &product,
                                &mut score,
                                MonomialDegree(scene.dim - 1),
                            );
                            lwe_ciphertext_plaintext_add_assign(
                                &mut score,
                                Plaintext(
                                    (scene.squared_norms[gallery_index] as u64)
                                        .wrapping_mul(score_delta),
                                ),
                            );
                            score
                        })
                        .collect()
                } else {
                    case.scores
                        .iter()
                        .map(|score| {
                            allocate_and_encrypt_new_lwe_ciphertext(
                                &big_secret_key,
                                Plaintext((*score as u64).wrapping_mul(score_delta)),
                                client_params.glwe_noise_distribution(),
                                modulus,
                                &mut generator,
                            )
                        })
                        .collect()
                };
                timing.score = score_started.elapsed().as_secs_f64();

                let search_started = Instant::now();
                let mut encrypted_low = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    big_size,
                    Plaintext((domain.lower as u64).wrapping_mul(score_delta)),
                    modulus,
                );
                let mut expected_low = domain.lower;
                let mut max_update_error_units = 0.0f64;
                let mut final_update_error_units = 0.0f64;
                let mut search_bits_correct = true;
                let mut round_trace = Vec::with_capacity(rounds as usize);
                for bit in (0..rounds).rev() {
                    let step_buckets = 1usize << bit;
                    let step_score = step_buckets as i64 * bin_width;
                    let mid_offset = step_score - 1;
                    let mut encrypted_mid = encrypted_low.clone();
                    lwe_ciphertext_plaintext_add_assign(
                        &mut encrypted_mid,
                        Plaintext((mid_offset as u64).wrapping_mul(score_delta)),
                    );
                    let predicates: Vec<Lwe> = encrypted_scores
                        .par_iter()
                        .map(|score| {
                            let mut difference = score.clone();
                            lwe_ciphertext_sub_assign(&mut difference, &encrypted_mid);
                            lwe_ciphertext_plaintext_sub_assign(
                                &mut difference,
                                Plaintext(score_delta >> 1),
                            );
                            periodic_compare(difference)
                        })
                        .collect();
                    let any = compact_or(predicates, &or_gate);
                    let expected_any = case
                        .scores
                        .iter()
                        .any(|score| *score <= expected_low + mid_offset);
                    let actual_any = decode_bool(&any);
                    search_bits_correct &= actual_any == expected_any;

                    let update_accumulator = generate_programmable_bootstrap_glwe_lut(
                        polynomial_size,
                        glwe_size,
                        16,
                        modulus,
                        score_delta,
                        move |value| if value == 0 { step_score as u64 } else { 0 },
                    );
                    let update = apply_pbs(&any, &update_accumulator);
                    lwe_ciphertext_add_assign(&mut encrypted_low, &update);
                    if !expected_any {
                        expected_low += step_score;
                    }
                    let expected_phase = (expected_low as u64).wrapping_mul(score_delta);
                    let actual_phase = decrypt_lwe_ciphertext(&big_secret_key, &encrypted_low).0;
                    let error = actual_phase.wrapping_sub(expected_phase) as i64 as f64
                        / score_delta as f64;
                    max_update_error_units = max_update_error_units.max(error.abs());
                    final_update_error_units = error;
                    round_trace.push((bit, expected_any, actual_any, error));
                }
                timing.search = search_started.elapsed().as_secs_f64();

                let equality_started = Instant::now();
                let mut encrypted_bucket_upper = encrypted_low.clone();
                lwe_ciphertext_plaintext_add_assign(
                    &mut encrypted_bucket_upper,
                    Plaintext(((bin_width - 1) as u64).wrapping_mul(score_delta)),
                );
                let equality_flags: Vec<Lwe> = encrypted_scores
                    .par_iter()
                    .map(|score| {
                        let mut difference = score.clone();
                        lwe_ciphertext_sub_assign(&mut difference, &encrypted_bucket_upper);
                        lwe_ciphertext_plaintext_sub_assign(
                            &mut difference,
                            Plaintext(score_delta >> 1),
                        );
                        periodic_compare(difference)
                    })
                    .collect();
                let equality_bits_correct =
                    equality_flags
                        .iter()
                        .zip(&case.scores)
                        .all(|(flag, score)| {
                            decode_bool(flag)
                                == (domain.bucket(*score, bin_width) == expected.bucket)
                        });
                timing.equality = equality_started.elapsed().as_secs_f64();

                let scan_started = Instant::now();
                let zero = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    big_size,
                    Plaintext(0u64),
                    modulus,
                );
                let prefixes = exclusive_prefix_or(&equality_flags, &zero, &or_gate);
                let inclusive: Vec<Lwe> = prefixes
                    .par_iter()
                    .zip(&equality_flags)
                    .map(|(prefix, equality)| or_gate(&[prefix.clone(), equality.clone()]))
                    .collect();
                let winners: Vec<Lwe> = inclusive
                    .into_iter()
                    .zip(&prefixes)
                    .map(|(mut inclusive, prefix)| {
                        lwe_ciphertext_sub_assign(&mut inclusive, prefix);
                        inclusive
                    })
                    .collect();
                let winner_bits: Vec<bool> = winners.iter().map(decode_bool).collect();
                let scan_correct = winner_bits.iter().filter(|bit| **bit).count() == 1
                    && winner_bits[expected.index];
                timing.scan = scan_started.elapsed().as_secs_f64();

                // Argmin-then-threshold letterale: una sola comparazione sul limite inferiore
                // cifrato del bin minimo. La soglia operativa va calibrata direttamente nello
                // spazio quantizzato (massima soglia con FPIR empirica entro il target).
                let threshold_started = Instant::now();
                let global_accept = if let Some(threshold_upper) =
                    quantized_threshold_upper(domain, case.threshold, bin_width)
                {
                    let mut difference = encrypted_low.clone();
                    lwe_ciphertext_plaintext_sub_assign(
                        &mut difference,
                        Plaintext(
                            (threshold_upper as u64)
                                .wrapping_mul(score_delta)
                                .wrapping_add(score_delta >> 1),
                        ),
                    );
                    periodic_compare(difference)
                } else {
                    zero.clone()
                };
                let threshold_bit_correct = decode_bool(&global_accept) == expected.matched;
                timing.threshold = threshold_started.elapsed().as_secs_f64();

                let output_started = Instant::now();
                let coded: Vec<Lwe> = winners
                    .par_iter()
                    .zip(&code_accumulators)
                    .map(|(winner, accumulator)| {
                        let mut pair = winner.clone();
                        lwe_ciphertext_add_assign(&mut pair, &global_accept);
                        apply_pbs(&pair, accumulator)
                    })
                    .collect();
                let mut encrypted_code = zero;
                for code in &coded {
                    lwe_ciphertext_add_assign(&mut encrypted_code, code);
                }
                let actual_code = decrypt_lwe_ciphertext(&big_secret_key, &encrypted_code)
                    .0
                    .wrapping_add(code_delta >> 1)
                    >> LOG_CODE_DELTA;
                let (actual_index, actual_match) = if actual_code == 0 {
                    (usize::MAX, false)
                } else {
                    (actual_code as usize - 1, true)
                };
                timing.output = output_started.elapsed().as_secs_f64();

                let correct = actual_match == expected.matched
                    && (!actual_match || actual_index == expected.index)
                    && search_bits_correct
                    && equality_bits_correct
                    && scan_correct
                    && threshold_bit_correct;
                let under_ten = timing.total() < 10.0;
                all_correct &= correct;
                all_under_ten &= under_ten;
                println!(
                    "RESULT,{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{}",
                    key_run,
                    case.source,
                    case.name,
                    n,
                    expected.index,
                    if actual_match {
                        actual_index.to_string()
                    } else {
                        "reject_sentinel".to_string()
                    },
                    expected.matched,
                    actual_match,
                    timing.score,
                    timing.search,
                    timing.equality,
                    timing.scan,
                    timing.threshold,
                    timing.output,
                    timing.total(),
                    max_update_error_units,
                    correct,
                    under_ten,
                );
                println!(
                    "DIAG,key={},case={},N={},search_bits_correct={},equality_bits_correct={},scan_correct={},threshold_bit_correct={},final_update_error_units={:.6},rounds={}",
                    key_run,
                    case.name,
                    n,
                    search_bits_correct,
                    equality_bits_correct,
                    scan_correct,
                    threshold_bit_correct,
                    final_update_error_units,
                    round_trace
                        .iter()
                        .map(|(bit, expected_any, actual_any, error)| format!(
                            "b{bit}:{}>{}:{error:.3}",
                            u8::from(*expected_any),
                            u8::from(*actual_any)
                        ))
                        .collect::<Vec<_>>()
                        .join("|"),
                );
            }
        }
    }

    println!(
        "SUMMARY,all_correct={},all_under_10s={},contract=zero_reject_or_index_plus_one,no_distance_output=true",
        all_correct, all_under_ten
    );
    if !all_correct || !all_under_ten {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analytic_q3_domains_are_tight_for_the_enrolled_gallery() {
        let scene = load_scene(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/results/scena_reale_q3.txt"
        ));
        assert_eq!(
            analytic_domain(&scene, 64, 3),
            ScoreDomain {
                lower: -2038,
                upper: 3338
            }
        );
        assert_eq!(
            analytic_domain(&scene, 128, 3),
            ScoreDomain {
                lower: -2038,
                upper: 3357
            }
        );
    }

    #[test]
    fn binary_search_matches_bucket_argmin_exhaustively() {
        let domain = ScoreDomain {
            lower: -17,
            upper: 76,
        };
        for bin_width in [1i64, 2, 3, 6] {
            let buckets = domain.width().div_ceil(bin_width as usize);
            let rounds = usize::BITS - (buckets - 1).leading_zeros();
            for first in domain.lower..=domain.upper {
                for second in domain.lower..=domain.upper {
                    let scores = [first, second];
                    let expected = clear_result(&scores, 0, domain, bin_width);
                    assert_eq!(
                        clear_binary_search_bucket(&scores, domain, bin_width, rounds),
                        expected.bucket,
                        "bin={bin_width}, scores={scores:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn first_template_wins_a_quantized_tie_even_if_its_exact_score_is_larger() {
        let domain = ScoreDomain {
            lower: -100,
            upper: 100,
        };
        let result = clear_result(&[-49, -52, 8], -52, domain, 6);
        assert_eq!(result.bucket, 8);
        assert_eq!(result.index, 0);
        assert!(result.matched);
    }

    #[test]
    fn strict_previous_bucket_rejects_the_same_minimum() {
        let domain = ScoreDomain {
            lower: -100,
            upper: 100,
        };
        let accepted = clear_result(&[-49, -52, 8], -52, domain, 6);
        let rejected = clear_result(&[-49, -52, 8], -53, domain, 6);
        assert!(accepted.matched);
        assert!(!rejected.matched);
    }

    #[test]
    fn final_code_lut_is_and_not_xor() {
        let index = 37;
        // (winner, accept) -> valore visto dalla LUT a p=16 -> codice applicativo.
        assert_eq!(code_lut_value(0, index), 0); // 00
        assert_eq!(code_lut_value(2, index), 0); // 10
        assert_eq!(code_lut_value(2, index), 0); // 01
        assert_eq!(code_lut_value(4, index), (index + 1) as u64); // 11
    }

    #[test]
    fn periodic_fold_preserves_inclusive_sign_over_padded_domain() {
        for difference in -MAX_PERIODIC_RADIUS..=MAX_PERIODIC_RADIUS {
            let folded = folded_clear_doubled(difference);
            assert_eq!(folded < 0, difference <= 0, "difference={difference}");
            assert!(folded.abs() < 1 << (64 - LOG_SCORE_DELTA));
        }
    }

    #[test]
    fn adversarial_cases_cover_accept_reject_and_non_exact_first_minimum() {
        let scene = load_scene(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/results/scena_reale_q3.txt"
        ));
        for n in [64usize, 128] {
            let domain = analytic_domain(&scene, n, 3);
            let case = adversarial_case(n, domain, 6, 10);
            let result = clear_result(&case.scores, case.threshold, domain, 6);
            assert_eq!(result.index, n / 2);
            assert_eq!(result.matched, n == 64);
            assert!(case.scores[n / 2] > case.scores[n / 2 + 1]);
            assert_eq!(
                domain.bucket(case.scores[n / 2], 6),
                domain.bucket(case.scores[n / 2 + 1], 6)
            );
        }
    }
}
