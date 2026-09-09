//! Benchmark del core riusabile `pipeline_tfhe_rs::private_argmin`.
//!
//! Questo binario contiene soltanto I/O della scena, cifratura client del probe impacchettato,
//! oracolo clear e decifratura dell'unico codice finale. Tutto il percorso server TFHE misurato e'
//! quello condiviso in `src/private_argmin.rs`.

use pipeline_tfhe_rs::{
    cauchy_score_domain, clear_private_argmin, expected_pbs_count_for_thresholds, private_argmin,
    TemplateView, CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET,
    PROBE_DIM, PROBE_NORM2_MAX,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const Q_PROBE_MAX: i64 = 3;

#[derive(Clone)]
struct Scene {
    gallery: Vec<Vec<i64>>,
    norm2: Vec<i64>,
    probes: Vec<Vec<i64>>,
    threshold: i64,
}

#[derive(Clone, Copy)]
enum CaseKind {
    SceneThreshold,
    WinnerStrictRegression,
    WinnerPermissive,
    LastWinnerPermissive,
    FirstTieStrictRegression,
    AllBelowDomain,
}

impl CaseKind {
    fn name(self) -> &'static str {
        match self {
            Self::SceneThreshold => "scene_threshold",
            Self::WinnerStrictRegression => "winner_strict_farther_permissive",
            Self::WinnerPermissive => "winner_permissive",
            Self::LastWinnerPermissive => "last_winner_permissive",
            Self::FirstTieStrictRegression => "first_tie_strict_later_permissive",
            Self::AllBelowDomain => "all_thresholds_below_domain",
        }
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
    assert!(header.len() >= 4);
    let dim = header[0] as usize;
    let gallery_size = header[1] as usize;
    let probe_count = header[2] as usize;
    let threshold = header[3];
    assert_eq!(dim, PROBE_DIM);
    let gallery: Vec<Vec<i64>> = (0..gallery_size)
        .map(|_| {
            rows.next()
                .expect("galleria troncata")
                .split_whitespace()
                .map(|value| value.parse().expect("template non numerico"))
                .collect()
        })
        .collect();
    assert!(gallery.iter().all(|template| template.len() == PROBE_DIM));
    let probes = (0..probe_count)
        .map(|_| {
            let row: Vec<i64> = rows
                .next()
                .expect("probe troncati")
                .split_whitespace()
                .map(|value| value.parse().expect("probe non numerico"))
                .collect();
            assert_eq!(row.len(), PROBE_DIM + 1);
            row[1..].to_vec()
        })
        .collect();
    let norm2 = gallery
        .iter()
        .map(|template| template.iter().map(|value| value * value).sum())
        .collect();
    Scene {
        gallery,
        norm2,
        probes,
        threshold,
    }
}

fn clear_scores(scene: &Scene, n: usize, probe: &[i64]) -> Vec<i64> {
    (0..n)
        .map(|index| {
            scene.norm2[index]
                - 2 * scene.gallery[index]
                    .iter()
                    .zip(probe)
                    .map(|(gallery, query)| gallery * query)
                    .sum::<i64>()
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
) -> GlweCiphertextOwned<u64> {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(probe
        .iter()
        .all(|value| (-Q_PROBE_MAX..=Q_PROBE_MAX).contains(value)));
    assert!(probe.iter().map(|value| value * value).sum::<i64>() <= PROBE_NORM2_MAX);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + 2 * PROBE_DIM - 2 < polynomial_size.0);
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let mut plaintext = vec![0u64; polynomial_size.0];
    for (index, value) in probe.iter().copied().enumerate() {
        plaintext[index] = (value as u64).wrapping_mul(full_delta);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + index] = (value as u64).wrapping_mul(low_delta);
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

fn argument<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|argument| argument == name)
        .map(|index| {
            args.get(index + 1)
                .unwrap_or_else(|| panic!("manca il valore di {name}"))
                .parse()
                .unwrap_or_else(|_| panic!("valore non valido per {name}"))
        })
        .unwrap_or(default)
}

fn selected_sizes(args: &[String]) -> Vec<usize> {
    let value = args
        .iter()
        .position(|argument| argument == "--sizes")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or("both");
    if value == "both" {
        return vec![64, 128];
    }
    let sizes: Vec<usize> = value
        .split(',')
        .map(|part| {
            let size: usize = part
                .parse()
                .unwrap_or_else(|_| panic!("--sizes non valido: {value}"));
            assert!(
                (1..=128).contains(&size),
                "--sizes fuori da 1..=128: {size}"
            );
            size
        })
        .collect();
    assert!(!sizes.is_empty());
    sizes
}

fn selected_cases(args: &[String]) -> Vec<CaseKind> {
    match args
        .iter()
        .position(|argument| argument == "--cases")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or("real")
    {
        "real" => vec![CaseKind::SceneThreshold],
        "adversarial" => vec![CaseKind::WinnerStrictRegression],
        "accept" => vec![CaseKind::WinnerPermissive],
        "last" => vec![CaseKind::LastWinnerPermissive],
        "edges" => vec![
            CaseKind::WinnerStrictRegression,
            CaseKind::LastWinnerPermissive,
        ],
        "tie" => vec![CaseKind::FirstTieStrictRegression],
        "reject" => vec![CaseKind::AllBelowDomain],
        "both" => vec![CaseKind::SceneThreshold, CaseKind::WinnerStrictRegression],
        "all" => vec![
            CaseKind::SceneThreshold,
            CaseKind::WinnerStrictRegression,
            CaseKind::WinnerPermissive,
            CaseKind::LastWinnerPermissive,
            CaseKind::FirstTieStrictRegression,
            CaseKind::AllBelowDomain,
        ],
        value => panic!("--cases non valido: {value}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|argument| argument == "--run") {
        eprintln!(
            "usage: argmin_bucket_bits_periodic --run \
             [--keys N] [--cases real|adversarial|accept|last|edges|tie|reject|both|all] \
             [--real-probes N] [--sizes 1..128[,N...]|both] [--scene FILE] [--allow-slow]"
        );
        return;
    }
    let key_runs: usize = argument(&args, "--keys", 1);
    let probe_count: usize = argument(&args, "--real-probes", 1);
    let require_under_ten = !args.iter().any(|argument| argument == "--allow-slow");
    let sizes = selected_sizes(&args);
    let cases = selected_cases(&args);
    let scene_path = args
        .iter()
        .position(|argument| argument == "--scene")
        .and_then(|index| args.get(index + 1))
        .cloned()
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    assert!(key_runs > 0 && probe_count > 0);
    let scene = load_scene(&scene_path);
    assert!(scene.gallery.len() >= *sizes.iter().max().unwrap());
    assert!(scene.probes.len() >= probe_count);

    println!(
        "CONFIG,core=pipeline_tfhe_rs::private_argmin,params=V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64,full_delta_log={},low_delta_log={},code_delta_log={},probe_norm2_max={},output=zero_reject_or_index_plus_one",
        FULL_DELTA_LOG,
        LOW_MOD16_DELTA_LOG,
        CODE_DELTA_LOG,
        PROBE_NORM2_MAX,
    );
    println!(
        "RESULT,key,case,probe,N,expected_code,actual_code,correct,setup_s,score_s,extract_s,select_s,scan_s,threshold_s,output_s,total_s,pbs_count,expected_pbs,under_10s"
    );
    let modulus = CiphertextModulus::<u64>::new_native();
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let mut all_correct = true;
    let mut all_under_ten = true;

    for key_run in 1..=key_runs {
        for &n in &sizes {
            let key_started = Instant::now();
            let client_key = ClientKey::new(PARAMS);
            let server_key = ServerKey::new(&client_key);
            let (glwe_secret_key, _, client_params) = client_key.into_raw_parts();
            let big_secret_key = glwe_secret_key.as_lwe_secret_key();
            let polynomial_size = glwe_secret_key.polynomial_size();
            let mut seeder_box = new_seeder();
            let seeder = seeder_box.as_mut();
            let mut generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            println!(
                "KEY,key={},N={},generation_s={:.6}",
                key_run,
                n,
                key_started.elapsed().as_secs_f64()
            );

            for probe_index in 0..probe_count {
                let probe = &scene.probes[probe_index];
                let scores = clear_scores(&scene, n, probe);
                let winner = scores
                    .iter()
                    .enumerate()
                    .min_by_key(|(index, score)| (**score, *index))
                    .map(|(index, _)| index)
                    .unwrap();
                for case in &cases {
                    let mut gallery_indices: Vec<usize> = (0..n).collect();
                    if matches!(case, CaseKind::LastWinnerPermissive) {
                        gallery_indices.swap(winner, n - 1);
                    }
                    if matches!(case, CaseKind::FirstTieStrictRegression) && n > 1 {
                        gallery_indices[0] = winner;
                        gallery_indices[1] = winner;
                    }
                    let case_scores: Vec<i64> =
                        gallery_indices.iter().map(|index| scores[*index]).collect();
                    let case_winner = case_scores
                        .iter()
                        .enumerate()
                        .min_by_key(|(index, score)| (**score, *index))
                        .map(|(index, _)| index)
                        .unwrap();
                    let thresholds = match case {
                        CaseKind::SceneThreshold => vec![scene.threshold; n],
                        CaseKind::WinnerStrictRegression => {
                            let mut values = vec![i64::MAX; n];
                            values[case_winner] = case_scores[case_winner].saturating_sub(1);
                            values
                        }
                        CaseKind::WinnerPermissive | CaseKind::LastWinnerPermissive => {
                            vec![i64::MAX; n]
                        }
                        CaseKind::FirstTieStrictRegression => {
                            let mut values = vec![i64::MAX; n];
                            values[case_winner] = case_scores[case_winner].saturating_sub(1);
                            values
                        }
                        CaseKind::AllBelowDomain => vec![i64::MIN; n],
                    };
                    let templates: Vec<_> = (0..n)
                        .map(|index| TemplateView {
                            template: &scene.gallery[gallery_indices[index]],
                            norm2: scene.norm2[gallery_indices[index]],
                            threshold: thresholds[index],
                        })
                        .collect();
                    let domain = cauchy_score_domain(&templates).expect("dominio galleria");
                    let expected =
                        clear_private_argmin(&case_scores, &templates).expect("oracolo clear");
                    let packed_probe = encrypt_packed_probe(
                        probe,
                        &glwe_secret_key,
                        client_params.glwe_noise_distribution(),
                        polynomial_size,
                        modulus,
                        &mut generator,
                    );
                    let output = private_argmin(&server_key, &packed_probe, &templates, domain)
                        .expect("core private_argmin");
                    let actual_code = decrypt_lwe_ciphertext(&big_secret_key, &output.code)
                        .0
                        .wrapping_add(code_delta >> 1)
                        >> CODE_DELTA_LOG;
                    let expected_pbs =
                        expected_pbs_count_for_thresholds(n, &thresholds, domain).unwrap();
                    let correct = actual_code == expected.code
                        && output.metrics.total_pbs_count == expected_pbs;
                    let under_ten = output.metrics.total_seconds < 10.0;
                    all_correct &= correct;
                    all_under_ten &= under_ten;
                    println!(
                        "RESULT,{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{}",
                        key_run,
                        case.name(),
                        probe_index,
                        n,
                        expected.code,
                        actual_code,
                        correct,
                        output.metrics.setup.seconds,
                        output.metrics.score.seconds,
                        output.metrics.extract.seconds,
                        output.metrics.select.seconds,
                        output.metrics.scan.seconds,
                        output.metrics.threshold.seconds,
                        output.metrics.output.seconds,
                        output.metrics.total_seconds,
                        output.metrics.total_pbs_count,
                        expected_pbs,
                        under_ten,
                    );
                }
            }
        }
    }

    println!(
        "SUMMARY,all_correct={},all_under_10s={},time_gate_enforced={},same_core=true,no_distance_output=true",
        all_correct, all_under_ten, require_under_ten
    );
    if !all_correct || (require_under_ten && !all_under_ten) {
        std::process::exit(1);
    }
}
