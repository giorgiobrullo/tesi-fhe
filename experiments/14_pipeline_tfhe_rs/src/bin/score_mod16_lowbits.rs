//! Audit isolato del canale esatto per i tre bit bassi del punteggio.
//!
//! Il punteggio traslato
//! `x = (||g||^2 - L) - 2 <g,q>` viene valutato una seconda volta nel toro. Con
//! `Delta=2^60` l'aritmetica lineare produce direttamente `x mod 16`; con
//! `Delta=2^61` produce `x mod 8` con il doppio del margine tra messaggi. I bit sono
//! estratti tramite l'API ufficiale WoP-PBS di tfhe-rs e ricodificati in bit booleani
//! `{0,2^60}` con un PBS il cui ingresso e' spostato di `q/8`, lontano dalle
//! discontinuita' negacicliche.
//!
//! Viene inoltre provato un layout a singolo GLWE: il probe a `Delta=2^51` occupa i
//! coefficienti `0..511`, mentre quello a `Delta=2^60` occupa `1024..1535`. Un solo
//! prodotto per il polinomio della galleria restituisce i due prodotti scalari ai gradi
//! 511 e 1535. I supporti risultanti `0..1022` e `1024..2046` non si sovrappongono e
//! non fanno wrap nel polinomio di taglia 2048.
//!
//! Nessun codice dell'estrattore e' copiato: questo harness chiama l'API pubblica
//! `extract_bits_from_lwe_ciphertext_mem_optimized` di tfhe-rs 0.11.

use dyn_stack::{GlobalPodBuffer, PodStack};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::time::Instant;
use tfhe::core_crypto::algorithms::lwe_wopbs::{
    extract_bits_from_lwe_ciphertext_mem_optimized,
    extract_bits_from_lwe_ciphertext_mem_optimized_requirement,
};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const SCORE_DIM: usize = 512;
const FULL_LOG_DELTA: u32 = 51;
const BOOL_LOG_DELTA: u32 = 60;
const BOOL_DELTA: u64 = 1u64 << BOOL_LOG_DELTA;
const PACKED_LOW_OFFSET: usize = 1024;
const FULL_SAMPLE_DEGREE: usize = SCORE_DIM - 1;
const PACKED_LOW_SAMPLE_DEGREE: usize = PACKED_LOW_OFFSET + SCORE_DIM - 1;
const Q_PROBE_DEFAULT: i64 = 3;
const PADDED_DOMAIN_WIDTH: i64 = 1 << 13;

type Lwe = LweCiphertextOwned<u64>;

#[derive(Clone, Copy, Debug)]
struct Channel {
    name: &'static str,
    bits: usize,
    log_delta: u32,
}

const MOD16: Channel = Channel {
    name: "fresh_mod16",
    bits: 4,
    log_delta: 60,
};
const MOD8: Channel = Channel {
    name: "fresh_mod8",
    bits: 3,
    log_delta: 61,
};

#[derive(Clone)]
struct Scene {
    gallery: Vec<Vec<i64>>,
    squared_norms: Vec<i64>,
    probes: Vec<Vec<i64>>,
}

struct BridgeOutput {
    extracted_msb_first: LweCiphertextListOwned<u64>,
    low_bits_msb_first: Vec<Lwe>,
}

#[derive(Default)]
struct AuditStats {
    values: usize,
    raw_bits: usize,
    raw_errors: usize,
    low_bits: usize,
    low_errors: usize,
    max_recode_phase_error: u64,
    failures: Vec<String>,
}

impl AuditStats {
    fn merge(&mut self, other: Self) {
        self.values += other.values;
        self.raw_bits += other.raw_bits;
        self.raw_errors += other.raw_errors;
        self.low_bits += other.low_bits;
        self.low_errors += other.low_errors;
        self.max_recode_phase_error = self
            .max_recode_phase_error
            .max(other.max_recode_phase_error);
        let remaining = 20usize.saturating_sub(self.failures.len());
        self.failures
            .extend(other.failures.into_iter().take(remaining));
    }

    fn correct(&self) -> bool {
        self.raw_errors == 0 && self.low_errors == 0
    }
}

fn argument<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|argument| argument == name)
        .map(|index| {
            args.get(index + 1)
                .unwrap_or_else(|| panic!("valore mancante per {name}"))
                .parse()
                .unwrap_or_else(|_| panic!("valore non valido per {name}"))
        })
        .unwrap_or(default)
}

fn load_scene(path: &str) -> Scene {
    let text = std::fs::read_to_string(path).expect("manca la scena reale");
    let mut rows = text.lines();
    let header: Vec<i64> = rows
        .next()
        .expect("scena vuota")
        .split_whitespace()
        .map(|value| value.parse().expect("header non numerico"))
        .collect();
    assert!(header.len() >= 3);
    let (dim, gallery_size, probe_count) = (
        usize::try_from(header[0]).unwrap(),
        usize::try_from(header[1]).unwrap(),
        usize::try_from(header[2]).unwrap(),
    );
    assert_eq!(dim, SCORE_DIM);
    let gallery: Vec<Vec<i64>> = (0..gallery_size)
        .map(|_| {
            let row: Vec<i64> = rows
                .next()
                .expect("galleria troncata")
                .split_whitespace()
                .map(|value| value.parse().expect("template non numerico"))
                .collect();
            assert_eq!(row.len(), dim);
            row
        })
        .collect();
    let probes: Vec<Vec<i64>> = (0..probe_count)
        .map(|_| {
            let row: Vec<i64> = rows
                .next()
                .expect("probe troncati")
                .split_whitespace()
                .map(|value| value.parse().expect("probe non numerico"))
                .collect();
            assert_eq!(row.len(), dim + 1);
            row[1..].to_vec()
        })
        .collect();
    let squared_norms = gallery
        .iter()
        .map(|template| template.iter().map(|value| value * value).sum())
        .collect();
    Scene {
        gallery,
        squared_norms,
        probes,
    }
}

fn analytic_domain(scene: &Scene, n: usize, q_probe: i64) -> (i64, i64) {
    (0..n)
        .map(|index| {
            let l1: i64 = scene.gallery[index].iter().map(|value| value.abs()).sum();
            let radius = 2 * q_probe * l1;
            (
                scene.squared_norms[index] - radius,
                scene.squared_norms[index] + radius,
            )
        })
        .fold((i64::MAX, i64::MIN), |(lower, upper), (lo, hi)| {
            (lower.min(lo), upper.max(hi))
        })
}

fn clear_score(scene: &Scene, identity: usize, probe: &[i64]) -> i64 {
    scene.squared_norms[identity]
        - 2 * scene.gallery[identity]
            .iter()
            .zip(probe)
            .map(|(gallery_value, probe_value)| gallery_value * probe_value)
            .sum::<i64>()
}

fn torus_encode(value: i64, log_delta: u32) -> u64 {
    (value as u64).wrapping_mul(1u64 << log_delta)
}

fn torus_distance(left: u64, right: u64) -> u64 {
    let forward = left.wrapping_sub(right);
    forward.min(forward.wrapping_neg())
}

fn boundary_points() -> Vec<i64> {
    let mut points = BTreeSet::new();
    points.extend(-33..=33);
    for center in [64i64, 128, 256, 512, 1024, 2048, 4096, 8191, 8192] {
        for offset in -2..=2 {
            points.insert(center + offset);
            points.insert(-center + offset);
        }
    }
    points.into_iter().collect()
}

fn extract_official_bits(
    input: &Lwe,
    channel: Channel,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
) -> LweCiphertextListOwned<u64> {
    let fft = Fft::new(fourier_bootstrap_key.polynomial_size());
    let fft = fft.as_view();
    let requirement = extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
        input.lwe_size().to_lwe_dimension(),
        key_switching_key.output_key_lwe_dimension(),
        fourier_bootstrap_key.glwe_size(),
        fourier_bootstrap_key.polynomial_size(),
        fft,
    )
    .unwrap();
    let mut memory = GlobalPodBuffer::new(requirement);
    let mut output = LweCiphertextListOwned::new(
        0u64,
        key_switching_key.output_lwe_size(),
        LweCiphertextCount(channel.bits),
        input.ciphertext_modulus(),
    );
    extract_bits_from_lwe_ciphertext_mem_optimized(
        input,
        &mut output,
        fourier_bootstrap_key,
        key_switching_key,
        DeltaLog(channel.log_delta as usize),
        ExtractedBitsCount(channel.bits),
        fft,
        PodStack::new(&mut memory),
    );
    output
}

fn recode_extracted_bit(
    input: LweCiphertextView<'_, u64>,
    accumulator: &GlweCiphertextOwned<u64>,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    large_size: LweSize,
    modulus: CiphertextModulus<u64>,
) -> Lwe {
    // L'estrattore restituisce 0 o q/2. Lo shift q/8 colloca i due ingressi a q/8 e
    // 5q/8, quindi a distanza q/8 dalle discontinuita' della LUT negaciclica.
    let mut shifted = LweCiphertextOwned::from_container(input.as_ref().to_vec(), modulus);
    lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(1u64 << 61));
    let mut output = LweCiphertext::new(0u64, large_size, modulus);
    programmable_bootstrap_lwe_ciphertext(
        &shifted,
        &mut output,
        accumulator,
        fourier_bootstrap_key,
    );
    lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(BOOL_DELTA >> 1));
    output
}

fn bridge_one(
    score: &Lwe,
    channel: Channel,
    recode_accumulator: &GlweCiphertextOwned<u64>,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    large_size: LweSize,
    modulus: CiphertextModulus<u64>,
) -> BridgeOutput {
    let extracted_msb_first =
        extract_official_bits(score, channel, fourier_bootstrap_key, key_switching_key);
    let low_start = channel.bits - 3;
    let low_bits_msb_first = extracted_msb_first
        .iter()
        .skip(low_start)
        .map(|bit| {
            recode_extracted_bit(
                bit,
                recode_accumulator,
                fourier_bootstrap_key,
                large_size,
                modulus,
            )
        })
        .collect();
    BridgeOutput {
        extracted_msb_first,
        low_bits_msb_first,
    }
}

fn encrypt_direct_scores(
    points: &[i64],
    channel: Channel,
    large_secret_key: &LweSecretKeyView<'_, u64>,
    noise_distribution: DynamicDistribution<u64>,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Vec<Lwe> {
    points
        .iter()
        .map(|point| {
            allocate_and_encrypt_new_lwe_ciphertext(
                large_secret_key,
                Plaintext(torus_encode(*point, channel.log_delta)),
                noise_distribution,
                modulus,
                generator,
            )
        })
        .collect()
}

fn gallery_polynomial(template: &[i64], polynomial_size: PolynomialSize) -> PolynomialOwned<u64> {
    let mut coefficients = vec![0u64; polynomial_size.0];
    for (coordinate, value) in template.iter().enumerate() {
        coefficients[FULL_SAMPLE_DEGREE - coordinate] = (-2 * value) as u64;
    }
    Polynomial::from_container(coefficients)
}

fn multiply_probe_by_gallery(
    encrypted_probe: &GlweCiphertextOwned<u64>,
    polynomial: &PolynomialOwned<u64>,
) -> GlweCiphertextOwned<u64> {
    let mut product = GlweCiphertextOwned::new(
        0u64,
        encrypted_probe.glwe_size(),
        encrypted_probe.polynomial_size(),
        encrypted_probe.ciphertext_modulus(),
    );
    for (mut output, input) in product
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(encrypted_probe.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_mul_assign(&mut output, &input, polynomial);
    }
    product
}

#[allow(clippy::too_many_arguments)]
fn score_separate_channel(
    scene: &Scene,
    probe: &[i64],
    n: usize,
    lower: i64,
    channel: Channel,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> (Vec<Lwe>, f64, f64) {
    let polynomial_size = glwe_secret_key.polynomial_size();
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, value) in probe.iter().enumerate() {
        plaintext[coordinate] = torus_encode(*value, channel.log_delta);
    }
    let encryption_started = Instant::now();
    let mut encrypted_probe = GlweCiphertextOwned::new(0u64, glwe_size, polynomial_size, modulus);
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted_probe,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    let encryption_s = encryption_started.elapsed().as_secs_f64();

    let score_started = Instant::now();
    let scores = (0..n)
        .into_par_iter()
        .map(|identity| {
            let polynomial = gallery_polynomial(&scene.gallery[identity], polynomial_size);
            let mut product = multiply_probe_by_gallery(&encrypted_probe, &polynomial);
            let constant = scene.squared_norms[identity] - lower;
            let mut body_view = product.get_mut_body();
            let body = body_view.as_mut();
            body[FULL_SAMPLE_DEGREE] =
                body[FULL_SAMPLE_DEGREE].wrapping_add(torus_encode(constant, channel.log_delta));
            let mut score = LweCiphertext::new(
                0u64,
                glwe_secret_key
                    .glwe_dimension()
                    .to_equivalent_lwe_dimension(polynomial_size)
                    .to_lwe_size(),
                modulus,
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &product,
                &mut score,
                MonomialDegree(FULL_SAMPLE_DEGREE),
            );
            score
        })
        .collect();
    (scores, encryption_s, score_started.elapsed().as_secs_f64())
}

#[allow(clippy::too_many_arguments)]
fn score_packed_dual_channel(
    scene: &Scene,
    probe: &[i64],
    n: usize,
    lower: i64,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> (Vec<Lwe>, Vec<Lwe>, f64, f64) {
    let polynomial_size = glwe_secret_key.polynomial_size();
    assert_eq!(polynomial_size.0, 2048, "layout verificato per N=2048");
    assert!(PACKED_LOW_SAMPLE_DEGREE + FULL_SAMPLE_DEGREE < polynomial_size.0);
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, value) in probe.iter().enumerate() {
        plaintext[coordinate] = torus_encode(*value, FULL_LOG_DELTA);
        plaintext[PACKED_LOW_OFFSET + coordinate] = torus_encode(*value, MOD16.log_delta);
    }
    let encryption_started = Instant::now();
    let mut encrypted_probe = GlweCiphertextOwned::new(0u64, glwe_size, polynomial_size, modulus);
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted_probe,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    let encryption_s = encryption_started.elapsed().as_secs_f64();

    let score_started = Instant::now();
    let pairs: Vec<(Lwe, Lwe)> = (0..n)
        .into_par_iter()
        .map(|identity| {
            let polynomial = gallery_polynomial(&scene.gallery[identity], polynomial_size);
            let mut product = multiply_probe_by_gallery(&encrypted_probe, &polynomial);
            let constant = scene.squared_norms[identity] - lower;
            let mut body_view = product.get_mut_body();
            let body = body_view.as_mut();
            body[FULL_SAMPLE_DEGREE] =
                body[FULL_SAMPLE_DEGREE].wrapping_add(torus_encode(constant, FULL_LOG_DELTA));
            body[PACKED_LOW_SAMPLE_DEGREE] = body[PACKED_LOW_SAMPLE_DEGREE]
                .wrapping_add(torus_encode(constant, MOD16.log_delta));
            let large_size = glwe_secret_key
                .glwe_dimension()
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size();
            let mut full_score = LweCiphertext::new(0u64, large_size, modulus);
            let mut low_score = LweCiphertext::new(0u64, large_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &product,
                &mut full_score,
                MonomialDegree(FULL_SAMPLE_DEGREE),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &product,
                &mut low_score,
                MonomialDegree(PACKED_LOW_SAMPLE_DEGREE),
            );
            (full_score, low_score)
        })
        .collect();
    let (full_scores, low_scores) = pairs.into_iter().unzip();
    (
        full_scores,
        low_scores,
        encryption_s,
        score_started.elapsed().as_secs_f64(),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|argument| argument == "--run") {
        eprintln!(
            "usage: score_mod16_lowbits --run [--keys N] [--n N] [--probes N] \
             [--scene FILE] [--q-probe Q]"
        );
        return;
    }
    let key_runs: usize = argument(&args, "--keys", 3);
    let n: usize = argument(&args, "--n", 128);
    let probe_count: usize = argument(&args, "--probes", 4);
    let q_probe: i64 = argument(&args, "--q-probe", Q_PROBE_DEFAULT);
    let scene_path = args
        .iter()
        .position(|argument| argument == "--scene")
        .map(|index| args[index + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").to_string());
    assert!(key_runs > 0 && n > 0 && probe_count > 0 && q_probe >= 0);

    let scene = load_scene(&scene_path);
    assert!(scene.gallery.len() >= n && scene.probes.len() >= probe_count);
    assert!(scene
        .probes
        .iter()
        .take(probe_count)
        .flatten()
        .all(|value| value.abs() <= q_probe));
    let (lower, upper) = analytic_domain(&scene, n, q_probe);
    assert!(upper - lower < PADDED_DOMAIN_WIDTH);

    for value in -32768i64..=32767 {
        for channel in [MOD16, MOD8] {
            let modulus = 1i64 << channel.bits;
            let expected = (value.rem_euclid(modulus) as u64) << channel.log_delta;
            assert_eq!(torus_encode(value, channel.log_delta), expected);
        }
    }

    println!(
        "CONFIG,params=V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64,log2_p_fail={},keys={},N={},probes={},domain_L={},domain_U={},domain_width={},direct_points={},recode=official_q_over_2_to_bool_q_over_16_shift,packed=delta51_at_0_511_delta60_at_1024_1535",
        PARAMS.log2_p_fail,
        key_runs,
        n,
        probe_count,
        lower,
        upper,
        upper - lower + 1,
        boundary_points().len(),
    );
    println!(
        "RESULT,key,mode,source,values,raw_bits,raw_errors,low_bits,low_errors,encrypt_s,score_s,bridge_s,input_phase_error_max,input_half_step,input_headroom,recode_phase_error_max,correct"
    );

    let points = boundary_points();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut globally_correct = true;

    for key_run in 1..=key_runs {
        let key_started = Instant::now();
        let client_key = ClientKey::new(PARAMS);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, small_secret_key, client_params) = client_key.into_raw_parts();
        let large_secret_key = glwe_secret_key.as_lwe_secret_key();
        let key_switching_key = &server_key.key_switching_key;
        let fourier_bootstrap_key = match &server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key,
            _ => panic!("attesa bootstrapping key classica"),
        };
        let polynomial_size = fourier_bootstrap_key.polynomial_size();
        assert_eq!(polynomial_size.0, 2048, "il layout packed richiede N=2048");
        let glwe_size = fourier_bootstrap_key.glwe_size();
        let large_size = large_secret_key.lwe_dimension().to_lwe_size();
        let recode_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::new(
                (BOOL_DELTA >> 1).wrapping_neg(),
                PlaintextCount(polynomial_size.0),
            ),
            modulus,
        );
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        println!(
            "KEY,key={},generation_s={:.6},polynomial_size={},large_lwe_dimension={},small_lwe_dimension={}",
            key_run,
            key_started.elapsed().as_secs_f64(),
            polynomial_size.0,
            large_size.to_lwe_dimension().0,
            key_switching_key.output_key_lwe_dimension().0,
        );

        let decode_raw = |ciphertext: LweCiphertextView<'_, u64>| -> u64 {
            let phase = decrypt_lwe_ciphertext(&small_secret_key, &ciphertext).0;
            let decomposer =
                SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));
            decomposer.closest_representable(phase) >> 63
        };
        let decode_bool = |ciphertext: &Lwe, expected: u64| -> (u64, u64) {
            let phase = decrypt_lwe_ciphertext(&large_secret_key, ciphertext).0;
            let decoded = (phase.wrapping_add(BOOL_DELTA >> 1) >> BOOL_LOG_DELTA) & 1;
            let error = torus_distance(phase, expected * BOOL_DELTA);
            (decoded, error)
        };

        let audit_outputs = |values: &[i64],
                             channel: Channel,
                             outputs: &[BridgeOutput],
                             source: &str|
         -> AuditStats {
            let mut stats = AuditStats::default();
            for (row, (value, output)) in values.iter().zip(outputs).enumerate() {
                stats.values += 1;
                for (position, bit) in output.extracted_msb_first.iter().enumerate() {
                    let bit_index = channel.bits - 1 - position;
                    let expected =
                        ((value.rem_euclid(1i64 << channel.bits) as u64) >> bit_index) & 1;
                    let actual = decode_raw(bit);
                    stats.raw_bits += 1;
                    if actual != expected {
                        stats.raw_errors += 1;
                        if stats.failures.len() < 20 {
                            stats.failures.push(format!(
                                "source={source} row={row} x={value} raw_bit={bit_index} expected={expected} actual={actual}"
                            ));
                        }
                    }
                }
                for (position, bit) in output.low_bits_msb_first.iter().enumerate() {
                    let bit_index = 2 - position;
                    let expected = ((value.rem_euclid(8) as u64) >> bit_index) & 1;
                    let (actual, phase_error) = decode_bool(bit, expected);
                    stats.low_bits += 1;
                    stats.max_recode_phase_error = stats.max_recode_phase_error.max(phase_error);
                    if actual != expected {
                        stats.low_errors += 1;
                        if stats.failures.len() < 20 {
                            stats.failures.push(format!(
                                "source={source} row={row} x={value} low_bit={bit_index} expected={expected} actual={actual} phase_error={phase_error}"
                            ));
                        }
                    }
                }
            }
            stats
        };

        for channel in [MOD16, MOD8] {
            let direct_encrypt_started = Instant::now();
            let direct_scores = encrypt_direct_scores(
                &points,
                channel,
                &large_secret_key,
                client_params.glwe_noise_distribution(),
                modulus,
                &mut generator,
            );
            let direct_encrypt_s = direct_encrypt_started.elapsed().as_secs_f64();
            let direct_bridge_started = Instant::now();
            let direct_outputs: Vec<_> = direct_scores
                .par_iter()
                .map(|score| {
                    bridge_one(
                        score,
                        channel,
                        &recode_accumulator,
                        fourier_bootstrap_key,
                        key_switching_key,
                        large_size,
                        modulus,
                    )
                })
                .collect();
            let direct_bridge_s = direct_bridge_started.elapsed().as_secs_f64();
            let direct_stats = audit_outputs(&points, channel, &direct_outputs, "direct");
            let input_error_max = direct_scores
                .iter()
                .zip(&points)
                .map(|(score, point)| {
                    torus_distance(
                        decrypt_lwe_ciphertext(&large_secret_key, score).0,
                        torus_encode(*point, channel.log_delta),
                    )
                })
                .max()
                .unwrap_or(0);
            let half_step = 1u64 << (channel.log_delta - 1);
            println!(
                "RESULT,{key_run},{},direct,{},{},{},{},{},{:.6},0.000000,{:.6},{},{},{},{},{}",
                channel.name,
                direct_stats.values,
                direct_stats.raw_bits,
                direct_stats.raw_errors,
                direct_stats.low_bits,
                direct_stats.low_errors,
                direct_encrypt_s,
                direct_bridge_s,
                input_error_max,
                half_step,
                half_step.saturating_sub(input_error_max),
                direct_stats.max_recode_phase_error,
                direct_stats.correct(),
            );
            for failure in &direct_stats.failures {
                println!("FAIL,key={key_run},mode={},{}", channel.name, failure);
            }
            globally_correct &= direct_stats.correct() && input_error_max < half_step;
        }

        for channel in [MOD16, MOD8] {
            let mut aggregate = AuditStats::default();
            let mut encryption_s = 0.0;
            let mut score_s = 0.0;
            let mut bridge_s = 0.0;
            let mut input_error_max = 0u64;
            for probe_index in 0..probe_count {
                // Ogni modo cifra direttamente il probe alla propria Delta. Non viene mai
                // riscalato il ciphertext Delta=2^51, che ne conserverebbe il cattivo SNR.
                let (scores, one_encryption_s, one_score_s) = score_separate_channel(
                    &scene,
                    &scene.probes[probe_index],
                    n,
                    lower,
                    channel,
                    &glwe_secret_key,
                    client_params.glwe_noise_distribution(),
                    modulus,
                    &mut generator,
                );
                encryption_s += one_encryption_s;
                score_s += one_score_s;
                let values: Vec<i64> = (0..n)
                    .map(|identity| {
                        clear_score(&scene, identity, &scene.probes[probe_index]) - lower
                    })
                    .collect();
                for (score, value) in scores.iter().zip(&values) {
                    let phase = decrypt_lwe_ciphertext(&large_secret_key, score).0;
                    input_error_max = input_error_max.max(torus_distance(
                        phase,
                        torus_encode(*value, channel.log_delta),
                    ));
                }
                let bridge_started = Instant::now();
                let outputs: Vec<_> = scores
                    .par_iter()
                    .map(|score| {
                        bridge_one(
                            score,
                            channel,
                            &recode_accumulator,
                            fourier_bootstrap_key,
                            key_switching_key,
                            large_size,
                            modulus,
                        )
                    })
                    .collect();
                bridge_s += bridge_started.elapsed().as_secs_f64();
                aggregate.merge(audit_outputs(
                    &values,
                    channel,
                    &outputs,
                    &format!("real_probe_{probe_index}"),
                ));
            }
            let half_step = 1u64 << (channel.log_delta - 1);
            println!(
                "RESULT,{key_run},{},leveled_real,{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{}",
                channel.name,
                aggregate.values,
                aggregate.raw_bits,
                aggregate.raw_errors,
                aggregate.low_bits,
                aggregate.low_errors,
                encryption_s,
                score_s,
                bridge_s,
                input_error_max,
                half_step,
                half_step.saturating_sub(input_error_max),
                aggregate.max_recode_phase_error,
                aggregate.correct(),
            );
            for failure in &aggregate.failures {
                println!("FAIL,key={key_run},mode={},{}", channel.name, failure);
            }
            globally_correct &= aggregate.correct() && input_error_max < half_step;
        }

        let mut packed_stats = AuditStats::default();
        let mut packed_encryption_s = 0.0;
        let mut packed_score_s = 0.0;
        let mut packed_bridge_s = 0.0;
        let mut packed_full_error_max = 0u64;
        let mut packed_low_error_max = 0u64;
        for probe_index in 0..probe_count {
            let (full_scores, low_scores, encryption_s, score_s) = score_packed_dual_channel(
                &scene,
                &scene.probes[probe_index],
                n,
                lower,
                &glwe_secret_key,
                client_params.glwe_noise_distribution(),
                modulus,
                &mut generator,
            );
            packed_encryption_s += encryption_s;
            packed_score_s += score_s;
            let values: Vec<i64> = (0..n)
                .map(|identity| clear_score(&scene, identity, &scene.probes[probe_index]) - lower)
                .collect();
            for ((full_score, low_score), value) in full_scores.iter().zip(&low_scores).zip(&values)
            {
                packed_full_error_max = packed_full_error_max.max(torus_distance(
                    decrypt_lwe_ciphertext(&large_secret_key, full_score).0,
                    torus_encode(*value, FULL_LOG_DELTA),
                ));
                packed_low_error_max = packed_low_error_max.max(torus_distance(
                    decrypt_lwe_ciphertext(&large_secret_key, low_score).0,
                    torus_encode(*value, MOD16.log_delta),
                ));
            }
            let bridge_started = Instant::now();
            let outputs: Vec<_> = low_scores
                .par_iter()
                .map(|score| {
                    bridge_one(
                        score,
                        MOD16,
                        &recode_accumulator,
                        fourier_bootstrap_key,
                        key_switching_key,
                        large_size,
                        modulus,
                    )
                })
                .collect();
            packed_bridge_s += bridge_started.elapsed().as_secs_f64();
            packed_stats.merge(audit_outputs(
                &values,
                MOD16,
                &outputs,
                &format!("packed_real_probe_{probe_index}"),
            ));
        }
        let packed_half_step = 1u64 << (MOD16.log_delta - 1);
        let full_half_step = 1u64 << (FULL_LOG_DELTA - 1);
        println!(
            "RESULT,{key_run},packed_dual_mod16,leveled_real,{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{}",
            packed_stats.values,
            packed_stats.raw_bits,
            packed_stats.raw_errors,
            packed_stats.low_bits,
            packed_stats.low_errors,
            packed_encryption_s,
            packed_score_s,
            packed_bridge_s,
            packed_low_error_max,
            packed_half_step,
            packed_half_step.saturating_sub(packed_low_error_max),
            packed_stats.max_recode_phase_error,
            packed_stats.correct(),
        );
        println!(
            "PACKED_FULL,key={key_run},values={},phase_error_max={},half_step={},headroom={},correct={}",
            n * probe_count,
            packed_full_error_max,
            full_half_step,
            full_half_step.saturating_sub(packed_full_error_max),
            packed_full_error_max < full_half_step,
        );
        for failure in &packed_stats.failures {
            println!("FAIL,key={key_run},mode=packed_dual_mod16,{failure}");
        }
        globally_correct &= packed_stats.correct()
            && packed_low_error_max < packed_half_step
            && packed_full_error_max < full_half_step;
    }

    println!("SUMMARY,correct={globally_correct}");
    assert!(
        globally_correct,
        "almeno un controllo del bridge low-bit e' fallito"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torus_encoding_is_exact_modulo_eight_and_sixteen() {
        for value in -65536i64..=65535 {
            for channel in [MOD16, MOD8] {
                let residue = value.rem_euclid(1i64 << channel.bits) as u64;
                assert_eq!(
                    torus_encode(value, channel.log_delta),
                    residue << channel.log_delta
                );
            }
        }
    }

    #[test]
    fn packed_convolution_supports_do_not_overlap_or_wrap() {
        let full_probe_support = 0..=SCORE_DIM - 1;
        let low_probe_support = PACKED_LOW_OFFSET..=PACKED_LOW_OFFSET + SCORE_DIM - 1;
        let gallery_support = 0..=SCORE_DIM - 1;
        let full_product = (
            full_probe_support.start() + gallery_support.start(),
            full_probe_support.end() + gallery_support.end(),
        );
        let low_product = (
            low_probe_support.start() + gallery_support.start(),
            low_probe_support.end() + gallery_support.end(),
        );
        assert_eq!(full_product, (0, 1022));
        assert_eq!(low_product, (1024, 2046));
        assert!(full_product.1 < low_product.0);
        assert!(low_product.1 < 2048);
        assert_eq!(FULL_SAMPLE_DEGREE, 511);
        assert_eq!(PACKED_LOW_SAMPLE_DEGREE, 1535);
    }

    #[test]
    fn boundary_set_covers_every_low_residue() {
        let points = boundary_points();
        for modulus in [8i64, 16] {
            let residues: BTreeSet<_> = points
                .iter()
                .map(|value| value.rem_euclid(modulus))
                .collect();
            assert_eq!(residues.len(), modulus as usize);
        }
    }
}
