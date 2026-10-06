//! A73: causally paired A62/A66 component benchmark.
//!
//! The binary is dry by default. `--run` requires hash-pinned scene, schedule and binary inputs,
//! generates one fresh A44 key per block, encrypts every query before timing, and evaluates A62
//! and A66 sequentially against the exact same immutable key, gallery and packed GLWE object.

use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const GALLERY_SIZE: usize = 127;
const DIMENSION: usize = 512;
const THRESHOLD: i64 = 4;
const EXPECTED_BR: u64 = 3_390;
const EXPECTED_KS: u64 = 3_009;
const EXPECTED_MARGINALS: u64 = 3_930;
const DEFAULT_TARGET_COMPONENT: &str = "target-a73-only";
const EPHEMERAL_TARGET_PREFIX: &str = "a73-isolated-target-";

const A62_PRIVATE: &[u8] =
    include_bytes!("../../a62-a53-a44-integrated-prototype/src/private_argmin.rs");
const A62_FHE: &[u8] = include_bytes!("../../a62-a53-a44-integrated-prototype/src/a53_scan/fhe.rs");
const A62_SCAN: &[u8] = include_bytes!("../../a62-a53-a44-integrated-prototype/src/a53_scan.rs");
const A62_LOCK: &[u8] = include_bytes!("../../a62-a53-a44-integrated-prototype/Cargo.lock");
const A66_PRIVATE: &[u8] =
    include_bytes!("../../a66-a62-latency-ready-prototype/src/private_argmin.rs");
const A66_FHE: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs");
const A66_SCAN: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/src/a53_scan.rs");
const A66_LOCK: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/Cargo.lock");

const SOURCE_GUARDS: &[(&str, &[u8], &str)] = &[
    (
        "a62_private",
        A62_PRIVATE,
        "69049071d6c72b32d2db8cbe2f9972ec61c06266382f448f5a199c49b3b5fbab",
    ),
    (
        "a62_fhe",
        A62_FHE,
        "a4dfbc7cd15bdc65ee699847b46147a0614bceccbdeb5317226103f7ffa68f9e",
    ),
    (
        "a62_scan",
        A62_SCAN,
        "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
    ),
    (
        "a62_lock",
        A62_LOCK,
        "52106bfed75fdf616971a0f0d1f3699cc6f34b410cf80557cb20669d72f1bbd1",
    ),
    (
        "a66_private",
        A66_PRIVATE,
        "92289e44e9c26c3190ac61c16c50e0e338bc9399d19fbf9231dacd50a6c3102b",
    ),
    (
        "a66_fhe",
        A66_FHE,
        "ad70a676fbce8e1f58b5d40a151d1ce186b0b90527c8cc50c3b9f9873cb85a99",
    ),
    (
        "a66_scan",
        A66_SCAN,
        "81752a5da894797faeecda02c4fff3ad5aba93efde60a400dd1c36304e4940a5",
    ),
    (
        "a66_lock",
        A66_LOCK,
        "b1d93f4a90df0b5a4fee8dabad7c71764e265f299a2baf3923d1aace76c6ab78",
    ),
];

type Glwe = GlweCiphertextOwned<u64>;
type Lwe = LweCiphertextOwned<u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairOrder {
    A62A66,
    A66A62,
}

impl PairOrder {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "A62_A66" => Ok(Self::A62A66),
            "A66_A62" => Ok(Self::A66A62),
            _ => Err(format!("ordine coppia sconosciuto: {value}")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::A62A66 => "A62_A66",
            Self::A66A62 => "A66_A62",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Warmup,
    Measured,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "warmup" => Ok(Self::Warmup),
            "measured" => Ok(Self::Measured),
            _ => Err(format!("fase sconosciuta: {value}")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Measured => "measured",
        }
    }

    fn included(self) -> bool {
        self == Self::Measured
    }
}

#[derive(Clone, Debug)]
struct ProbeSpec {
    slot: usize,
    source_index: usize,
    expected_min_score: i64,
    expected_argmin: usize,
    expected_code: u64,
    vector: Vec<i64>,
}

#[derive(Clone, Debug)]
struct Scene {
    gallery: Vec<Vec<i64>>,
    threshold: i64,
    probes: Vec<ProbeSpec>,
}

#[derive(Clone, Debug)]
struct ScheduleRow {
    pair_sequence: usize,
    block: usize,
    phase: Phase,
    phase_position: usize,
    probe_slot: usize,
    repetition: usize,
    pair_order: PairOrder,
}

#[derive(Clone, Debug)]
struct Schedule {
    stage: String,
    rows: Vec<ScheduleRow>,
}

#[derive(Debug)]
struct Args {
    run: bool,
    scene: Option<PathBuf>,
    schedule: Option<PathBuf>,
    expected_scene_sha256: Option<String>,
    expected_schedule_sha256: Option<String>,
    expected_binary_sha256: Option<String>,
    threads: usize,
}

#[derive(Debug)]
struct PairInput {
    row: ScheduleRow,
    input_sha256: String,
    packed_probe: Glwe,
}

#[derive(Debug)]
struct TimedA62 {
    wall_s: f64,
    output: Result<a62::A62PrivateArgminOutput, a62::PrivateArgminError>,
}

#[derive(Debug)]
struct TimedA66 {
    wall_s: f64,
    output: Result<a66::A62PrivateArgminOutput, a66::PrivateArgminError>,
}

#[derive(Debug)]
struct RawPairOutcome {
    row: ScheduleRow,
    input_sha256: String,
    a62: TimedA62,
    a66: TimedA66,
}

fn sha256_bytes(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|payload| sha256_bytes(&payload))
        .map_err(|error| format!("lettura hash {}: {error}", path.display()))
}

fn verify_embedded_sources() -> Result<(), String> {
    for (label, payload, expected) in SOURCE_GUARDS {
        let actual = sha256_bytes(payload);
        if actual != *expected {
            return Err(format!("source guard {label}: {actual} != {expected}"));
        }
    }
    if a62::a53_scan::fhe::A62_EXPERIMENT_ACK
        != "A62_INTEGRATED_UNVALIDATED_FHE_EXPERIMENT_WITH_FRESH_A44_KEYS"
    {
        return Err("ACK A62 non atteso".into());
    }
    if a66::a53_scan::fhe::A66_EXPERIMENT_ACK
        != "A66_LATENCY_READY_UNVALIDATED_FHE_EXPERIMENT_WITH_FRESH_A44_KEYS"
    {
        return Err("ACK A66 non atteso".into());
    }
    if a62::A44_PARAMETER_FINGERPRINT_SHA256 != a66::A44_PARAMETER_FINGERPRINT_SHA256
        || a62::A44_PARAMETER_FINGERPRINT_SHA256
            != "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    {
        return Err("fingerprint A44 A62/A66 divergente".into());
    }
    let counts62 =
        a62::a62_aligned_operation_counts(GALLERY_SIZE).ok_or("conteggio A62 N=127 assente")?;
    let counts66 =
        a66::a62_aligned_operation_counts(GALLERY_SIZE).ok_or("conteggio A66 N=127 assente")?;
    for counts in [
        (
            counts62.blind_rotations,
            counts62.key_switches,
            counts62.output_marginals,
        ),
        (
            counts66.blind_rotations,
            counts66.key_switches,
            counts66.output_marginals,
        ),
    ] {
        if counts != (EXPECTED_BR, EXPECTED_KS, EXPECTED_MARGINALS) {
            return Err("anchor A62/A66 N=127 divergente".into());
        }
    }
    Ok(())
}

fn parse_cli() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|argument| argument == "--help") {
        println!(
            "A73 is dry by default. Run requires --run --scene=PATH --schedule=PATH \
             --expected-scene-sha256=HEX --expected-schedule-sha256=HEX \
             --expected-binary-sha256=HEX --threads=N"
        );
        std::process::exit(0);
    }
    let value = |prefix: &str| {
        raw.iter()
            .find_map(|argument| argument.strip_prefix(prefix).map(str::to_owned))
    };
    let value_prefixes = [
        "--scene=",
        "--schedule=",
        "--expected-scene-sha256=",
        "--expected-schedule-sha256=",
        "--expected-binary-sha256=",
        "--threads=",
    ];
    for argument in &raw {
        if argument != "--run"
            && !value_prefixes
                .iter()
                .any(|prefix| argument.starts_with(prefix))
        {
            return Err(format!("argomento sconosciuto: {argument}"));
        }
    }
    let threads = value("--threads=")
        .map(|candidate| {
            candidate
                .parse::<usize>()
                .map_err(|_| format!("threads non valido: {candidate}"))
        })
        .transpose()?
        .unwrap_or(1);
    if threads == 0 {
        return Err("threads deve essere positivo".into());
    }
    Ok(Args {
        run: raw.iter().any(|argument| argument == "--run"),
        scene: value("--scene=").map(PathBuf::from),
        schedule: value("--schedule=").map(PathBuf::from),
        expected_scene_sha256: value("--expected-scene-sha256="),
        expected_schedule_sha256: value("--expected-schedule-sha256="),
        expected_binary_sha256: value("--expected-binary-sha256="),
        threads,
    })
}

fn require_hash<'a>(label: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    let value = value.ok_or_else(|| format!("hash {label} mancante"))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("hash {label} non valido"));
    }
    Ok(value)
}

fn verify_run_inputs(args: &Args) -> Result<(PathBuf, PathBuf, String), String> {
    let executable = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
    let isolated_target = executable.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        value == DEFAULT_TARGET_COMPONENT || value.starts_with(EPHEMERAL_TARGET_PREFIX)
    });
    if !isolated_target {
        return Err(format!(
            "binario fuori da un target A73 isolato: {}",
            executable.display()
        ));
    }
    let actual_binary = sha256_file(&executable)?;
    let expected_binary = require_hash("binary", args.expected_binary_sha256.as_deref())?;
    if actual_binary != expected_binary {
        return Err(format!(
            "binary hash mismatch: {actual_binary} != {expected_binary}"
        ));
    }
    let scene = args
        .scene
        .clone()
        .ok_or_else(|| "--scene richiesto".to_string())?;
    let schedule = args
        .schedule
        .clone()
        .ok_or_else(|| "--schedule richiesto".to_string())?;
    for (label, path, expected) in [
        (
            "scene",
            &scene,
            require_hash("scene", args.expected_scene_sha256.as_deref())?,
        ),
        (
            "schedule",
            &schedule,
            require_hash("schedule", args.expected_schedule_sha256.as_deref())?,
        ),
    ] {
        let actual = sha256_file(path)?;
        if actual != expected {
            return Err(format!("{label} hash mismatch: {actual} != {expected}"));
        }
    }
    Ok((scene, schedule, actual_binary))
}

fn next_token<T, I>(tokens: &mut I, label: &str) -> Result<T, String>
where
    T: FromStr,
    T::Err: Display,
    I: Iterator,
    I::Item: AsRef<str>,
{
    let raw = tokens
        .next()
        .ok_or_else(|| format!("token {label} mancante"))?;
    raw.as_ref()
        .parse::<T>()
        .map_err(|error| format!("token {label} non valido: {error}"))
}

fn parse_scene(path: &Path) -> Result<Scene, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("scene: {error}"))?;
    let mut tokens = text.split_whitespace();
    if tokens.next() != Some("A73SCENE1") {
        return Err("magic scena A73 non valido".into());
    }
    let gallery_size: usize = next_token(&mut tokens, "gallery_size")?;
    let dimension: usize = next_token(&mut tokens, "dimension")?;
    let threshold: i64 = next_token(&mut tokens, "threshold")?;
    let probe_count: usize = next_token(&mut tokens, "probe_count")?;
    if (gallery_size, dimension, threshold, probe_count) != (GALLERY_SIZE, DIMENSION, THRESHOLD, 5)
    {
        return Err("geometria scena DigiFace A73 divergente".into());
    }
    let mut gallery = Vec::with_capacity(gallery_size);
    for row in 0..gallery_size {
        let mut vector = Vec::with_capacity(dimension);
        for coordinate in 0..dimension {
            let value: i64 = next_token(&mut tokens, "gallery_coordinate")?;
            if !(-3..=3).contains(&value) {
                return Err(format!("gallery[{row}][{coordinate}] fuori [-3,3]"));
            }
            vector.push(value);
        }
        gallery.push(vector);
    }
    let mut probes = Vec::with_capacity(probe_count);
    for expected_slot in 0..probe_count {
        let slot: usize = next_token(&mut tokens, "probe_slot")?;
        let source_index: usize = next_token(&mut tokens, "probe_source")?;
        let expected_min_score: i64 = next_token(&mut tokens, "expected_min_score")?;
        let expected_argmin: usize = next_token(&mut tokens, "expected_argmin")?;
        let expected_code: u64 = next_token(&mut tokens, "expected_code")?;
        if slot != expected_slot {
            return Err("ordine slot probe divergente".into());
        }
        let mut vector = Vec::with_capacity(dimension);
        for coordinate in 0..dimension {
            let value: i64 = next_token(&mut tokens, "probe_coordinate")?;
            if !(-3..=3).contains(&value) {
                return Err(format!("probe[{slot}][{coordinate}] fuori [-3,3]"));
            }
            vector.push(value);
        }
        if vector.iter().all(|value| *value == 0) {
            return Err(format!("probe {slot} triviale"));
        }
        probes.push(ProbeSpec {
            slot,
            source_index,
            expected_min_score,
            expected_argmin,
            expected_code,
            vector,
        });
    }
    if tokens.next().is_some() {
        return Err("token trailing nella scena".into());
    }
    Ok(Scene {
        gallery,
        threshold,
        probes,
    })
}

fn parse_schedule(path: &Path) -> Result<Schedule, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("schedule: {error}"))?;
    let mut tokens = text.split_whitespace();
    if tokens.next() != Some("A73SCHED1") {
        return Err("magic schedule A73 non valido".into());
    }
    let stage = tokens
        .next()
        .ok_or_else(|| "stage mancante".to_string())?
        .to_string();
    let row_count: usize = next_token(&mut tokens, "row_count")?;
    let mut rows = Vec::with_capacity(row_count);
    for expected_sequence in 0..row_count {
        let pair_sequence: usize = next_token(&mut tokens, "pair_sequence")?;
        let block: usize = next_token(&mut tokens, "block")?;
        let phase = Phase::parse(tokens.next().ok_or_else(|| "phase mancante".to_string())?)?;
        let phase_position: usize = next_token(&mut tokens, "phase_position")?;
        let probe_slot: usize = next_token(&mut tokens, "probe_slot")?;
        let repetition: usize = next_token(&mut tokens, "repetition")?;
        let pair_order = PairOrder::parse(
            tokens
                .next()
                .ok_or_else(|| "pair_order mancante".to_string())?,
        )?;
        if pair_sequence != expected_sequence || probe_slot >= 5 {
            return Err("sequenza o probe slot schedule divergente".into());
        }
        rows.push(ScheduleRow {
            pair_sequence,
            block,
            phase,
            phase_position,
            probe_slot,
            repetition,
            pair_order,
        });
    }
    if tokens.next().is_some() {
        return Err("token trailing nello schedule".into());
    }
    validate_schedule(&stage, &rows)?;
    Ok(Schedule { stage, rows })
}

fn validate_schedule(stage: &str, rows: &[ScheduleRow]) -> Result<(), String> {
    let (blocks, probes, repetitions, warmups): (Vec<usize>, usize, usize, usize) = match stage {
        "smoke" => (vec![0], 1, 2, 1),
        "initial" => ((0..3).collect(), 5, 4, 4),
        "extension" => ((3..6).collect(), 5, 4, 4),
        _ => return Err(format!("stage sconosciuto: {stage}")),
    };
    let observed_blocks: Vec<usize> = rows
        .iter()
        .map(|row| row.block)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if observed_blocks != blocks {
        return Err("blocchi schedule divergenti".into());
    }
    let expected_rows = blocks.len() * (warmups + probes * repetitions);
    if rows.len() != expected_rows {
        return Err(format!(
            "cardinalita schedule divergente: {} != {expected_rows}",
            rows.len()
        ));
    }
    for block in blocks {
        let block_rows: Vec<&ScheduleRow> = rows.iter().filter(|row| row.block == block).collect();
        if block_rows
            .iter()
            .filter(|row| row.phase == Phase::Warmup)
            .count()
            != warmups
        {
            return Err(format!("warm-up block {block} divergenti"));
        }
        for probe_slot in 0..probes {
            let cell: Vec<&ScheduleRow> = block_rows
                .iter()
                .copied()
                .filter(|row| row.phase == Phase::Measured && row.probe_slot == probe_slot)
                .collect();
            if cell.len() != repetitions {
                return Err(format!("cardinalita cella {block}/{probe_slot} divergente"));
            }
            for order in [PairOrder::A62A66, PairOrder::A66A62] {
                if cell.iter().filter(|row| row.pair_order == order).count() != repetitions / 2 {
                    return Err(format!("ordine sbilanciato in {block}/{probe_slot}"));
                }
            }
        }
    }
    Ok(())
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn clear_scores(gallery: &[Vec<i64>], probe: &[i64]) -> Vec<i64> {
    gallery
        .iter()
        .map(|template| {
            squared_norm(template)
                - 2 * template
                    .iter()
                    .zip(probe)
                    .map(|(left, right)| left * right)
                    .sum::<i64>()
        })
        .collect()
}

fn validate_scene_oracles(scene: &Scene) -> Result<(), String> {
    let templates62 = scene
        .gallery
        .iter()
        .map(|template| a62::TemplateView {
            template,
            norm2: squared_norm(template),
            threshold: scene.threshold,
        })
        .collect::<Vec<_>>();
    let templates66 = scene
        .gallery
        .iter()
        .map(|template| a66::TemplateView {
            template,
            norm2: squared_norm(template),
            threshold: scene.threshold,
        })
        .collect::<Vec<_>>();
    let plan62 =
        a62::plan_private_argmin_execution(&templates62).map_err(|error| error.to_string())?;
    let plan66 =
        a66::plan_private_argmin_execution(&templates66).map_err(|error| error.to_string())?;
    if !plan62.aligned_fast_path
        || !plan66.aligned_fast_path
        || plan62.execution_domain.lower != plan66.execution_domain.lower
        || plan62.execution_domain.upper != plan66.execution_domain.upper
    {
        return Err("planner A62/A66 divergente o non allineato".into());
    }
    for probe in &scene.probes {
        let scores = clear_scores(&scene.gallery, &probe.vector);
        let clear62 =
            a62::clear_private_argmin(&scores, &templates62).map_err(|error| error.to_string())?;
        let clear66 =
            a66::clear_private_argmin(&scores, &templates66).map_err(|error| error.to_string())?;
        let minimum = scores[clear62.winner_index];
        if clear62.winner_index != clear66.winner_index
            || clear62.code != clear66.code
            || minimum != probe.expected_min_score
            || clear62.winner_index != probe.expected_argmin
            || clear62.code != probe.expected_code
        {
            return Err(format!(
                "oracolo frontier {} divergente",
                probe.source_index
            ));
        }
    }
    Ok(())
}

fn encrypt_packed_probe(
    probe: &[i64],
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    polynomial_size: PolynomialSize,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    assert_eq!(probe.len(), DIMENSION);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= a62::PROBE_NORM2_MAX);
    assert!(a62::LOW_MOD16_POLYNOMIAL_OFFSET + DIMENSION <= polynomial_size.0);
    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << a62::FULL_DELTA_LOG);
        plaintext[a62::LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << a62::LOW_MOD16_DELTA_LOG);
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

fn decode_digit(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (a62::BOOL_DELTA_LOG - 1))
        >> a62::BOOL_DELTA_LOG
        & 15
}

fn timed_a62(
    pool: &ThreadPool,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[a62::TemplateView<'_>],
    domain: a62::ScoreDomain,
) -> TimedA62 {
    let started = Instant::now();
    let output = pool.install(|| {
        a62::private_argmin_a62(
            a62::A44_PARAMETER_BINDING,
            server_key,
            packed_probe,
            templates,
            domain,
        )
    });
    TimedA62 {
        wall_s: started.elapsed().as_secs_f64(),
        output,
    }
}

fn timed_a66(
    pool: &ThreadPool,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[a66::TemplateView<'_>],
    domain: a66::ScoreDomain,
) -> TimedA66 {
    let started = Instant::now();
    let output = pool.install(|| {
        a66::private_argmin_a62(
            a66::A44_PARAMETER_BINDING,
            server_key,
            packed_probe,
            templates,
            domain,
        )
    });
    TimedA66 {
        wall_s: started.elapsed().as_secs_f64(),
        output,
    }
}

#[cfg(unix)]
fn process_peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to writable storage for one `rusage`; libc initializes it on zero.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: a zero return from `getrusage` initialized the structure.
    let kib_or_bytes = unsafe { usage.assume_init() }.ru_maxrss;
    if kib_or_bytes < 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(kib_or_bytes as u64)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some((kib_or_bytes as u64).saturating_mul(1024))
    }
}

#[cfg(not(unix))]
fn process_peak_rss_bytes() -> Option<u64> {
    None
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            current if current <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", current as u32));
            }
            current => output.push(current),
        }
    }
    output.push('"');
    output
}

fn hash_roots(low: &Lwe, high: &Lwe) -> Result<(Vec<u8>, String), String> {
    let bytes = bincode::serialize(&(low, high)).map_err(|error| error.to_string())?;
    let digest = sha256_bytes(&bytes);
    Ok((bytes, digest))
}

fn run_block(
    block: usize,
    rows: &[ScheduleRow],
    scene: &Scene,
    pool: &ThreadPool,
    threads: usize,
    stage: &str,
) -> Result<(usize, usize), String> {
    let key_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let norms = scene
        .gallery
        .iter()
        .map(|row| squared_norm(row))
        .collect::<Vec<_>>();
    let templates62 = scene
        .gallery
        .iter()
        .zip(&norms)
        .map(|(template, norm2)| a62::TemplateView {
            template,
            norm2: *norm2,
            threshold: scene.threshold,
        })
        .collect::<Vec<_>>();
    let templates66 = scene
        .gallery
        .iter()
        .zip(&norms)
        .map(|(template, norm2)| a66::TemplateView {
            template,
            norm2: *norm2,
            threshold: scene.threshold,
        })
        .collect::<Vec<_>>();
    let plan62 =
        a62::plan_private_argmin_execution(&templates62).map_err(|error| error.to_string())?;
    let plan66 =
        a66::plan_private_argmin_execution(&templates66).map_err(|error| error.to_string())?;
    if !plan62.aligned_fast_path
        || !plan66.aligned_fast_path
        || plan62.execution_domain.lower != plan66.execution_domain.lower
        || plan62.execution_domain.upper != plan66.execution_domain.upper
    {
        return Err("planner runtime A62/A66 divergente".into());
    }

    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let probe = scene
            .probes
            .get(row.probe_slot)
            .ok_or_else(|| format!("probe slot {} assente", row.probe_slot))?;
        let packed_probe = encrypt_packed_probe(
            &probe.vector,
            &glwe_secret_key,
            client_params.glwe_noise_distribution(),
            polynomial_size,
            modulus,
            &mut generator,
        );
        let serialized = bincode::serialize(&packed_probe).map_err(|error| error.to_string())?;
        prepared.push(PairInput {
            row: row.clone(),
            input_sha256: sha256_bytes(&serialized),
            packed_probe,
        });
    }
    println!(
        "{{\"record\":\"key_block\",\"block\":{block},\"threads\":{threads},\"keygen_and_prepare_s\":{:.9},\"pairs_pre_encrypted\":{},\"key_ephemeral\":true,\"secret_persisted\":false,\"peak_rss_bytes_after_prepare\":{}}}",
        key_started.elapsed().as_secs_f64(),
        prepared.len(),
        process_peak_rss_bytes().map_or("null".to_string(), |value| value.to_string()),
    );

    // No output is decrypted, serialized, hashed or inspected while the paired timings run.
    // Both members of every pair are evaluated sequentially against the same borrowed object;
    // all outcomes remain owned until every timing in this key block has completed.
    let mut raw_outcomes = Vec::with_capacity(prepared.len());
    for input in prepared {
        let (a62, a66) = match input.row.pair_order {
            PairOrder::A62A66 => (
                timed_a62(
                    pool,
                    &server_key,
                    &input.packed_probe,
                    &templates62,
                    plan62.execution_domain,
                ),
                timed_a66(
                    pool,
                    &server_key,
                    &input.packed_probe,
                    &templates66,
                    plan66.execution_domain,
                ),
            ),
            PairOrder::A66A62 => {
                let a66 = timed_a66(
                    pool,
                    &server_key,
                    &input.packed_probe,
                    &templates66,
                    plan66.execution_domain,
                );
                let a62 = timed_a62(
                    pool,
                    &server_key,
                    &input.packed_probe,
                    &templates62,
                    plan62.execution_domain,
                );
                (a62, a66)
            }
        };
        raw_outcomes.push(RawPairOutcome {
            row: input.row,
            input_sha256: input.input_sha256,
            a62,
            a66,
        });
    }
    let peak_after_all_timings = process_peak_rss_bytes();

    let mut passed = 0usize;
    let mut failed = 0usize;
    for raw in raw_outcomes {
        let probe = &scene.probes[raw.row.probe_slot];
        match (raw.a62.output, raw.a66.output) {
            (Ok(output62), Ok(output66)) => {
                let low62 = decode_digit(&big_secret_key, &output62.low_digit);
                let high62 = decode_digit(&big_secret_key, &output62.high_digit);
                let low66 = decode_digit(&big_secret_key, &output66.low_digit);
                let high66 = decode_digit(&big_secret_key, &output66.high_digit);
                let code62 = low62 + 15 * high62;
                let code66 = low66 + 15 * high66;
                let (bytes62, hash62) = hash_roots(&output62.low_digit, &output62.high_digit)?;
                let (bytes66, hash66) = hash_roots(&output66.low_digit, &output66.high_digit)?;
                let counts62 = a62::a62_aligned_operation_counts(GALLERY_SIZE).unwrap();
                let counts66 = a66::a62_aligned_operation_counts(GALLERY_SIZE).unwrap();
                let semantics_pass = code62 == probe.expected_code
                    && code66 == probe.expected_code
                    && code62 == code66;
                let counts_pass = output62.metrics.total_pbs_count == EXPECTED_BR
                    && output66.metrics.total_pbs_count == EXPECTED_BR
                    && counts62.blind_rotations == EXPECTED_BR
                    && counts66.blind_rotations == EXPECTED_BR
                    && counts62.key_switches == EXPECTED_KS
                    && counts66.key_switches == EXPECTED_KS
                    && counts62.output_marginals == EXPECTED_MARGINALS
                    && counts66.output_marginals == EXPECTED_MARGINALS;
                let pair_pass = semantics_pass && counts_pass;
                passed += usize::from(pair_pass);
                failed += usize::from(!pair_pass);
                println!(
                    "{{\"record\":\"pair\",\"stage\":{},\"block\":{},\"pair_sequence\":{},\"phase\":{},\"included_in_analysis\":{},\"phase_position\":{},\"probe_slot\":{},\"probe_source_index\":{},\"repetition\":{},\"pair_order\":{},\"threads\":{},\"same_server_key_object\":true,\"same_gallery_backing\":true,\"same_packed_ciphertext_object\":true,\"input_ciphertext_sha256\":{},\"expected_min_score\":{},\"expected_argmin\":{},\"expected_code\":{},\"a62_low\":{},\"a62_high\":{},\"a62_code\":{},\"a66_low\":{},\"a66_high\":{},\"a66_code\":{},\"a62_wall_s\":{:.9},\"a66_wall_s\":{:.9},\"a62_internal_total_s\":{:.9},\"a66_internal_total_s\":{:.9},\"a62_setup_s\":{:.9},\"a66_setup_s\":{:.9},\"a62_setup_pbs\":{},\"a66_setup_pbs\":{},\"a62_score_s\":{:.9},\"a66_score_s\":{:.9},\"a62_score_pbs\":{},\"a66_score_pbs\":{},\"a62_extract_s\":{:.9},\"a66_extract_s\":{:.9},\"a62_extract_pbs\":{},\"a66_extract_pbs\":{},\"a62_select_s\":{:.9},\"a66_select_s\":{:.9},\"a62_select_pbs\":{},\"a66_select_pbs\":{},\"a62_scan_s\":{:.9},\"a66_scan_s\":{:.9},\"a62_scan_pbs\":{},\"a66_scan_pbs\":{},\"a62_threshold_s\":{:.9},\"a66_threshold_s\":{:.9},\"a62_threshold_pbs\":{},\"a66_threshold_pbs\":{},\"a62_output_s\":{:.9},\"a66_output_s\":{:.9},\"a62_output_pbs\":{},\"a66_output_pbs\":{},\"a62_pbs\":{},\"a66_pbs\":{},\"key_switches\":{},\"marginals\":{},\"a62_result_bytes\":{},\"a66_result_bytes\":{},\"a62_result_sha256\":{},\"a66_result_sha256\":{},\"result_ciphertext_byte_identical\":{},\"semantics_pass\":{},\"counts_pass\":{},\"pair_pass\":{}}}",
                    json_escape(stage),
                    raw.row.block,
                    raw.row.pair_sequence,
                    json_escape(raw.row.phase.label()),
                    raw.row.phase.included(),
                    raw.row.phase_position,
                    probe.slot,
                    probe.source_index,
                    raw.row.repetition,
                    json_escape(raw.row.pair_order.label()),
                    threads,
                    json_escape(&raw.input_sha256),
                    probe.expected_min_score,
                    probe.expected_argmin,
                    probe.expected_code,
                    low62,
                    high62,
                    code62,
                    low66,
                    high66,
                    code66,
                    raw.a62.wall_s,
                    raw.a66.wall_s,
                    output62.metrics.total_seconds,
                    output66.metrics.total_seconds,
                    output62.metrics.setup.seconds,
                    output66.metrics.setup.seconds,
                    output62.metrics.setup.pbs_count,
                    output66.metrics.setup.pbs_count,
                    output62.metrics.score.seconds,
                    output66.metrics.score.seconds,
                    output62.metrics.score.pbs_count,
                    output66.metrics.score.pbs_count,
                    output62.metrics.extract.seconds,
                    output66.metrics.extract.seconds,
                    output62.metrics.extract.pbs_count,
                    output66.metrics.extract.pbs_count,
                    output62.metrics.select.seconds,
                    output66.metrics.select.seconds,
                    output62.metrics.select.pbs_count,
                    output66.metrics.select.pbs_count,
                    output62.metrics.scan.seconds,
                    output66.metrics.scan.seconds,
                    output62.metrics.scan.pbs_count,
                    output66.metrics.scan.pbs_count,
                    output62.metrics.threshold.seconds,
                    output66.metrics.threshold.seconds,
                    output62.metrics.threshold.pbs_count,
                    output66.metrics.threshold.pbs_count,
                    output62.metrics.output.seconds,
                    output66.metrics.output.seconds,
                    output62.metrics.output.pbs_count,
                    output66.metrics.output.pbs_count,
                    output62.metrics.total_pbs_count,
                    output66.metrics.total_pbs_count,
                    EXPECTED_KS,
                    EXPECTED_MARGINALS,
                    bytes62.len(),
                    bytes66.len(),
                    json_escape(&hash62),
                    json_escape(&hash66),
                    bytes62 == bytes66,
                    semantics_pass,
                    counts_pass,
                    pair_pass,
                );
            }
            (left, right) => {
                failed += 1;
                let error62 = left
                    .err()
                    .map_or_else(|| "none".into(), |error| error.to_string());
                let error66 = right
                    .err()
                    .map_or_else(|| "none".into(), |error| error.to_string());
                println!(
                    "{{\"record\":\"pair_error\",\"block\":{},\"pair_sequence\":{},\"phase\":{},\"included_in_analysis\":{},\"probe_slot\":{},\"pair_order\":{},\"threads\":{},\"same_packed_ciphertext_object\":true,\"a62_wall_s\":{:.9},\"a66_wall_s\":{:.9},\"a62_error\":{},\"a66_error\":{},\"pair_pass\":false}}",
                    raw.row.block,
                    raw.row.pair_sequence,
                    json_escape(raw.row.phase.label()),
                    raw.row.phase.included(),
                    raw.row.probe_slot,
                    json_escape(raw.row.pair_order.label()),
                    threads,
                    raw.a62.wall_s,
                    raw.a66.wall_s,
                    json_escape(&error62),
                    json_escape(&error66),
                );
            }
        }
    }
    println!(
        "{{\"record\":\"rss\",\"block\":{block},\"threads\":{threads},\"scope\":\"process_high_water_not_variant_attributable\",\"peak_rss_bytes_after_all_pair_timings\":{}}}",
        peak_after_all_timings.map_or("null".to_string(), |value| value.to_string()),
    );
    Ok((passed, failed))
}

fn run_experiment(
    args: &Args,
    scene_path: &Path,
    schedule_path: &Path,
    binary_sha256: &str,
) -> Result<(), String> {
    let scene = parse_scene(scene_path)?;
    let schedule = parse_schedule(schedule_path)?;
    validate_scene_oracles(&scene)?;
    let pool = ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .thread_name(|index| format!("a73-rayon-{index}"))
        .build()
        .map_err(|error| format!("pool Rayon: {error}"))?;
    println!(
        "{{\"record\":\"meta\",\"variant\":\"a73_a62_vs_a66_component_paired\",\"baseline\":\"a62\",\"candidate\":\"a66\",\"stage\":{},\"threads\":{},\"gallery_size\":{},\"dimension\":{},\"threshold\":{},\"binary_sha256\":{},\"scene_sha256\":{},\"schedule_sha256\":{},\"params_fingerprint_sha256\":{},\"N127_BR\":{},\"N127_KS\":{},\"N127_marginals\":{},\"same_key_within_pair\":true,\"same_gallery_within_pair\":true,\"same_packed_ciphertext_object_within_pair\":true,\"decrypt_policy\":\"after_both_variants_and_after_all_pair_timings_in_key_block\",\"rss_scope\":\"process_high_water_not_variant_attributable\"}}",
        json_escape(&schedule.stage),
        args.threads,
        GALLERY_SIZE,
        DIMENSION,
        THRESHOLD,
        json_escape(binary_sha256),
        json_escape(&sha256_file(scene_path)?),
        json_escape(&sha256_file(schedule_path)?),
        json_escape(a62::A44_PARAMETER_FINGERPRINT_SHA256),
        EXPECTED_BR,
        EXPECTED_KS,
        EXPECTED_MARGINALS,
    );

    let mut by_block: BTreeMap<usize, Vec<ScheduleRow>> = BTreeMap::new();
    for row in schedule.rows {
        by_block.entry(row.block).or_default().push(row);
    }
    let mut passed = 0usize;
    let mut failed = 0usize;
    for (block, rows) in by_block {
        let (block_passed, block_failed) =
            run_block(block, &rows, &scene, &pool, args.threads, &schedule.stage)?;
        passed += block_passed;
        failed += block_failed;
    }
    let measured = schedule_expected_measured(&schedule.stage);
    let warmups = schedule_expected_warmups(&schedule.stage);
    let expected_total = measured + warmups;
    let status = if failed == 0 && passed == expected_total {
        "PASS"
    } else {
        "FAIL"
    };
    println!(
        "{{\"record\":\"summary\",\"status\":\"{status}\",\"stage\":{},\"threads\":{},\"measured_pairs\":{},\"excluded_warmup_pairs\":{},\"total_pairs\":{},\"passed_pairs\":{},\"failed_pairs\":{},\"key_blocks\":{},\"keys_ephemeral\":true,\"secret_material_persisted\":false,\"promotion_allowed\":false}}",
        json_escape(&schedule.stage),
        args.threads,
        measured,
        warmups,
        expected_total,
        passed,
        failed,
        if schedule.stage == "smoke" { 1 } else { 3 },
    );
    if status != "PASS" {
        return Err("una o piu coppie A73 non hanno superato il gate".into());
    }
    Ok(())
}

fn schedule_expected_measured(stage: &str) -> usize {
    if stage == "smoke" {
        2
    } else {
        60
    }
}

fn schedule_expected_warmups(stage: &str) -> usize {
    if stage == "smoke" {
        1
    } else {
        12
    }
}

fn dry_plan(args: &Args) {
    println!(
        "{{\"record\":\"plan\",\"status\":\"PASS_DRY_NO_KEYGEN_NO_FHE\",\"variant\":\"a73_a62_vs_a66_component_paired\",\"baseline\":\"a62\",\"candidate\":\"a66\",\"source_guards\":{},\"gallery_size\":127,\"dimension\":512,\"wire\":\"two_p16_base15\",\"N127_BR\":3390,\"N127_KS\":3009,\"N127_marginals\":3930,\"requested_threads\":{},\"isolated_target_component\":\"target-a73-only\",\"run_requires_scene_schedule_and_binary_hashes\":true}}",
        SOURCE_GUARDS.len(),
        args.threads,
    );
}

fn real_main() -> Result<(), String> {
    verify_embedded_sources()?;
    let args = parse_cli()?;
    if !args.run {
        dry_plan(&args);
        return Ok(());
    }
    let (scene, schedule, binary_sha256) = verify_run_inputs(&args)?;
    run_experiment(&args, &scene, &schedule, &binary_sha256)
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!(
            "{{\"record\":\"fatal\",\"status\":\"FAIL\",\"error\":{}}}",
            json_escape(&error)
        );
        std::process::exit(2);
    }
}
