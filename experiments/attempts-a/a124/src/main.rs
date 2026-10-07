//! A124: A66 thread sweep at N=64, 127 and 128.
//!
//! The binary is dry by default. `--run` requires hash-pinned scene, schedule and binary inputs,
//! generates one fresh A44 key per block, encrypts every query before timing, and evaluates the
//! frozen A66 circuit once per scheduled query against the same immutable key and gallery. There is
//! no paired variant: the design measures one circuit across gallery sizes and Rayon thread counts.

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

const DIMENSION: usize = 512;
const THRESHOLD: i64 = 4;
const PROBE_COUNT: usize = 5;
const ALLOWED_GALLERY_SIZES: &[usize] = &[64, 127, 128];
const ANCHOR_N127: (u64, u64, u64) = (3_390, 3_009, 3_930);
const DEFAULT_TARGET_COMPONENT: &str = "target-a124-only";
const EPHEMERAL_TARGET_PREFIX: &str = "a124-isolated-target-";

const A66_PRIVATE: &[u8] =
    include_bytes!("../../a66-a62-latency-ready-prototype/src/private_argmin.rs");
const A66_FHE: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/src/a53_scan/fhe.rs");
const A66_SCAN: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/src/a53_scan.rs");
const A66_LOCK: &[u8] = include_bytes!("../../a66-a62-latency-ready-prototype/Cargo.lock");

const SOURCE_GUARDS: &[(&str, &[u8], &str)] = &[
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
        matches!(self, Self::Measured)
    }
}

#[derive(Clone, Debug)]
struct ScheduleRow {
    sequence: usize,
    block: usize,
    phase: Phase,
    phase_position: usize,
    probe_slot: usize,
    repetition: usize,
}

#[derive(Debug)]
struct Schedule {
    stage: String,
    gallery_size: usize,
    threads: usize,
    rows: Vec<ScheduleRow>,
}

#[derive(Debug)]
struct ProbeSpec {
    slot: usize,
    source_index: usize,
    expected_min_score: i64,
    expected_argmin: usize,
    expected_code: u64,
    vector: Vec<i64>,
}

#[derive(Debug)]
struct Scene {
    gallery: Vec<Vec<i64>>,
    threshold: i64,
    probes: Vec<ProbeSpec>,
}

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
struct QueryInput {
    row: ScheduleRow,
    input_sha256: String,
    packed_probe: Glwe,
}

#[derive(Debug)]
struct TimedA66 {
    wall_s: f64,
    output: Result<a66::A62PrivateArgminOutput, a66::PrivateArgminError>,
}

#[derive(Debug)]
struct RawOutcome {
    row: ScheduleRow,
    input_sha256: String,
    timed: TimedA66,
}

#[derive(Clone, Copy, Debug)]
struct StageShape {
    blocks: &'static [usize],
    probe_slots: &'static [usize],
    repetitions: usize,
    warmups: usize,
}

fn stage_shape(stage: &str) -> Result<StageShape, String> {
    match stage {
        "smoke" => Ok(StageShape {
            blocks: &[0],
            probe_slots: &[0, 1],
            repetitions: 1,
            warmups: 1,
        }),
        "sweep" => Ok(StageShape {
            blocks: &[0, 1],
            probe_slots: &[0, 1, 2, 3, 4],
            repetitions: 1,
            warmups: 2,
        }),
        _ => Err(format!("stage sconosciuto: {stage}")),
    }
}

fn sha256_bytes(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|payload| sha256_bytes(&payload))
        .map_err(|error| format!("lettura hash {}: {error}", path.display()))
}

fn expected_counts(gallery_size: usize) -> Result<(u64, u64, u64), String> {
    let counts = a66::a62_aligned_operation_counts(gallery_size)
        .ok_or_else(|| format!("conteggio A66 N={gallery_size} assente"))?;
    Ok((
        counts.blind_rotations,
        counts.key_switches,
        counts.output_marginals,
    ))
}

fn verify_embedded_sources() -> Result<(), String> {
    for (label, payload, expected) in SOURCE_GUARDS {
        let actual = sha256_bytes(payload);
        if actual != *expected {
            return Err(format!("source guard {label}: {actual} != {expected}"));
        }
    }
    if a66::a53_scan::fhe::A66_EXPERIMENT_ACK
        != "A66_LATENCY_READY_UNVALIDATED_FHE_EXPERIMENT_WITH_FRESH_A44_KEYS"
    {
        return Err("ACK A66 non atteso".into());
    }
    if a66::A44_PARAMETER_FINGERPRINT_SHA256
        != "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"
    {
        return Err("fingerprint A44 divergente".into());
    }
    if expected_counts(127)? != ANCHOR_N127 {
        return Err("anchor A66 N=127 divergente da A73".into());
    }
    for gallery_size in ALLOWED_GALLERY_SIZES {
        expected_counts(*gallery_size)?;
    }
    Ok(())
}

fn parse_cli() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|argument| argument == "--help") {
        println!(
            "A124 is dry by default. Run requires --run --scene=PATH --schedule=PATH \
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
            "binario fuori da un target A124 isolato: {}",
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
    if tokens.next() != Some("A124SCENE1") {
        return Err("magic scena A124 non valido".into());
    }
    let gallery_size: usize = next_token(&mut tokens, "gallery_size")?;
    let dimension: usize = next_token(&mut tokens, "dimension")?;
    let threshold: i64 = next_token(&mut tokens, "threshold")?;
    let probe_count: usize = next_token(&mut tokens, "probe_count")?;
    if !ALLOWED_GALLERY_SIZES.contains(&gallery_size)
        || (dimension, threshold, probe_count) != (DIMENSION, THRESHOLD, PROBE_COUNT)
    {
        return Err("geometria scena DigiFace A124 divergente".into());
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
    if tokens.next() != Some("A124SCHED1") {
        return Err("magic schedule A124 non valido".into());
    }
    let stage = tokens
        .next()
        .ok_or_else(|| "stage mancante".to_string())?
        .to_string();
    let gallery_size: usize = next_token(&mut tokens, "gallery_size")?;
    let threads: usize = next_token(&mut tokens, "threads")?;
    let row_count: usize = next_token(&mut tokens, "row_count")?;
    let mut rows = Vec::with_capacity(row_count);
    for expected_sequence in 0..row_count {
        let sequence: usize = next_token(&mut tokens, "sequence")?;
        let block: usize = next_token(&mut tokens, "block")?;
        let phase = Phase::parse(tokens.next().ok_or_else(|| "phase mancante".to_string())?)?;
        let phase_position: usize = next_token(&mut tokens, "phase_position")?;
        let probe_slot: usize = next_token(&mut tokens, "probe_slot")?;
        let repetition: usize = next_token(&mut tokens, "repetition")?;
        if sequence != expected_sequence || probe_slot >= PROBE_COUNT {
            return Err("sequenza o probe slot schedule divergente".into());
        }
        rows.push(ScheduleRow {
            sequence,
            block,
            phase,
            phase_position,
            probe_slot,
            repetition,
        });
    }
    if tokens.next().is_some() {
        return Err("token trailing nello schedule".into());
    }
    validate_schedule(&stage, &rows)?;
    Ok(Schedule {
        stage,
        gallery_size,
        threads,
        rows,
    })
}

fn validate_schedule(stage: &str, rows: &[ScheduleRow]) -> Result<(), String> {
    let shape = stage_shape(stage)?;
    let observed_blocks: Vec<usize> = rows
        .iter()
        .map(|row| row.block)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if observed_blocks != shape.blocks {
        return Err("blocchi schedule divergenti".into());
    }
    let expected_rows =
        shape.blocks.len() * (shape.warmups + shape.probe_slots.len() * shape.repetitions);
    if rows.len() != expected_rows {
        return Err(format!(
            "cardinalita schedule divergente: {} != {expected_rows}",
            rows.len()
        ));
    }
    for block in shape.blocks {
        let block_rows: Vec<&ScheduleRow> = rows.iter().filter(|row| row.block == *block).collect();
        if block_rows
            .iter()
            .filter(|row| row.phase == Phase::Warmup)
            .count()
            != shape.warmups
        {
            return Err(format!("warm-up block {block} divergenti"));
        }
        for probe_slot in shape.probe_slots {
            let cell = block_rows
                .iter()
                .filter(|row| row.phase == Phase::Measured && row.probe_slot == *probe_slot)
                .count();
            if cell != shape.repetitions {
                return Err(format!("cardinalita cella {block}/{probe_slot} divergente"));
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

fn template_views(scene: &Scene) -> Vec<a66::TemplateView<'_>> {
    scene
        .gallery
        .iter()
        .map(|template| a66::TemplateView {
            template,
            norm2: squared_norm(template),
            threshold: scene.threshold,
        })
        .collect()
}

fn validate_scene_oracles(scene: &Scene) -> Result<a66::PrivateArgminExecutionPlan, String> {
    let templates = template_views(scene);
    let plan = a66::plan_private_argmin_execution(&templates).map_err(|error| error.to_string())?;
    if !plan.aligned_fast_path {
        return Err("planner A66 non allineato: la scena non usa il fast path".into());
    }
    for probe in &scene.probes {
        let scores = clear_scores(&scene.gallery, &probe.vector);
        let clear =
            a66::clear_private_argmin(&scores, &templates).map_err(|error| error.to_string())?;
        let minimum = scores[clear.winner_index];
        if minimum != probe.expected_min_score
            || clear.winner_index != probe.expected_argmin
            || clear.code != probe.expected_code
        {
            return Err(format!(
                "oracolo frontier {} divergente",
                probe.source_index
            ));
        }
    }
    Ok(plan)
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
    assert!(squared_norm(probe) <= a66::PROBE_NORM2_MAX);
    assert!(a66::LOW_MOD16_POLYNOMIAL_OFFSET + DIMENSION <= polynomial_size.0);
    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[coordinate] = (value as u64).wrapping_mul(1u64 << a66::FULL_DELTA_LOG);
        plaintext[a66::LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << a66::LOW_MOD16_DELTA_LOG);
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
        .wrapping_add(1u64 << (a66::BOOL_DELTA_LOG - 1))
        >> a66::BOOL_DELTA_LOG
        & 15
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

#[allow(clippy::too_many_arguments)]
fn run_block(
    block: usize,
    rows: &[ScheduleRow],
    scene: &Scene,
    plan: a66::PrivateArgminExecutionPlan,
    pool: &ThreadPool,
    threads: usize,
    stage: &str,
) -> Result<(usize, usize), String> {
    let gallery_size = scene.gallery.len();
    let (expected_br, expected_ks, expected_marginals) = expected_counts(gallery_size)?;
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

    let templates = template_views(scene);
    let runtime_plan =
        a66::plan_private_argmin_execution(&templates).map_err(|error| error.to_string())?;
    if runtime_plan != plan {
        return Err("planner runtime A66 divergente dal piano validato".into());
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
        prepared.push(QueryInput {
            row: row.clone(),
            input_sha256: sha256_bytes(&serialized),
            packed_probe,
        });
    }
    println!(
        "{{\"record\":\"key_block\",\"block\":{block},\"gallery_size\":{gallery_size},\"threads\":{threads},\"keygen_and_prepare_s\":{:.9},\"queries_pre_encrypted\":{},\"key_ephemeral\":true,\"secret_persisted\":false,\"peak_rss_bytes_after_prepare\":{}}}",
        key_started.elapsed().as_secs_f64(),
        prepared.len(),
        process_peak_rss_bytes().map_or("null".to_string(), |value| value.to_string()),
    );

    // No output is decrypted, serialized, hashed or inspected while the timings run.
    let mut raw_outcomes = Vec::with_capacity(prepared.len());
    for input in prepared {
        let timed = timed_a66(
            pool,
            &server_key,
            &input.packed_probe,
            &templates,
            plan.execution_domain,
        );
        raw_outcomes.push(RawOutcome {
            row: input.row,
            input_sha256: input.input_sha256,
            timed,
        });
    }
    let peak_after_all_timings = process_peak_rss_bytes();

    let mut passed = 0usize;
    let mut failed = 0usize;
    for raw in raw_outcomes {
        let probe = &scene.probes[raw.row.probe_slot];
        match raw.timed.output {
            Ok(output) => {
                let low = decode_digit(&big_secret_key, &output.low_digit);
                let high = decode_digit(&big_secret_key, &output.high_digit);
                let code = low + 15 * high;
                let (bytes, hash) = hash_roots(&output.low_digit, &output.high_digit)?;
                let semantics_pass = code == probe.expected_code;
                let counts_pass = output.metrics.total_pbs_count == expected_br;
                let query_pass = semantics_pass && counts_pass;
                passed += usize::from(query_pass);
                failed += usize::from(!query_pass);
                println!(
                    "{{\"record\":\"query\",\"stage\":{},\"gallery_size\":{},\"threads\":{},\"block\":{},\"sequence\":{},\"phase\":{},\"included_in_analysis\":{},\"phase_position\":{},\"probe_slot\":{},\"probe_source_index\":{},\"repetition\":{},\"input_ciphertext_sha256\":{},\"expected_min_score\":{},\"expected_argmin\":{},\"expected_code\":{},\"low\":{},\"high\":{},\"code\":{},\"wall_s\":{:.9},\"internal_total_s\":{:.9},\"setup_s\":{:.9},\"setup_pbs\":{},\"score_s\":{:.9},\"score_pbs\":{},\"extract_s\":{:.9},\"extract_pbs\":{},\"select_s\":{:.9},\"select_pbs\":{},\"scan_s\":{:.9},\"scan_pbs\":{},\"threshold_s\":{:.9},\"threshold_pbs\":{},\"output_s\":{:.9},\"output_pbs\":{},\"pbs\":{},\"expected_br\":{},\"expected_ks\":{},\"expected_marginals\":{},\"result_bytes\":{},\"result_sha256\":{},\"semantics_pass\":{},\"counts_pass\":{},\"query_pass\":{}}}",
                    json_escape(stage),
                    gallery_size,
                    threads,
                    raw.row.block,
                    raw.row.sequence,
                    json_escape(raw.row.phase.label()),
                    raw.row.phase.included(),
                    raw.row.phase_position,
                    probe.slot,
                    probe.source_index,
                    raw.row.repetition,
                    json_escape(&raw.input_sha256),
                    probe.expected_min_score,
                    probe.expected_argmin,
                    probe.expected_code,
                    low,
                    high,
                    code,
                    raw.timed.wall_s,
                    output.metrics.total_seconds,
                    output.metrics.setup.seconds,
                    output.metrics.setup.pbs_count,
                    output.metrics.score.seconds,
                    output.metrics.score.pbs_count,
                    output.metrics.extract.seconds,
                    output.metrics.extract.pbs_count,
                    output.metrics.select.seconds,
                    output.metrics.select.pbs_count,
                    output.metrics.scan.seconds,
                    output.metrics.scan.pbs_count,
                    output.metrics.threshold.seconds,
                    output.metrics.threshold.pbs_count,
                    output.metrics.output.seconds,
                    output.metrics.output.pbs_count,
                    output.metrics.total_pbs_count,
                    expected_br,
                    expected_ks,
                    expected_marginals,
                    bytes.len(),
                    json_escape(&hash),
                    semantics_pass,
                    counts_pass,
                    query_pass,
                );
            }
            Err(error) => {
                failed += 1;
                println!(
                    "{{\"record\":\"query_error\",\"gallery_size\":{},\"threads\":{},\"block\":{},\"sequence\":{},\"phase\":{},\"included_in_analysis\":{},\"probe_slot\":{},\"wall_s\":{:.9},\"error\":{},\"query_pass\":false}}",
                    gallery_size,
                    threads,
                    raw.row.block,
                    raw.row.sequence,
                    json_escape(raw.row.phase.label()),
                    raw.row.phase.included(),
                    raw.row.probe_slot,
                    raw.timed.wall_s,
                    json_escape(&error.to_string()),
                );
            }
        }
    }
    println!(
        "{{\"record\":\"rss\",\"block\":{block},\"gallery_size\":{gallery_size},\"threads\":{threads},\"scope\":\"process_high_water\",\"peak_rss_bytes_after_all_timings\":{}}}",
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
    if schedule.gallery_size != scene.gallery.len() {
        return Err("gallery_size dello schedule diverso dalla scena".into());
    }
    if schedule.threads != args.threads {
        return Err("threads dello schedule diversi da --threads".into());
    }
    let plan = validate_scene_oracles(&scene)?;
    let gallery_size = scene.gallery.len();
    let (expected_br, expected_ks, expected_marginals) = expected_counts(gallery_size)?;
    let pool = ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .thread_name(|index| format!("a124-rayon-{index}"))
        .build()
        .map_err(|error| format!("pool Rayon: {error}"))?;
    println!(
        "{{\"record\":\"meta\",\"variant\":\"a124_a66_thread_sweep\",\"circuit\":\"a66\",\"stage\":{},\"gallery_size\":{},\"threads\":{},\"dimension\":{},\"threshold\":{},\"binary_sha256\":{},\"scene_sha256\":{},\"schedule_sha256\":{},\"params_fingerprint_sha256\":{},\"expected_br\":{},\"expected_ks\":{},\"expected_marginals\":{},\"execution_domain_lower\":{},\"execution_domain_upper\":{},\"aligned_fast_path\":{},\"decrypt_policy\":\"after_all_timings_in_key_block\",\"rss_scope\":\"process_high_water\"}}",
        json_escape(&schedule.stage),
        gallery_size,
        args.threads,
        DIMENSION,
        THRESHOLD,
        json_escape(binary_sha256),
        json_escape(&sha256_file(scene_path)?),
        json_escape(&sha256_file(schedule_path)?),
        json_escape(a66::A44_PARAMETER_FINGERPRINT_SHA256),
        expected_br,
        expected_ks,
        expected_marginals,
        plan.execution_domain.lower,
        plan.execution_domain.upper,
        plan.aligned_fast_path,
    );

    let shape = stage_shape(&schedule.stage)?;
    let mut by_block: BTreeMap<usize, Vec<ScheduleRow>> = BTreeMap::new();
    for row in schedule.rows {
        by_block.entry(row.block).or_default().push(row);
    }
    let mut passed = 0usize;
    let mut failed = 0usize;
    for (block, rows) in by_block {
        let (block_passed, block_failed) = run_block(
            block,
            &rows,
            &scene,
            plan,
            &pool,
            args.threads,
            &schedule.stage,
        )?;
        passed += block_passed;
        failed += block_failed;
    }
    let measured = shape.blocks.len() * shape.probe_slots.len() * shape.repetitions;
    let warmups = shape.blocks.len() * shape.warmups;
    let expected_total = measured + warmups;
    let status = if failed == 0 && passed == expected_total {
        "PASS"
    } else {
        "FAIL"
    };
    println!(
        "{{\"record\":\"summary\",\"status\":\"{status}\",\"stage\":{},\"gallery_size\":{},\"threads\":{},\"measured_queries\":{},\"excluded_warmup_queries\":{},\"total_queries\":{},\"passed_queries\":{},\"failed_queries\":{},\"key_blocks\":{},\"keys_ephemeral\":true,\"secret_material_persisted\":false,\"promotion_allowed\":false}}",
        json_escape(&schedule.stage),
        gallery_size,
        args.threads,
        measured,
        warmups,
        expected_total,
        passed,
        failed,
        shape.blocks.len(),
    );
    if status != "PASS" {
        return Err("una o piu query A124 non hanno superato il gate".into());
    }
    Ok(())
}

fn dry_plan(args: &Args) -> Result<(), String> {
    let mut counts = String::new();
    for (index, gallery_size) in ALLOWED_GALLERY_SIZES.iter().enumerate() {
        let (br, ks, marginals) = expected_counts(*gallery_size)?;
        if index > 0 {
            counts.push(',');
        }
        counts.push_str(&format!(
            "{{\"gallery_size\":{gallery_size},\"br\":{br},\"ks\":{ks},\"marginals\":{marginals}}}"
        ));
    }
    println!(
        "{{\"record\":\"plan\",\"status\":\"PASS_DRY_NO_KEYGEN_NO_FHE\",\"variant\":\"a124_a66_thread_sweep\",\"circuit\":\"a66\",\"source_guards\":{},\"gallery_sizes\":[64,127,128],\"dimension\":512,\"wire\":\"two_p16_base15\",\"counts\":[{counts}],\"requested_threads\":{},\"isolated_target_component\":\"target-a124-only\",\"run_requires_scene_schedule_and_binary_hashes\":true}}",
        SOURCE_GUARDS.len(),
        args.threads,
    );
    Ok(())
}

fn real_main() -> Result<(), String> {
    verify_embedded_sources()?;
    let args = parse_cli()?;
    if !args.run {
        return dry_plan(&args);
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
