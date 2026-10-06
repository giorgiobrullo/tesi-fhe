//! Fail-closed A112 Head Start R3/R4 component-smoke candidate.
//!
//! SOURCE STATUS ONLY: this file has not been type-checked, compiled, keyed, or executed.  A
//! future authorized run compares two independent corrected big-to-small key-switch arms, the
//! direct R2B oracle against the frozen A98 adapter, and the resulting stock blind rotations.

#[allow(dead_code)]
#[path = "../../src/lib.rs"]
mod a112_candidate;
#[allow(dead_code)]
#[path = "../../../a98-head-start-exact-adapter-port/src/lib.rs"]
mod a98_port;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use a112_candidate::{
    a112_local_corrected_keyswitch, reference_head_start_modulus_switch,
    reference_patch_corrected_keyswitch, ReferencePatchIter,
};
use a98_port::{exact_head_start_modulus_switch, HeadStartDecompositionIter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::algorithms::slice_algorithms::slice_wrapping_sub_scalar_mul_assign;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::*;

const WRAPPER_PREREGISTRATION_SHA256: &str =
    "6e8a6568ee0d7a9c1d580d4984dbdfbb9dc64d560bf55a2664aedb3c2aca14cb";
const WRAPPER_MANIFEST_SHA256: &str =
    "f43c8a9d53183e13a38bae5f5510837113ce423bd85ea35f93ac61bedcaca247";
const WRAPPER_README_SHA256: &str =
    "de722b98fea199cb1c0565a487b15910b18020cb6b4363955e1c8558b9c69430";
const WRAPPER_API_AUDIT_SHA256: &str =
    "c9f5f15c6a72b677367240460b8c4720ea72efa8df2fafd27cbed536dccca065";
const WRAPPER_SOURCE_PINS_SHA256: &str =
    "775f10ae4c326bd09c4ae3b618fb445bad8f9ac66c799daa9f6d8452a574a9f1";
const A112_PARENT_README_SHA256: &str =
    "1fa2fb8a170d6b55cf3e40e9711e63e215f7c7b3c54fa5a69c5bdaf0d05bd6b3";
const A112_API_AUDIT_SHA256: &str =
    "82d339170765c24dbf6128e3fa5b52682d8ff46d7ea92cd0bb84f87c45e8a12d";
const A112_PARENT_PREREGISTRATION_SHA256: &str =
    "041090dc27c08b6d858cd591d012ccbf36b3f63be66cc1bf803547a829940e3d";
const A112_PARENT_SOURCE_PINS_SHA256: &str =
    "ed714f87ce35f64de3dcaae047edcc9b12995d18aed4957417763f42235370cb";
const A112_PARENT_STATIC_REPORT_SHA256: &str =
    "d634e7a67c712060bddc3884d79ad72ecde4684c454b73bea2935397ec1de2ab";
const A112_PARENT_MODEL_SHA256: &str =
    "ee62e5837edf5f342181087a1da0226a51894502f67de244371e3cb3213d6750";
const A112_PARENT_SOURCE_SHA256: &str =
    "09908a40d3f078e07aaf210821353af83f6f6698b4aa8d1d2ca7532e299da93e";
const A112_PARENT_TEST_SHA256: &str =
    "de452f2bb8b08a60d076685a43eee43bbc4561cd6c67598e7e9c11eba1d52187";

const A98_R2B_RAW_SHA256: &str =
    "bd4cfd5e7bdf2bffd4d0dfc6ac1fc3042536d9b5493b09945fe9325f3f46f9d1";
const A98_PORT_SOURCE_SHA256: &str =
    "a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4";
const HEAD_START_PATCH_SHA256: &str =
    "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc";

const TFHE_KEYSWITCH_SHA256: &str =
    "4e21ac924972ca8884257aa5bb778f672c07b4c35be542b51e86583bfcd45913";
const TFHE_KSK_GENERATION_SHA256: &str =
    "bc6d7052c5735576b9248d03b4d79db45897133f7b825f8a627aa6be95f2fe27";
const TFHE_LWE_ENCRYPTION_SHA256: &str =
    "9e360ca3da9d4a7ecd01cfe36396ae15b7ace6ba5b582d4c7df3e006a3969d0a";
const TFHE_BSK_GENERATION_SHA256: &str =
    "efb3b96b252f8d17907bb94cadbe15a807a6156ef37693fe06c40507705345fd";
const TFHE_BSK_CONVERSION_SHA256: &str =
    "c861ec7b23782772516f178da3541065f787ff5f214b9cef14ce954814fa6e37";
const TFHE_FFT64_PBS_SHA256: &str =
    "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71";
const TFHE_GLWE_SECRET_KEY_SHA256: &str =
    "a5656381b3191eb7c0769950e3be157701ff88a1b6bc11942d5e0c4c05ef2948";
const TFHE_KSK_ENTITY_SHA256: &str =
    "89fbabeb594381e9e27d1aa0dbea57bfbbe306a8a9d89df09e744da274079c72";
const TFHE_LAZY_MS_SHA256: &str =
    "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d";
const TFHE_SAMPLE_EXTRACTION_SHA256: &str =
    "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43";
const TFHE_CRATE_ARCHIVE_SHA256: &str =
    "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52";

const PROTECTED_RITARATURA_SHA256: &str =
    "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab";
const PROTECTED_MEETING_SHA256: &str =
    "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745";
const PROTECTED_A38_SHA256: &str =
    "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37";

const TFHE_REGISTRY_ROOT: &str =
    "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0";
const TFHE_ARCHIVE: &str =
    "/opt/cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0.crate";

const BIG_LWE_DIMENSION: usize = 2048;
const SMALL_LWE_DIMENSION: usize = 859;
const GLWE_DIMENSION: usize = 1;
const POLYNOMIAL_SIZE: usize = 2048;
const KS_BASE_LOG: usize = 3;
const KS_LEVEL_COUNT: usize = 5;
const KS_PRECISION: usize = KS_BASE_LOG * KS_LEVEL_COUNT;
const PBS_BASE_LOG: usize = 23;
const PBS_LEVEL_COUNT: usize = 1;
const PBS_LOG_MODULUS: usize = 12;
const BLIND_ROTATION_MODULUS: usize = 1 << PBS_LOG_MODULUS;
const SCORE_DELTA_LOG: usize = 51;
const SCORE_DELTA: u64 = 1_u64 << SCORE_DELTA_LOG;
const SCORE_MAX: u64 = 4095;
const PBS_SHIFT: usize = u64::BITS as usize - PBS_LOG_MODULUS;
const PBS_STEP: u64 = 1_u64 << PBS_SHIFT;
const PBS_HALF_STEP: u64 = PBS_STEP >> 1;
const KS_DISCARDED_BITS: usize = u64::BITS as usize - KS_PRECISION;
const KS_ROUNDING_HALF: u64 = 1_u64 << (KS_DISCARDED_BITS - 1);
const LWE_NOISE_STDDEV: f64 = 2.3088161607134664e-6;
const GLWE_NOISE_STDDEV: f64 = 2.845267479601915e-15;
const RAYON_THREADS: usize = 8;
const MAX_TIE_EXTENSION: usize = 64;

const SECRET_SEED: u128 = 0xa1120000000000000000000000000001;
const ENCRYPTION_SEED: u128 = 0xa1120000000000000000000000000002;
const NOISE_ROOT_SEED: u128 = 0xa1120000000000000000000000000003;
const EXPECTED_DIGIT_STREAM_SHA256: &str =
    "cca1c6d6728dcee2c18920e5985557541e07ddb49e4b6820094971ee5e29a184";

#[derive(Debug)]
enum GateError {
    Invalid(String),
    RejectR3(String),
    RejectR2b(String),
    RejectR4(String),
}

impl GateError {
    fn status(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "INVALID",
            Self::RejectR3(_) => "REJECT_R3",
            Self::RejectR2b(_) => "REJECT_R2B",
            Self::RejectR4(_) => "REJECT_R4",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Invalid(message)
            | Self::RejectR3(message)
            | Self::RejectR2b(message)
            | Self::RejectR4(message) => message,
        }
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::RejectR3(_) => 3,
            Self::RejectR2b(_) => 4,
            Self::RejectR4(_) => 5,
        }
    }
}

type GateResult<T> = Result<T, GateError>;

fn invalid<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::Invalid(message.into()))
}

fn reject_r3<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::RejectR3(message.into()))
}

fn reject_r2b<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::RejectR2b(message.into()))
}

fn reject_r4<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::RejectR4(message.into()))
}

struct JsonlSink {
    writer: BufWriter<File>,
}

impl JsonlSink {
    fn create_new(path: &Path) -> GateResult<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                GateError::Invalid(format!(
                    "result path must be new and creatable ({}): {error}",
                    path.display()
                ))
            })?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    fn emit(&mut self, value: &Value) -> GateResult<()> {
        serde_json::to_writer(&mut self.writer, value)
            .map_err(|error| GateError::Invalid(format!("cannot encode JSONL: {error}")))?;
        self.writer
            .write_all(b"\n")
            .map_err(|error| GateError::Invalid(format!("cannot terminate JSONL: {error}")))?;
        self.writer
            .flush()
            .map_err(|error| GateError::Invalid(format!("cannot flush JSONL: {error}")))?;
        Ok(())
    }
}

fn emit_stdout(value: &Value) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, value);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> GateResult<String> {
    let bytes = fs::read(path)
        .map_err(|error| GateError::Invalid(format!("cannot read {}: {error}", path.display())))?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_u64s(values: &[u64]) -> String {
    let mut hasher = Sha256::new();
    for &value in values {
        hasher.update(value.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn require_hash(path: &Path, expected: &str) -> GateResult<String> {
    let actual = sha256_file(path)?;
    if actual != expected {
        return invalid(format!(
            "hash drift for {}: expected {expected}, observed {actual}",
            path.display()
        ));
    }
    Ok(actual)
}

fn require_environment_hash(name: &str, actual: &str) -> GateResult<()> {
    let expected = env::var(name)
        .map_err(|_| GateError::Invalid(format!("required environment {name} is absent")))?;
    if expected != actual {
        return invalid(format!(
            "{name} mismatch: environment {expected}, observed {actual}"
        ));
    }
    Ok(())
}

fn verify_build_report(
    path: &Path,
    source_sha256: &str,
    manifest_sha256: &str,
    lock_sha256: &str,
    executable_sha256: &str,
) -> GateResult<Value> {
    let bytes = fs::read(path).map_err(|error| {
        GateError::Invalid(format!("cannot read build report {}: {error}", path.display()))
    })?;
    let report: Value = serde_json::from_slice(&bytes).map_err(|error| {
        GateError::Invalid(format!("invalid build report JSON {}: {error}", path.display()))
    })?;
    let build = report
        .get("build")
        .and_then(Value::as_object)
        .ok_or_else(|| GateError::Invalid("build report lacks build object".into()))?;
    if report.get("schema").and_then(Value::as_str)
        != Some("a112.head-start-r3-r4.wrapper-build-report.v1")
        || report.get("status").and_then(Value::as_str)
            != Some("PASS_OFFLINE_LOCKED_BUILD_NOT_RUN")
        || report.get("source_sha256").and_then(Value::as_str) != Some(source_sha256)
        || report.get("manifest_sha256").and_then(Value::as_str) != Some(manifest_sha256)
        || report.get("lock_sha256").and_then(Value::as_str) != Some(lock_sha256)
        || report.get("executable_sha256").and_then(Value::as_str) != Some(executable_sha256)
        || build.get("offline").and_then(Value::as_bool) != Some(true)
        || build.get("locked").and_then(Value::as_bool) != Some(true)
        || build.get("release").and_then(Value::as_bool) != Some(true)
        || build.get("jobs").and_then(Value::as_u64) != Some(1)
        || report.get("keygen_run_during_build").and_then(Value::as_bool) != Some(false)
        || report.get("fhe_run_during_build").and_then(Value::as_bool) != Some(false)
    {
        return invalid("build report contract or exact hash linkage mismatch");
    }
    Ok(report)
}

fn verified_relative_path(root: &Path, relative: &str) -> GateResult<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return invalid(format!("source-pin path is not strictly relative: {relative}"));
    }
    Ok(root.join(path))
}

fn verify_source_pin_document(path: &Path, repo: &Path) -> GateResult<Value> {
    let bytes = fs::read(path).map_err(|error| {
        GateError::Invalid(format!("cannot read source pins {}: {error}", path.display()))
    })?;
    let pins: Value = serde_json::from_slice(&bytes).map_err(|error| {
        GateError::Invalid(format!("invalid source-pin JSON {}: {error}", path.display()))
    })?;
    let tfhe = pins
        .get("tfhe")
        .and_then(Value::as_object)
        .ok_or_else(|| GateError::Invalid("source pins lack tfhe object".into()))?;
    if pins.get("status").and_then(Value::as_str)
        != Some("STATIC_PINS_ONLY_NOT_COMPILED_NOT_RUN")
        || tfhe.get("version").and_then(Value::as_str) != Some("1.7.0")
        || tfhe.get("registry_root").and_then(Value::as_str) != Some(TFHE_REGISTRY_ROOT)
    {
        return invalid("source-pin status, version, or registry root drift");
    }

    let archive = tfhe
        .get("crate_archive")
        .and_then(Value::as_object)
        .ok_or_else(|| GateError::Invalid("source pins lack crate_archive object".into()))?;
    let archive_path = archive
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| GateError::Invalid("source pins lack crate archive path".into()))?;
    let archive_sha256 = archive
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| GateError::Invalid("source pins lack crate archive hash".into()))?;
    if archive_path != TFHE_ARCHIVE || archive_sha256 != TFHE_CRATE_ARCHIVE_SHA256 {
        return invalid("source-pin crate archive identity drift");
    }
    require_hash(Path::new(archive_path), archive_sha256)?;

    let selected = tfhe
        .get("selected_sources")
        .and_then(Value::as_object)
        .ok_or_else(|| GateError::Invalid("source pins lack selected_sources object".into()))?;
    for (relative, expected) in selected {
        let expected = expected.as_str().ok_or_else(|| {
            GateError::Invalid(format!("source pin for {relative} is not a string"))
        })?;
        require_hash(
            &verified_relative_path(Path::new(TFHE_REGISTRY_ROOT), relative)?,
            expected,
        )?;
    }

    let frozen = pins
        .get("frozen_inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| GateError::Invalid("source pins lack frozen_inputs object".into()))?;
    for (relative, expected) in frozen {
        let expected = expected.as_str().ok_or_else(|| {
            GateError::Invalid(format!("frozen-input pin for {relative} is not a string"))
        })?;
        require_hash(&verified_relative_path(repo, relative)?, expected)?;
    }

    Ok(json!({
        "status": "PASS",
        "tfhe_version": "1.7.0",
        "selected_tfhe_sources_checked": selected.len(),
        "frozen_inputs_checked": frozen.len(),
        "crate_archive_checked": true
    }))
}

fn repo_paths() -> GateResult<(PathBuf, PathBuf, PathBuf)> {
    let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let a112 = runtime
        .parent()
        .ok_or_else(|| GateError::Invalid("runtime wrapper has no A112 parent".into()))?
        .to_path_buf();
    let repo = a112
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| GateError::Invalid("A112 directory has no repository parent".into()))?
        .to_path_buf();
    Ok((repo, a112, runtime))
}

fn verify_r2b_raw(path: &Path) -> GateResult<Value> {
    let text = fs::read_to_string(path).map_err(|error| {
        GateError::Invalid(format!("cannot read R2B raw {}: {error}", path.display()))
    })?;
    let mut summaries = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|error| {
            GateError::Invalid(format!("invalid R2B JSONL line {}: {error}", line_index + 1))
        })?;
        if value.get("record").and_then(Value::as_str) == Some("summary") {
            summaries.push(value);
        }
    }
    if summaries.len() != 1 {
        return invalid(format!(
            "R2B raw needs one summary, observed {}",
            summaries.len()
        ));
    }
    let summary = summaries.pop().expect("length checked");
    let not_run = summary
        .get("not_run")
        .and_then(Value::as_array)
        .ok_or_else(|| GateError::Invalid("R2B summary missing not_run".into()))?;
    if summary.get("status").and_then(Value::as_str)
        != Some("PASS_COMPONENT_FHE_SMOKE_R2B")
        || summary.get("cases_passed").and_then(Value::as_u64) != Some(14)
        || summary.get("tie_zero_cases").and_then(Value::as_u64) != Some(6)
        || summary.get("tie_one_cases").and_then(Value::as_u64) != Some(8)
        || !not_run
            .iter()
            .any(|value| value.as_str() == Some("R3_corrected_keyswitch"))
        || !not_run
            .iter()
            .any(|value| value.as_str() == Some("R4_composed_KS_to_PBS"))
    {
        return invalid("R2B prerequisite summary drift");
    }
    Ok(summary)
}

struct Provenance {
    record: Value,
    result_path: PathBuf,
}

fn verify_provenance() -> GateResult<Provenance> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1] != "--run-authorized-r3-r4" {
        return invalid("expected exactly one argument: --run-authorized-r3-r4");
    }
    if env::var("A112_AUTHORIZED").ok().as_deref()
        != Some(WRAPPER_PREREGISTRATION_SHA256)
    {
        return invalid("A112_AUTHORIZED does not equal the wrapper preregistration hash");
    }
    if env::var("A112_ROOT_CLEAN_LOAD_GATE").ok().as_deref()
        != Some("ROOT_CONFIRMED_LOAD_AT_OR_BELOW_24_NO_COMPETING_FHE")
    {
        return invalid("missing exact root clean-load/no-competing-FHE token");
    }
    if env::var("RAYON_NUM_THREADS").ok().as_deref() != Some("8") {
        return invalid("RAYON_NUM_THREADS must be exactly 8");
    }
    if rayon::current_num_threads() != RAYON_THREADS {
        return invalid(format!(
            "Rayon initialized with {} threads instead of {RAYON_THREADS}",
            rayon::current_num_threads()
        ));
    }
    if env::var("A112_R2B_RAW_SHA256").ok().as_deref() != Some(A98_R2B_RAW_SHA256) {
        return invalid("A112_R2B_RAW_SHA256 does not equal the protected raw hash");
    }

    let (repo, a112, runtime) = repo_paths()?;
    let preregistration = require_hash(
        &runtime.join("WRAPPER_PREREGISTRATION.json"),
        WRAPPER_PREREGISTRATION_SHA256,
    )?;
    let manifest = require_hash(&runtime.join("Cargo.toml"), WRAPPER_MANIFEST_SHA256)?;
    let wrapper_readme = require_hash(&runtime.join("README.md"), WRAPPER_README_SHA256)?;
    let wrapper_api_audit = require_hash(
        &runtime.join("WRAPPER_API_AUDIT.md"),
        WRAPPER_API_AUDIT_SHA256,
    )?;
    let wrapper_source_pins = require_hash(
        &runtime.join("WRAPPER_SOURCE_PINS.json"),
        WRAPPER_SOURCE_PINS_SHA256,
    )?;
    let wrapper_source_pin_verification =
        verify_source_pin_document(&runtime.join("WRAPPER_SOURCE_PINS.json"), &repo)?;
    let source = sha256_file(&runtime.join("src/main.rs"))?;
    require_environment_hash("A112_RUNTIME_SOURCE_SHA256", &source)?;
    require_environment_hash("A112_RUNTIME_MANIFEST_SHA256", &manifest)?;

    let lock = sha256_file(&runtime.join("Cargo.lock"))?;
    require_environment_hash("A112_RUNTIME_LOCK_SHA256", &lock)?;
    let executable = env::current_exe()
        .map_err(|error| GateError::Invalid(format!("cannot locate executable: {error}")))?;
    let executable_hash = sha256_file(&executable)?;
    require_environment_hash("A112_EXECUTABLE_SHA256", &executable_hash)?;
    let build_report_path = runtime.join("WRAPPER_BUILD_REPORT.json");
    let build_report = sha256_file(&build_report_path)?;
    require_environment_hash("A112_BUILD_REPORT_SHA256", &build_report)?;
    let build_report_record = verify_build_report(
        &build_report_path,
        &source,
        &manifest,
        &lock,
        &executable_hash,
    )?;

    let parent_hashes = json!({
        "README.md": require_hash(&a112.join("README.md"), A112_PARENT_README_SHA256)?,
        "API_AUDIT.md": require_hash(&a112.join("API_AUDIT.md"), A112_API_AUDIT_SHA256)?,
        "PREREGISTRATION.json": require_hash(&a112.join("PREREGISTRATION.json"), A112_PARENT_PREREGISTRATION_SHA256)?,
        "SOURCE_PINS.json": require_hash(&a112.join("SOURCE_PINS.json"), A112_PARENT_SOURCE_PINS_SHA256)?,
        "STATIC_REPORT.json": require_hash(&a112.join("STATIC_REPORT.json"), A112_PARENT_STATIC_REPORT_SHA256)?,
        "a112_static_model.py": require_hash(&a112.join("a112_static_model.py"), A112_PARENT_MODEL_SHA256)?,
        "src/lib.rs": require_hash(&a112.join("src/lib.rs"), A112_PARENT_SOURCE_SHA256)?,
        "tests/test_static_model.py": require_hash(&a112.join("tests/test_static_model.py"), A112_PARENT_TEST_SHA256)?
    });
    let r2b_path = repo.join(
        "tmp/a98-head-start-exact-adapter-port/artifacts/a98_r2b_component_smoke_2026-09-03T0517.jsonl",
    );
    let r2b_hash = require_hash(&r2b_path, A98_R2B_RAW_SHA256)?;
    let r2b_summary = verify_r2b_raw(&r2b_path)?;
    let a98_source = require_hash(
        &repo.join("tmp/a98-head-start-exact-adapter-port/src/lib.rs"),
        A98_PORT_SOURCE_SHA256,
    )?;
    let patch = require_hash(
        &repo.join("tmp/pdfs/head-start.patch"),
        HEAD_START_PATCH_SHA256,
    )?;

    let protected = json!({
        "ritaratura_soglia": require_hash(
            &repo.join("experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt"),
            PROTECTED_RITARATURA_SHA256,
        )?,
        "meeting": require_hash(&repo.join("ultimo-meeting-transcription.md"), PROTECTED_MEETING_SHA256)?,
        "a38": require_hash(&repo.join("tmp/a38-combined-prototype/README.md"), PROTECTED_A38_SHA256)?
    });

    let tfhe = PathBuf::from(TFHE_REGISTRY_ROOT);
    let upstream = json!({
        "lwe_keyswitch": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_keyswitch.rs"), TFHE_KEYSWITCH_SHA256)?,
        "ksk_generation": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_keyswitch_key_generation.rs"), TFHE_KSK_GENERATION_SHA256)?,
        "lwe_encryption": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_encryption.rs"), TFHE_LWE_ENCRYPTION_SHA256)?,
        "bsk_generation": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_bootstrap_key_generation.rs"), TFHE_BSK_GENERATION_SHA256)?,
        "bsk_conversion": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_bootstrap_key_conversion.rs"), TFHE_BSK_CONVERSION_SHA256)?,
        "fft64_pbs": require_hash(&tfhe.join("src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs"), TFHE_FFT64_PBS_SHA256)?,
        "glwe_secret_key": require_hash(&tfhe.join("src/core_crypto/entities/glwe_secret_key.rs"), TFHE_GLWE_SECRET_KEY_SHA256)?,
        "ksk_entity": require_hash(&tfhe.join("src/core_crypto/entities/lwe_keyswitch_key.rs"), TFHE_KSK_ENTITY_SHA256)?,
        "lazy_ms": require_hash(&tfhe.join("src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs"), TFHE_LAZY_MS_SHA256)?,
        "sample_extraction": require_hash(&tfhe.join("src/core_crypto/algorithms/glwe_sample_extraction.rs"), TFHE_SAMPLE_EXTRACTION_SHA256)?,
        "crate_archive": require_hash(Path::new(TFHE_ARCHIVE), TFHE_CRATE_ARCHIVE_SHA256)?
    });

    let result_raw = env::var("A112_RESULT_PATH")
        .map_err(|_| GateError::Invalid("A112_RESULT_PATH is absent".into()))?;
    let result_path = PathBuf::from(&result_raw);
    let filename = result_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GateError::Invalid("result path has no UTF-8 filename".into()))?;
    if !filename.starts_with("a112_r3_r4_") || !filename.ends_with(".jsonl") {
        return invalid("result filename must match a112_r3_r4_*.jsonl");
    }
    if result_path.exists() {
        return invalid("result path already exists");
    }
    let expected_parent = fs::canonicalize(a112.join("artifacts")).map_err(|error| {
        GateError::Invalid(format!("cannot canonicalize A112 artifacts directory: {error}"))
    })?;
    let supplied_parent = result_path
        .parent()
        .ok_or_else(|| GateError::Invalid("result path has no parent".into()))?;
    let supplied_parent = fs::canonicalize(supplied_parent).map_err(|error| {
        GateError::Invalid(format!("cannot canonicalize result parent: {error}"))
    })?;
    if supplied_parent != expected_parent {
        return invalid(format!(
            "result parent must be {}, observed {}",
            expected_parent.display(),
            supplied_parent.display()
        ));
    }

    Ok(Provenance {
        result_path,
        record: json!({
            "record": "provenance",
            "status": "PASS",
            "stage": "A112_R3_R4",
            "wrapper_preregistration_sha256": preregistration,
            "wrapper_manifest_sha256": manifest,
            "wrapper_readme_sha256": wrapper_readme,
            "wrapper_api_audit_sha256": wrapper_api_audit,
            "wrapper_source_pins_sha256": wrapper_source_pins,
            "wrapper_source_pin_verification": wrapper_source_pin_verification,
            "wrapper_source_sha256": source,
            "wrapper_lock_sha256": lock,
            "wrapper_build_report_sha256": build_report,
            "wrapper_build_report": build_report_record,
            "executable_path": executable,
            "executable_sha256": executable_hash,
            "immutable_parent_hashes": parent_hashes,
            "a98_r2b_raw_sha256": r2b_hash,
            "a98_r2b_summary": r2b_summary,
            "a98_port_source_sha256": a98_source,
            "head_start_patch_sha256": patch,
            "protected_hashes": protected,
            "tfhe_1_7_hashes": upstream,
            "rayon_threads": rayon::current_num_threads(),
            "root_clean_load_gate": "present_exact",
            "claim_boundary": "component-only; not an exact-ID or performance result"
        }),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureFamily {
    HonestGaussian,
    KeyConsistentNonGaussian,
    TieExtensionGaussian,
}

impl FixtureFamily {
    fn label(self) -> &'static str {
        match self {
            Self::HonestGaussian => "honest_gaussian_encryption",
            Self::KeyConsistentNonGaussian => "key_consistent_non_gaussian",
            Self::TieExtensionGaussian => "tie_extension_honest_gaussian",
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureSpec {
    id: &'static str,
    family: FixtureFamily,
    plaintext: u64,
    injected_error: Option<i64>,
    mask_pattern: Option<&'static str>,
    expected_mask_sha256: Option<&'static str>,
}

fn score_plaintext(score: u64) -> GateResult<u64> {
    if score > SCORE_MAX {
        return invalid(format!("score {score} is outside 12 bits"));
    }
    Ok(score << SCORE_DELTA_LOG)
}

fn base_fixture_specs() -> GateResult<Vec<FixtureSpec>> {
    Ok(vec![
        FixtureSpec { id: "h_score_0", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(0)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_1", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(1)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_2", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(2)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_2047", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(2047)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_2048", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(2048)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_4094", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(4094)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_score_4095", family: FixtureFamily::HonestGaussian, plaintext: score_plaintext(4095)?, injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_negative_one", family: FixtureFamily::HonestGaussian, plaintext: 0_u64.wrapping_sub(SCORE_DELTA), injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "h_wrap_high", family: FixtureFamily::HonestGaussian, plaintext: u64::MAX.wrapping_sub(SCORE_DELTA).wrapping_add(1), injected_error: None, mask_pattern: None, expected_mask_sha256: None },
        FixtureSpec { id: "i_state_16384", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: score_plaintext(1)?, injected_error: Some(1), mask_pattern: Some("single_state_16384_1"), expected_mask_sha256: Some("88f8e63ab46717bd2b67ac55e9c15987ca4687a8ba5f9bfa116d003787f07741") },
        FixtureSpec { id: "i_state_16385", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: score_plaintext(2047)?, injected_error: Some(-1), mask_pattern: Some("single_state_16385_-1"), expected_mask_sha256: Some("701fc6f9543d5bada28952f2284d27a638139f56fb8d26f942155b800f088685") },
        FixtureSpec { id: "i_state_18204", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: score_plaintext(2048)?, injected_error: Some(1), mask_pattern: Some("single_state_18204_1"), expected_mask_sha256: Some("d643d2c781b0f23736c716d003281fc768f72ac3105abd4bf5898b02096c4bce") },
        FixtureSpec { id: "i_state_18205", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: score_plaintext(4095)?, injected_error: Some(-1), mask_pattern: Some("single_state_18205_-1"), expected_mask_sha256: Some("514c20139ab03270605ce0a58ae0d7922dd18e1c225223dfa2be8bf334cdac2e") },
        FixtureSpec { id: "i_negative_correction", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: 0_u64.wrapping_sub(SCORE_DELTA), injected_error: Some(-(1 << 20)), mask_pattern: Some("negative_correction_all_minus_one"), expected_mask_sha256: Some("8729cea9f823c70ae5411848d7e79fe34937c1a1ab5dc52dac5cd46b80959a3b") },
        FixtureSpec { id: "i_positive_correction", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: score_plaintext(4095)?, injected_error: Some(1 << 20), mask_pattern: Some("positive_correction_all_plus_one"), expected_mask_sha256: Some("9020d3138618679b49944d0da3ee1e4a532d843e13c69808ffdb453e5e1ff7ac") },
        FixtureSpec { id: "i_wrap_palette", family: FixtureFamily::KeyConsistentNonGaussian, plaintext: u64::MAX, injected_error: Some(-1), mask_pattern: Some("wrap_palette"), expected_mask_sha256: Some("e637ee446d076b370dcc074d287b714ed1e180144eb40c95ecd3acb7e4607ac2") },
    ])
}

fn state_coefficient(state: u64, signed_residual: i64) -> GateResult<u64> {
    if state >= 1_u64 << KS_PRECISION
        || signed_residual <= -(KS_ROUNDING_HALF as i64)
        || signed_residual >= KS_ROUNDING_HALF as i64
    {
        return invalid("invalid state-coefficient fixture geometry");
    }
    let rounded = state << KS_DISCARDED_BITS;
    let coefficient = rounded.wrapping_add(signed_residual as u64);
    let observed = coefficient.wrapping_add(KS_ROUNDING_HALF)
        & (1_u64 << KS_DISCARDED_BITS).wrapping_neg();
    if observed != rounded {
        return invalid("state coefficient does not round to requested state");
    }
    Ok(coefficient)
}

fn fixture_mask(pattern: &str) -> GateResult<Vec<u64>> {
    let mut mask = vec![0_u64; BIG_LWE_DIMENSION];
    if let Some(rest) = pattern.strip_prefix("single_state_") {
        let (state_text, residual_text) = rest
            .rsplit_once('_')
            .ok_or_else(|| GateError::Invalid(format!("invalid single-state pattern {pattern}")))?;
        let state: u64 = state_text
            .parse()
            .map_err(|_| GateError::Invalid(format!("invalid fixture state {state_text}")))?;
        let residual: i64 = residual_text
            .parse()
            .map_err(|_| GateError::Invalid(format!("invalid fixture residual {residual_text}")))?;
        mask[state as usize % BIG_LWE_DIMENSION] = state_coefficient(state, residual)?;
        return Ok(mask);
    }
    match pattern {
        "negative_correction_all_minus_one" => {
            Ok(vec![state_coefficient(1, -1)?; BIG_LWE_DIMENSION])
        }
        "positive_correction_all_plus_one" => {
            Ok(vec![state_coefficient(1, 1)?; BIG_LWE_DIMENSION])
        }
        "wrap_palette" => {
            let palette = [
                0,
                1,
                KS_ROUNDING_HALF - 1,
                KS_ROUNDING_HALF,
                KS_ROUNDING_HALF + 1,
                u64::MAX,
                u64::MAX - KS_ROUNDING_HALF,
                u64::MAX - KS_ROUNDING_HALF + 1,
            ];
            for (index, value) in mask.iter_mut().enumerate() {
                *value = palette[index % palette.len()];
            }
            Ok(mask)
        }
        _ => invalid(format!("unknown fixture pattern {pattern}")),
    }
}

fn assemble_key_consistent_lwe(
    secret: &LweSecretKey<&[u64]>,
    mask: &[u64],
    plaintext: u64,
    signed_error: i64,
) -> GateResult<LweCiphertextOwned<u64>> {
    if secret.as_ref().len() != BIG_LWE_DIMENSION || mask.len() != BIG_LWE_DIMENSION {
        return invalid("key-consistent fixture dimension mismatch");
    }
    if secret.as_ref().iter().any(|&bit| bit > 1) {
        return invalid("large key is not binary");
    }
    let body = mask.iter().zip(secret.as_ref()).fold(
        plaintext.wrapping_add(signed_error as u64),
        |sum, (&coefficient, &bit)| sum.wrapping_add(coefficient.wrapping_mul(bit)),
    );
    let mut container = Vec::with_capacity(BIG_LWE_DIMENSION + 1);
    container.extend_from_slice(mask);
    container.push(body);
    Ok(LweCiphertextOwned::from_container(
        container,
        CiphertextModulus::new_native(),
    ))
}

fn validate_no_key_digit_stream() -> GateResult<String> {
    let base_log = DecompositionBaseLog(KS_BASE_LOG);
    let level_count = DecompositionLevelCount(KS_LEVEL_COUNT);
    let mut hasher = Sha256::new();
    for state in 0..(1_u64 << KS_PRECISION) {
        let reference: Vec<u64> = ReferencePatchIter::new(state)
            .map_err(|error| GateError::Invalid(format!("reference iterator: {error:?}")))?
            .map(|term| term.value())
            .collect();
        let local: Vec<u64> = HeadStartDecompositionIter::from_truncated_state(
            state,
            base_log,
            level_count,
        )
        .map_err(|error| GateError::Invalid(format!("A98 iterator: {error}")))?
        .map(|term| term.value())
        .collect();
        if reference != local || reference.len() != KS_LEVEL_COUNT {
            return reject_r3(format!("digit stream mismatch at state {state}"));
        }
        hasher.update(state.to_le_bytes());
        for value in reference {
            hasher.update(value.to_le_bytes());
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn exhaustive_first_ksk_block(
    key: &LweKeyswitchKeyOwned<u64>,
) -> GateResult<(String, f64)> {
    let started = Instant::now();
    let mut hasher = Sha256::new();
    let output_len = LweDimension(SMALL_LWE_DIMENSION).to_lwe_size().0;
    let base_log = DecompositionBaseLog(KS_BASE_LOG);
    let level_count = DecompositionLevelCount(KS_LEVEL_COUNT);
    for state in 0..(1_u64 << KS_PRECISION) {
        let mut reference_output = vec![0_u64; output_len];
        let reference_block = key
            .iter()
            .next()
            .ok_or_else(|| GateError::Invalid("KSK has no input block".into()))?;
        let reference_terms = ReferencePatchIter::new(state)
            .map_err(|error| GateError::Invalid(format!("reference iterator: {error:?}")))?;
        for (level_ciphertext, term) in reference_block.iter().zip(reference_terms) {
            slice_wrapping_sub_scalar_mul_assign(
                &mut reference_output,
                level_ciphertext.as_ref(),
                term.value(),
            );
        }

        let mut local_output = vec![0_u64; output_len];
        let local_block = key
            .iter()
            .next()
            .ok_or_else(|| GateError::Invalid("KSK has no input block".into()))?;
        let local_terms = HeadStartDecompositionIter::from_truncated_state(
            state,
            base_log,
            level_count,
        )
        .map_err(|error| GateError::Invalid(format!("A98 iterator: {error}")))?;
        for (level_ciphertext, term) in local_block.iter().zip(local_terms) {
            slice_wrapping_sub_scalar_mul_assign(
                &mut local_output,
                level_ciphertext.as_ref(),
                term.value(),
            );
        }
        if reference_output != local_output {
            return reject_r3(format!(
                "first-KSK-block scalar contribution mismatch at state {state}"
            ));
        }
        hasher.update(state.to_le_bytes());
        for value in reference_output {
            hasher.update(value.to_le_bytes());
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    if !seconds.is_finite() || seconds < 0.0 {
        return invalid("non-finite exhaustive KSK-block diagnostic time");
    }
    Ok((format!("{:x}", hasher.finalize()), seconds))
}

fn lifted_round(value: u64) -> u64 {
    value.wrapping_add(PBS_HALF_STEP) >> PBS_SHIFT << PBS_SHIFT
}

fn direct_r2b_oracle(mask: &[u64]) -> (i128, i128, u64, i128) {
    let mut d_sum = 0_i128;
    let mut h_sum = 0_i128;
    for &coefficient in mask {
        let residual = lifted_round(coefficient).wrapping_sub(coefficient) as i64;
        let half = residual / 2;
        d_sum += i128::from(residual);
        h_sum += i128::from(2 * half - residual);
    }
    let tie = u64::from(h_sum < 0 && h_sum % 2 != 0);
    let correction = if d_sum >= 0 {
        (d_sum + 1) / 2
    } else {
        d_sum / 2
    };
    (d_sum, h_sum, tie, correction)
}

fn ideal_monic_division(input: &[u64], degree: usize) -> GateResult<Vec<u64>> {
    if input.len() != POLYNOMIAL_SIZE || degree >= 2 * POLYNOMIAL_SIZE {
        return invalid("invalid ideal monomial-division geometry");
    }
    let exponent = (2 * POLYNOMIAL_SIZE - degree) % (2 * POLYNOMIAL_SIZE);
    let mut output = vec![0_u64; POLYNOMIAL_SIZE];
    for (index, &coefficient) in input.iter().enumerate() {
        let reduced = (index + exponent) % (2 * POLYNOMIAL_SIZE);
        if reduced < POLYNOMIAL_SIZE {
            output[reduced] = output[reduced].wrapping_add(coefficient);
        } else {
            output[reduced - POLYNOMIAL_SIZE] =
                output[reduced - POLYNOMIAL_SIZE].wrapping_sub(coefficient);
        }
    }
    Ok(output)
}

fn nearest_rank(sorted: &[u64], numerator: usize, denominator: usize) -> GateResult<u64> {
    if sorted.is_empty() || numerator == 0 || numerator > denominator || denominator == 0 {
        return invalid("invalid quantile request");
    }
    let rank = numerator
        .checked_mul(sorted.len())
        .and_then(|value| value.checked_add(denominator - 1))
        .ok_or_else(|| GateError::Invalid("quantile rank overflow".into()))?
        / denominator;
    Ok(sorted[rank.saturating_sub(1)])
}

#[derive(Clone, Copy)]
struct PhaseDiagnostics {
    maximum: u64,
    signed_at_maximum: i64,
    index_at_maximum: usize,
    p50: u64,
    p95: u64,
    p99: u64,
}

fn phase_diagnostics(observed: &[u64], expected: &[u64]) -> GateResult<PhaseDiagnostics> {
    if observed.len() != expected.len() {
        return invalid("phase diagnostic length mismatch");
    }
    let mut absolute = Vec::with_capacity(observed.len());
    let mut maximum = 0_u64;
    let mut signed_at_maximum = 0_i64;
    let mut index_at_maximum = 0_usize;
    for (index, (&actual, &ideal)) in observed.iter().zip(expected).enumerate() {
        let signed = actual.wrapping_sub(ideal) as i64;
        let magnitude = signed.unsigned_abs();
        absolute.push(magnitude);
        if magnitude > maximum {
            maximum = magnitude;
            signed_at_maximum = signed;
            index_at_maximum = index;
        }
    }
    absolute.sort_unstable();
    Ok(PhaseDiagnostics {
        maximum,
        signed_at_maximum,
        index_at_maximum,
        p50: nearest_rank(&absolute, 50, 100)?,
        p95: nearest_rank(&absolute, 95, 100)?,
        p99: nearest_rank(&absolute, 99, 100)?,
    })
}

fn ramp_decode_degree(value: u64) -> usize {
    ((value.wrapping_add(PBS_HALF_STEP) >> PBS_SHIFT) as usize)
        & (BLIND_ROTATION_MODULUS - 1)
}

fn run_blind_rotation(
    switched: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &GlweCiphertextOwned<u64>,
    fourier_bsk: &FourierLweBootstrapKeyOwned,
) -> (GlweCiphertextOwned<u64>, f64) {
    let mut output = lut.clone();
    let started = Instant::now();
    blind_rotate_assign(
        std::hint::black_box(switched),
        std::hint::black_box(&mut output),
        std::hint::black_box(fourier_bsk),
    );
    (output, started.elapsed().as_secs_f64())
}

struct CaseOutcome {
    tie: u64,
    reference_ks_seconds: f64,
    local_ks_seconds: f64,
    reference_pbs_seconds: f64,
    local_pbs_seconds: f64,
    maximum_full_glwe_error: u64,
}

#[allow(clippy::too_many_arguments)]
fn process_case(
    sink: &mut JsonlSink,
    index: usize,
    id: &str,
    family: FixtureFamily,
    input: &LweCiphertextOwned<u64>,
    target_plaintext: u64,
    injected_error: Option<i64>,
    glwe_secret: &GlweSecretKeyOwned<u64>,
    big_secret: &LweSecretKey<&[u64]>,
    small_secret: &LweSecretKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    fourier_bsk: &FourierLweBootstrapKeyOwned,
    lut: &GlweCiphertextOwned<u64>,
    lut_body: &[u64],
) -> GateResult<CaseOutcome> {
    let input_phase = decrypt_lwe_ciphertext(big_secret, input).0;
    let input_error = input_phase.wrapping_sub(target_plaintext) as i64;
    if let Some(expected) = injected_error {
        if input_error != expected {
            return invalid(format!(
                "key-consistent input phase error drift for {id}: expected {expected}, observed {input_error}"
            ));
        }
    }

    let make_small = || {
        LweCiphertextOwned::new(
            0_u64,
            LweDimension(SMALL_LWE_DIMENSION).to_lwe_size(),
            CiphertextModulus::new_native(),
        )
    };
    let mut reference_small = make_small();
    let mut local_small = make_small();

    let run_reference_ks = |output: &mut LweCiphertextOwned<u64>| -> GateResult<f64> {
        let started = Instant::now();
        reference_patch_corrected_keyswitch(ksk, input, output)
            .map_err(|error| GateError::Invalid(format!("reference KS rejected {id}: {error:?}")))?;
        Ok(started.elapsed().as_secs_f64())
    };
    let run_local_ks = |output: &mut LweCiphertextOwned<u64>| -> GateResult<f64> {
        let started = Instant::now();
        a112_local_corrected_keyswitch(ksk, input, output)
            .map_err(|error| GateError::Invalid(format!("local KS rejected {id}: {error:?}")))?;
        Ok(started.elapsed().as_secs_f64())
    };
    let (reference_ks_seconds, local_ks_seconds, r3_order) = if index % 2 == 0 {
        (
            run_reference_ks(&mut reference_small)?,
            run_local_ks(&mut local_small)?,
            "REFERENCE_THEN_LOCAL",
        )
    } else {
        let local = run_local_ks(&mut local_small)?;
        let reference = run_reference_ks(&mut reference_small)?;
        (reference, local, "LOCAL_THEN_REFERENCE")
    };
    if reference_small.as_ref() != local_small.as_ref() {
        return reject_r3(format!("post-KS ciphertext mismatch for {id}"));
    }
    let reference_small_phase = decrypt_lwe_ciphertext(small_secret, &reference_small).0;
    let local_small_phase = decrypt_lwe_ciphertext(small_secret, &local_small).0;
    if reference_small_phase != local_small_phase {
        return reject_r3(format!("post-KS decrypted phase mismatch for {id}"));
    }

    let (d, h, tie, direct_correction_signed) =
        direct_r2b_oracle(reference_small.get_mask().as_ref());
    let reference_switched = reference_head_start_modulus_switch(reference_small.clone())
        .map_err(|error| GateError::Invalid(format!("reference R2B rejected {id}: {error:?}")))?;
    let local_switched = exact_head_start_modulus_switch(
        local_small.clone(),
        CiphertextModulusLog(PBS_LOG_MODULUS),
    )
    .map_err(|error| GateError::Invalid(format!("A98 R2B rejected {id}: {error}")))?;

    let reference_mask_degrees: Vec<usize> = reference_switched.mask().collect();
    let local_mask_degrees: Vec<usize> = local_switched.mask().collect();
    let reference_body_degree = reference_switched.body();
    let local_body_degree = local_switched.body();
    let (_, reference_correction, reference_log) =
        reference_switched.clone().into_raw_parts();
    let (_, local_correction, local_log) = local_switched.clone().into_raw_parts();
    let direct_correction = (direct_correction_signed as i64) as u64;
    if reference_correction != direct_correction
        || local_correction != direct_correction
        || reference_log != CiphertextModulusLog(PBS_LOG_MODULUS)
        || local_log != CiphertextModulusLog(PBS_LOG_MODULUS)
        || reference_switched.lwe_dimension().0 != SMALL_LWE_DIMENSION
        || local_switched.lwe_dimension().0 != SMALL_LWE_DIMENSION
        || reference_mask_degrees != local_mask_degrees
        || reference_body_degree != local_body_degree
    {
        return reject_r2b(format!("pre-FFT R2B mismatch for {id}"));
    }

    let ((reference_glwe, reference_pbs_seconds), (local_glwe, local_pbs_seconds), r4_order) =
        if index % 2 == 0 {
            (
                run_blind_rotation(&reference_switched, lut, fourier_bsk),
                run_blind_rotation(&local_switched, lut, fourier_bsk),
                "REFERENCE_THEN_LOCAL",
            )
        } else {
            let local = run_blind_rotation(&local_switched, lut, fourier_bsk);
            let reference = run_blind_rotation(&reference_switched, lut, fourier_bsk);
            (reference, local, "LOCAL_THEN_REFERENCE")
        };
    let timings = [
        reference_ks_seconds,
        local_ks_seconds,
        reference_pbs_seconds,
        local_pbs_seconds,
    ];
    if timings.iter().any(|value| !value.is_finite() || *value < 0.0) {
        return invalid(format!("non-finite diagnostic timing for {id}"));
    }
    if reference_glwe.as_ref() != local_glwe.as_ref() {
        return reject_r4(format!("post-blind-rotation GLWE mismatch for {id}"));
    }

    let mut reference_plaintext = PlaintextList::new(0_u64, PlaintextCount(POLYNOMIAL_SIZE));
    let mut local_plaintext = PlaintextList::new(0_u64, PlaintextCount(POLYNOMIAL_SIZE));
    decrypt_glwe_ciphertext(glwe_secret, &reference_glwe, &mut reference_plaintext);
    decrypt_glwe_ciphertext(glwe_secret, &local_glwe, &mut local_plaintext);
    if reference_plaintext.as_ref() != local_plaintext.as_ref() {
        return reject_r4(format!("decrypted GLWE mismatch for {id}"));
    }

    let output_lwe_size = LweDimension(BIG_LWE_DIMENSION).to_lwe_size();
    let mut reference_sample = LweCiphertextOwned::new(
        0_u64,
        output_lwe_size,
        CiphertextModulus::new_native(),
    );
    let mut local_sample = LweCiphertextOwned::new(
        0_u64,
        output_lwe_size,
        CiphertextModulus::new_native(),
    );
    extract_lwe_sample_from_glwe_ciphertext(
        &reference_glwe,
        &mut reference_sample,
        MonomialDegree(0),
    );
    extract_lwe_sample_from_glwe_ciphertext(&local_glwe, &mut local_sample, MonomialDegree(0));
    if reference_sample.as_ref() != local_sample.as_ref() {
        return reject_r4(format!("degree-zero extracted LWE mismatch for {id}"));
    }
    let reference_output_phase = decrypt_lwe_ciphertext(big_secret, &reference_sample).0;
    let local_output_phase = decrypt_lwe_ciphertext(big_secret, &local_sample).0;
    if reference_output_phase != local_output_phase {
        return reject_r4(format!("degree-zero decrypted output mismatch for {id}"));
    }

    let mask_phase = reference_mask_degrees.iter().zip(small_secret.as_ref()).fold(
        0_usize,
        |sum, (&degree, &secret)| {
            (sum + degree * secret as usize) % BLIND_ROTATION_MODULUS
        },
    );
    let switched_phase_degree =
        (reference_body_degree + BLIND_ROTATION_MODULUS - mask_phase)
            % BLIND_ROTATION_MODULUS;
    let ideal_plaintext = ideal_monic_division(lut_body, switched_phase_degree)?;
    let diagnostics = phase_diagnostics(reference_plaintext.as_ref(), &ideal_plaintext)?;
    let ideal_output_phase = ideal_plaintext[0];
    let decoded_reference = ramp_decode_degree(reference_output_phase);
    let decoded_local = ramp_decode_degree(local_output_phase);
    let decoded_ideal = ramp_decode_degree(ideal_output_phase);
    if decoded_reference != decoded_local || decoded_reference != decoded_ideal {
        return reject_r4(format!("ideal ramp decode mismatch for {id}"));
    }

    sink.emit(&json!({
        "record": if family == FixtureFamily::TieExtensionGaussian { "tie_extension_case" } else { "base_case" },
        "status": "PASS",
        "index": index,
        "id": id,
        "family": family.label(),
        "input_ciphertext_sha256": sha256_u64s(input.as_ref()),
        "target_plaintext_hex": format!("0x{target_plaintext:016x}"),
        "input_phase_hex": format!("0x{input_phase:016x}"),
        "input_signed_error": input_error,
        "injected_error": injected_error,
        "r3": {
            "arm_order": r3_order,
            "reference_seconds_diagnostic": reference_ks_seconds,
            "local_seconds_diagnostic": local_ks_seconds,
            "post_ks_ciphertext_sha256": sha256_u64s(reference_small.as_ref()),
            "post_ks_phase_hex": format!("0x{reference_small_phase:016x}"),
            "post_ks_signed_error_vs_target": reference_small_phase.wrapping_sub(target_plaintext) as i64,
            "post_ks_signed_phase_delta_vs_input": reference_small_phase.wrapping_sub(input_phase) as i64,
            "bitwise_equal": true
        },
        "r2b": {
            "D": d.to_string(),
            "H": h.to_string(),
            "tie": tie,
            "direct_correction_signed": direct_correction_signed.to_string(),
            "correction_hex": format!("0x{direct_correction:016x}"),
            "mask_degrees_sha256": sha256_u64s(&reference_mask_degrees.iter().map(|&degree| degree as u64).collect::<Vec<_>>()),
            "body_degree": reference_body_degree,
            "switched_phase_degree": switched_phase_degree,
            "pre_fft_equal": true
        },
        "r4": {
            "arm_order": r4_order,
            "reference_seconds_diagnostic": reference_pbs_seconds,
            "local_seconds_diagnostic": local_pbs_seconds,
            "post_blind_rotation_sha256": sha256_u64s(reference_glwe.as_ref()),
            "degree_zero_lwe_sha256": sha256_u64s(reference_sample.as_ref()),
            "degree_zero_phase_hex": format!("0x{reference_output_phase:016x}"),
            "ideal_phase_hex": format!("0x{ideal_output_phase:016x}"),
            "signed_phase_error": reference_output_phase.wrapping_sub(ideal_output_phase) as i64,
            "decoded_degree": decoded_reference,
            "ideal_decoded_degree": decoded_ideal,
            "bitwise_equal": true,
            "ideal_decode_equal": true
        },
        "full_glwe_error_diagnostic": {
            "maximum_absolute": diagnostics.maximum,
            "signed_at_maximum": diagnostics.signed_at_maximum,
            "index_at_maximum": diagnostics.index_at_maximum,
            "p50_absolute_nearest_rank": diagnostics.p50,
            "p95_absolute_nearest_rank": diagnostics.p95,
            "p99_absolute_nearest_rank": diagnostics.p99,
            "decision_role": "diagnostic_only_no_cap_no_independence_assumption"
        },
        "claim_boundary": "one paired component case; not exact-ID"
    }))?;

    Ok(CaseOutcome {
        tie,
        reference_ks_seconds,
        local_ks_seconds,
        reference_pbs_seconds,
        local_pbs_seconds,
        maximum_full_glwe_error: diagnostics.maximum,
    })
}

fn execute(sink: &mut JsonlSink, provenance: Value) -> GateResult<()> {
    let wall_started = Instant::now();
    sink.emit(&provenance)?;

    if BIG_LWE_DIMENSION != GLWE_DIMENSION * POLYNOMIAL_SIZE
        || BLIND_ROTATION_MODULUS != 2 * POLYNOMIAL_SIZE
        || KS_PRECISION != 15
        || PBS_LOG_MODULUS != 12
        || SCORE_MAX * SCORE_DELTA >= 1_u64 << 63
    {
        return invalid("compiled constant geometry drift");
    }
    let fixture_specs = base_fixture_specs()?;
    if fixture_specs.len() != 16 {
        return invalid("base fixture count drift");
    }
    let no_key_digit_stream_sha256 = validate_no_key_digit_stream()?;
    if no_key_digit_stream_sha256 != EXPECTED_DIGIT_STREAM_SHA256 {
        return reject_r3(format!(
            "finite digit-stream hash drift: expected {EXPECTED_DIGIT_STREAM_SHA256}, observed {no_key_digit_stream_sha256}"
        ));
    }

    let mut lut = GlweCiphertextOwned::new(
        0_u64,
        GlweDimension(GLWE_DIMENSION).to_glwe_size(),
        PolynomialSize(POLYNOMIAL_SIZE),
        CiphertextModulus::new_native(),
    );
    let lut_body: Vec<u64> = (0..POLYNOMIAL_SIZE)
        .map(|index| (index as u64).wrapping_mul(PBS_STEP))
        .collect();
    lut.get_mut_body().as_mut().copy_from_slice(&lut_body);

    sink.emit(&json!({
        "record": "run_start",
        "status": "PASS_PREFLIGHT",
        "stage": "A112_R3_R4",
        "base_cases": 16,
        "maximum_tie_extension_cases": MAX_TIE_EXTENSION,
        "no_key_digit_states": 1 << KS_PRECISION,
        "no_key_digit_stream_sha256": no_key_digit_stream_sha256,
        "params": {
            "big_lwe_dimension": BIG_LWE_DIMENSION,
            "small_lwe_dimension": SMALL_LWE_DIMENSION,
            "glwe_dimension": GLWE_DIMENSION,
            "polynomial_size": POLYNOMIAL_SIZE,
            "ks_base_log": KS_BASE_LOG,
            "ks_level_count": KS_LEVEL_COUNT,
            "pbs_base_log": PBS_BASE_LOG,
            "pbs_level_count": PBS_LEVEL_COUNT,
            "pbs_log_modulus": PBS_LOG_MODULUS,
            "score_delta_log": SCORE_DELTA_LOG,
            "ciphertext_modulus": "native_u64"
        },
        "public_test_seeds": {
            "secret": format!("0x{SECRET_SEED:032x}"),
            "encryption": format!("0x{ENCRYPTION_SEED:032x}"),
            "noise_root": format!("0x{NOISE_ROOT_SEED:032x}"),
            "warning": "reconstructible test-only keys; never deploy or reuse"
        },
        "shared_lut_body_sha256": sha256_u64s(&lut_body),
        "timing_role": "diagnostic_only_not_a_benchmark",
        "phase_error_cap": null,
        "exact_id_promotion": false
    }))?;

    let mut noise_seeder =
        DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(NOISE_ROOT_SEED));
    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(Seed(SECRET_SEED));
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        Seed(ENCRYPTION_SEED),
        &mut noise_seeder,
    );

    let secret_started = Instant::now();
    let glwe_secret = allocate_and_generate_new_binary_glwe_secret_key(
        GlweDimension(GLWE_DIMENSION),
        PolynomialSize(POLYNOMIAL_SIZE),
        &mut secret_generator,
    );
    let small_secret = allocate_and_generate_new_binary_lwe_secret_key(
        LweDimension(SMALL_LWE_DIMENSION),
        &mut secret_generator,
    );
    let secret_seconds = secret_started.elapsed().as_secs_f64();
    if glwe_secret.as_ref().iter().any(|&bit| bit > 1)
        || small_secret.as_ref().iter().any(|&bit| bit > 1)
        || glwe_secret.as_ref().iter().all(|&bit| bit == 0)
        || small_secret.as_ref().iter().all(|&bit| bit == 0)
    {
        return invalid("binary secret-key sanity check failed");
    }
    let big_secret = glwe_secret.as_lwe_secret_key();

    let ksk_started = Instant::now();
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_secret,
        &small_secret,
        DecompositionBaseLog(KS_BASE_LOG),
        DecompositionLevelCount(KS_LEVEL_COUNT),
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(LWE_NOISE_STDDEV)),
        CiphertextModulus::new_native(),
        &mut encryption_generator,
    );
    let ksk_seconds = ksk_started.elapsed().as_secs_f64();
    let ksk_sha256 = sha256_u64s(ksk.as_ref());
    let ksk_coefficients = ksk.as_ref().len();

    let bsk_started = Instant::now();
    let standard_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_secret,
        &glwe_secret,
        DecompositionBaseLog(PBS_BASE_LOG),
        DecompositionLevelCount(PBS_LEVEL_COUNT),
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(GLWE_NOISE_STDDEV)),
        CiphertextModulus::new_native(),
        &mut encryption_generator,
    );
    let bsk_seconds = bsk_started.elapsed().as_secs_f64();
    let standard_bsk_sha256 = sha256_u64s(standard_bsk.as_ref());
    let standard_bsk_coefficients = standard_bsk.as_ref().len();

    let fourier_started = Instant::now();
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        standard_bsk.input_lwe_dimension(),
        standard_bsk.glwe_size(),
        standard_bsk.polynomial_size(),
        standard_bsk.decomposition_base_log(),
        standard_bsk.decomposition_level_count(),
    );
    let fft = Fft::new(PolynomialSize(POLYNOMIAL_SIZE));
    fourier_bsk
        .as_mut_view()
        .par_fill_with_forward_fourier(standard_bsk.as_view(), fft.as_view());
    let fourier_seconds = fourier_started.elapsed().as_secs_f64();
    drop(standard_bsk);

    for value in [
        secret_seconds,
        ksk_seconds,
        bsk_seconds,
        fourier_seconds,
    ] {
        if !value.is_finite() || value < 0.0 {
            return invalid("non-finite key-setup diagnostic timing");
        }
    }
    let (ksk_block_sha256, ksk_block_seconds) = exhaustive_first_ksk_block(&ksk)?;
    sink.emit(&json!({
        "record": "fresh_key",
        "status": "PASS",
        "key_index": 0,
        "ephemeral": true,
        "persisted_key_bytes": false,
        "secret_key_hashes_emitted": false,
        "public_seed_warning": "all secret material is reconstructible and test-only",
        "secret_generation_seconds_diagnostic": secret_seconds,
        "ksk_generation_seconds_diagnostic": ksk_seconds,
        "standard_bsk_generation_seconds_diagnostic": bsk_seconds,
        "fourier_conversion_seconds_diagnostic": fourier_seconds,
        "ksk_sha256": ksk_sha256,
        "ksk_u64_coefficients": ksk_coefficients,
        "standard_bsk_sha256": standard_bsk_sha256,
        "standard_bsk_u64_coefficients": standard_bsk_coefficients,
        "standard_bsk_dropped_after_fourier_conversion": true,
        "drop_is_verified_zeroization": false
    }))?;
    sink.emit(&json!({
        "record": "r3_exhaustive_block",
        "status": "PASS",
        "states": 1 << KS_PRECISION,
        "ksk_input_block_index": 0,
        "reference_local_scalar_contributions_equal": true,
        "output_stream_sha256": ksk_block_sha256,
        "seconds_diagnostic": ksk_block_seconds,
        "classification": "R3 component arithmetic only, not an encrypted semantic trial"
    }))?;

    let mut inputs = Vec::with_capacity(fixture_specs.len());
    for spec in fixture_specs {
        let input = match spec.family {
            FixtureFamily::HonestGaussian => allocate_and_encrypt_new_lwe_ciphertext(
                &big_secret,
                Plaintext(spec.plaintext),
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(GLWE_NOISE_STDDEV)),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            ),
            FixtureFamily::KeyConsistentNonGaussian => {
                let pattern = spec
                    .mask_pattern
                    .ok_or_else(|| GateError::Invalid(format!("{} has no mask pattern", spec.id)))?;
                let mask = fixture_mask(pattern)?;
                let mask_hash = sha256_u64s(&mask);
                if Some(mask_hash.as_str()) != spec.expected_mask_sha256 {
                    return invalid(format!("{} mask hash drift: {mask_hash}", spec.id));
                }
                assemble_key_consistent_lwe(
                    &big_secret,
                    &mask,
                    spec.plaintext,
                    spec.injected_error.ok_or_else(|| {
                        GateError::Invalid(format!("{} has no explicit error", spec.id))
                    })?,
                )?
            }
            FixtureFamily::TieExtensionGaussian => {
                return invalid("tie extension cannot appear in base fixture ledger");
            }
        };
        inputs.push((spec, input));
    }

    let mut tie_zero = 0_usize;
    let mut tie_one = 0_usize;
    let mut reference_ks_total = 0.0_f64;
    let mut local_ks_total = 0.0_f64;
    let mut reference_pbs_total = 0.0_f64;
    let mut local_pbs_total = 0.0_f64;
    let mut maximum_full_glwe_error = 0_u64;
    let mut cases_passed = 0_usize;
    for (index, (spec, input)) in inputs.iter().enumerate() {
        let outcome = process_case(
            sink,
            index,
            spec.id,
            spec.family,
            input,
            spec.plaintext,
            spec.injected_error,
            &glwe_secret,
            &big_secret,
            &small_secret,
            &ksk,
            &fourier_bsk,
            &lut,
            &lut_body,
        )?;
        tie_zero += usize::from(outcome.tie == 0);
        tie_one += usize::from(outcome.tie == 1);
        reference_ks_total += outcome.reference_ks_seconds;
        local_ks_total += outcome.local_ks_seconds;
        reference_pbs_total += outcome.reference_pbs_seconds;
        local_pbs_total += outcome.local_pbs_seconds;
        maximum_full_glwe_error =
            maximum_full_glwe_error.max(outcome.maximum_full_glwe_error);
        cases_passed += 1;
    }

    let mut tie_extension_attempts = 0_usize;
    while (tie_zero == 0 || tie_one == 0) && tie_extension_attempts < MAX_TIE_EXTENSION {
        let attempt = tie_extension_attempts;
        let score = ((attempt * 73 + 19) % 4096) as u64;
        let plaintext = score_plaintext(score)?;
        let input = allocate_and_encrypt_new_lwe_ciphertext(
            &big_secret,
            Plaintext(plaintext),
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(GLWE_NOISE_STDDEV)),
            CiphertextModulus::new_native(),
            &mut encryption_generator,
        );
        let id = format!("t_tie_extension_{attempt:02}");
        let index = 16 + attempt;
        let outcome = process_case(
            sink,
            index,
            &id,
            FixtureFamily::TieExtensionGaussian,
            &input,
            plaintext,
            None,
            &glwe_secret,
            &big_secret,
            &small_secret,
            &ksk,
            &fourier_bsk,
            &lut,
            &lut_body,
        )?;
        tie_zero += usize::from(outcome.tie == 0);
        tie_one += usize::from(outcome.tie == 1);
        reference_ks_total += outcome.reference_ks_seconds;
        local_ks_total += outcome.local_ks_seconds;
        reference_pbs_total += outcome.reference_pbs_seconds;
        local_pbs_total += outcome.local_pbs_seconds;
        maximum_full_glwe_error =
            maximum_full_glwe_error.max(outcome.maximum_full_glwe_error);
        cases_passed += 1;
        tie_extension_attempts += 1;
    }
    if tie_zero == 0 || tie_one == 0 {
        return invalid(format!(
            "missing post-KS tie class after {MAX_TIE_EXTENSION} bounded extension attempts"
        ));
    }

    let total_seconds = wall_started.elapsed().as_secs_f64();
    if !total_seconds.is_finite() || total_seconds < 0.0 {
        return invalid("non-finite total diagnostic timing");
    }
    sink.emit(&json!({
        "record": "summary",
        "status": "PASS_R4_COMPOSED_SMOKE",
        "stage": "A112_R3_R4",
        "fresh_keys": 1,
        "base_cases_expected": 16,
        "base_cases_passed": 16,
        "tie_extension_attempts": tie_extension_attempts,
        "cases_passed_total": cases_passed,
        "post_ks_tie_zero_cases": tie_zero,
        "post_ks_tie_one_cases": tie_one,
        "r3_post_ks_bitwise_mismatches": 0,
        "r2b_pre_fft_mismatches": 0,
        "r4_post_blind_rotation_mismatches": 0,
        "r4_degree_zero_mismatches": 0,
        "maximum_full_glwe_phase_error_diagnostic": maximum_full_glwe_error,
        "phase_error_cap": null,
        "full_glwe_independence_assumed": false,
        "timings_diagnostic": {
            "reference_ks_total_seconds": reference_ks_total,
            "local_ks_total_seconds": local_ks_total,
            "reference_pbs_total_seconds": reference_pbs_total,
            "local_pbs_total_seconds": local_pbs_total,
            "wall_total_seconds": total_seconds,
            "benchmark_or_speedup_claim": false
        },
        "not_run": [
            "fresh_key_campaign",
            "Delta51_exhaustive_0_through_4095",
            "DirtyMSB_four_step_reconstruction",
            "comparator_limb_mapping",
            "tournament_or_all_pairs_exact_ID",
            "inclusive_threshold_and_zero_ID_output",
            "composed_p_fail",
            "end_to_end_latency"
        ],
        "promotion_allowed": false,
        "claim_boundary": "One-key paired KS->R2B->PBS component smoke only. No complete score, comparator, stable tie-first selection, inclusive threshold, encrypted 0/ID, p_fail, latency or speedup claim follows."
    }))?;
    Ok(())
}

fn run() -> GateResult<()> {
    let provenance = verify_provenance()?;
    let mut sink = JsonlSink::create_new(&provenance.result_path)?;
    match execute(&mut sink, provenance.record) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = sink.emit(&json!({
                "record": "fatal",
                "status": error.status(),
                "message": error.message(),
                "partial_output_valid": false,
                "promotion_allowed": false
            }));
            Err(error)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_stdout(&json!({
                "record": "fatal_stdout",
                "status": error.status(),
                "message": error.message(),
                "partial_output_valid": false
            }));
            ExitCode::from(error.exit_code())
        }
    }
}
