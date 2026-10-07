#[allow(dead_code)]
#[path = "../../src/lib.rs"]
mod frozen_port;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use frozen_port::exact_head_start_modulus_switch;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::*;

const AUTHORIZED_PREREG_SHA256: &str =
    "a4b7e4f22dd259aca00504a33225cfafd8eaf8346e1759ad0a66bbf4a01825fb";
const ORIGINAL_R2_PREREG_SHA256: &str =
    "2fe4fe948a0d734b50aa66c4723f1562bb6fb9062f9b75f999efe3e04df3088d";
const ORIGINAL_R2_SOURCE_SHA256: &str =
    "527e6c29370a705500194dfded899a299abf7f2a0744093c32b0a32083363175";
const ORIGINAL_R2_MANIFEST_SHA256: &str =
    "5b416241704bd9ea9965243501e9acfa9ba084531c26180320fe21f2bd61e5a8";
const ORIGINAL_R2_LOCK_SHA256: &str =
    "5a06cb6acb31a924f87676964ffa385d52f41addb29acedb9c1686949bc64696";
const R2_BLOCKER_SHA256: &str = "d8664c855e8b2f50bbb214baa45554d980610039dce3dd7f07a44aa6b1f29155";
const R2B_PROTOCOL_SHA256: &str =
    "547e4f837047c268b9b0835bf90583860942121cbcf5e583b2d15c7e8738bac9";
const FROZEN_SOURCE_SHA256: &str =
    "a750dc4eebef73238ae80fcfde90c8b0fa6995d150c5b9120a1adbb37f9dfce4";
const STATIC_REPORT_SHA256: &str =
    "003f32e547dc376bea2fdb7d2d6dc10174ccc14ae456596c3ea5dfecbfc60e86";
const COMPILE_LOCK_SHA256: &str =
    "f080b69b592f6d741a03c282afe1d6168d4e96071f9e24da17be311ef36b7242";
const HEAD_START_PATCH_SHA256: &str =
    "d19b72f6257d3db93e3651d87779816be4f210f60bf274cea5799b50743368cc";
const A89_ORACLE_SHA256: &str = "50943b7fd7b2fa9073497ea2e6ba37c36b836fe5a3bfc06b01fb8fb6e4643df6";
const TFHE_FFT64_PBS_SHA256: &str =
    "21c8009e0999c78401dea57a1d7bcbe91c47b80b231357b42eab9552a20abd71";
const TFHE_BSK_GENERATION_SHA256: &str =
    "efb3b96b252f8d17907bb94cadbe15a807a6156ef37693fe06c40507705345fd";
const TFHE_LAZY_MS_SHA256: &str =
    "68b692b3e941b98a4a0290e67979733f82a0449e95856f7d1f821140159f562d";
const TFHE_SAMPLE_EXTRACTION_SHA256: &str =
    "981d3839cd83cb8c24b02fe48d945d61e23c9c0f2e714b554d9296eed304ec43";
const TFHE_LWE_ENCRYPTION_SHA256: &str =
    "9e360ca3da9d4a7ecd01cfe36396ae15b7ace6ba5b582d4c7df3e006a3969d0a";
const TFHE_GLWE_SECRET_KEY_SHA256: &str =
    "a5656381b3191eb7c0769950e3be157701ff88a1b6bc11942d5e0c4c05ef2948";
const TFHE_LWE_CIPHERTEXT_SHA256: &str =
    "5306733d19aa463cab2952f36a313e41fa33870584de9ba179390ee0e403d3fc";
const TFHE_CRATE_ARCHIVE_SHA256: &str =
    "f341a7a6fe90bf813ecb2b098f04c0e5bca82436ddd1b256e6f1ec68be58da52";

const SECRET_SEED: u128 = 0xa9800000000000000000000000000001;
const ENCRYPTION_SEED: u128 = 0xa9800000000000000000000000000002;
const NOISE_ROOT_SEED: u128 = 0xa9800000000000000000000000000003;
const XORSHIFT_CASE_SEED: u64 = 0xa980000000000004;

const LWE_DIMENSION: usize = 859;
const GLWE_DIMENSION: usize = 1;
const POLYNOMIAL_SIZE: usize = 2048;
const LOG_MODULUS: usize = 12;
const BLIND_ROTATION_MODULUS: usize = 1 << LOG_MODULUS;
const PBS_BASE_LOG: usize = 23;
const PBS_LEVEL_COUNT: usize = 1;
const GLWE_NOISE_STDDEV: f64 = 2.845267479601915e-15;
const SHIFT: usize = u64::BITS as usize - LOG_MODULUS;
const STEP: u64 = 1_u64 << SHIFT;
const HALF_STEP: u64 = STEP >> 1;
const ROUNDING_BOUNDARY_63: u64 = 63 * STEP + HALF_STEP;
const EXPECTED_LUT_BODY_SHA256: &str =
    "a9a70a617f48ebbf2625b34f590349afafe4530f8d5fd480eff94be993ea7f77";

const TFHE_REGISTRY_ROOT: &str =
    "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0";
const TFHE_ARCHIVE: &str =
    "/opt/cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/tfhe-1.7.0.crate";

#[derive(Debug)]
enum GateError {
    Invalid(String),
    Reject(String),
}

impl GateError {
    fn status(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "INVALID",
            Self::Reject(_) => "REJECT",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Reject(message) => message,
        }
    }
}

type GateResult<T> = Result<T, GateError>;

#[derive(Clone)]
struct Case {
    index: usize,
    id: &'static str,
    mask: Vec<u64>,
    body: u64,
    expected_d: i128,
    expected_h: i128,
    expected_tie: u64,
    expected_correction: i128,
    expected_mask_sha256: &'static str,
    expected_input_sha256: &'static str,
    expected_reference_body_degree: Option<usize>,
    expected_direct_centered_body_degree: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct PhaseErrorDiagnostics {
    maximum: u64,
    signed_at_maximum: i64,
    index_at_maximum: usize,
    p50_absolute: u64,
    p95_absolute: u64,
    p99_absolute: u64,
}

fn invalid<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::Invalid(message.into()))
}

fn reject<T>(message: impl Into<String>) -> GateResult<T> {
    Err(GateError::Reject(message.into()))
}

fn emit(value: Value) -> GateResult<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)
        .map_err(|error| GateError::Invalid(format!("cannot encode JSONL: {error}")))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| GateError::Invalid(format!("cannot terminate JSONL record: {error}")))?;
    stdout
        .flush()
        .map_err(|error| GateError::Invalid(format!("cannot flush JSONL record: {error}")))?;
    Ok(())
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

fn require_hash_environment(name: &str, actual: &str) -> GateResult<()> {
    let expected = env::var(name).map_err(|_| {
        GateError::Invalid(format!("required environment variable {name} is absent"))
    })?;
    if expected != actual {
        return invalid(format!(
            "{name} mismatch: expected from environment {expected}, observed {actual}"
        ));
    }
    Ok(())
}

fn repo_paths() -> GateResult<(PathBuf, PathBuf)> {
    let runtime_gate = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let a98 = runtime_gate
        .parent()
        .ok_or_else(|| GateError::Invalid("runtime gate has no A98 parent".into()))?
        .to_path_buf();
    let repo = a98
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| GateError::Invalid("A98 directory has no repository parent".into()))?
        .to_path_buf();
    Ok((repo, a98))
}

fn verify_provenance() -> GateResult<Value> {
    let args: Vec<String> = env::args().collect();
    if args.as_slice() != [args[0].clone(), "--run-authorized-r2b".to_string()] {
        return invalid("expected exactly one argument: --run-authorized-r2b");
    }
    if env::var("A98_R2B_AUTHORIZED").ok().as_deref() != Some(AUTHORIZED_PREREG_SHA256) {
        return invalid("A98_R2B_AUTHORIZED does not equal the frozen preregistration SHA-256");
    }
    if env::var("RAYON_NUM_THREADS").ok().as_deref() != Some("8") {
        return invalid("RAYON_NUM_THREADS must be exactly 8");
    }
    if rayon::current_num_threads() != 8 {
        return invalid(format!(
            "Rayon initialized with {} threads instead of 8",
            rayon::current_num_threads()
        ));
    }

    let (repo, a98) = repo_paths()?;
    let preregistration = require_hash(
        &a98.join("R2B_PREREGISTRATION.json"),
        AUTHORIZED_PREREG_SHA256,
    )?;
    let original_r2_preregistration = require_hash(
        &a98.join("R2_PREREGISTRATION.json"),
        ORIGINAL_R2_PREREG_SHA256,
    )?;
    let original_r2_source = require_hash(
        &a98.join("runtime-gate/src/main.rs"),
        ORIGINAL_R2_SOURCE_SHA256,
    )?;
    let original_r2_manifest = require_hash(
        &a98.join("runtime-gate/Cargo.toml"),
        ORIGINAL_R2_MANIFEST_SHA256,
    )?;
    let original_r2_lock = require_hash(
        &a98.join("runtime-gate/Cargo.lock"),
        ORIGINAL_R2_LOCK_SHA256,
    )?;
    let r2_blocker = require_hash(&a98.join("R2_BLOCKER_NO_RUN.json"), R2_BLOCKER_SHA256)?;
    let r2b_protocol = require_hash(&a98.join("R2B_PROTOCOL.md"), R2B_PROTOCOL_SHA256)?;
    let frozen_source = require_hash(&a98.join("src/lib.rs"), FROZEN_SOURCE_SHA256)?;
    let static_report = require_hash(&a98.join("STATIC_REPORT.json"), STATIC_REPORT_SHA256)?;
    let compile_lock = require_hash(&a98.join("compile-gate/Cargo.lock"), COMPILE_LOCK_SHA256)?;
    let a89_oracle = require_hash(
        &repo.join("tmp/a89-centered-ms-adapter-preflight/a89_centered_ms.py"),
        A89_ORACLE_SHA256,
    )?;
    let patch = require_hash(
        &repo.join("tmp/pdfs/head-start.patch"),
        HEAD_START_PATCH_SHA256,
    )?;
    let protected_ritaratura = require_hash(
        &repo.join("experiments/14_pipeline_tfhe_rs/results/ritaratura_soglia.txt"),
        "e490b7431e3531b532d4a383e6d0d1231bb4537126ec2ec4e01eb9202f0db3ab",
    )?;
    let protected_meeting = require_hash(
        &repo.join("ultimo-meeting-transcription.md"),
        "01e08d541287aa057441f3861e549408ec8bf1448f20ae6193fc1be8b1e87745",
    )?;
    let protected_a38 = require_hash(
        &repo.join("tmp/a38-combined-prototype/README.md"),
        "156a35f3407a5914ea6712ad2c5e76f413f1f125bc275371e8fe6d4f7dcd4d37",
    )?;
    let tfhe_root = PathBuf::from(TFHE_REGISTRY_ROOT);
    let tfhe_fft = require_hash(
        &tfhe_root.join("src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64_pbs.rs"),
        TFHE_FFT64_PBS_SHA256,
    )?;
    let tfhe_bsk = require_hash(
        &tfhe_root.join("src/core_crypto/algorithms/lwe_bootstrap_key_generation.rs"),
        TFHE_BSK_GENERATION_SHA256,
    )?;
    let tfhe_lazy = require_hash(
        &tfhe_root.join("src/core_crypto/entities/modulus_switched_lwe_ciphertext.rs"),
        TFHE_LAZY_MS_SHA256,
    )?;
    let tfhe_sample_extraction = require_hash(
        &tfhe_root.join("src/core_crypto/algorithms/glwe_sample_extraction.rs"),
        TFHE_SAMPLE_EXTRACTION_SHA256,
    )?;
    let tfhe_lwe_encryption = require_hash(
        &tfhe_root.join("src/core_crypto/algorithms/lwe_encryption.rs"),
        TFHE_LWE_ENCRYPTION_SHA256,
    )?;
    let tfhe_glwe_secret_key = require_hash(
        &tfhe_root.join("src/core_crypto/entities/glwe_secret_key.rs"),
        TFHE_GLWE_SECRET_KEY_SHA256,
    )?;
    let tfhe_lwe_ciphertext = require_hash(
        &tfhe_root.join("src/core_crypto/entities/lwe_ciphertext.rs"),
        TFHE_LWE_CIPHERTEXT_SHA256,
    )?;
    let tfhe_archive = require_hash(Path::new(TFHE_ARCHIVE), TFHE_CRATE_ARCHIVE_SHA256)?;
    let executable = env::current_exe().map_err(|error| {
        GateError::Invalid(format!("cannot locate current executable: {error}"))
    })?;
    let executable_sha256 = sha256_file(&executable)?;
    let runtime_source_sha256 = sha256_file(&a98.join("r2b-runtime-gate/src/main.rs"))?;
    let runtime_manifest_sha256 = sha256_file(&a98.join("r2b-runtime-gate/Cargo.toml"))?;
    let runtime_lock_sha256 = sha256_file(&a98.join("r2b-runtime-gate/Cargo.lock"))?;
    require_hash_environment("A98_R2B_RUNTIME_SOURCE_SHA256", &runtime_source_sha256)?;
    require_hash_environment("A98_R2B_RUNTIME_MANIFEST_SHA256", &runtime_manifest_sha256)?;
    require_hash_environment("A98_R2B_RUNTIME_LOCK_SHA256", &runtime_lock_sha256)?;
    require_hash_environment("A98_R2B_EXECUTABLE_SHA256", &executable_sha256)?;

    Ok(json!({
        "record": "provenance",
        "status": "PASS",
        "stage": "A98_R2B",
        "preregistration_sha256": preregistration,
        "original_r2": {
            "preregistration_sha256": original_r2_preregistration,
            "source_sha256": original_r2_source,
            "manifest_sha256": original_r2_manifest,
            "lock_sha256": original_r2_lock,
            "blocker_sha256": r2_blocker,
            "r2b_protocol_sha256": r2b_protocol
        },
        "frozen_source_sha256": frozen_source,
        "static_report_sha256": static_report,
        "compile_lock_sha256": compile_lock,
        "runtime_source_sha256": runtime_source_sha256,
        "runtime_manifest_sha256": runtime_manifest_sha256,
        "runtime_lock_sha256": runtime_lock_sha256,
        "executable_path": executable,
        "executable_sha256": executable_sha256,
        "a89_oracle_sha256": a89_oracle,
        "head_start_patch_sha256": patch,
        "tfhe_fft64_pbs_sha256": tfhe_fft,
        "tfhe_bsk_generation_sha256": tfhe_bsk,
        "tfhe_lazy_ms_sha256": tfhe_lazy,
        "tfhe_sample_extraction_sha256": tfhe_sample_extraction,
        "tfhe_lwe_encryption_sha256": tfhe_lwe_encryption,
        "tfhe_glwe_secret_key_sha256": tfhe_glwe_secret_key,
        "tfhe_lwe_ciphertext_sha256": tfhe_lwe_ciphertext,
        "tfhe_crate_archive_sha256": tfhe_archive,
        "protected_hashes": {
            "ritaratura_soglia": protected_ritaratura,
            "meeting_transcription": protected_meeting,
            "a38_readme": protected_a38
        },
        "rayon_threads": rayon::current_num_threads()
    }))
}

fn cycle(values: &[u64]) -> Vec<u64> {
    (0..LWE_DIMENSION)
        .map(|index| values[index % values.len()])
        .collect()
}

fn xorshift_mask() -> (Vec<u64>, u64) {
    let edge_palette = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        u64::MAX,
        u64::MAX - (HALF_STEP - 1),
    ];
    let mut state = XORSHIFT_CASE_SEED;
    let mut mask = Vec::with_capacity(LWE_DIMENSION);
    for _ in 0..LWE_DIMENSION {
        state ^= state.wrapping_shl(13);
        state ^= state >> 7;
        state ^= state.wrapping_shl(17);
        mask.push(state);
    }
    mask[..edge_palette.len()].copy_from_slice(&edge_palette);
    (mask, state)
}

#[allow(clippy::too_many_arguments)]
fn case(
    index: usize,
    id: &'static str,
    mask: Vec<u64>,
    body: u64,
    expected_d: i128,
    expected_h: i128,
    expected_tie: u64,
    expected_correction: i128,
    expected_mask_sha256: &'static str,
    expected_input_sha256: &'static str,
    expected_reference_body_degree: Option<usize>,
    expected_direct_centered_body_degree: Option<usize>,
) -> Case {
    Case {
        index,
        id,
        mask,
        body,
        expected_d,
        expected_h,
        expected_tie,
        expected_correction,
        expected_mask_sha256,
        expected_input_sha256,
        expected_reference_body_degree,
        expected_direct_centered_body_degree,
    }
}

fn make_cases() -> GateResult<Vec<Case>> {
    let zeros = vec![0; LWE_DIMENSION];
    let mut single_pos = zeros.clone();
    single_pos[0] = STEP - 1;
    let mut single_neg = zeros.clone();
    single_neg[0] = 1;
    let mut cancel_pair = zeros.clone();
    cancel_pair[0] = STEP - 1;
    cancel_pair[1] = 1;
    let alternating_pos: Vec<_> = (0..LWE_DIMENSION)
        .map(|index| if index % 2 == 0 { STEP - 1 } else { 1 })
        .collect();
    let alternating_neg: Vec<_> = (0..LWE_DIMENSION)
        .map(|index| if index % 2 == 0 { 1 } else { STEP - 1 })
        .collect();
    let edge_palette = [
        0,
        1,
        HALF_STEP - 1,
        HALF_STEP,
        HALF_STEP + 1,
        STEP - 1,
        u64::MAX,
        u64::MAX - (HALF_STEP - 1),
    ];
    let wrap_palette = [
        u64::MAX,
        u64::MAX - 1,
        u64::MAX - HALF_STEP + 1,
        u64::MAX - HALF_STEP,
        u64::MAX - HALF_STEP - 1,
        STEP - 1,
        1,
        0,
    ];
    let (xorshift, xorshift_final_state) = xorshift_mask();
    if xorshift_final_state != 0x3b7cec6a75dc728d {
        return invalid(format!(
            "xorshift final-state drift: 0x{xorshift_final_state:016x}"
        ));
    }

    Ok(vec![
        case(
            0,
            "c00_zero_anchor",
            zeros,
            63 * STEP,
            0,
            0,
            0,
            0,
            "7f554882eb43b453b57f23b79994387802c63c7df6a2a177a6ae6d310fe009bb",
            "60a3f61f1a47f51243d6f6d1fc9a29469217811763305fc6963e7fa89adf99aa",
            None,
            None,
        ),
        case(
            1,
            "c01_single_pos_anchor",
            single_pos.clone(),
            63 * STEP,
            1,
            -1,
            1,
            1,
            "e1d00d0f27532e65ec162a72c664656dd0e8f74443beda3017974b401c5effd2",
            "c913de50b0a53efee7f1a9c9a29d502cf1d843fe9738aec75c0116d3fae1337c",
            None,
            None,
        ),
        case(
            2,
            "c02_single_pos_below",
            single_pos.clone(),
            ROUNDING_BOUNDARY_63 - 1,
            1,
            -1,
            1,
            1,
            "e1d00d0f27532e65ec162a72c664656dd0e8f74443beda3017974b401c5effd2",
            "e2859a9707e6247b30c2c8b46bb3cdb3ea0b41bf312c6726e72fd761a384cd7a",
            Some(64),
            Some(63),
        ),
        case(
            3,
            "c03_single_pos_at",
            single_pos.clone(),
            ROUNDING_BOUNDARY_63,
            1,
            -1,
            1,
            1,
            "e1d00d0f27532e65ec162a72c664656dd0e8f74443beda3017974b401c5effd2",
            "c8e5341508cf512c30567eda70bf26d384df93de47572f0118570df718d95c82",
            None,
            None,
        ),
        case(
            4,
            "c04_single_pos_above",
            single_pos,
            ROUNDING_BOUNDARY_63 + 1,
            1,
            -1,
            1,
            1,
            "e1d00d0f27532e65ec162a72c664656dd0e8f74443beda3017974b401c5effd2",
            "f6e21e7397a8df9e62778fef87b93bceb35aaed51c7ea9eb699d0e27bb46ad1f",
            None,
            None,
        ),
        case(
            5,
            "c05_single_neg_at",
            single_neg,
            ROUNDING_BOUNDARY_63,
            -1,
            1,
            0,
            0,
            "359d66c27b635e56aeb55dc5cbdb075c532d00356f6d98d89cb91869566205f5",
            "71a9644d0947fcd8f6d351760ddb2356911aa06e7b484a7524cb80c398087b78",
            None,
            None,
        ),
        case(
            6,
            "c06_cancel_pair_at",
            cancel_pair,
            ROUNDING_BOUNDARY_63,
            0,
            0,
            0,
            0,
            "28d1594812971811db5db6bc8ff27280999b2ee3882de6a2b54c49733eb5a1d4",
            "5d9b06c8026d89ca5ab086ea1bc95a9bede6f9e670b8479725d56446f2623655",
            None,
            None,
        ),
        case(
            7,
            "c07_all_pos_hits_boundary",
            vec![STEP - 1; LWE_DIMENSION],
            ROUNDING_BOUNDARY_63 - 430,
            859,
            -859,
            1,
            430,
            "36e5dd5f5f806156f9dde4e04824b6804eb3178a11584adff6f3e590a078329f",
            "27407d9c74883ae698b29e38a91fb876ce187ca17bc330f943ad1236074c45bf",
            Some(64),
            None,
        ),
        case(
            8,
            "c08_all_neg_hits_boundary",
            vec![1; LWE_DIMENSION],
            ROUNDING_BOUNDARY_63 + 429,
            -859,
            859,
            0,
            -429,
            "515384bbb6152241ad0255f68c859620c17fb7222e9557e64a3f7d5efa99b00e",
            "7b55996f99a0eb1f0e6995bb036b0cd80efef2a92d3fb1aaf361e74693e9062b",
            Some(64),
            None,
        ),
        case(
            9,
            "c09_alternating_pos_hits_boundary",
            alternating_pos,
            ROUNDING_BOUNDARY_63 - 1,
            1,
            -1,
            1,
            1,
            "1ae6300e2270bffad1f7c694ec202dc1ab0168d4e9705d177a6c9dd85c304eab",
            "a5f45bd309658adc3c087400b2d779573435bab71486c5e7c3ffc1856304c550",
            Some(64),
            None,
        ),
        case(
            10,
            "c10_alternating_neg_at",
            alternating_neg,
            ROUNDING_BOUNDARY_63,
            -1,
            1,
            0,
            0,
            "6d681912aa81745ad07fda9a422f3cf3ff158d8a144afdb2bcc6652f3aa37046",
            "7aab9a96837e6560efee8a826c0e910126c994b6596809aa467e54a181a73d65",
            None,
            None,
        ),
        case(
            11,
            "c11_edge_cycle_wrap_body",
            cycle(&edge_palette),
            u64::MAX,
            479633360314957931,
            -105,
            1,
            239816680157478966,
            "ed1f8479c3842e69ace900a622f0310e0141e1b2e1bf636b576e31020de60adc",
            "b3848f885262426ec097d6fdbf891e1527461a301f434c6a6a991191a0212ddc",
            None,
            None,
        ),
        case(
            12,
            "c12_xorshift_edge_injected",
            xorshift,
            u64::MAX,
            -43147405316823370,
            12,
            0,
            -21573702658411685,
            "1b8b2d8ff630a706a9a231aae4ec5d5efba60cffc2365cd868d4c5f16293aee5",
            "3e29863b44b3e8aeed44e1070549a4d7567179570a1d151e504940828326445e",
            None,
            None,
        ),
        case(
            13,
            "c13_wrap_cycle_low_body",
            cycle(&wrap_palette),
            1,
            -238690780250635643,
            -1,
            1,
            -119345390125317821,
            "e3dd1f782c9869d6d8b885c5807a0f98dc70e924e567f0989d1076ec90e84b65",
            "f10bfe1fb0f194274ac6fca74289561785dc4495152b9029bed0c24e8738153f",
            None,
            None,
        ),
    ])
}

fn lifted_round(value: u64) -> u64 {
    value.wrapping_add(HALF_STEP) >> SHIFT << SHIFT
}

fn direct_oracle(mask: &[u64]) -> (i128, i128, u64, i128) {
    let mut d_sum = 0_i128;
    let mut h_sum = 0_i128;
    for &coefficient in mask {
        let d = lifted_round(coefficient).wrapping_sub(coefficient) as i64;
        let half = d / 2;
        d_sum += i128::from(d);
        h_sum += i128::from(2 * half - d);
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
        return invalid("invalid nearest-rank quantile request");
    }
    let rank = numerator
        .checked_mul(sorted.len())
        .and_then(|value| value.checked_add(denominator - 1))
        .ok_or_else(|| GateError::Invalid("nearest-rank quantile overflow".into()))?
        / denominator;
    Ok(sorted[rank.saturating_sub(1)])
}

fn phase_error_diagnostics(
    observed: &[u64],
    expected: &[u64],
) -> GateResult<PhaseErrorDiagnostics> {
    if observed.len() != expected.len() {
        return invalid("phase-error inputs have different lengths");
    }
    let mut maximum = 0_u64;
    let mut signed_at_maximum = 0_i64;
    let mut index_at_maximum = 0_usize;
    let mut absolute_errors = Vec::with_capacity(observed.len());
    for (index, (&actual, &ideal)) in observed.iter().zip(expected).enumerate() {
        let signed = actual.wrapping_sub(ideal) as i64;
        let absolute = signed.unsigned_abs();
        absolute_errors.push(absolute);
        if absolute > maximum {
            maximum = absolute;
            signed_at_maximum = signed;
            index_at_maximum = index;
        }
    }
    absolute_errors.sort_unstable();
    Ok(PhaseErrorDiagnostics {
        maximum,
        signed_at_maximum,
        index_at_maximum,
        p50_absolute: nearest_rank(&absolute_errors, 50, 100)?,
        p95_absolute: nearest_rank(&absolute_errors, 95, 100)?,
        p99_absolute: nearest_rank(&absolute_errors, 99, 100)?,
    })
}

fn ramp_decode_degree(value: u64) -> usize {
    ((value.wrapping_add(HALF_STEP) >> SHIFT) as usize) & (BLIND_ROTATION_MODULUS - 1)
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

fn run() -> GateResult<()> {
    let wall_started = Instant::now();
    let provenance = verify_provenance()?;
    emit(provenance)?;

    if LWE_DIMENSION != 859
        || GLWE_DIMENSION != 1
        || POLYNOMIAL_SIZE != 2048
        || LOG_MODULUS != 12
        || PBS_BASE_LOG != 23
        || PBS_LEVEL_COUNT != 1
        || BLIND_ROTATION_MODULUS != 2 * POLYNOMIAL_SIZE
    {
        return invalid("compiled parameter geometry drift");
    }

    let cases = make_cases()?;
    if cases.len() != 14
        || cases
            .iter()
            .enumerate()
            .any(|(index, case)| index != case.index)
    {
        return invalid("case count or fixed order drift");
    }
    for case in &cases {
        let mask_hash = sha256_u64s(&case.mask);
        let mut input = case.mask.clone();
        input.push(case.body);
        let input_hash = sha256_u64s(&input);
        let (d, h, tie, correction) = direct_oracle(&case.mask);
        if mask_hash != case.expected_mask_sha256
            || input_hash != case.expected_input_sha256
            || d != case.expected_d
            || h != case.expected_h
            || tie != case.expected_tie
            || correction != case.expected_correction
        {
            return invalid(format!("preregistered case drift for {}", case.id));
        }
    }

    let mut lut = GlweCiphertextOwned::new(
        0_u64,
        GlweDimension(GLWE_DIMENSION).to_glwe_size(),
        PolynomialSize(POLYNOMIAL_SIZE),
        CiphertextModulus::new_native(),
    );
    let lut_body_values: Vec<u64> = (0..POLYNOMIAL_SIZE)
        .map(|index| (index as u64).wrapping_mul(STEP))
        .collect();
    if sha256_u64s(&lut_body_values) != EXPECTED_LUT_BODY_SHA256 {
        return invalid("shared LUT body hash drift");
    }
    lut.get_mut_body()
        .as_mut()
        .copy_from_slice(&lut_body_values);

    emit(json!({
        "record": "run_start",
        "status": "PASS_PREFLIGHT",
        "stage": "A98_R2B",
        "authorized_preregistration_sha256": AUTHORIZED_PREREG_SHA256,
        "fresh_key_count": 1,
        "case_count": cases.len(),
        "params": {
            "id": "A44-p16",
            "lwe_dimension": LWE_DIMENSION,
            "glwe_dimension": GLWE_DIMENSION,
            "polynomial_size": POLYNOMIAL_SIZE,
            "log_modulus": LOG_MODULUS,
            "pbs_base_log": PBS_BASE_LOG,
            "pbs_level_count": PBS_LEVEL_COUNT,
            "glwe_noise_stddev": format!("{GLWE_NOISE_STDDEV:.16e}"),
            "ciphertext_modulus": "native_u64"
        },
        "seeds": {
            "secret": format!("0x{SECRET_SEED:032x}"),
            "encryption": format!("0x{ENCRYPTION_SEED:032x}"),
            "noise_root": format!("0x{NOISE_ROOT_SEED:032x}"),
            "xorshift_case": format!("0x{XORSHIFT_CASE_SEED:016x}")
        },
        "shared_lut_body_sha256": EXPECTED_LUT_BODY_SHA256,
        "input_lwe_noise": "none_crafted_raw_container",
        "primary_adapter_equivalence_gate": "bitwise_reference_vs_adapter",
        "consumed_output": "degree_zero_sample_extraction",
        "phase_error_decision_role": "diagnostic_only_no_cap",
        "warmup_cases": 0,
        "timing_scope": "diagnostic_not_benchmark"
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
    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        GlweDimension(GLWE_DIMENSION),
        PolynomialSize(POLYNOMIAL_SIZE),
        &mut secret_generator,
    );
    let small_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        LweDimension(LWE_DIMENSION),
        &mut secret_generator,
    );
    let secret_key_generation_s = secret_started.elapsed().as_secs_f64();
    if small_secret_key.as_ref().iter().all(|&bit| bit == 0)
        || small_secret_key.as_ref().iter().all(|&bit| bit == 1)
        || small_secret_key.as_ref().iter().any(|&bit| bit > 1)
        || glwe_secret_key.as_ref().iter().any(|&bit| bit > 1)
    {
        return invalid("deterministic binary secret-key sanity check failed");
    }

    let bsk_started = Instant::now();
    let standard_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_secret_key,
        &glwe_secret_key,
        DecompositionBaseLog(PBS_BASE_LOG),
        DecompositionLevelCount(PBS_LEVEL_COUNT),
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(GLWE_NOISE_STDDEV)),
        CiphertextModulus::new_native(),
        &mut encryption_generator,
    );
    let standard_bsk_generation_s = bsk_started.elapsed().as_secs_f64();
    let standard_bsk_sha256 = sha256_u64s(standard_bsk.as_ref());
    let standard_bsk_u64_coefficients = standard_bsk.as_ref().len();
    let standard_bsk_bytes = standard_bsk_u64_coefficients * std::mem::size_of::<u64>();

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
    let fourier_conversion_s = fourier_started.elapsed().as_secs_f64();
    drop(standard_bsk);

    emit(json!({
        "record": "fresh_key",
        "status": "PASS",
        "key_index": 0,
        "ephemeral": true,
        "persisted_key_bytes": false,
        "key_hash_scope": "test_only_reproducible_public_seed_not_a_real_secret",
        "secret_key_generation_s": secret_key_generation_s,
        "standard_bsk_generation_s": standard_bsk_generation_s,
        "fourier_conversion_s": fourier_conversion_s,
        "small_secret_key_sha256": sha256_u64s(small_secret_key.as_ref()),
        "glwe_secret_key_sha256": sha256_u64s(glwe_secret_key.as_ref()),
        "standard_bsk_sha256": standard_bsk_sha256,
        "standard_bsk_u64_coefficients": standard_bsk_u64_coefficients,
        "standard_bsk_bytes": standard_bsk_bytes
    }))?;

    let mut reference_seconds = 0.0_f64;
    let mut adapter_seconds = 0.0_f64;
    let mut maximum_full_glwe_phase_error = 0_u64;
    let mut consumed_sample_decode_matches_ideal = 0_usize;
    let mut tie_zero_cases = 0_usize;
    let mut tie_one_cases = 0_usize;
    let mut direct_centered_degree_mismatch_cases = 0_usize;
    let output_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();
    let output_lwe_size = GlweDimension(GLWE_DIMENSION)
        .to_equivalent_lwe_dimension(PolynomialSize(POLYNOMIAL_SIZE))
        .to_lwe_size();

    for case in &cases {
        let case_started = Instant::now();
        let mut container = case.mask.clone();
        container.push(case.body);
        let lwe =
            LweCiphertextOwned::from_container(container, CiphertextModulus::<u64>::new_native());
        let raw_phase = case
            .mask
            .iter()
            .zip(small_secret_key.as_ref())
            .fold(case.body, |phase, (&mask, &secret)| {
                phase.wrapping_sub(mask.wrapping_mul(secret))
            });

        let (d, h, tie, reference_correction_signed) = direct_oracle(&case.mask);
        let reference_correction = (reference_correction_signed as i64) as u64;
        let reference = LazyStandardModulusSwitchedLweCiphertext::<u64, usize, _>::from_raw_parts(
            lwe.clone(),
            reference_correction,
            CiphertextModulusLog(LOG_MODULUS),
        );
        let adapter =
            exact_head_start_modulus_switch(lwe.clone(), CiphertextModulusLog(LOG_MODULUS))
                .map_err(|error| {
                    GateError::Invalid(format!("A98 adapter rejected {}: {error}", case.id))
                })?;
        let (adapter_lwe, adapter_correction, adapter_log) = adapter.into_raw_parts();
        if adapter_lwe != lwe {
            return reject(format!("A98 changed the input LWE for {}", case.id));
        }
        if adapter_correction != reference_correction {
            return reject(format!(
                "raw correction mismatch for {}: reference 0x{reference_correction:016x}, A98 0x{adapter_correction:016x}",
                case.id
            ));
        }
        let adapter = LazyStandardModulusSwitchedLweCiphertext::<u64, usize, _>::from_raw_parts(
            adapter_lwe,
            adapter_correction,
            adapter_log,
        );
        let centered = lwe_ciphertext_centered_binary_modulus_switch::<u64, usize, _>(
            lwe.clone(),
            CiphertextModulusLog(LOG_MODULUS),
        );
        let (_, centered_raw_correction, _) = centered.clone().into_raw_parts();

        let reference_mask_degrees: Vec<usize> = reference.mask().collect();
        let adapter_mask_degrees: Vec<usize> = adapter.mask().collect();
        let reference_body_degree = reference.body();
        let adapter_body_degree = adapter.body();
        let centered_body_degree = centered.body();
        if reference.log_modulus() != adapter.log_modulus()
            || reference.lwe_dimension() != adapter.lwe_dimension()
            || reference_mask_degrees != adapter_mask_degrees
            || reference_body_degree != adapter_body_degree
        {
            return reject(format!("pre-FFT degree mismatch for {}", case.id));
        }
        if let Some(expected) = case.expected_reference_body_degree {
            if reference_body_degree != expected {
                return invalid(format!(
                    "reference boundary drift for {}: expected {expected}, observed {reference_body_degree}",
                    case.id
                ));
            }
        }
        if let Some(expected) = case.expected_direct_centered_body_degree {
            if centered_body_degree != expected {
                return invalid(format!(
                    "direct-centered boundary drift for {}: expected {expected}, observed {centered_body_degree}",
                    case.id
                ));
            }
        }
        if centered_body_degree != reference_body_degree {
            direct_centered_degree_mismatch_cases += 1;
        }

        let ((reference_output, reference_s), (adapter_output, adapter_s), arm_order) =
            if case.index % 2 == 0 {
                let reference_result = run_blind_rotation(&reference, &lut, &fourier_bsk);
                let adapter_result = run_blind_rotation(&adapter, &lut, &fourier_bsk);
                (reference_result, adapter_result, "REFERENCE_THEN_A98")
            } else {
                let adapter_result = run_blind_rotation(&adapter, &lut, &fourier_bsk);
                let reference_result = run_blind_rotation(&reference, &lut, &fourier_bsk);
                (reference_result, adapter_result, "A98_THEN_REFERENCE")
            };
        reference_seconds += reference_s;
        adapter_seconds += adapter_s;

        if reference_output.as_ref() != adapter_output.as_ref() {
            return reject(format!(
                "blind-rotation ciphertext mismatch for {}",
                case.id
            ));
        }
        let reference_output_sha256 = sha256_u64s(reference_output.as_ref());
        let adapter_output_sha256 = sha256_u64s(adapter_output.as_ref());

        let mut reference_plaintext = PlaintextList::new(0_u64, PlaintextCount(POLYNOMIAL_SIZE));
        let mut adapter_plaintext = PlaintextList::new(0_u64, PlaintextCount(POLYNOMIAL_SIZE));
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &reference_output,
            &mut reference_plaintext,
        );
        decrypt_glwe_ciphertext(&glwe_secret_key, &adapter_output, &mut adapter_plaintext);
        if reference_plaintext.as_ref() != adapter_plaintext.as_ref() {
            return reject(format!("decrypted-output mismatch for {}", case.id));
        }

        let mut reference_sample = LweCiphertextOwned::new(
            0_u64,
            output_lwe_size,
            CiphertextModulus::<u64>::new_native(),
        );
        let mut adapter_sample = LweCiphertextOwned::new(
            0_u64,
            output_lwe_size,
            CiphertextModulus::<u64>::new_native(),
        );
        extract_lwe_sample_from_glwe_ciphertext(
            &reference_output,
            &mut reference_sample,
            MonomialDegree(0),
        );
        extract_lwe_sample_from_glwe_ciphertext(
            &adapter_output,
            &mut adapter_sample,
            MonomialDegree(0),
        );
        if reference_sample.as_ref() != adapter_sample.as_ref() {
            return reject(format!("degree-0 extracted LWE mismatch for {}", case.id));
        }
        let reference_sample_plaintext =
            decrypt_lwe_ciphertext(&output_lwe_secret_key, &reference_sample).0;
        let adapter_sample_plaintext =
            decrypt_lwe_ciphertext(&output_lwe_secret_key, &adapter_sample).0;
        if reference_sample_plaintext != adapter_sample_plaintext {
            return reject(format!(
                "degree-0 extracted plaintext mismatch for {}",
                case.id
            ));
        }
        if reference_sample_plaintext != reference_plaintext.as_ref()[0]
            || adapter_sample_plaintext != adapter_plaintext.as_ref()[0]
        {
            return reject(format!(
                "degree-0 extraction does not match decrypted GLWE coefficient zero for {}",
                case.id
            ));
        }

        let mask_phase = reference_mask_degrees
            .iter()
            .zip(small_secret_key.as_ref())
            .fold(0_usize, |sum, (&degree, &secret)| {
                (sum + degree * secret as usize) % BLIND_ROTATION_MODULUS
            });
        let switched_phase_degree =
            (reference_body_degree + BLIND_ROTATION_MODULUS - mask_phase) % BLIND_ROTATION_MODULUS;
        let ideal_plaintext = ideal_monic_division(&lut_body_values, switched_phase_degree)?;
        let full_glwe_diagnostics =
            phase_error_diagnostics(reference_plaintext.as_ref(), &ideal_plaintext)?;
        maximum_full_glwe_phase_error =
            maximum_full_glwe_phase_error.max(full_glwe_diagnostics.maximum);
        let expected_sample_plaintext = ideal_plaintext[0];
        let consumed_sample_phase_error =
            reference_sample_plaintext.wrapping_sub(expected_sample_plaintext) as i64;
        let reference_decoded_degree = ramp_decode_degree(reference_sample_plaintext);
        let adapter_decoded_degree = ramp_decode_degree(adapter_sample_plaintext);
        let ideal_decoded_degree = ramp_decode_degree(expected_sample_plaintext);
        if reference_decoded_degree != adapter_decoded_degree {
            return reject(format!(
                "degree-0 ramp-decoded output mismatch for {}",
                case.id
            ));
        }
        consumed_sample_decode_matches_ideal +=
            usize::from(reference_decoded_degree == ideal_decoded_degree);
        tie_zero_cases += usize::from(tie == 0);
        tie_one_cases += usize::from(tie == 1);

        emit(json!({
            "record": "case",
            "status": "PASS",
            "index": case.index,
            "id": case.id,
            "mask_sha256": sha256_u64s(&case.mask),
            "input_sha256": case.expected_input_sha256,
            "raw_body_hex": format!("0x{:016x}", case.body),
            "raw_phase_hex": format!("0x{raw_phase:016x}"),
            "D": d.to_string(),
            "H": h.to_string(),
            "tie_bit": tie,
            "reference_correction_signed": reference_correction_signed.to_string(),
            "reference_correction_hex": format!("0x{reference_correction:016x}"),
            "adapter_correction_hex": format!("0x{adapter_correction:016x}"),
            "centered_raw_correction_hex": format!("0x{centered_raw_correction:016x}"),
            "reference_body_degree": reference_body_degree,
            "adapter_body_degree": adapter_body_degree,
            "direct_centered_body_degree": centered_body_degree,
            "mask_degrees_sha256": sha256_u64s(&reference_mask_degrees.iter().map(|&x| x as u64).collect::<Vec<_>>()),
            "switched_phase_degree": switched_phase_degree,
            "arm_order": arm_order,
            "reference_blind_rotation_s": reference_s,
            "adapter_blind_rotation_s": adapter_s,
            "case_wall_s": case_started.elapsed().as_secs_f64(),
            "reference_output_sha256": reference_output_sha256,
            "adapter_output_sha256": adapter_output_sha256,
            "reference_decrypted_sha256": sha256_u64s(reference_plaintext.as_ref()),
            "adapter_decrypted_sha256": sha256_u64s(adapter_plaintext.as_ref()),
            "degree_zero_sample": {
                "reference_lwe_sha256": sha256_u64s(reference_sample.as_ref()),
                "adapter_lwe_sha256": sha256_u64s(adapter_sample.as_ref()),
                "reference_plaintext_hex": format!("0x{reference_sample_plaintext:016x}"),
                "adapter_plaintext_hex": format!("0x{adapter_sample_plaintext:016x}"),
                "ideal_plaintext_hex": format!("0x{expected_sample_plaintext:016x}"),
                "signed_phase_error": consumed_sample_phase_error,
                "absolute_phase_error": consumed_sample_phase_error.unsigned_abs(),
                "reference_ramp_decoded_degree": reference_decoded_degree,
                "adapter_ramp_decoded_degree": adapter_decoded_degree,
                "ideal_ramp_decoded_degree": ideal_decoded_degree,
                "decode_matches_ideal_diagnostic": reference_decoded_degree == ideal_decoded_degree,
                "decision_role": "paired_equality_exact_ideal_error_and_decode_diagnostic"
            },
            "full_glwe_phase_diagnostics": {
                "maximum_absolute": full_glwe_diagnostics.maximum,
                "signed_at_maximum": full_glwe_diagnostics.signed_at_maximum,
                "index_at_maximum": full_glwe_diagnostics.index_at_maximum,
                "p50_absolute_nearest_rank": full_glwe_diagnostics.p50_absolute,
                "p95_absolute_nearest_rank": full_glwe_diagnostics.p95_absolute,
                "p99_absolute_nearest_rank": full_glwe_diagnostics.p99_absolute,
                "decision_role": "diagnostic_only_no_cap_no_independence_assumption"
            }
        }))?;
    }

    if tie_zero_cases == 0 || tie_one_cases == 0 {
        return invalid("smoke did not retain both tie classes");
    }

    emit(json!({
        "record": "summary",
        "status": "PASS_COMPONENT_FHE_SMOKE_R2B",
        "stage": "A98_R2B",
        "fresh_keys": 1,
        "cases_expected": 14,
        "cases_passed": 14,
        "tie_zero_cases": tie_zero_cases,
        "tie_one_cases": tie_one_cases,
        "direct_centered_degree_mismatch_cases": direct_centered_degree_mismatch_cases,
        "consumed_sample_decode_matches_ideal_diagnostic": consumed_sample_decode_matches_ideal,
        "maximum_full_glwe_phase_error_diagnostic": maximum_full_glwe_phase_error,
        "phase_error_cap": null,
        "phase_error_decision_role": "diagnostic_only",
        "full_glwe_correlation_model": "not_assumed",
        "primary_adapter_equivalence_gate": "bitwise_reference_vs_adapter_pre_fft_and_post_blind_rotation",
        "consumed_output_gate": "degree_zero_extracted_lwe_and_decrypted_ramp_degree_equal_between_arms",
        "reference_blind_rotation_total_s": reference_seconds,
        "adapter_blind_rotation_total_s": adapter_seconds,
        "total_wall_s": wall_started.elapsed().as_secs_f64(),
        "not_run": [
            "R3_corrected_keyswitch",
            "R4_composed_KS_to_PBS",
            "R5_fresh_key_campaign",
            "2048_mask_campaign",
            "composed_p_fail",
            "exact_ID_integration"
        ],
        "claim_boundary": "A98-R2B single-key component correctness smoke only; timings and all ideal-phase errors are diagnostic, and no patched-binary, p_fail, latency, composed-pipeline, or exact-ID claim follows."
    }))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = emit(json!({
                "record": "fatal",
                "status": error.status(),
                "message": error.message()
            }));
            ExitCode::from(match error {
                GateError::Invalid(_) => 2,
                GateError::Reject(_) => 3,
            })
        }
    }
}
