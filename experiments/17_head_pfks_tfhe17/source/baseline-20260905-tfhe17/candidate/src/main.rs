//! BASELINE_20260905_TFHE17 fixed same-key/input refresh pair pilot. No observer feature or speed promotion.
#[cfg(feature = "diagnostic-trace")]
compile_error!("BASELINE_20260905_TFHE17 timing refuses diagnostic-trace");

use baseline_20260905_tfhe17::{
    a126_aligned_operation_counts, a62_aligned_operation_counts, clear_private_argmin,
    plan_private_argmin_execution, private_argmin_a126, private_argmin_a62, A62PrivateArgminOutput,
    TemplateView, A44_PARAMETER_BINDING, A44_PARAMETER_CANONICAL,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;

const SOURCE: &str = include_str!("../SOURCE_DIGEST.txt");
const PLAN: &str = include_str!("../../PILOT.json");
const THREADS: usize = 8;
const N: usize = 127;
const ACK: &str = "BASELINE_20260905_TFHE17_ROOT_EXCLUSIVE_UNQUALIFIED_PILOT";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn word_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for word in words {
        h.update(word.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
fn emit(file: &mut File, value: Value) {
    writeln!(file, "{value}").unwrap();
    file.sync_all().unwrap();
}
fn ns(duration: std::time::Duration) -> u64 {
    duration.as_nanos().try_into().unwrap()
}

struct Timed {
    start_ns: u64,
    end_ns: u64,
    output: Result<A62PrivateArgminOutput, baseline_20260905_tfhe17::PrivateArgminError>,
}

fn timed(
    fused: bool,
    pool: &ThreadPool,
    epoch: Instant,
    server: &ServerKey,
    input: &GlweCiphertextOwned<u64>,
    templates: &[TemplateView<'_>],
    domain: baseline_20260905_tfhe17::ScoreDomain,
) -> Timed {
    // Select the endpoint before the timer. The identical bracket includes pool.install,
    // parameter validation and all endpoint setup/evaluation. No output inspection here.
    let evaluator = if fused {
        private_argmin_a126
    } else {
        private_argmin_a62
    };
    let start = Instant::now();
    let output =
        pool.install(|| evaluator(A44_PARAMETER_BINDING, server, input, templates, domain));
    let end = Instant::now();
    Timed {
        start_ns: ns(start.duration_since(epoch)),
        end_ns: ns(end.duration_since(epoch)),
        output,
    }
}

fn run(directory: &Path, run_id: &str) {
    assert!(directory.is_absolute());
    let metadata = fs::symlink_metadata(directory).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert!(
        !run_id.is_empty()
            && run_id.len() <= 80
            && run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
    assert_eq!(
        std::env::var("BASELINE_20260905_TFHE17_RUN_ACK").as_deref(),
        Ok(ACK)
    );
    assert_eq!(
        std::env::var("BASELINE_20260905_TFHE17_SOURCE_SHA256").as_deref(),
        Ok(SOURCE.trim())
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("8"));
    assert_eq!(
        std::env::var("BASELINE_20260905_TFHE17_GUARD_MODE").as_deref(),
        Ok("ROOT_PREFLIGHT_ONLY_UNQUALIFIED")
    );
    let binary = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    assert!(binary
        .components()
        .any(|x| x.as_os_str() == "target-baseline-20260905-tfhe17-only"));
    let binary_hash = hash(&fs::read(binary).unwrap());
    assert_eq!(
        std::env::var("BASELINE_20260905_TFHE17_BINARY_SHA256").as_deref(),
        Ok(binary_hash.as_str())
    );
    let plan: Value = serde_json::from_str(PLAN).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("records.jsonl"))
        .unwrap();
    let epoch = Instant::now();
    emit(
        &mut file,
        json!({"record":"run_start","schema":"baseline-20260905-tfhe17.pilot.v1","run_id":run_id,
        "source_sha256":SOURCE.trim(),"binary_sha256":binary_hash,"pid":std::process::id(),
        "plan_sha256":hash(PLAN.as_bytes()),"core_sha256":hash(include_bytes!("private_argmin.rs")),
        "parameter_canonical":A44_PARAMETER_CANONICAL,"threads_requested":THREADS,
        "trace_feature":false,"guard_status":"UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR",
        "timer":"std::time::Instant around pool.install + complete untraced endpoint",
        "timer_epoch":"process-local Instant; not aligned to OS collector",
        "observer_policy":"durable timing-only record after each pair; outputs retained and inspected after all pairs",
        "speedup_promotion_allowed":false,"actual_p_fail":null}),
    );
    let pool = ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .unwrap();
    assert_eq!(pool.current_num_threads(), THREADS);
    let client = ClientKey::new(PARAMS);
    let server = ServerKey::new(&client);
    let (glwe, _small, parameters, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => panic!("pilot requires Standard client key"),
    };
    let big = glwe.as_lwe_secret_key();
    let key_id = match &server.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => word_hash(key.key_switching_key.as_ref()),
        _ => panic!("pilot requires Standard server key"),
    };
    let mut gallery = vec![vec![1i64; 512]; N];
    for template in &mut gallery[..N - 1] {
        template[..128].fill(-1);
    }
    let templates: Vec<_> = gallery
        .iter()
        .map(|g| TemplateView {
            template: g,
            norm2: 512,
            threshold: -1,
        })
        .collect();
    let execution = plan_private_argmin_execution(&templates).unwrap();
    assert!(execution.aligned_fast_path);
    assert_eq!(
        (
            execution.execution_domain.lower,
            execution.execution_domain.upper
        ),
        (-1024, 1962)
    );
    let scores: Vec<i64> = gallery
        .iter()
        .map(|g| 512 - 2 * g.iter().sum::<i64>())
        .collect();
    let clear = clear_private_argmin(&scores, &templates).unwrap();
    assert_eq!(
        (clear.winner_index, clear.code, clear.matched),
        (126, 127, true)
    );
    let old = a62_aligned_operation_counts(N).unwrap();
    let new = a126_aligned_operation_counts(N).unwrap();
    assert_eq!(
        (old.blind_rotations, old.key_switches, old.output_marginals),
        (3390, 3009, 3930)
    );
    assert_eq!(
        (new.blind_rotations, new.key_switches, new.output_marginals),
        (3263, 2882, 3930)
    );
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut plaintext = vec![0u64; 2048];
    for i in 0..512 {
        plaintext[i] = 1u64 << 52;
        plaintext[1024 + i] = 1u64 << 60;
    }
    let rows = plan["pairs"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let mut prepared = Vec::with_capacity(rows.len());
    for row in rows {
        let mut input = GlweCiphertext::new(
            0u64,
            GlweSize(2),
            PolynomialSize(2048),
            CiphertextModulus::new_native(),
        );
        encrypt_glwe_ciphertext(
            &glwe,
            &mut input,
            &PlaintextList::from_container(plaintext.clone()),
            parameters.glwe_noise_distribution(),
            &mut generator,
        );
        assert!(input.get_mask().as_ref().iter().any(|&a| a != 0));
        prepared.push((row.clone(), word_hash(input.as_ref()), input));
    }
    emit(
        &mut file,
        json!({"record":"prepared_block","key_id":key_id,"fresh_keys":1,
        "key_id_definition":"SHA256 public native KSK u64LE; shared server object",
        "input_hashes":prepared.iter().map(|(_,h,_)|h).collect::<Vec<_>>(),
        "ciphertexts_pre_encrypted":6,"gallery":"A133 n127_last_id",
        "domain":[-1024,1962],"expected_code":127,"secret_key_bytes_persisted":false}),
    );
    let mut results = Vec::with_capacity(rows.len());
    for (row, input_hash, input) in &prepared {
        let sequence = row["sequence"].as_u64().unwrap();
        let first_fused = row["order"].as_str().unwrap() == "BA";
        let first = timed(
            first_fused,
            &pool,
            epoch,
            &server,
            input,
            &templates,
            execution.execution_domain,
        );
        let second = timed(
            !first_fused,
            &pool,
            epoch,
            &server,
            input,
            &templates,
            execution.execution_domain,
        );
        let (baseline, fused) = if first_fused {
            (second, first)
        } else {
            (first, second)
        };
        emit(
            &mut file,
            json!({"record":"pair_timing","sequence":sequence,"phase":row["phase"],
            "order":row["order"],"key_id":key_id,"input_sha256":input_hash,
            "same_key_gallery_input_source_binding":true,
            "baseline_start_ns":baseline.start_ns,"baseline_end_ns":baseline.end_ns,
            "fused_start_ns":fused.start_ns,"fused_end_ns":fused.end_ns,
            "baseline_wall_ns":baseline.end_ns-baseline.start_ns,
            "fused_wall_ns":fused.end_ns-fused.start_ns,
            "outputs_inspected":false,"guard_status":"UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR"}),
        );
        results.push((baseline, fused));
    }
    // No decryption, output hash/serialization/drop or phase observation preceded this point.
    let mut passed = 0;
    for ((row, input_hash, input), (baseline, fused)) in prepared.iter().zip(results) {
        assert_eq!(
            &word_hash(input.as_ref()),
            input_hash,
            "shared immutable input changed"
        );
        let mut arms = Vec::new();
        for (label, result, br, select) in [
            ("A", baseline.output, 3390u64, 1603u64),
            ("B", fused.output, 3263u64, 1476u64),
        ] {
            match result {
                Ok(output)=>{
                    let decode=|ct:&LweCiphertextOwned<u64>| decrypt_lwe_ciphertext(&big,ct).0.wrapping_add(1u64<<58)>>59;
                    let low=decode(&output.low_digit); let high=decode(&output.high_digit);
                    let stages=[output.metrics.extract.pbs_count,output.metrics.select.pbs_count,output.metrics.scan.pbs_count];
                    let pass=low==7 && high==8 && output.metrics.total_pbs_count==br && stages==[1651,select,136];
                    arms.push(json!({"arm":label,"evaluation_ok":true,"low":low,"high":high,"code":low+15*high,
                        "total_br":output.metrics.total_pbs_count,"stage_br":stages,
                        "low_sha256":word_hash(output.low_digit.as_ref()),"high_sha256":word_hash(output.high_digit.as_ref()),"pass":pass}));
                },
                Err(error)=>arms.push(json!({"arm":label,"evaluation_ok":false,"error":error.to_string(),"pass":false})),
            }
        }
        let pass = arms.iter().all(|arm| arm["pass"] == true);
        passed += usize::from(pass);
        emit(
            &mut file,
            json!({"record":"pair_validation","sequence":row["sequence"],"input_sha256":input_hash,"arms":arms,"pass":pass}),
        );
    }
    emit(
        &mut file,
        json!({"record":"summary","status":"PILOT_COMPLETE","pairs":6,"warmup_pairs":2,"measured_pairs":4,
        "evaluations":12,"pairs_pass":passed,"all_correct":passed==6,
        "guard_status":"UNQUALIFIED_NO_ALIGNED_OS_COLLECTOR","speedup_promotion_allowed":false,
        "confidence_interval":null,"actual_p_fail":null}),
    );
    assert_eq!(
        passed, 6,
        "pilot correctness/count gate failed; preserve all timings"
    );
    println!("BASELINE_20260905_TFHE17 pilot complete; paired timings remain descriptive and guard-unqualified.");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("{PLAN}");
        return;
    }
    assert_eq!(args.len(), 3, "use private root launcher");
    assert_eq!(args[0], "--run-pilot");
    run(Path::new(&args[1]), &args[2]);
}
