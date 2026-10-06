//! One A137 direct PFKS primitive with frozen A147 client-only independent row measurement.
#[path = "row_observer.rs"]
mod rows;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    ShortintParameterSet, V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};
use tfhe::shortint::ClientKey;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn words_hash(words: &[u64]) -> String {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}
fn source_id() -> &'static str {
    include_str!("../source-id.txt").trim()
}
fn emit(file: &mut File, value: Value) {
    writeln!(file, "{value}").expect("private evidence write");
    file.sync_data().expect("durable evidence");
}
fn predicted(p: &rows::Prediction) -> Value {
    json!({"modular":p.modular.to_string(),"centered":p.centered.to_string(),
        "lifted":p.lifted.to_string(),"wrap_quotient":p.wrap_quotient.to_string(),
        "distinct_nonzero_row_functionals":p.distinct_nonzero_row_functionals})
}

fn run(output_path: PathBuf) {
    assert!(output_path.is_absolute(), "private output must be absolute");
    let parent = output_path.parent().expect("private parent");
    let parent_meta = fs::symlink_metadata(parent).expect("private directory exists");
    assert!(parent_meta.is_dir() && !parent_meta.file_type().is_symlink());
    assert_eq!(
        parent_meta.permissions().mode() & 0o777,
        0o700,
        "private parent must be0700"
    );
    assert_eq!(
        std::env::var("A151_CLEARED_SOURCE_ID").ok().as_deref(),
        Some(source_id())
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("1"));
    let binary_hash =
        hash(&fs::read(std::env::current_exe().expect("current executable")).expect("read binary"));
    assert_eq!(
        std::env::var("A151_EXPECTED_BINARY_SHA256").ok().as_deref(),
        Some(binary_hash.as_str())
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output_path)
        .expect("new private evidence file");
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    let params_hash = hash(include_bytes!("../PARAMETERS.json"));
    emit(
        &mut file,
        json!({"record":"meta","artifact":"A151","evidence_kind":"RUNTIME_PRIVATE","source_id":source_id(),
        "binary_sha256":binary_hash,"params_sha256":params_hash,"process_id":std::process::id(),
        "observer_sha256":hash(include_bytes!("row_observer.rs")),"tfhe":"0.11.3",
        "scope":"client-local primitive gate; no benchmark, key membership proof or tails"}),
    );
    let expected: ShortintParameterSet = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64.into();
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let (glwe_secret, small_secret, actual_parameters) = client.into_raw_parts();
    assert_eq!(actual_parameters, expected);
    assert_eq!(small_secret.lwe_dimension(), LweDimension(859));
    assert_eq!(glwe_secret.glwe_dimension(), GlweDimension(1));
    assert_eq!(glwe_secret.polynomial_size(), PolynomialSize(2048));
    let big_secret = glwe_secret.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_words: Vec<u64> = include_bytes!("../window.u64le")
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    assert_eq!(polynomial_words.len(), 2048);
    let function_hash = words_hash(&polynomial_words);
    let polynomial = Polynomial::from_container(polynomial_words);
    let mut key = LwePrivateFunctionalPackingKeyswitchKey::new(
        0u64,
        DecompositionBaseLog(24),
        DecompositionLevelCount(1),
        big_secret.lwe_dimension(),
        GlweSize(2),
        PolynomialSize(2048),
        modulus,
    );
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big_secret,
        &glwe_secret,
        &mut key,
        actual_parameters.glwe_noise_distribution(),
        &mut generator,
        |value| value,
        &polynomial,
    );
    let key_hash = words_hash(key.as_ref());
    emit(
        &mut file,
        json!({"record":"key_bound","key_sha256":key_hash,"function_sha256":function_hash,
        "scalar_function":"identity","effective_function":"W0_radius63","row_levels":2049,
        "pfks_base_log":24,"pfks_levels":1,"base_parameters_equal":true,"key_words":key.as_ref().len()}),
    );

    // Critical ordering: actual independent row measurement precedes even payload encryption.
    let samples = rows::measure_key_rows(
        &key,
        &big_secret,
        &glwe_secret,
        rows::KeyFunction::Window { radius: 63 },
        rows::Projection::Coefficient,
        &[0],
    );
    assert_eq!(samples.key_hash(), key_hash);
    assert_eq!(samples.measured_row_levels(), 2049);
    assert_eq!(samples.measured_target_count(), 1);
    emit(
        &mut file,
        json!({"record":"rows_measured","key_sha256":samples.key_hash(),
        "kernel_sha256":samples.kernel_hash(),"row_levels":samples.measured_row_levels(),
        "targets":[0],"payload_exists":false,"pfks_output_exists":false,
        "raw_row_data_persisted":false,"samples_client_memory_only":true}),
    );

    // Frozen A137 fixture2 left[0] =3 at Delta59, encrypted with its GLWE Gaussian distribution.
    let mut payload = LweCiphertext::new(0u64, LweSize(2049), modulus);
    encrypt_lwe_ciphertext(
        &big_secret,
        &mut payload,
        Plaintext(3u64 << 59),
        actual_parameters.glwe_noise_distribution(),
        &mut generator,
    );
    assert!(payload.get_mask().as_ref().iter().any(|&word| word != 0));
    let payload_hash = words_hash(payload.as_ref());
    let before = rows::predict(&samples, &[&payload], &[0], &[1]);
    let before_json = predicted(&before);
    emit(
        &mut file,
        json!({"record":"prediction_before_pfks","key_sha256":key_hash,
        "payload_sha256":payload_hash,"fixture":"accept_threshold_left","fixture_index":2,
        "payload_side":"left","payload_lane":0,"message":3,"delta_log":59,"target":0,
        "nontrivial_payload":true,"prediction":before_json,"pfks_calls_so_far":0}),
    );

    let mut output = GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
    private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&key, &mut output, &payload);
    let output_hash = words_hash(output.as_ref());
    let positive = rows::compare_payload(&samples, &payload, &output, 0);
    let mut changed_output = output.clone();
    let original_body = changed_output.get_body().as_ref()[0];
    changed_output.get_mut_body().as_mut()[0] = original_body.wrapping_add(1);
    let negative = rows::compare_payload(&samples, &payload, &changed_output, 0);
    let after = rows::predict(&samples, &[&payload], &[0], &[1]);
    let prediction_fixed = before_json == predicted(&after)
        && before_json == predicted(&positive.predicted)
        && before_json == predicted(&negative.predicted);
    let observed_changes_by_one =
        negative.observed_aggregate == positive.observed_aggregate.wrapping_add(1);
    let key_unchanged = words_hash(key.as_ref()) == key_hash;
    let payload_unchanged = words_hash(payload.as_ref()) == payload_hash;
    emit(
        &mut file,
        json!({"record":"comparison","key_sha256":key_hash,"payload_sha256":payload_hash,
        "output_sha256":output_hash,"changed_output_sha256":words_hash(changed_output.as_ref()),
        "observed_aggregate":positive.observed_aggregate.to_string(),
        "changed_observed_aggregate":negative.observed_aggregate.to_string(),
        "positive_equal":positive.modular_equal,"changed_output_equal":negative.modular_equal,
        "prediction_fixed":prediction_fixed,"observed_changes_by_one":observed_changes_by_one,
        "key_unchanged":key_unchanged,"payload_unchanged":payload_unchanged,
        "prediction_after":predicted(&after),"pfks_calls":1,"other_server_crypto_calls":0}),
    );
    let pass = positive.modular_equal
        && !negative.modular_equal
        && prediction_fixed
        && observed_changes_by_one
        && key_unchanged
        && payload_unchanged;
    emit(
        &mut file,
        json!({"record":"summary","status":if pass {"PASS_ONE_PAYLOAD_ROW_IDENTITY"} else {"FAIL_PRESERVED"},
        "row_levels":2049,"targets":1,"payloads":1,"pfks_calls":1,"changed_output_control_pass":!negative.modular_equal,
        "tails":"OPEN","covariance":"OPEN","function_label_authentication":"source-bound, not proved by closure",
        "support_and_final_correctness":"NOT_TESTED_no_BR_selector_or_scan"}),
    );
    assert!(pass, "private evidence retained; do not expand failed gate");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!(
            "{}",
            json!({"status":"PLAN_NO_FHE","artifact":"A151","source_id":source_id(),
            "mode":"one A137 direct payload, target0, all2049 rows, 24x1","requires":"verified clear workload window and private runner"})
        );
        return;
    }
    assert!(
        args.len() == 5
            && args[0] == "--run-authorized"
            && args[1] == "--pfks"
            && args[2] == "24x1"
            && args[3] == "--output",
        "exactly --run-authorized --pfks 24x1 --output ABSOLUTE_PRIVATE_PATH"
    );
    run(PathBuf::from(&args[4]));
}
