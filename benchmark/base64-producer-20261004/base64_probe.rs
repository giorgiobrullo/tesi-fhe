//! One fresh family, eight fixed normalized inputs and one conditional scoring-prefix check.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};

const PROBE_SCHEMA: &str = "base64-producer-probe.v1";
const MAX_CASES: usize = 9;
const DIRECT_SCORES: [u64; 8] = [63, 64, 0, 4095, 127, 128, 1023, 1024];
const HEAD_DELTA: u64 = 1 << 56;
const CHUNK_DELTA: u64 = 1 << 57;
const HEAD_OFFSET: u64 = 63 * (1 << 55);

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
struct LocalCounts { br: usize, ks: usize, samples: usize, gadget_levels: usize }

fn accumulator128(values: &[u64]) -> Glwe {
    assert_eq!(values.len(), 128, "INTERNAL_CONFIGURATION_FAILURE: table length");
    let mut body: Vec<_> = values.iter().flat_map(|v| std::iter::repeat_n(*v, 16)).collect();
    for value in &mut body[..8] { *value = value.wrapping_neg(); }
    body.rotate_left(8);
    let mut result = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
    result.get_mut_body().as_mut().copy_from_slice(&body);
    result
}

fn extract_counted(accumulator: &Glwe, counts: &mut LocalCounts) -> Lwe {
    let mut result = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
    extract_lwe_sample_from_glwe_ciphertext(accumulator, &mut result, MonomialDegree(0));
    counts.samples += 1;
    result
}

// Return [high, low]. Each normalizer gets a fresh accumulator and the SAME switched input.
fn base64_chunks(input: &Lwe, keys: &EvaluationKeys, counts: &mut LocalCounts) -> [Lwe; 2] {
    let ShortintBootstrappingKey::Classic(ordinary) = &keys.adapter.bootstrapping_key;
    let mut shifted = input.clone();
    lwe_ciphertext_plaintext_sub_assign(&mut shifted, Plaintext(HEAD_DELTA));
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(&keys.adapter.key_switching_key, &shifted, &mut small)
        .expect("INTERNAL_CONFIGURATION_FAILURE: Head corrected KS");
    counts.ks += 1;
    let switched = crate::a98::exact_head_start_modulus_switch(small, CiphertextModulusLog(12))
        .expect("INTERNAL_CONFIGURATION_FAILURE: Head exact MS");
    let values: Vec<_> = (0u64..128).map(|m| (m / 2).wrapping_mul(HEAD_DELTA).wrapping_sub(HEAD_OFFSET)).collect();
    let mut head_accumulator = accumulator128(&values);
    tfhe::core_crypto::algorithms::blind_rotate_assign(&switched, &mut head_accumulator, &keys.head);
    counts.br += 1;
    counts.gadget_levels += keys.head.decomposition_level_count().0;
    let mut head = extract_counted(&head_accumulator, counts);
    lwe_ciphertext_plaintext_add_assign(&mut head, Plaintext(HEAD_OFFSET));

    let mut twice_head = head.clone();
    for word in twice_head.as_mut() { *word = word.wrapping_mul(2); }
    let mut dirty = input.clone();
    lwe_ciphertext_sub_assign(&mut dirty, &twice_head);
    for word in dirty.as_mut() { *word = word.wrapping_mul(32); }
    let mut small = Lwe::new(0, LweSize(860), CiphertextModulus::new_native());
    crate::a112::a112_local_corrected_keyswitch(&keys.adapter.key_switching_key, &dirty, &mut small)
        .expect("INTERNAL_CONFIGURATION_FAILURE: dirty corrected KS");
    counts.ks += 1;
    let switched = crate::a98::exact_head_start_modulus_switch(small, CiphertextModulusLog(12))
        .expect("INTERNAL_CONFIGURATION_FAILURE: dirty exact MS");
    let tables = [
        (0u64..128).map(|r| (r % 64).wrapping_mul(CHUNK_DELTA)).collect::<Vec<_>>(),
        (0u64..128).map(|r| (r / 64).wrapping_mul(CHUNK_DELTA)).collect::<Vec<_>>(),
    ];
    let [low, carry] = tables.map(|values| {
        let mut accumulator = accumulator128(&values);
        tfhe::core_crypto::algorithms::blind_rotate_assign(&switched, &mut accumulator, ordinary);
        counts.br += 1;
        counts.gadget_levels += ordinary.decomposition_level_count().0;
        extract_counted(&accumulator, counts)
    });
    lwe_ciphertext_add_assign(&mut twice_head, &carry);
    [twice_head, low]
}

fn append_row(writer: &mut BufWriter<File>, row: &Value) {
    serde_json::to_writer(&mut *writer, row).expect("CONFIG_OR_IO_FAILURE: row JSON");
    writer.write_all(b"\n").expect("CONFIG_OR_IO_FAILURE: row newline");
    writer.flush().expect("CONFIG_OR_IO_FAILURE: row flush");
}

struct HashWriter { inner: BufWriter<File>, digest: Sha256, bytes: u64 }
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.digest.update(&bytes[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}

// The public header and opaque payload are written once; this helper never reads them back.
fn save_envelope<T: Serialize>(directory: &Path, name: &str, kind: &str, value: &T) -> Value {
    let file = OpenOptions::new().write(true).create_new(true).open(directory.join(name))
        .expect("CONFIG_OR_IO_FAILURE: exclusive envelope creation");
    let mut writer = HashWriter { inner: BufWriter::new(file), digest: Sha256::new(), bytes: 0 };
    let header = json!({"format": "base64-producer-local-envelope.v1", "kind": kind,
        "params_id": private_argmin::A44_PARAMS_ID,
        "parameter_fingerprint_sha256": private_argmin::A44_PARAMETER_FINGERPRINT_SHA256,
        "encoding": "bincode-1.3.3", "family": "fresh-family-1"});
    let header_bytes = serde_json::to_vec(&header).expect("CONFIG_OR_IO_FAILURE: envelope header");
    writer.write_all(b"B64PENV1").expect("CONFIG_OR_IO_FAILURE: envelope magic");
    writer.write_all(&(header_bytes.len() as u64).to_le_bytes()).expect("CONFIG_OR_IO_FAILURE: header length");
    writer.write_all(&header_bytes).expect("CONFIG_OR_IO_FAILURE: public header");
    bincode::serialize_into(&mut writer, value).expect("CONFIG_OR_IO_FAILURE: opaque serialization");
    writer.flush().expect("CONFIG_OR_IO_FAILURE: envelope flush");
    writer.inner.get_ref().sync_all().expect("CONFIG_OR_IO_FAILURE: envelope sync");
    json!({"path": name, "bytes": writer.bytes, "sha256": format!("{:x}", writer.digest.finalize()), "header": header})
}

fn complete(directory: &Path, writer: &mut BufWriter<File>, completed: usize, passed: bool) {
    let row = json!({"record": "complete", "schema": PROBE_SCHEMA, "passed": passed,
        "status": if passed { "PRODUCER_PASS_9_CHECKS" } else { "PRODUCER_REJECTED" },
        "max_cases": MAX_CASES, "completed_cases": completed, "unexecuted_cases": MAX_CASES - completed,
        "key_families": 1, "timing": false, "stop_first_semantic_divergence": true});
    append_row(writer, &row);
    let mut file = OpenOptions::new().write(true).create_new(true).open(directory.join("COMPLETE.json"))
        .expect("CONFIG_OR_IO_FAILURE: exclusive completion creation");
    serde_json::to_writer_pretty(&mut file, &row).expect("CONFIG_OR_IO_FAILURE: completion JSON");
    file.write_all(b"\n").expect("CONFIG_OR_IO_FAILURE: completion newline");
    file.sync_all().expect("CONFIG_OR_IO_FAILURE: completion sync");
}

fn check_case(directory: &Path, writer: &mut BufWriter<File>, index: usize, kind: &str,
    scores: &[u64], inputs: Vec<Lwe>, keys: &EvaluationKeys, secret: &LweSecretKeyView<'_, u64>,
    query_envelope: Value,
) {
    assert!(index < MAX_CASES && inputs.len() == scores.len(), "INTERNAL_CONFIGURATION_FAILURE: case shape");
    let input_envelope = save_envelope(directory, &format!("case-{index}-inputs.envelope"), "input-lwes", &inputs);
    let mut counts = LocalCounts::default();
    let outputs: Vec<_> = inputs.iter().map(|input| base64_chunks(input, keys, &mut counts)).collect();
    assert_eq!(counts, LocalCounts { br: 3 * inputs.len(), ks: 2 * inputs.len(),
        samples: 3 * inputs.len(), gadget_levels: 4 * inputs.len() },
        "INTERNAL_CONFIGURATION_FAILURE: actual producer operations");
    let expected: Vec<_> = scores.iter().map(|x| [x / 64, x % 64]).collect();
    let decoded: Vec<_> = outputs.iter().map(|pair| pair.each_ref().map(|ciphertext| {
        let chunk = decrypt_lwe_ciphertext(secret, ciphertext).0.wrapping_add(CHUNK_DELTA / 2) >> 57;
        (chunk < 64).then_some(chunk)
    })).collect();
    let canonical = decoded.iter().flatten().all(Option::is_some);
    let passed = canonical && decoded == expected.iter().map(|pair| pair.map(Some)).collect::<Vec<_>>();
    let failed_outputs_envelope = if passed { Value::Null } else {
        save_envelope(directory, &format!("case-{index}-failed-final.envelope"), "final-chunks", &outputs)
    };
    append_row(writer, &json!({"record": "case", "schema": PROBE_SCHEMA, "case_index": index,
        "kind": kind, "normalized_scores": scores, "expected": expected, "decoded": decoded,
        "canonical": canonical, "passed": passed, "actual_counts": counts, "timing": false,
        "input_envelope": input_envelope, "failed_outputs_envelope": failed_outputs_envelope,
        "query_envelope": query_envelope}));
    if !passed {
        complete(directory, writer, index + 1, false);
        panic!("PRODUCER_REJECTED: case {index}; later cases not executed");
    }
}

fn expanded(prefix: [i64; 2]) -> Vec<i64> {
    let mut result = vec![0; private_argmin::PROBE_DIM];
    result[..2].copy_from_slice(&prefix);
    result
}

fn validate_geometry(keys: &EvaluationKeys) {
    let ShortintBootstrappingKey::Classic(ordinary) = &keys.adapter.bootstrapping_key;
    for (key, base, levels) in [(&keys.head, 15, 2), (ordinary, 23, 1)] {
        assert_eq!((key.input_lwe_dimension().0, key.output_lwe_dimension().0, key.glwe_size().0,
            key.polynomial_size().0, key.decomposition_base_log().0, key.decomposition_level_count().0),
            (859, 2048, 2, 2048, base, levels), "CONFIG_OR_IO_FAILURE: actual PBS geometry");
    }
    let ks = &keys.adapter.key_switching_key;
    assert_eq!((ks.input_key_lwe_dimension().0, ks.output_key_lwe_dimension().0,
        ks.decomposition_base_log().0, ks.decomposition_level_count().0), (2048, 859, 3, 5),
        "CONFIG_OR_IO_FAILURE: actual KS geometry");
    assert!(ks.ciphertext_modulus().is_native_modulus(), "CONFIG_OR_IO_FAILURE: native KS required");
}

#[test]
#[ignore = "one fresh family, up to nine producer checks; run alone, no timing"]
fn normalized_public_fixtures_without_timing() {
    let query = expanded([1, 1]);
    let vectors = [expanded([1, 0]), expanded([0, 1])];
    let templates = std::array::from_fn::<_, 2, _>(|i| TemplateView {
        template: &vectors[i], norm2: 1, threshold: [-2, -1][i],
    });
    let execution = plan(&templates).expect("CONFIG_OR_IO_FAILURE: admitted prefix fixture");
    assert_eq!((execution.execution_domain.lower, execution.execution_domain.upper), (-63, 65),
        "CONFIG_OR_IO_FAILURE: exact prefix domain");
    let scores = std::array::from_fn::<_, 2, _>(|i| templates[i].norm2 - 2 * query.iter()
        .zip(templates[i].template).map(|(q, t)| q * t).sum::<i64>());
    assert_eq!(scores, [-1, -1], "CONFIG_OR_IO_FAILURE: public prefix scores");
    assert_eq!(scores.map(|s| s - execution.execution_domain.lower), [62, 62],
        "CONFIG_OR_IO_FAILURE: public normalized prefix");
    let directory = PathBuf::from(std::env::var_os("BASE64_PRODUCER_OUTPUT_DIR")
        .expect("CONFIG_OR_IO_FAILURE: BASE64_PRODUCER_OUTPUT_DIR required"));
    assert!(directory.is_absolute(), "CONFIG_OR_IO_FAILURE: absolute output path required");
    fs::create_dir(&directory).expect("CONFIG_OR_IO_FAILURE: output directory must be new");
    let mut rows = BufWriter::new(OpenOptions::new().write(true).create_new(true)
        .open(directory.join("rows.jsonl")).expect("CONFIG_OR_IO_FAILURE: exclusive rows creation"));
    setup_custom_fft_plan(Plan::new(1024, Method::UserProvided { base_algo: FftAlgo::Dif4, base_n: 1024 }));
    let pool = rayon::ThreadPoolBuilder::new().num_threads(16).build()
        .expect("CONFIG_OR_IO_FAILURE: fixed Rayon pool");
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), 16, "CONFIG_OR_IO_FAILURE: pool size");
        crate::smallcuts::set_profiling(false);
        let client = tfhe::shortint::ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let ordinary = tfhe::shortint::ServerKey::new(&client);
        let bundle = generate_bundle(&client, ordinary).expect("CONFIG_OR_IO_FAILURE: fresh bundle");
        let client_envelope = save_envelope(&directory, "client-key.envelope", "client-key", &client);
        let server_envelope = save_envelope(&directory, "server-bundle.envelope", "ordinary-head-pfks-bundle", &bundle);
        let evaluation = EvaluationKeys::from_bundle(bundle).expect("CONFIG_OR_IO_FAILURE: evaluation keys");
        validate_geometry(&evaluation);
        let (glwe_secret, _, parameters, _) = match client.atomic_pattern {
            AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
            _ => panic!("CONFIG_OR_IO_FAILURE: Standard family required"),
        };
        let big_secret = glwe_secret.as_lwe_secret_key();
        let mut seeder = new_seeder();
        let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());
        append_row(&mut rows, &json!({"record": "metadata", "schema": PROBE_SCHEMA,
            "package": env!("CARGO_PKG_NAME"), "tfhe": "1.8.1", "max_cases": MAX_CASES,
            "key_families": 1, "key_generation_attempts": 1, "saved_key_load": false,
            "direct_scores": DIRECT_SCORES, "conditional_prefix_scores": [62, 62],
            "conditional_prefix_fixture": {"query_prefix": [1, 1], "templates_prefix": [[1, 0], [0, 1]],
                "thresholds": [-2, -1], "scores": scores, "execution_domain": [-63, 65]},
            "params_id": private_argmin::A44_PARAMS_ID,
            "parameter_fingerprint_sha256": private_argmin::A44_PARAMETER_FINGERPRINT_SHA256,
            "geometry": {"small_lwe_dimension": 859, "glwe_size": 2, "polynomial_size": 2048,
                "head_base_log": 15, "head_levels": 2, "normalizer_base_log": 23, "normalizer_levels": 1},
            "fft": {"complex_size": 1024, "algorithm": "Dif4", "base_n": 1024},
            "rayon_threads": 16, "pilot_encoding_logs": [57, 57], "input_encoding_log": 51,
            "head_encoding_log": 56, "normalizer_input_encoding_log": 56,
            "normalizers": "two scalar BRs on one switched object", "timing": false,
            "profiling": false, "build_rustc": option_env!("BASE64_PRODUCER_BUILD_RUSTC"),
            "client_key_envelope": client_envelope, "server_bundle_envelope": server_envelope,
            "claim_scope": "test-only producer; inherited service variant and custom 128-state LUTs not qualified; no comparator, selector, latency or failure bound"}));
        for (index, score) in DIRECT_SCORES.into_iter().enumerate() {
            let mut input = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
            encrypt_lwe_ciphertext(&big_secret, &mut input, Plaintext(score << 51),
                parameters.glwe_noise_distribution(), &mut generator);
            check_case(&directory, &mut rows, index, "direct_normalized", &[score], vec![input], &evaluation, &big_secret, Value::Null);
        }
        // This encryption and real prefix are reached only after all eight direct inputs pass.
        let mut coefficients = vec![0u64; 2048];
        for (i, value) in query.iter().copied().enumerate() {
            coefficients[i] = (value as u64).wrapping_mul(1 << 51);
            coefficients[1024 + i] = (value.rem_euclid(16) as u64).wrapping_mul(1 << 60);
        }
        let mut packed = Glwe::new(0, GlweSize(2), PolynomialSize(2048), CiphertextModulus::new_native());
        encrypt_glwe_ciphertext(&glwe_secret, &mut packed, &PlaintextList::from_container(coefficients),
            parameters.glwe_noise_distribution(), &mut generator);
        let query_envelope = save_envelope(&directory, "prefix-query.envelope", "query-glwe", &packed);
        let inputs = private_argmin::head_pfks_score_prefix_with_parallel(&evaluation.adapter, &packed,
            &templates, execution.execution_domain, true).expect("INTERNAL_CONFIGURATION_FAILURE: actual score prefix");
        check_case(&directory, &mut rows, 8, "actual_prefix", &[62, 62], inputs, &evaluation, &big_secret, query_envelope);
        complete(&directory, &mut rows, MAX_CASES, true);
    });
}
