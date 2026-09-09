use pfks_core::service::{self, EvaluationKeys, TemplateView};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;

const SOURCE: &str = include_str!("../../SOURCE_DIGEST.txt");
const SIZES: &[usize] = &[
    1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 126, 127, 128, 129, 224,
];
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn words_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for word in words {
        h.update(word.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
fn emit(file: &mut fs::File, mut value: Value) {
    value["observed_unix_ns"] = json!(unix_ns());
    serde_json::to_writer(&mut *file, &value).unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();
}

struct Scene {
    name: String,
    query: Vec<i64>,
    gallery: Vec<Vec<i64>>,
    norms: Vec<i64>,
    scores: Vec<i64>,
    expected: usize,
}
impl Scene {
    fn new(n: usize, name: &str) -> Self {
        let query = vec![1; 512];
        let mut gallery: Vec<Vec<i64>> = (0..n)
            .map(|i| {
                let mut t = vec![1; 512];
                for j in 0..5 {
                    t[(i + j) % 512] = 0;
                }
                t
            })
            .collect();
        let winner = |index: usize| {
            let mut t = vec![1; 512];
            t[index % 512] = 0;
            t
        };
        match name {
            "last" => gallery[n - 1] = winner(n - 1),
            "first" => gallery[0] = winner(0),
            "tie" => {
                gallery[n - 1] = winner(n - 1);
                if n > 1 {
                    gallery[n - 2] = winner(n - 2);
                }
            }
            "inclusive" | "reject" => {
                for (i, t) in gallery.iter_mut().enumerate() {
                    t.fill(0);
                    t[i % 512] = -1;
                }
                let t = &mut gallery[n - 1];
                t.fill(0);
                if name == "inclusive" {
                    t[(n - 1) % 512] = 1;
                } else {
                    t[0] = -1;
                    t[1..4].fill(1);
                }
            }
            "high_reject" => {
                for (i, t) in gallery.iter_mut().enumerate() {
                    t.fill(-1);
                    t[i % 512] = 0;
                }
            }
            _ => panic!("unknown scene"),
        }
        let norms: Vec<i64> = gallery
            .iter()
            .map(|t| t.iter().map(|x| x * x).sum())
            .collect();
        let scores: Vec<i64> = gallery
            .iter()
            .zip(&norms)
            .map(|(t, norm)| norm - 2 * t.iter().zip(&query).map(|(a, b)| a * b).sum::<i64>())
            .collect();
        let minimum = *scores.iter().min().unwrap();
        let expected = if minimum <= -1 {
            scores.iter().position(|v| *v == minimum).unwrap() + 1
        } else {
            0
        };
        assert!(norms.iter().all(|x| *x <= 511));
        Self {
            name: name.into(),
            query,
            gallery,
            norms,
            scores,
            expected,
        }
    }
    fn fast_views(&self) -> Vec<TemplateView<'_>> {
        self.gallery
            .iter()
            .zip(&self.norms)
            .map(|(t, n)| TemplateView {
                template: t,
                norm2: *n,
                threshold: -1,
            })
            .collect()
    }
    fn old_views(&self) -> Vec<older::TemplateView<'_>> {
        self.gallery
            .iter()
            .zip(&self.norms)
            .map(|(t, n)| older::TemplateView {
                template: t,
                norm2: *n,
                threshold: -1,
            })
            .collect()
    }
    fn r3_views(&self) -> Vec<r3::TemplateView<'_>> {
        self.gallery
            .iter()
            .zip(&self.norms)
            .map(|(t, n)| r3::TemplateView {
                template: t,
                norm2: *n,
                threshold: -1,
            })
            .collect()
    }
    fn record(&self) -> Value {
        json!({"name":self.name,"n":self.gallery.len(),"query":self.query,"gallery":self.gallery,
            "norms":self.norms,"scores":self.scores,"uniform_threshold":-1,"expected_id":self.expected})
    }
}

fn encrypt(query: &[i64], log: u32, secret: &GlweSecretKeyOwned<u64>) -> Glwe {
    let mut plain = vec![0u64; 2048];
    for (i, x) in query.iter().enumerate() {
        plain[i] = (*x as u64).wrapping_mul(1u64 << log);
        plain[1024 + i] = (x.rem_euclid(16) as u64) << 60;
    }
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut ct = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(2048),
        CiphertextModulus::new_native(),
    );
    encrypt_glwe_ciphertext(
        secret,
        &mut ct,
        &PlaintextList::from_container(plain),
        PARAMS.glwe_noise_distribution,
        &mut generator,
    );
    assert!(ct.get_mask().as_ref().iter().any(|x| *x != 0));
    ct
}

fn input_observation(
    ct: &Glwe,
    query: &[i64],
    log: u32,
    secret: &GlweSecretKeyOwned<u64>,
) -> Value {
    let mut plain = PlaintextList::new(0u64, PlaintextCount(2048));
    decrypt_glwe_ciphertext(secret, ct, &mut plain);
    let mut expected = vec![0u64; 2048];
    for (i, x) in query.iter().enumerate() {
        expected[i] = (*x as u64).wrapping_mul(1u64 << log);
        expected[1024 + i] = (x.rem_euclid(16) as u64) << 60;
    }
    let max_error = plain
        .as_ref()
        .iter()
        .zip(expected)
        .map(|(p, e)| (p.wrapping_sub(e) as i64 as i128).abs())
        .max()
        .unwrap();
    json!({"coefficient_checks":2048,"max_abs_error_torus":max_error as u64,"pass":max_error < (1i128<<(log-1))})
}

struct Output {
    digits: [Lwe; 2],
    counts: Value,
}
fn evaluate(arm: &str, scene: &Scene, input: &Glwe, keys: &EvaluationKeys, serial: bool) -> Output {
    let n = scene.gallery.len();
    match arm {
        "M" => {
            let views = scene.fast_views();
            let plan = service::plan(&views).unwrap();
            let (low, high, c) = if serial {
                keys.evaluate_serial(input, &views, plan.execution_domain)
            } else {
                keys.evaluate(input, &views, plan.execution_domain)
            }
            .unwrap();
            Output {
                digits: [low, high],
                counts: json!({"br":c.br,"ks":c.ks,"marginals":c.marginals,"pfks":c.pfks,"initial_samples":c.initial_samples}),
            }
        }
        "A126" => {
            assert!(!serial);
            let views = scene.old_views();
            let plan = older::plan_private_argmin_execution(&views).unwrap();
            assert!(plan.aligned_fast_path);
            let out = older::private_argmin_a126(
                older::A44_PARAMETER_BINDING,
                keys.ordinary(),
                input,
                &views,
                plan.execution_domain,
            )
            .unwrap();
            let c = older::a126_aligned_operation_counts(n).unwrap();
            assert_eq!(out.metrics.total_pbs_count, c.blind_rotations);
            Output {
                digits: [out.low_digit, out.high_digit],
                counts: json!({"br":out.metrics.total_pbs_count,"ks":c.key_switches,"marginals":c.output_marginals,"pfks":0,"initial_samples":2*n,"ks_marginals_evidence":"source-derived; runtime BR checked"}),
            }
        }
        "R3" => {
            assert!(!serial);
            let out =
                r3::nibble::parallel_nibble_id(keys.ordinary(), input, &scene.r3_views()).unwrap();
            Output {
                digits: [out.low_digit, out.high_digit],
                counts: json!({"br":out.br,"ks":out.ks,"marginals":out.pbs_samples,"pfks":0,"initial_samples":2*n}),
            }
        }
        _ => panic!("unknown arm"),
    }
}

fn observe(output: &Output, expected: usize, secret: &GlweSecretKeyOwned<u64>) -> Value {
    let big = secret.as_lwe_secret_key();
    let phases: Vec<u64> = output
        .digits
        .iter()
        .map(|ct| decrypt_lwe_ciphertext(&big, ct).0)
        .collect();
    let digits: Vec<u64> = phases
        .iter()
        .map(|v| v.wrapping_add(1 << 58) >> 59)
        .collect();
    let id = digits[0] + 15 * digits[1];
    let errors: Vec<i64> = phases
        .iter()
        .zip([expected % 15, expected / 15])
        .map(|(phase, d)| phase.wrapping_sub((d as u64) << 59) as i64)
        .collect();
    let pass = digits.iter().all(|v| *v < 15) && id == expected as u64;
    json!({"digits":digits,"id":id,"phases":phases,"errors_torus":errors,"counts":output.counts,
        "ciphertext_words":output.digits.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
        "ciphertext_sha256":output.digits.iter().map(|ct|words_hash(ct.as_ref())).collect::<Vec<_>>(),"pass":pass})
}

fn run_block(
    file: &mut fs::File,
    pool: &ThreadPool,
    keys: &EvaluationKeys,
    secret: &GlweSecretKeyOwned<u64>,
    scene: &Scene,
    phase: &str,
    index: usize,
    order: &[&str],
) -> bool {
    let head = encrypt(&scene.query, 51, secret);
    let legacy = encrypt(&scene.query, 52, secret);
    let input_hashes = [words_hash(head.as_ref()), words_hash(legacy.as_ref())];
    assert_ne!(input_hashes[0], input_hashes[1]);
    let head_observation = input_observation(&head, &scene.query, 51, secret);
    let legacy_observation = input_observation(&legacy, &scene.query, 52, secret);
    assert_eq!(head_observation["pass"], true);
    assert_eq!(legacy_observation["pass"], true);
    emit(
        file,
        json!({"record":"block_start","phase":phase,"n":scene.gallery.len(),"scene":scene.name,"index":index,"order":order,
        "inputs":[{"profile":"native51/60","sha256":input_hashes[0],"words":head.as_ref(),"observation":head_observation},
        {"profile":"native52/60","sha256":input_hashes[1],"words":legacy.as_ref(),"observation":legacy_observation}]}),
    );
    let mut completed = Vec::new();
    for arm in order {
        let ct = if *arm == "M" { &head } else { &legacy };
        let start_unix_ns = unix_ns();
        let begun = Instant::now();
        let output = pool.install(|| evaluate(arm, scene, ct, keys, false));
        let elapsed_ns = begun.elapsed().as_nanos() as u64;
        completed.push((*arm, output, elapsed_ns, start_unix_ns));
    }
    let observations: Vec<Value> = completed.iter().map(|(arm,out,ns,start)| json!({"arm":arm,"elapsed_ns":ns,"start_unix_ns":start,"output":observe(out,scene.expected,secret)})).collect();
    let unchanged = input_hashes == [words_hash(head.as_ref()), words_hash(legacy.as_ref())];
    let pass = unchanged && observations.iter().all(|o| o["output"]["pass"] == true);
    emit(
        file,
        json!({"record":"block","phase":phase,"n":scene.gallery.len(),"scene":scene.name,"index":index,
        "order":order,"input_sha256":input_hashes,"outputs":observations,"inputs_unchanged":unchanged,
        "all_clocks_before_decryption":true,"pass":pass}),
    );
    pass
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: binary ABS_OUTPUT_JSONL KEY_INDEX smoke|campaign"
    );
    let path = Path::new(&args[1]);
    assert!(path.is_absolute());
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let key_index: usize = args[2].parse().unwrap();
    assert!(key_index < 3);
    let mode = args[3].as_str();
    assert!(matches!(mode, "smoke" | "campaign"));
    assert_eq!(env::var("FAST_SCALING_SOURCE").unwrap(), SOURCE.trim());
    let binary = hash(&fs::read(env::current_exe().unwrap()).unwrap());
    assert_eq!(env::var("FAST_SCALING_BINARY").unwrap(), binary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let pool = ThreadPoolBuilder::new().num_threads(8).build().unwrap();
    emit(
        &mut file,
        json!({"record":"meta","schema":"fast-core-scaling.v1","source_sha256":SOURCE.trim(),"binary_sha256":binary,
        "pid":std::process::id(),"key_index":key_index,"mode":mode,"threads":8,"sizes":SIZES,
        "parameter_fingerprint":older::A44_PARAMETER_FINGERPRINT_SHA256,"native_input_profiles":true,
        "byte_identical_inputs_between_profiles":false,"same_plaintext_and_key_family":true,
        "secrets_serialized":false,"service":false,"formal_failure_bound":null}),
    );
    let begun = Instant::now();
    let client = tfhe::shortint::ClientKey::new(PARAMS);
    let ordinary = pool.install(|| tfhe::shortint::ServerKey::new(&client));
    older::validate_a44_parameter_binding(older::A44_PARAMETER_BINDING, &ordinary).unwrap();
    let bundle = pool
        .install(|| service::generate_bundle(&client, ordinary))
        .unwrap();
    let bundle_bytes = bincode::serialize(&bundle).unwrap();
    let family = hash(&bundle_bytes);
    let serialized_bytes = bundle_bytes.len();
    drop(bundle_bytes);
    let keys = EvaluationKeys::from_bundle(bundle).unwrap();
    let (secret, _, _, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(k) => k.into_raw_parts(),
        _ => panic!("Standard client required"),
    };
    emit(
        &mut file,
        json!({"record":"key","key_index":key_index,"key_family_sha256":family,
        "evaluation_bundle_serialized_bytes":serialized_bytes,"setup_ns":begun.elapsed().as_nanos() as u64,
        "ordinary_generated_from_same_client":true,"selected_pfks_base":22,"head_decomposition":[15,2],
        "secret_material_saved":false}),
    );
    let correctness_sizes: &[usize] = if mode == "smoke" {
        &[1, 3, 15, 127, 128, 129, 224]
    } else {
        SIZES
    };
    let scenes: &[&str] = if mode == "smoke" {
        &["last", "tie", "inclusive", "reject"]
    } else {
        &["last", "tie", "inclusive", "reject", "high_reject"]
    };
    let mut blocks = 0;
    for &n in correctness_sizes {
        for &name in scenes {
            let scene = Scene::new(n, name);
            emit(&mut file, json!({"record":"scene","scene":scene.record()}));
            let order: &[&str] = if n <= 128 { &["M", "A126"] } else { &["M"] };
            let pass = run_block(
                &mut file,
                &pool,
                &keys,
                &secret,
                &scene,
                "correctness",
                blocks,
                order,
            );
            blocks += 1;
            if !pass {
                emit(
                    &mut file,
                    json!({"record":"summary","blocks":blocks,"pass":false}),
                );
                std::process::exit(1);
            }
        }
    }
    // Determinism checks do not contribute to timing statistics.
    let serial_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    for n in [3, 127, 224] {
        let scene = Scene::new(n, "tie");
        let input = encrypt(&scene.query, 51, &secret);
        let serial = serial_pool.install(|| evaluate("M", &scene, &input, &keys, true));
        let parallel = pool.install(|| evaluate("M", &scene, &input, &keys, false));
        let same = serial
            .digits
            .iter()
            .zip(&parallel.digits)
            .all(|(a, b)| a.as_ref() == b.as_ref());
        let observation = observe(&serial, scene.expected, &secret);
        let parallel_observation = observe(&parallel, scene.expected, &secret);
        let pass = same && observation["pass"] == true && parallel_observation["pass"] == true;
        emit(
            &mut file,
            json!({"record":"serial_parallel","n":n,"scene":scene.record(),"input_words":input.as_ref(),
            "input_sha256":words_hash(input.as_ref()),"same_ciphertext_words":same,"serial_output":observation,
            "parallel_output":parallel_observation,"pass":pass}),
        );
        assert!(pass);
    }
    if mode == "campaign" {
        // Size order rotates by key; every size has both endpoint orders per scene.
        let mut size_order = SIZES.to_vec();
        size_order.rotate_left(key_index * 5);
        for n in size_order {
            let anchor = matches!(n, 4 | 16 | 127 | 128);
            for index in 0..if anchor { 8 } else { 6 } {
                let name = if index < 2 {
                    "last"
                } else if anchor {
                    match (index - 2) % 3 {
                        0 => "last",
                        1 => "first",
                        _ => "tie",
                    }
                } else if index % 2 == 0 {
                    "last"
                } else {
                    "first"
                };
                let scene = Scene::new(n, name);
                emit(&mut file, json!({"record":"scene","scene":scene.record()}));
                let order: &[&str] = if n > 128 {
                    &["M"]
                } else if anchor {
                    match index {
                        0 | 2 => &["M", "A126", "R3"],
                        1 | 5 => &["R3", "A126", "M"],
                        3 => &["A126", "R3", "M"],
                        4 => &["R3", "M", "A126"],
                        6 => &["M", "R3", "A126"],
                        _ => &["A126", "M", "R3"],
                    }
                } else if (index / 2 + index % 2) % 2 == 0 {
                    &["M", "A126"]
                } else {
                    &["A126", "M"]
                };
                let phase = if index < 2 { "warmup" } else { "measured" };
                let pass = run_block(
                    &mut file, &pool, &keys, &secret, &scene, phase, index, order,
                );
                blocks += 1;
                if !pass {
                    emit(
                        &mut file,
                        json!({"record":"summary","blocks":blocks,"pass":false}),
                    );
                    std::process::exit(1);
                }
            }
        }
    }
    emit(
        &mut file,
        json!({"record":"summary","key_index":key_index,"mode":mode,"blocks":blocks,"pass":true}),
    );
}
