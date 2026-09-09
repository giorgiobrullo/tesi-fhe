use fast::service::{self, EvaluationKeys, TemplateView};
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
const GATE_SIZES: &[usize] = &[1, 15, 224, 225, 228, 1024];
const PILOT_SIZES: &[usize] = &[224, 225, 256, 512, 1024];
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
include!("common.rs");

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
                let base = i % 512;
                let last_offset = 4 + i / 512;
                for offset in [0, 1, 2, 3, last_offset] {
                    t[(base + offset) % 512] = 0;
                }
                t
            })
            .collect();
        assert_eq!(
            gallery
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            n
        );
        let winner = |i: usize| {
            let mut t = vec![1; 512];
            t[i % 512] = 0;
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
            _ => panic!("unknown fixture"),
        }
        let norms: Vec<i64> = gallery
            .iter()
            .map(|t| t.iter().map(|v| v * v).sum())
            .collect();
        let scores: Vec<i64> = gallery
            .iter()
            .zip(&norms)
            .map(|(t, n)| n - 2 * t.iter().sum::<i64>())
            .collect();
        let minimum = *scores.iter().min().unwrap();
        let expected = if minimum <= -1 {
            scores.iter().position(|s| *s == minimum).unwrap() + 1
        } else {
            0
        };
        Self {
            name: name.into(),
            query,
            gallery,
            norms,
            scores,
            expected,
        }
    }
    fn record(&self) -> Value {
        json!({"name":self.name,"n":self.gallery.len(),"query":self.query,"gallery":self.gallery,
        "norms":self.norms,"scores":self.scores,"threshold":-1,"expected_id":self.expected})
    }
    fn views(&self) -> Vec<TemplateView<'_>> {
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
}

fn evaluate(arm: &str, scene: &Scene, input: &Glwe, keys: &EvaluationKeys, serial: bool) -> Output {
    match arm {
        "M3" => {
            let views = scene.views();
            let plan = service::plan(&views).unwrap();
            assert!(plan.aligned_fast_path);
            let (low, middle, high, c) = if serial {
                keys.evaluate_serial(input, &views, plan.execution_domain)
            } else {
                keys.evaluate(input, &views, plan.execution_domain)
            }
            .unwrap();
            Output {
                digits: [low, middle, high],
                counts: json!({"br":c.br,"ks":c.ks,"pfks":c.pfks,"marginals":c.marginals,"initial_samples":c.initial_samples}),
            }
        }
        "A126_3" => {
            assert!(!serial);
            let views = scene.old_views();
            let plan = older::a126_wide::plan(&views).unwrap();
            assert!(plan.aligned_fast_path);
            let out = older::a126_wide::evaluate(
                older::A44_PARAMETER_BINDING,
                keys.ordinary(),
                input,
                &views,
                plan.execution_domain,
            )
            .unwrap();
            let c = out.structural_counts;
            assert_eq!(out.metrics.total_pbs_count, c.br);
            assert_eq!(out.scan_expected_counts, out.scan_observed_counts);
            Output {
                digits: [out.low_digit, out.middle_digit, out.high_digit],
                counts: json!({"br":out.metrics.total_pbs_count,"ks":c.ks,
                "pfks":0,"marginals":c.marginals,"initial_samples":c.initial_samples,
                "ks_marginals_evidence":"source-derived; runtime BR and scan checked",
                "scan_expected":format!("{:?}",out.scan_expected_counts),"scan_observed":format!("{:?}",out.scan_observed_counts)}),
            }
        }
        _ => panic!("unknown arm"),
    }
}

fn block(
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
    let hashes = [words_hash(head.as_ref()), words_hash(legacy.as_ref())];
    let observations = [
        input_observation(&head, &scene.query, 51, secret),
        input_observation(&legacy, &scene.query, 52, secret),
    ];
    assert!(observations.iter().all(|v| v["pass"] == true));
    emit(
        file,
        json!({"record":"block_start","phase":phase,"index":index,"scene":scene.record(),"order":order,
        "inputs":[{"profile":"native51/60","words":head.as_ref(),"sha256":hashes[0],"observation":observations[0]},
        {"profile":"native52/60","words":legacy.as_ref(),"sha256":hashes[1],"observation":observations[1]}]}),
    );
    let mut completed = Vec::new();
    for arm in order {
        let input = if *arm == "M3" { &head } else { &legacy };
        let start = unix_ns();
        let begun = Instant::now();
        let output = pool.install(|| evaluate(arm, scene, input, keys, false));
        let elapsed = begun.elapsed().as_nanos() as u64;
        completed.push((*arm, output, start, elapsed));
    }
    let outputs: Vec<_> = completed
        .iter()
        .map(|(arm, out, start, elapsed)| {
            json!({"arm":arm,"start_unix_ns":start,"elapsed_ns":elapsed,
        "output":observe(out,scene.expected,secret)})
        })
        .collect();
    let unchanged = hashes == [words_hash(head.as_ref()), words_hash(legacy.as_ref())];
    let pass = unchanged && outputs.iter().all(|v| v["output"]["pass"] == true);
    emit(
        file,
        json!({"record":"block","phase":phase,"index":index,"n":scene.gallery.len(),"scene":scene.name,"order":order,
        "input_sha256":hashes,"outputs":outputs,"inputs_unchanged":unchanged,"all_clocks_before_observations":true,"pass":pass}),
    );
    pass
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 4, "usage: binary ABS_RAW KEY_INDEX gate|pilot");
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
    assert!(matches!(mode, "gate" | "pilot"));
    if mode == "pilot" {
        assert_eq!(key_index, 0);
    }
    let binary = hash(&fs::read(env::current_exe().unwrap()).unwrap());
    assert_eq!(env::var("FAST_WIDE_SOURCE").unwrap(), SOURCE.trim());
    assert_eq!(env::var("FAST_WIDE_BINARY").unwrap(), binary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let pool = ThreadPoolBuilder::new().num_threads(8).build().unwrap();
    emit(
        &mut file,
        json!({"record":"meta","schema":"fast-core-wide-id.v1","source_sha256":SOURCE.trim(),"binary_sha256":binary,
        "pid":std::process::id(),"key_index":key_index,"mode":mode,"threads":8,"id_base":15,"id_digits":3,
        "gate_sizes":GATE_SIZES,"pilot_sizes":PILOT_SIZES,"control":"explicitly adapted A126 three-digit scan; frozen two-digit control unchanged",
        "formal_failure_bound":null,"service":false}),
    );
    let begun = Instant::now();
    let client = tfhe::shortint::ClientKey::new(PARAMS);
    let ordinary = pool.install(|| tfhe::shortint::ServerKey::new(&client));
    let bundle = pool
        .install(|| service::generate_bundle(&client, ordinary))
        .unwrap();
    let bytes = bincode::serialize(&bundle).unwrap();
    let family = hash(&bytes);
    let size = bytes.len();
    drop(bytes);
    let keys = EvaluationKeys::from_bundle(bundle).unwrap();
    let (secret, _, _, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(k) => k.into_raw_parts(),
        _ => unreachable!(),
    };
    emit(
        &mut file,
        json!({"record":"key","key_index":key_index,"key_family_sha256":family,"bundle_bytes":size,
        "setup_ns":begun.elapsed().as_nanos() as u64,"same_actual_key_family_for_both_arms":true,"secrets_saved":false}),
    );
    let mut blocks = 0;
    if mode == "gate" {
        for n in GATE_SIZES {
            for name in ["last", "tie", "inclusive", "reject"] {
                let scene = Scene::new(*n, name);
                let pass = block(
                    &mut file,
                    &pool,
                    &keys,
                    &secret,
                    &scene,
                    "correctness",
                    blocks,
                    &["M3", "A126_3"],
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
        let scene = Scene::new(225, "tie");
        let input = encrypt(&scene.query, 51, &secret);
        let input_sha = words_hash(input.as_ref());
        let input_check = input_observation(&input, &scene.query, 51, &secret);
        assert_eq!(input_check["pass"], true);
        let serial_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let serial = serial_pool.install(|| evaluate("M3", &scene, &input, &keys, true));
        let parallel = pool.install(|| evaluate("M3", &scene, &input, &keys, false));
        let same = serial
            .digits
            .iter()
            .zip(&parallel.digits)
            .all(|(a, b)| a.as_ref() == b.as_ref());
        let serial_result = observe(&serial, scene.expected, &secret);
        let parallel_result = observe(&parallel, scene.expected, &secret);
        let input_unchanged = input_sha == words_hash(input.as_ref());
        let pass = same
            && input_unchanged
            && serial_result["pass"] == true
            && parallel_result["pass"] == true;
        emit(
            &mut file,
            json!({"record":"serial_parallel","scene":scene.record(),"input_words":input.as_ref(),"input_sha256":input_sha,
            "input_observation":input_check,"input_unchanged":input_unchanged,
            "serial":serial_result,"parallel":parallel_result,"same_words":same,"pass":pass}),
        );
        assert!(pass);
    } else {
        for n in PILOT_SIZES {
            for index in 0..6 {
                let name = if index < 2 || index % 2 == 0 {
                    "last"
                } else {
                    "first"
                };
                let order: &[&str] = if (index / 2 + index % 2) % 2 == 0 {
                    &["M3", "A126_3"]
                } else {
                    &["A126_3", "M3"]
                };
                let scene = Scene::new(*n, name);
                let phase = if index < 2 { "warmup" } else { "measured" };
                let pass = block(
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
        json!({"record":"summary","mode":mode,"key_index":key_index,"blocks":blocks,"pass":true}),
    );
}
