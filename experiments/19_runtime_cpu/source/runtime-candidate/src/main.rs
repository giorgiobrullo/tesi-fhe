use fast::service::{self, EvaluationKeys, ExecutionMode, TemplateView, ThresholdMode};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, BufRead, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;

const SOURCE: &str = include_str!("../SOURCE_DIGEST.txt");
const SCHEMA: &str = "fast-compiler-comparison.v1";
type Glwe = GlweCiphertextOwned<u64>;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn words_hash(words: &[u64]) -> String {
    let mut digest = Sha256::new();
    for word in words {
        digest.update(word.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn emit(mut value: Value) {
    value["observed_unix_ns"] = json!(unix_ns());
    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, &value).unwrap();
    out.write_all(b"\n").unwrap();
    out.flush().unwrap();
}

fn check_directory(path: &Path) {
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

fn read_private(path: &Path) -> Vec<u8> {
    check_directory(path.parent().unwrap());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    fs::read(path).unwrap()
}

fn write_private(path: &Path, bytes: &[u8]) {
    check_directory(path.parent().unwrap());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[derive(Serialize, Deserialize)]
struct Scene {
    name: String,
    category: String,
    timed: bool,
    query: Vec<i64>,
    gallery: Vec<Vec<i64>>,
    norms: Vec<i64>,
    scores: Vec<i64>,
    thresholds: Vec<i64>,
    expected_id: usize,
    plan: Value,
}

fn template_for_score(score: i64, rotation: usize) -> Vec<i64> {
    for norm in (0..=511).rev() {
        let numerator = score + norm;
        if numerator >= 0 && numerator % 4 == 0 && numerator / 4 <= norm {
            let negatives = (numerator / 4) as usize;
            let mut template = vec![0; 512];
            for i in 0..norm as usize {
                template[(i + rotation) % 512] = if i < negatives { -1 } else { 1 };
            }
            return template;
        }
    }
    panic!("unrepresentable synthetic score {score}");
}

fn mode_json(mode: ExecutionMode) -> Value {
    match mode {
        ExecutionMode::MixedWinnerThreshold => json!({"kind":"mixed"}),
        ExecutionMode::Uniform(ThresholdMode::AllReject) => json!({"kind":"public_reject"}),
        ExecutionMode::Uniform(ThresholdMode::AllAccept) => json!({"kind":"public_accept"}),
        ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score }) => {
            json!({"kind":"sentinel","score":score})
        }
    }
}

fn counts_json(counts: service::Counts) -> Value {
    json!({"br":counts.br,"ks":counts.ks,"pfks":counts.pfks,
        "marginals":counts.marginals,"initial_samples":counts.initial_samples})
}

impl Scene {
    fn views(&self) -> Vec<TemplateView<'_>> {
        self.gallery
            .iter()
            .zip(&self.norms)
            .zip(&self.thresholds)
            .map(|((template, norm), threshold)| TemplateView {
                template,
                norm2: *norm,
                threshold: *threshold,
            })
            .collect()
    }

    fn new(
        name: &str,
        category: &str,
        timed: bool,
        scores: Vec<i64>,
        thresholds: Vec<i64>,
    ) -> Self {
        assert_eq!(scores.len(), thresholds.len());
        let query = vec![1; 512];
        let gallery: Vec<_> = scores
            .iter()
            .enumerate()
            .map(|(i, score)| template_for_score(*score, i))
            .collect();
        let norms: Vec<i64> = gallery
            .iter()
            .map(|row| row.iter().map(|v| v * v).sum())
            .collect();
        let recomputed: Vec<i64> = gallery
            .iter()
            .zip(&norms)
            .map(|(row, norm)| norm - 2 * row.iter().zip(&query).map(|(a, b)| a * b).sum::<i64>())
            .collect();
        assert_eq!(scores, recomputed);
        let minimum = *scores.iter().min().unwrap();
        let winner = scores.iter().position(|score| *score == minimum).unwrap();
        let expected_id = if minimum <= thresholds[winner] {
            winner + 1
        } else {
            0
        };
        let mut scene = Self {
            name: name.into(),
            category: category.into(),
            timed,
            query,
            gallery,
            norms,
            scores,
            thresholds,
            expected_id,
            plan: Value::Null,
        };
        let views = scene.views();
        let plan = service::plan(&views).unwrap();
        match category {
            "aligned" => assert!(plan.aligned_fast_path),
            "general" => {
                assert!(!plan.aligned_fast_path && matches!(plan.mode, ExecutionMode::Uniform(_)))
            }
            "mixed" => assert_eq!(plan.mode, ExecutionMode::MixedWinnerThreshold),
            _ => panic!("unknown category"),
        }
        assert!(!matches!(
            plan.mode,
            ExecutionMode::Uniform(ThresholdMode::AllAccept | ThresholdMode::AllReject)
        ));
        scene.plan = json!({
            "cauchy_domain":[plan.cauchy_domain.lower,plan.cauchy_domain.upper],
            "execution_domain":[plan.execution_domain.lower,plan.execution_domain.upper],
            "aligned":plan.aligned_fast_path,"mode":mode_json(plan.mode),
            "counts":counts_json(service::operation_counts(scene.gallery.len(),plan.mode).unwrap()),
        });
        scene
    }

    fn last(
        n: usize,
        category: &str,
        timed: bool,
        winner: i64,
        loser: i64,
        threshold: i64,
    ) -> Self {
        let mut scores = vec![loser; n];
        scores[n - 1] = winner;
        let mut thresholds = vec![threshold; n];
        if category == "mixed" {
            thresholds.fill(threshold - 1);
            thresholds[n - 1] = threshold;
        }
        Self::new(
            &format!("{category}_last_{n}_{winner}"),
            category,
            timed,
            scores,
            thresholds,
        )
    }
}

fn scenes() -> Vec<Scene> {
    let mut result = vec![
        Scene::last(3, "aligned", false, -1, 3, -1),
        Scene::last(3, "aligned", false, 0, 3, -1),
        Scene::last(3, "general", false, 273, 277, 273),
        Scene::last(3, "general", false, 274, 277, 273),
        Scene::new(
            "mixed_first_tie_accept",
            "mixed",
            false,
            vec![273, 277, 273],
            vec![273, 272, 272],
        ),
        Scene::new(
            "mixed_first_tie_reject",
            "mixed",
            false,
            vec![273, 277, 273],
            vec![272, i64::MAX, 273],
        ),
        Scene::new(
            "mixed_nearest_reject_farther_accept",
            "mixed",
            false,
            vec![277, 277, 273],
            vec![i64::MAX, i64::MAX, 272],
        ),
        Scene::last(224, "general", false, 273, 277, 273),
        Scene::last(225, "mixed", false, 273, 277, 273),
    ];
    for n in [64, 128] {
        result.push(Scene::last(n, "aligned", true, -1, 3, -1));
        result.push(Scene::last(n, "general", true, 273, 277, 273));
        result.push(Scene::last(n, "mixed", true, 273, 277, 273));
    }
    result
}

fn plaintext(query: &[i64]) -> Vec<u64> {
    let mut result = vec![0; 2048];
    for (i, value) in query.iter().enumerate() {
        result[i] = (*value as u64).wrapping_mul(1 << 51);
        result[1024 + i] = (value.rem_euclid(16) as u64) << 60;
    }
    result
}

fn encrypt(query: &[i64], secret: &GlweSecretKeyOwned<u64>) -> Glwe {
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
        &PlaintextList::from_container(plaintext(query)),
        PARAMS.glwe_noise_distribution,
        &mut generator,
    );
    assert!(ct.get_mask().as_ref().iter().any(|value| *value != 0));
    ct
}

fn input_error(ct: &Glwe, query: &[i64], secret: &GlweSecretKeyOwned<u64>) -> u64 {
    let mut decrypted = PlaintextList::new(0, PlaintextCount(2048));
    decrypt_glwe_ciphertext(secret, ct, &mut decrypted);
    let error = decrypted
        .as_ref()
        .iter()
        .zip(plaintext(query))
        .map(|(value, expected)| (value.wrapping_sub(expected) as i64 as i128).abs())
        .max()
        .unwrap();
    assert!(error < (1i128 << 50));
    error as u64
}

#[derive(Serialize, Deserialize)]
struct Input {
    scene: usize,
    repetition: usize,
    phase: String,
    file: String,
    file_sha256: String,
    words_sha256: String,
    words: Vec<u64>,
    input_max_error_torus: u64,
}

#[derive(Serialize, Deserialize)]
struct Fixture {
    schema: String,
    source_sha256: String,
    creator_binary_sha256: String,
    key_index: usize,
    threads: usize,
    bundle_sha256: String,
    bundle_bytes: usize,
    secret_sha256: String,
    scenes: Vec<Scene>,
    inputs: Vec<Input>,
}

fn prepare(directory: &Path, threads: usize, key_index: usize, binary: &str) {
    check_directory(directory.parent().unwrap());
    fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    let begun = Instant::now();
    let client = tfhe::shortint::ClientKey::new(PARAMS);
    let ordinary = pool.install(|| tfhe::shortint::ServerKey::new(&client));
    let bundle = pool
        .install(|| service::generate_bundle(&client, ordinary))
        .unwrap();
    let bytes = bincode::serialize(&bundle).unwrap();
    service::validate_serialized_bundle_size(bytes.len()).unwrap();
    let family = hash(&bytes);
    let bundle_bytes = bytes.len();
    write_private(&directory.join("bundle.bin"), &bytes);
    drop(bytes);
    drop(bundle);
    let (secret, _, _, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => panic!("Standard client required"),
    };
    let secret_bytes = bincode::serialize(&secret).unwrap();
    write_private(&directory.join("secret.bin"), &secret_bytes);
    let mut fixture = Fixture {
        schema: SCHEMA.into(),
        source_sha256: SOURCE.trim().into(),
        creator_binary_sha256: binary.into(),
        key_index,
        threads,
        bundle_sha256: family,
        bundle_bytes,
        secret_sha256: hash(&secret_bytes),
        scenes: scenes(),
        inputs: Vec::new(),
    };
    for (scene_index, scene) in fixture.scenes.iter().enumerate() {
        for repetition in 0..if scene.timed { 6 } else { 1 } {
            let phase = if !scene.timed {
                "correctness"
            } else if repetition < 2 {
                "warmup"
            } else {
                "measured"
            };
            let ct = encrypt(&scene.query, &secret);
            let bytes = bincode::serialize(&ct).unwrap();
            let file = format!("input-{:03}.bin", fixture.inputs.len());
            write_private(&directory.join(&file), &bytes);
            fixture.inputs.push(Input {
                scene: scene_index,
                repetition,
                phase: phase.into(),
                file,
                file_sha256: hash(&bytes),
                words_sha256: words_hash(ct.as_ref()),
                words: ct.as_ref().to_vec(),
                input_max_error_torus: input_error(&ct, &scene.query, &secret),
            });
        }
    }
    assert_eq!(fixture.scenes.len(), 15);
    assert_eq!(fixture.inputs.len(), 45);
    let bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    write_private(&directory.join("fixture.json"), &bytes);
    emit(
        json!({"record":"prepared","schema":SCHEMA,"source_sha256":SOURCE.trim(),
        "binary_sha256":binary,"key_index":key_index,"threads":threads,
        "fixture_sha256":hash(&bytes),"bundle_sha256":fixture.bundle_sha256,
        "bundle_bytes":fixture.bundle_bytes,"scenes":15,"inputs":45,
        "setup_ns":begun.elapsed().as_nanos() as u64,"private_directory":directory}),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    command: String,
    input: Option<usize>,
    token: Option<String>,
}

fn worker(directory: &Path, threads: usize, arm: &str, binary: &str) {
    let fixture_bytes = read_private(&directory.join("fixture.json"));
    assert_eq!(
        hash(&fixture_bytes),
        env::var("COMPILER_FIXTURE_SHA256").unwrap()
    );
    let fixture: Fixture = serde_json::from_slice(&fixture_bytes).unwrap();
    assert_eq!(fixture.schema, SCHEMA);
    assert_eq!(fixture.source_sha256, SOURCE.trim());
    assert_eq!(fixture.threads, threads);
    let bundle_bytes = read_private(&directory.join("bundle.bin"));
    assert_eq!(bundle_bytes.len(), fixture.bundle_bytes);
    assert_eq!(hash(&bundle_bytes), fixture.bundle_sha256);
    let bundle = bincode::deserialize(&bundle_bytes).unwrap();
    drop(bundle_bytes);
    let keys = EvaluationKeys::from_bundle(bundle).unwrap();
    let secret_bytes = read_private(&directory.join("secret.bin"));
    assert_eq!(hash(&secret_bytes), fixture.secret_sha256);
    let secret: GlweSecretKeyOwned<u64> = bincode::deserialize(&secret_bytes).unwrap();
    let mut inputs: Vec<Glwe> = Vec::new();
    for input in &fixture.inputs {
        assert_eq!(Path::new(&input.file).components().count(), 1);
        let bytes = read_private(&directory.join(&input.file));
        assert_eq!(hash(&bytes), input.file_sha256);
        let ct: Glwe = bincode::deserialize(&bytes).unwrap();
        assert_eq!(words_hash(ct.as_ref()), input.words_sha256);
        assert_eq!(ct.as_ref(), input.words.as_slice());
        assert_eq!(
            input_error(&ct, &fixture.scenes[input.scene].query, &secret),
            input.input_max_error_torus
        );
        inputs.push(ct);
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    emit(
        json!({"record":"ready","schema":SCHEMA,"arm":arm,"pid":std::process::id(),
        "runtime_features":fast::runtime_features(),
        "binary_sha256":binary,"source_sha256":SOURCE.trim(),"threads":threads,
        "key_index":fixture.key_index,"fixture_sha256":hash(&fixture_bytes),
        "bundle_sha256":fixture.bundle_sha256,"inputs":inputs.len(),
        "input_profile":"native51/60","id_base":15,"id_digits":3}),
    );
    for line in io::stdin().lock().lines() {
        let command: Command = serde_json::from_str(&line.unwrap()).unwrap();
        if command.command == "stop" {
            assert!(command.input.is_none());
            emit(json!({"record":"stopped","arm":arm}));
            return;
        }
        assert_eq!(command.command, "evaluate");
        let input_index = command.input.unwrap();
        let description = &fixture.inputs[input_index];
        let scene = &fixture.scenes[description.scene];
        let input = &inputs[input_index];
        let views = scene.views();
        let plan = service::plan(&views).unwrap();
        let before = words_hash(input.as_ref());
        let start_unix_ns = unix_ns();
        let begun = Instant::now();
        let (low, middle, high, counts) = pool
            .install(|| keys.evaluate(input, &views, plan.execution_domain))
            .unwrap();
        let elapsed_ns = begun.elapsed().as_nanos() as u64;
        let end_unix_ns = unix_ns();
        // Observe only after the full encrypted score-to-three-digit endpoint returned.
        let roots = [low, middle, high];
        let big = secret.as_lwe_secret_key();
        let phases: Vec<_> = roots
            .iter()
            .map(|ct| decrypt_lwe_ciphertext(&big, ct).0)
            .collect();
        let digits: Vec<_> = phases
            .iter()
            .map(|phase| phase.wrapping_add(1 << 58) >> 59)
            .collect();
        let expected_digits = [
            scene.expected_id % 15,
            (scene.expected_id / 15) % 15,
            scene.expected_id / 225,
        ];
        let errors: Vec<i64> = phases
            .iter()
            .zip(expected_digits)
            .map(|(phase, digit)| phase.wrapping_sub((digit as u64) << 59) as i64)
            .collect();
        let id = digits[0] + 15 * digits[1] + 225 * digits[2];
        let unchanged = before == words_hash(input.as_ref());
        let counts = counts_json(counts);
        let pass = unchanged
            && before == description.words_sha256
            && id == scene.expected_id as u64
            && digits.iter().all(|digit| *digit < 15)
            && counts == scene.plan["counts"];
        emit(
            json!({"record":"evaluation","schema":SCHEMA,"arm":arm,"token":command.token,
            "runtime_features":fast::runtime_features(),
            "key_index":fixture.key_index,"scene":description.scene,"name":scene.name,
            "n":scene.gallery.len(),"input":input_index,"phase":description.phase,
            "repetition":description.repetition,"input_sha256":before,"input_unchanged":unchanged,
            "bundle_sha256":fixture.bundle_sha256,"binary_sha256":binary,"source_sha256":SOURCE.trim(),
            "threads":threads,"start_unix_ns":start_unix_ns,"end_unix_ns":end_unix_ns,"elapsed_ns":elapsed_ns,
            "expected_id":scene.expected_id,"id":id,"digits":digits,"phases":phases,
            "errors_torus":errors,"counts":counts,
            "ciphertext_words":roots.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
            "ciphertext_sha256":roots.iter().map(|ct|words_hash(ct.as_ref())).collect::<Vec<_>>(),
            "timing_scope":"keys.evaluate including encrypted scores and tournament; excluding input load, public scene views/plan and decryption",
            "pass":pass}),
        );
        if !pass {
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "usage: binary prepare|worker ABS_DIRECTORY THREADS KEY_INDEX|ARM"
    );
    let threads: usize = args[3].parse().unwrap();
    assert!((1..=64).contains(&threads));
    assert!(
        SOURCE.trim().len() == 64 && SOURCE.trim().bytes().all(|byte| byte.is_ascii_hexdigit()),
        "freeze the runtime candidate before compiling a worker"
    );
    assert_eq!(env::var("COMPILER_SOURCE_SHA256").unwrap(), SOURCE.trim());
    let binary = hash(&fs::read(env::current_exe().unwrap()).unwrap());
    assert_eq!(env::var("COMPILER_BINARY_SHA256").unwrap(), binary);
    let directory = Path::new(&args[2]);
    match args[1].as_str() {
        "prepare" => {
            let key_index: usize = args[4].parse().unwrap();
            assert!(key_index < 3);
            prepare(directory, threads, key_index, &binary);
        }
        "worker" => {
            assert!(["baseline", "native_only", "thin_single_unit"].contains(&args[4].as_str()));
            worker(directory, threads, &args[4], &binary);
        }
        _ => panic!("unknown command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_semantics_and_dispatch_cover_contracts() {
        let all = scenes();
        assert_eq!(
            all[..9].iter().map(|s| s.expected_id).collect::<Vec<_>>(),
            [3, 0, 3, 0, 1, 0, 0, 224, 225]
        );
        assert_eq!(all.iter().filter(|scene| scene.timed).count(), 6);
        assert!(all
            .iter()
            .all(|scene| scene.norms.iter().all(|norm| *norm <= 511)));
    }

    #[test]
    fn native_query_layout_keeps_both_scales() {
        let words = plaintext(&[-1, 0, 1]);
        assert_eq!(&words[..3], &[0u64.wrapping_sub(1 << 51), 0, 1 << 51]);
        assert_eq!(&words[1024..1027], &[15 << 60, 0, 1 << 60]);
        assert!(words[3..1024].iter().all(|value| *value == 0));
    }
}
