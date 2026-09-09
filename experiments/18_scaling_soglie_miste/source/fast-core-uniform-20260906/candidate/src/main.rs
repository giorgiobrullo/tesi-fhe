use fast::service::{self, EvaluationKeys, TemplateView, ThresholdMode};
use rayon::ThreadPoolBuilder;
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
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
include!("common.rs");

#[derive(Clone)]
struct Case {
    name: String,
    n: usize,
    threshold: i64,
    winner_score: i64,
    loser_score: i64,
    first_last_tie: bool,
    serial: bool,
    parent: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (n, threshold) in [(3, 4), (127, -1), (224, -1)] {
        cases.push(Case {
            name: format!("aligned_{n}"),
            n,
            threshold,
            winner_score: -511,
            loser_score: -507,
            first_last_tie: false,
            serial: n == 3,
            parent: true,
        });
    }
    for n in [1, 3, 128, 129, 224] {
        for (label, score) in [("inclusive", 273), ("reject", 274)] {
            cases.push(Case {
                name: format!("T273_{label}_{n}"),
                n,
                threshold: 273,
                winner_score: score,
                loser_score: 277,
                first_last_tie: false,
                serial: (n == 128 && label == "inclusive") || (n == 129 && label == "reject"),
                parent: false,
            });
        }
    }
    for (name, n, threshold, winner_score, loser_score, tie, serial) in [
        ("carry_1024", 3, 87, 87, 89, false, true),
        (
            "top_clipping_counterexample",
            3,
            273,
            1111,
            1533,
            false,
            false,
        ),
        ("public_reject_min", 1, i64::MIN, -511, -507, false, true),
        ("public_reject_224", 224, -2000, -511, -507, false, false),
        ("public_accept_max", 1, i64::MAX, 273, 277, false, true),
        ("public_accept_upper", 224, 1959, 273, 277, true, false),
        (
            "public_accept_max_129",
            129,
            i64::MAX,
            273,
            277,
            false,
            false,
        ),
    ] {
        cases.push(Case {
            name: name.into(),
            n,
            threshold,
            winner_score,
            loser_score,
            first_last_tie: tie,
            serial,
            parent: false,
        });
    }
    assert_eq!(cases.len(), 20);
    cases
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
    panic!("score cannot be represented by this fixture");
}

fn mode_json(mode: ThresholdMode) -> Value {
    match mode {
        ThresholdMode::AllReject => json!({"kind":"public_reject"}),
        ThresholdMode::AllAccept => json!({"kind":"public_accept"}),
        ThresholdMode::CompareSentinel { score } => json!({"kind":"sentinel","score":score}),
    }
}

fn output(low: Lwe, high: Lwe, counts: service::Counts) -> Output {
    Output {
        digits: [low, high],
        counts: json!({"br":counts.br,"ks":counts.ks,"marginals":counts.marginals,
        "pfks":counts.pfks,"initial_samples":counts.initial_samples}),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3, "usage: binary ABS_OUTPUT_JSONL KEY_INDEX");
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
    let binary = hash(&fs::read(env::current_exe().unwrap()).unwrap());
    assert_eq!(env::var("FAST_UNIFORM_SOURCE").unwrap(), SOURCE.trim());
    assert_eq!(env::var("FAST_UNIFORM_BINARY").unwrap(), binary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let pool = ThreadPoolBuilder::new().num_threads(8).build().unwrap();
    let serial_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    emit(
        &mut file,
        json!({"record":"meta","schema":"fast-core-uniform.v1","source_sha256":SOURCE.trim(),
        "binary_sha256":binary,"pid":std::process::id(),"key_index":key_index,"threads":8,
        "cases":20,"native_profile":"51/60","parent_byte_comparison":true,
        "timing_claim":false,"service":false,"formal_failure_bound":null}),
    );
    let begun = Instant::now();
    let client = tfhe::shortint::ClientKey::new(PARAMS);
    let ordinary = pool.install(|| tfhe::shortint::ServerKey::new(&client));
    let bundle = pool
        .install(|| service::generate_bundle(&client, ordinary))
        .unwrap();
    let bytes = bincode::serialize(&bundle).unwrap();
    let family = hash(&bytes);
    let bundle_bytes = bytes.len();
    let parent_bundle: parent::service::ServerBundle = bincode::deserialize(&bytes).unwrap();
    assert_eq!(bincode::serialize(&parent_bundle).unwrap(), bytes);
    drop(bytes);
    let keys = EvaluationKeys::from_bundle(bundle).unwrap();
    let parent_keys = parent::service::EvaluationKeys::from_bundle(parent_bundle).unwrap();
    let (secret, _, _, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(k) => k.into_raw_parts(),
        _ => unreachable!(),
    };
    emit(
        &mut file,
        json!({"record":"key","key_index":key_index,"key_family_sha256":family,"bundle_bytes":bundle_bytes,
        "setup_ns":begun.elapsed().as_nanos() as u64,"same_serialized_bundle_for_parent":true,"secrets_saved":false}),
    );
    let query = vec![1i64; 512];
    let mut complete = 0;
    for case in cases() {
        let mut gallery: Vec<_> = (0..case.n)
            .map(|i| template_for_score(case.loser_score, i))
            .collect();
        gallery[case.n - 1] = template_for_score(case.winner_score, case.n - 1);
        if case.first_last_tie {
            gallery[0] = template_for_score(case.winner_score, 0);
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
        let expected = if minimum <= case.threshold {
            scores.iter().position(|s| *s == minimum).unwrap() + 1
        } else {
            0
        };
        let templates: Vec<_> = gallery
            .iter()
            .zip(&norms)
            .map(|(t, n)| TemplateView {
                template: t,
                norm2: *n,
                threshold: case.threshold,
            })
            .collect();
        let plan = service::plan(&templates).unwrap();
        let input = encrypt(&query, 51, &secret);
        let input_sha = words_hash(input.as_ref());
        let input_check = input_observation(&input, &query, 51, &secret);
        assert_eq!(input_check["pass"], true);
        emit(
            &mut file,
            json!({"record":"case_start","index":complete,"name":case.name,"n":case.n,"threshold":case.threshold,
            "query":query,"gallery":gallery,"norms":norms,"scores":scores,"expected_id":expected,
            "cauchy_domain":[plan.cauchy_domain.lower,plan.cauchy_domain.upper],
            "execution_domain":[plan.execution_domain.lower,plan.execution_domain.upper],"aligned":plan.aligned_fast_path,
            "mode":mode_json(plan.mode),"input_words":input.as_ref(),"input_sha256":input_sha,"input_observation":input_check,
            "serial_requested":case.serial,"parent_requested":case.parent}),
        );
        let begun = Instant::now();
        let (low, high, c) = pool
            .install(|| keys.evaluate(&input, &templates, plan.execution_domain))
            .unwrap();
        let elapsed = begun.elapsed().as_nanos() as u64;
        let parallel = output(low, high, c);
        let serial = if case.serial {
            let (low, high, c) = serial_pool
                .install(|| keys.evaluate_serial(&input, &templates, plan.execution_domain))
                .unwrap();
            Some(output(low, high, c))
        } else {
            None
        };
        let previous = if case.parent {
            let views: Vec<_> = gallery
                .iter()
                .zip(&norms)
                .map(|(t, n)| parent::service::TemplateView {
                    template: t,
                    norm2: *n,
                    threshold: case.threshold,
                })
                .collect();
            let previous_plan = parent::service::plan(&views).unwrap();
            assert_eq!(
                (
                    previous_plan.execution_domain.lower,
                    previous_plan.execution_domain.upper
                ),
                (plan.execution_domain.lower, plan.execution_domain.upper)
            );
            let (low, high, c) = pool
                .install(|| parent_keys.evaluate(&input, &views, previous_plan.execution_domain))
                .unwrap();
            Some(Output {
                digits: [low, high],
                counts: json!({"br":c.br,"ks":c.ks,"pfks":c.pfks,"marginals":c.marginals,"initial_samples":c.initial_samples}),
            })
        } else {
            None
        };
        // Observe only after all requested graphs returned and kept their actual roots.
        let parallel_record = observe(&parallel, expected, &secret);
        let serial_record = serial.as_ref().map(|o| observe(o, expected, &secret));
        let parent_record = previous.as_ref().map(|o| observe(o, expected, &secret));
        let equal = |other: &Output| {
            parallel
                .digits
                .iter()
                .zip(&other.digits)
                .all(|(a, b)| a.as_ref() == b.as_ref())
        };
        let serial_equal = serial.as_ref().map(equal);
        let parent_equal = previous.as_ref().map(equal);
        let unchanged = input_sha == words_hash(input.as_ref());
        let pass = parallel_record["pass"] == true
            && serial_record.as_ref().map_or(true, |o| o["pass"] == true)
            && parent_record.as_ref().map_or(true, |o| o["pass"] == true)
            && serial_equal != Some(false)
            && parent_equal != Some(false)
            && unchanged;
        emit(
            &mut file,
            json!({"record":"case","index":complete,"name":case.name,"n":case.n,"mode":mode_json(plan.mode),
            "parallel":parallel_record,"serial":serial_record,"parent":parent_record,"serial_equal":serial_equal,"parent_equal":parent_equal,
            "parallel_elapsed_ns_diagnostic_only":elapsed,"input_unchanged":unchanged,"pass":pass}),
        );
        complete += 1;
        if !pass {
            emit(
                &mut file,
                json!({"record":"summary","complete_cases":complete,"pass":false}),
            );
            std::process::exit(1);
        }
    }
    // Public rejection must retain shape/domain/mixed-threshold guards before its zero shortcut.
    let template = template_for_score(-511, 0);
    let norm = template.iter().map(|v| v * v).sum();
    let entries = [TemplateView {
        template: &template,
        norm2: norm,
        threshold: i64::MIN,
    }];
    let domain = service::plan(&entries).unwrap().execution_domain;
    let wrong_shape = Glwe::new(
        0,
        GlweSize(1),
        PolynomialSize(2048),
        CiphertextModulus::new_native(),
    );
    let wrong_domain = service::ScoreDomain {
        lower: domain.lower + 1,
        upper: domain.upper,
    };
    let input = encrypt(&query, 51, &secret);
    let mut mixed = vec![entries[0], entries[0]];
    mixed[1].threshold = 273;
    let errors = [
        keys.evaluate(&wrong_shape, &entries, domain).err(),
        keys.evaluate(&input, &entries, wrong_domain).err(),
        keys.evaluate(&input, &mixed, domain).err(),
    ];
    let guards = errors.iter().all(Option::is_some);
    emit(
        &mut file,
        json!({"record":"negative_guards","errors":errors,"additional_native_input_words":input.as_ref(),
        "additional_native_input_sha256":words_hash(input.as_ref()),"pass":guards}),
    );
    emit(
        &mut file,
        json!({"record":"summary","complete_cases":complete,"key_index":key_index,"pass":guards}),
    );
    assert!(guards);
}
