//! Separate diagnostic client: secrets are used only outside the server calls.
use fast::service::{self, EvaluationKeys};
use fast::shared_normalizers::{Mode, Pair, PairTrace, Switched};
use rayon::{prelude::*, ThreadPoolBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;

const SOURCE: &str = include_str!("../../SOURCE_DIGEST.txt");
const DELTA: u64 = 1 << 58;
const MODES: [Mode; 4] = [
    Mode::Scalar,
    Mode::ResidualOnly,
    Mode::CarryOnly,
    Mode::Both,
];
type Lwe = LweCiphertextOwned<u64>;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn word_hash(words: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}
fn emit(value: Value) {
    println!("{}", serde_json::to_string(&value).unwrap());
    io::stdout().flush().unwrap();
}
fn save_private(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn load_private(path: &Path) -> Vec<u8> {
    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
    fs::read(path).unwrap()
}
fn ms(word: u64) -> usize {
    (word.wrapping_add(1 << 51) >> 52) as usize
}
fn switched_degrees(ciphertext: &Switched) -> Vec<u64> {
    ciphertext
        .mask()
        .map(|degree| degree as u64)
        .chain(std::iter::once(ciphertext.body() as u64))
        .collect()
}
fn address(ciphertext: &Switched, secret: &LweSecretKeyOwned<u64>) -> usize {
    let dot = ciphertext
        .mask()
        .zip(secret.as_ref())
        .fold(0u64, |sum, (degree, bit)| {
            sum.wrapping_add(degree as u64 * bit)
        });
    (ciphertext.body() as u64).wrapping_sub(dot) as usize % 4096
}

fn table_value(values: &[u64], degree: usize) -> u64 {
    let shifted = (degree + 32) % 4096;
    let value = values[(shifted % 2048) / 64];
    if shifted < 2048 {
        value
    } else {
        value.wrapping_neg()
    }
}
fn pair_values(pair: Pair, lane: usize) -> Vec<u64> {
    (0..32u64)
        .map(|r| match (pair, lane) {
            (_, 0) => (r % 16) << 59,
            (Pair::Residual, 1) => (r / 16) << 58,
            (Pair::Carry, 1) => (r / 16) << 59,
            _ => unreachable!(),
        })
        .collect()
}

fn ideal(score: u64) -> ([u64; 2], [[u64; 2]; 2], [u64; 3]) {
    let mut state = score << 51;
    let mut heads = Vec::new();
    for (t, multiplier) in [(4, 8), (5, 16)] {
        let offset = ((1u64 << t) - 1) * (DELTA / 2);
        let values: Vec<_> = (0..32u64)
            .map(|r| (r >> (5 - t)).wrapping_mul(DELTA).wrapping_sub(offset))
            .collect();
        let output = table_value(&values, ms(state.wrapping_sub(DELTA))).wrapping_add(offset);
        state = state
            .wrapping_sub(output.wrapping_mul(1 << (5 - t)))
            .wrapping_mul(multiplier);
        heads.push(output);
    }
    let residual =
        std::array::from_fn(|lane| table_value(&pair_values(Pair::Residual, lane), ms(state)));
    let carry_input = heads[1].wrapping_add(residual[1]);
    let carry =
        std::array::from_fn(|lane| table_value(&pair_values(Pair::Carry, lane), ms(carry_input)));
    let outputs = [
        residual[0],
        carry[0],
        heads[0].wrapping_mul(2).wrapping_add(carry[1]),
    ];
    assert_eq!(
        outputs,
        [
            (score % 16) << 59,
            ((score / 16) % 16) << 59,
            (score / 256) << 59
        ]
    );
    ([state, carry_input], [residual, carry], outputs)
}

fn encrypt_score(score: u64, secret: &GlweSecretKeyOwned<u64>) -> Lwe {
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut output = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
    encrypt_lwe_ciphertext(
        &secret.as_lwe_secret_key(),
        &mut output,
        Plaintext(score << 51),
        PARAMS.glwe_noise_distribution,
        &mut generator,
    );
    assert!(output.get_mask().as_ref().iter().any(|word| *word != 0));
    output
}

fn pair_observation(
    trace: &PairTrace,
    ideal_input: u64,
    ideal_outputs: [u64; 2],
    big: &GlweSecretKeyOwned<u64>,
    small: &LweSecretKeyOwned<u64>,
) -> (Value, bool) {
    let degree = address(&trace.switched, small);
    let (switched_source, body_correction, switched_log) = trace.switched.clone().into_raw_parts();
    assert_eq!(switched_log.0, 12);
    let phases: Vec<_> = trace
        .outputs
        .iter()
        .map(|ct| decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), ct).0)
        .collect();
    let intended: Vec<_> = (0..2)
        .map(|lane| table_value(&pair_values(trace.pair, lane), degree))
        .collect();
    let errors: Vec<_> = phases
        .iter()
        .zip(ideal_outputs)
        .map(|(phase, expected)| phase.wrapping_sub(expected) as i64)
        .collect();
    let raw_errors: Vec<_> = phases
        .iter()
        .zip(&intended)
        .map(|(phase, expected)| phase.wrapping_sub(*expected) as i64)
        .collect();
    let units = if trace.pair == Pair::Residual {
        [1u64 << 59, 1u64 << 58]
    } else {
        [1u64 << 59; 2]
    };
    let mut pass = intended == ideal_outputs
        && errors
            .iter()
            .zip(units)
            .all(|(error, unit)| error.unsigned_abs() < unit / 2);
    let common_record = trace.common.as_ref().map(|common| {
        let mut phase = PlaintextList::new(0, PlaintextCount(2048));
        decrypt_glwe_ciphertext(big, common, &mut phase);
        let carry_values = pair_values(trace.pair, 1);
        let errors: Vec<_> = phase.as_ref().iter().enumerate().map(|(index, phase)| {
            let intended = table_value(&carry_values, (index + degree) % 4096);
            phase.wrapping_sub(intended) as i64
        }).collect();
        let at = |exponent: usize| -> u64 {
            if exponent == 0 { errors[0] as u64 } else { (errors[2048 - exponent] as u64).wrapping_neg() }
        };
        let multiplier = if trace.pair == Pair::Residual { 2u64 } else { 1u64 };
        let low = (0..16).fold(0u64, |sum, j| {
            let coefficient = if j == 15 { (-15i64) as u64 } else { 1 };
            sum.wrapping_add(at(64 + 64*j).wrapping_mul(coefficient).wrapping_mul(multiplier))
        });
        let carry = errors[0] as u64;
        let closure = [low as i64, carry as i64] == raw_errors.as_slice();
        pass &= closure;
        let max_error = errors.iter().map(|error| error.unsigned_abs()).max().unwrap();
        json!({"words":common.as_ref(),"words_sha256":word_hash(common.as_ref()),
            "phase_words":phase.as_ref(),"error_words_signed":errors,
            "max_coefficient_error_torus":max_error,
            "l1_error_bounds_decimal":[(u128::from(max_error) * 30 * u128::from(multiplier)).to_string(),
                                      u128::from(max_error).to_string()],
            "exact_correlated_error_closure":closure})
    });
    (
        json!({"pair":trace.pair.name(),"shared":trace.shared,
        "input_words":trace.input.as_ref(),"switched_degrees":switched_degrees(&trace.switched),
        "switched_source_words":switched_source.as_ref(),"body_correction_before_ms":body_correction,
        "switched_log_modulus":switched_log.0,
        "switched_source_phase":decrypt_lwe_ciphertext(small, &switched_source).0,
        "input_phase":decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), &trace.input).0,
        "input_error_torus":decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), &trace.input).0.wrapping_sub(ideal_input) as i64,
        "actual_fine_address":degree,"ideal_fine_address":ms(ideal_input),
        "ideal_input_phase":ideal_input,"intended_at_address":intended,"ideal_outputs":ideal_outputs,
        "phases":phases,"errors_torus":errors,"errors_at_address_torus":raw_errors,
        "ciphertext_words":trace.outputs.iter().map(|ct| ct.as_ref()).collect::<Vec<_>>(),
        "common":common_record,"pass":pass}),
        pass,
    )
}

fn prepare(directory: &Path, threads: usize, binary: &str) {
    fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    let client = tfhe::shortint::ClientKey::new(PARAMS);
    let ordinary = pool.install(|| tfhe::shortint::ServerKey::new(&client));
    let bundle = pool
        .install(|| service::generate_bundle(&client, ordinary))
        .unwrap();
    let bundle = bincode::serialize(&bundle).unwrap();
    service::validate_serialized_bundle_size(bundle.len()).unwrap();
    let (big, small, _, _) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => unreachable!(),
    };
    let big = bincode::serialize(&big).unwrap();
    let small = bincode::serialize(&small).unwrap();
    let manifest = json!({"schema":"shared-normalizer-keys.v1","source_sha256":SOURCE.trim(),
        "creator_binary_sha256":binary,"threads":threads,"bundle_sha256":hash(&bundle),
        "big_secret_sha256":hash(&big),"small_secret_sha256":hash(&small),
        "input_profile":"fresh big-LWE Delta51 with A44 GLWE-noise distribution; not the packed score producer"});
    save_private(&directory.join("bundle.bin"), &bundle);
    save_private(&directory.join("big-secret.bin"), &big);
    save_private(&directory.join("small-secret.bin"), &small);
    let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    save_private(&directory.join("manifest.json"), &bytes);
    emit(json!({"record":"prepared","manifest":manifest,"manifest_sha256":hash(&bytes)}));
}

fn run(directory: &Path, threads: usize, stage: &str, binary: &str) {
    let bytes = load_private(&directory.join("manifest.json"));
    assert_eq!(
        hash(&bytes),
        env::var("NORMALIZER_GATE_MANIFEST_SHA256").unwrap()
    );
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest["source_sha256"], SOURCE.trim());
    let bundle = load_private(&directory.join("bundle.bin"));
    assert_eq!(hash(&bundle), manifest["bundle_sha256"]);
    let keys = EvaluationKeys::from_bundle(bincode::deserialize(&bundle).unwrap()).unwrap();
    let big = load_private(&directory.join("big-secret.bin"));
    assert_eq!(hash(&big), manifest["big_secret_sha256"]);
    let big: GlweSecretKeyOwned<u64> = bincode::deserialize(&big).unwrap();
    let small = load_private(&directory.join("small-secret.bin"));
    assert_eq!(hash(&small), manifest["small_secret_sha256"]);
    let small: LweSecretKeyOwned<u64> = bincode::deserialize(&small).unwrap();
    let scores: Vec<u64> = match stage {
        "smoke" => vec![
            0, 1, 15, 15, 16, 31, 32, 255, 255, 256, 511, 512, 1023, 1023, 1024, 2047, 2048, 2622,
            2623, 2623, 2624, 4094, 4095, 4095,
        ],
        "sweep" => (0..4096).collect(),
        _ => panic!("stage must be smoke or sweep"),
    };
    // Adjacent smoke pairs include independently encrypted ties. The sweep's
    // explicit32left indices straddle carries and retain nearby same-cell controls.
    let consumer_indices: Vec<usize> = if stage == "smoke" {
        (0..scores.len()).collect()
    } else {
        vec![
            0, 14, 15, 16, 30, 31, 32, 62, 63, 64, 126, 127, 128, 254, 255, 256, 510, 511, 512,
            1022, 1023, 1024, 2046, 2047, 2048, 2621, 2622, 2623, 2624, 4093, 4094, 4095,
        ]
    };
    let inputs: Vec<_> = scores
        .iter()
        .map(|score| encrypt_score(*score, &big))
        .collect();
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    emit(
        json!({"record":"start","stage":stage,"scores":scores,"modes":MODES.map(Mode::name),
        "source_sha256":SOURCE.trim(),"binary_sha256":binary,"threads":threads,
        "consumer_indices":consumer_indices,"key_manifest_sha256":hash(&bytes),"bundle_sha256":manifest["bundle_sha256"],
        "comparison_kind":"same fresh nontrivial input words/key within each mode group; primitive diagnostics, not timings"}),
    );
    let mut ingress_count = 0;
    let mut consumer_count = 0;
    let mut scalar_carry_anchors: Vec<Vec<Vec<u64>>> = Vec::with_capacity(scores.len());
    for mode in MODES {
        fast::shared_normalizers::set_mode(mode);
        let mut outputs: Vec<[Lwe; 3]> = Vec::with_capacity(scores.len());
        // Bounded batches keep raw diagnostic memory limited. Output is in input order.
        for chunk_start in (0..scores.len()).step_by(16) {
            let chunk_end = (chunk_start + 16).min(scores.len());
            let traced: Vec<_> = pool.install(|| {
                (chunk_start..chunk_end)
                    .into_par_iter()
                    .map(|index| keys.trace_shared_normalizer_ingress(&inputs[index], mode))
                    .collect()
            });
            for (index, trace) in (chunk_start..chunk_end).zip(traced) {
                // Before decryption: compare both actual pair inputs, switched words,
                // both carry ciphertexts, and the final top against scalar mode.
                let anchor: Vec<Vec<u64>> = trace
                    .pairs
                    .iter()
                    .flat_map(|pair| {
                        [
                            pair.input.as_ref().to_vec(),
                            switched_degrees(&pair.switched),
                            pair.outputs[1].as_ref().to_vec(),
                        ]
                    })
                    .chain(std::iter::once(trace.outputs[2].as_ref().to_vec()))
                    .collect();
                let scalar_carry_feedback_fullword_equal = if mode == Mode::Scalar {
                    assert_eq!(scalar_carry_anchors.len(), index);
                    scalar_carry_anchors.push(anchor.clone());
                    true
                } else {
                    anchor == scalar_carry_anchors[index]
                };
                if !scalar_carry_feedback_fullword_equal {
                    emit(
                        json!({"record":"carry_equality_failure","mode":mode.name(),"index":index,
                        "actual_anchor":anchor,"scalar_anchor":scalar_carry_anchors[index],"pass":false}),
                    );
                    std::process::exit(1);
                }
                let (ideal_inputs, ideal_pairs, expected) = ideal(scores[index]);
                let mut pass = true;
                let pairs: Vec<_> = trace
                    .pairs
                    .iter()
                    .enumerate()
                    .map(|(pair, trace)| {
                        let (record, pair_pass) = pair_observation(
                            trace,
                            ideal_inputs[pair],
                            ideal_pairs[pair],
                            &big,
                            &small,
                        );
                        pass &= pair_pass;
                        record
                    })
                    .collect();
                let phases: Vec<_> = trace
                    .outputs
                    .iter()
                    .map(|ct| decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), ct).0)
                    .collect();
                let errors: Vec<_> = phases
                    .iter()
                    .zip(expected)
                    .map(|(phase, expected)| phase.wrapping_sub(expected) as i64)
                    .collect();
                pass &= errors.iter().all(|error| error.unsigned_abs() < (1 << 58));
                emit(
                    json!({"record":"ingress","index":index,"score":scores[index],"mode":mode.name(),
                    "input_words":inputs[index].as_ref(),"input_sha256":word_hash(inputs[index].as_ref()),
                    "input_phase":decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), &inputs[index]).0,
                    "input_error_torus":decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), &inputs[index]).0.wrapping_sub(scores[index] << 51) as i64,
                    "scalar_carry_feedback_fullword_equal":scalar_carry_feedback_fullword_equal,
                    "pairs":pairs,"phases":phases,"errors_torus":errors,"expected_phases":expected,
                    "ciphertext_words":trace.outputs.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
                    "br":6-mode.saved_br_per_score(),"ks":4,"logical_output_samples":6,
                    "carry_feedback":"residual carry enters v1 with multiplier1; carry-top enters top with multiplier1; original Head digit0 multiplier2 retained",
                    "pass":pass}),
                );
                if !pass {
                    std::process::exit(1);
                }
                outputs.push(trace.outputs);
                ingress_count += 1;
            }
        }
        for &index in &consumer_indices {
            let right = (index + 1) % scores.len();
            let tuple = pool.install(|| {
                keys.consume_shared_normalizer_pair(&[
                    outputs[index].clone(),
                    outputs[right].clone(),
                ])
            });
            let winner = if scores[index] <= scores[right] {
                index
            } else {
                right
            };
            let identity = if winner == index { 1u64 } else { 2u64 };
            let score = scores[winner];
            let expected = [score / 256, (score / 16) % 16, score % 16, identity, 0, 0];
            let phases: Vec<_> = tuple
                .iter()
                .map(|ct| decrypt_lwe_ciphertext(&big.as_lwe_secret_key(), ct).0)
                .collect();
            let errors: Vec<_> = phases
                .iter()
                .zip(expected)
                .map(|(phase, digit)| phase.wrapping_sub(digit << 59) as i64)
                .collect();
            let pass = errors.iter().all(|error| error.unsigned_abs() < (1 << 58));
            emit(
                json!({"record":"pfks_consumer","mode":mode.name(),"left_index":index,"right_index":right,
                "left_score":scores[index],"right_score":scores[right],"expected_digits":expected,
                "phases":phases,"errors_torus":errors,"ciphertext_words":tuple.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
                "br":5,"ks":4,"pfks":5,"logical_output_samples":8,"pass":pass}),
            );
            if !pass {
                std::process::exit(1);
            }
            consumer_count += 1;
        }
    }
    emit(
        json!({"record":"summary","stage":stage,"ingress_outputs":ingress_count,
        "pfks_consumers":consumer_count,"pass":true,
        "limitations":"one actual key family; fresh noisy raw-score inputs, not packed-query score noise; no full-query timing or failure bound"}),
    );
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "normalizer_gate prepare|run ABS_PRIVATE_DIRECTORY THREADS smoke|sweep"
    );
    let binary = hash(&fs::read(env::current_exe().unwrap()).unwrap());
    assert_eq!(binary, env::var("COMPILER_BINARY_SHA256").unwrap());
    assert_eq!(SOURCE.trim(), env::var("COMPILER_SOURCE_SHA256").unwrap());
    setup_custom_fft_plan(Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    ));
    let directory = Path::new(&args[2]);
    assert!(directory.is_absolute());
    let threads: usize = args[3].parse().unwrap();
    assert!((1..=16).contains(&threads));
    match args[1].as_str() {
        "prepare" => prepare(directory, threads, &binary),
        "run" => run(directory, threads, &args[4], &binary),
        _ => panic!("expected prepare or run"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn independent_ideal_model_reconstructs_all_4096_scores() {
        for score in 0..4096 {
            super::ideal(score);
        }
    }
}
