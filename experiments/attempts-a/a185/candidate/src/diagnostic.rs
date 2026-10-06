//! Diagnostic extraction gate. Server evaluation never receives a secret key or clear score.
//! Client phase inspection occurs only after every server arm for that case has completed.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const A169_SCHEMA: &str = "a169.low_b0_b1_direct_scale.v1";
const A169_SOURCE: &str = include_str!("../SOURCE_DIGEST.txt");
const A169_ACK: &str = "A185_ACTUAL_CONSUMER_AUTHORIZED";

const FULL_DELTA_LOG: u32 = 52;
const LOW_DELTA_LOG: u32 = 60;
const BOOL_DELTA_LOG: u32 = 59;
const PROBE_DIM: usize = 512;
const LOW_OFFSET: usize = 1024;
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

include!("frozen_extract.rs");

#[derive(Clone, Copy)]
enum Expectation {
    Residual { delta_log: u32, removed: u32 },
    Bit { bit: u32, delta_log: u32 },
    RawCorrection { bit: u32, delta_log: u32 },
}

impl Expectation {
    fn word(self, x: u64) -> u64 {
        match self {
            Self::Residual { delta_log, removed } => {
                (x & !((1u64 << removed) - 1)).wrapping_shl(delta_log)
            }
            Self::Bit { bit, delta_log } => ((x >> bit) & 1).wrapping_shl(delta_log),
            Self::RawCorrection { bit, delta_log } => ((x >> bit) & 1)
                .wrapping_shl(delta_log)
                .wrapping_sub(1u64 << (delta_log - 1)),
        }
    }

    fn delta_log(self) -> u32 {
        match self {
            Self::Residual { delta_log, .. }
            | Self::Bit { delta_log, .. }
            | Self::RawCorrection { delta_log, .. } => delta_log,
        }
    }
}

struct Snapshot {
    stage: String,
    small_key: bool,
    ciphertext: Lwe,
    expectation: Expectation,
}

struct Arm {
    name: &'static str,
    trace: Vec<Snapshot>,
    weighted_bits: Vec<Lwe>,
    top_residual: Lwe,
    pbs: u64,
    ks: u64,
    frozen_control_identical: Option<bool>,
}

fn snapshot(
    trace: &mut Vec<Snapshot>,
    stage: impl Into<String>,
    ciphertext: &Lwe,
    small_key: bool,
    expectation: Expectation,
) {
    trace.push(Snapshot {
        stage: stage.into(),
        small_key,
        ciphertext: ciphertext.clone(),
        expectation,
    });
}

fn scaled(input: &Lwe, shift: u32) -> Lwe {
    let mut output = input.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(1u64 << shift));
    output
}

fn snapshot_raw_correction(
    trace: &mut Vec<Snapshot>,
    prefix: &str,
    bit: u32,
    log: u32,
    correction: &Lwe,
) {
    // Undo only the public alpha offset; this recovers the exact PBS output bytes.
    let mut raw = correction.clone();
    lwe_ciphertext_plaintext_sub_assign(&mut raw, Plaintext(1u64 << (log - 1)));
    snapshot(
        trace,
        format!("{prefix}.pbs_raw_b{bit}"),
        &raw,
        false,
        Expectation::RawCorrection {
            bit,
            delta_log: log,
        },
    );
}

fn accumulator(
    bsk: &FourierLweBootstrapKeyOwned,
    correction_log: u32,
    with_boolean: bool,
) -> CorrectionAccumulator {
    let alpha = 1u64 << (correction_log - 1);
    let plaintexts = if with_boolean {
        fused_correction_accumulator_body(bsk.polynomial_size(), alpha, 1u64 << 58)
    } else {
        vec![alpha.wrapping_neg(); bsk.polynomial_size().0]
    };
    let glwe = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        bsk.glwe_size(),
        &PlaintextList::from_container(plaintexts),
        CiphertextModulus::new_native(),
    );
    if with_boolean {
        CorrectionAccumulator::WithBoolean(glwe)
    } else {
        CorrectionAccumulator::Single(glwe)
    }
}

/// A transparent copy of the frozen loop with ciphertext snapshots at every boundary.
/// The control arm separately runs the verbatim frozen helpers and compares the outputs.
fn traced_extract(
    input: &Lwe,
    bsk: &FourierLweBootstrapKeyOwned,
    ksk: &LweKeyswitchKeyOwned<u64>,
    delta_log: u32,
    first_global_bit: u32,
    bit_count: u32,
    correction_count: u32,
    prefix: &str,
    trace: &mut Vec<Snapshot>,
    counter: &AtomicU64,
    drop_first_correction: bool,
) -> (CapturedExtractedBits, Lwe) {
    let mut residual = input.clone();
    let mut captured = CapturedExtractedBits {
        small_lsb_first: Vec::new(),
        corrections_lsb_first: Vec::new(),
        canonical_bits_lsb_first: vec![None; bit_count as usize],
    };
    for local_bit in 0..bit_count {
        let global_bit = first_global_bit + local_bit;
        snapshot(
            trace,
            format!("{prefix}.residual_before_b{global_bit}"),
            &residual,
            false,
            Expectation::Residual {
                delta_log: delta_log - first_global_bit,
                removed: global_bit,
            },
        );
        let shifted = scaled(&residual, 63 - delta_log - local_bit);
        let bit_expectation = Expectation::Bit {
            bit: global_bit,
            delta_log: 63,
        };
        snapshot(
            trace,
            format!("{prefix}.shift_b{global_bit}"),
            &shifted,
            false,
            bit_expectation,
        );
        let mut small = LweCiphertext::new(0, ksk.output_lwe_size(), input.ciphertext_modulus());
        keyswitch_lwe_ciphertext(ksk, &shifted, &mut small);
        snapshot(
            trace,
            format!("{prefix}.ks_b{global_bit}"),
            &small,
            true,
            bit_expectation,
        );
        captured.small_lsb_first.push(small.clone());
        if local_bit >= correction_count {
            continue;
        }
        let correction_log = delta_log + local_bit;
        let fused = (3..=6).contains(&global_bit) && correction_log < 60;
        let extracted = correction_from_small_bit(
            &small,
            &accumulator(bsk, correction_log, fused),
            bsk,
            input.lwe_size(),
            1u64 << (correction_log - 1),
            counter,
        );
        snapshot_raw_correction(
            trace,
            prefix,
            global_bit,
            correction_log,
            &extracted.correction,
        );
        snapshot(
            trace,
            format!("{prefix}.pbs_correction_b{global_bit}"),
            &extracted.correction,
            false,
            Expectation::Bit {
                bit: global_bit,
                delta_log: correction_log,
            },
        );
        if let Some(boolean) = &extracted.boolean {
            snapshot(
                trace,
                format!("{prefix}.fused_boolean_b{global_bit}"),
                boolean,
                false,
                Expectation::Bit {
                    bit: global_bit,
                    delta_log: BOOL_DELTA_LOG,
                },
            );
        }
        if !(drop_first_correction && local_bit == 0) {
            lwe_ciphertext_sub_assign(&mut residual, &extracted.correction);
        }
        captured.corrections_lsb_first.push(extracted.correction);
        captured.canonical_bits_lsb_first[local_bit as usize] = extracted.boolean;
    }
    (captured, residual)
}

fn same_lwe(left: &Lwe, right: &Lwe) -> bool {
    left.as_ref() == right.as_ref()
}

fn same_capture(left: &CapturedExtractedBits, right: &CapturedExtractedBits) -> bool {
    left.small_lsb_first.len() == right.small_lsb_first.len()
        && left.corrections_lsb_first.len() == right.corrections_lsb_first.len()
        && left.canonical_bits_lsb_first.len() == right.canonical_bits_lsb_first.len()
        && left
            .small_lsb_first
            .iter()
            .zip(&right.small_lsb_first)
            .all(|(a, b)| same_lwe(a, b))
        && left
            .corrections_lsb_first
            .iter()
            .zip(&right.corrections_lsb_first)
            .all(|(a, b)| same_lwe(a, b))
        && left
            .canonical_bits_lsb_first
            .iter()
            .zip(&right.canonical_bits_lsb_first)
            .all(|(a, b)| match (a, b) {
                (Some(a), Some(b)) => same_lwe(a, b),
                (None, None) => true,
                _ => false,
            })
}

fn split_arm(full: &Lwe, low: &Lwe, sk: &ServerKey, name: &'static str) -> Arm {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A125 requires classic BSK"),
    };
    let ksk = &sk.key_switching_key;
    let counter = AtomicU64::new(0);
    let mut trace = Vec::new();
    snapshot(
        &mut trace,
        "score.full",
        full,
        false,
        Expectation::Residual {
            delta_log: 52,
            removed: 0,
        },
    );
    snapshot(
        &mut trace,
        "score.low",
        low,
        false,
        Expectation::Residual {
            delta_log: 60,
            removed: 0,
        },
    );
    let (low_bits, _) = traced_extract(
        low, bsk, ksk, 60, 0, 4, 3, "low", &mut trace, &counter, false,
    );
    let low_accs: Vec<_> = (0..3)
        .map(|bit| accumulator(bsk, 60 + bit, false))
        .collect();
    let frozen_counter = AtomicU64::new(0);
    let frozen_low =
        extract_bits_with_corrections(low, bsk, ksk, &low_accs, 60, 4, &frozen_counter);
    let mut identical = same_capture(&low_bits, &frozen_low);
    let mut high_input = full.clone();
    let mut recoded = Vec::new();
    for bit in 0..4u32 {
        let log = 52 + bit;
        let output = correction_from_small_bit(
            &low_bits.small_lsb_first[bit as usize],
            &accumulator(bsk, log, bit == 3),
            bsk,
            full.lwe_size(),
            1u64 << (log - 1),
            &counter,
        );
        snapshot(
            &mut trace,
            format!("low_to_full.pbs_correction_b{bit}"),
            &output.correction,
            false,
            Expectation::Bit {
                bit,
                delta_log: log,
            },
        );
        snapshot_raw_correction(&mut trace, "low_to_full", bit, log, &output.correction);
        if let Some(boolean) = &output.boolean {
            snapshot(
                &mut trace,
                "low_to_full.fused_boolean_b3",
                boolean,
                false,
                Expectation::Bit { bit, delta_log: 59 },
            );
        }
        lwe_ciphertext_sub_assign(&mut high_input, &output.correction);
        recoded.push(output);
    }
    let (high_bits, top_residual) = traced_extract(
        &high_input,
        bsk,
        ksk,
        56,
        4,
        4,
        4,
        "high",
        &mut trace,
        &counter,
        false,
    );
    let high_accs: Vec<_> = (0..4)
        .map(|bit| accumulator(bsk, 56 + bit, bit < 3))
        .collect();
    let frozen_high = extract_bits_with_all_corrections(
        &high_input,
        bsk,
        ksk,
        &high_accs,
        56,
        4,
        &frozen_counter,
    );
    identical &= same_capture(&high_bits, &frozen_high);
    identical &= frozen_counter.load(Ordering::Relaxed) == 7;
    let mut weighted_bits = low_bits.corrections_lsb_first.clone();
    weighted_bits.push(recoded[3].boolean.as_ref().unwrap().clone());
    weighted_bits.extend(
        high_bits.canonical_bits_lsb_first[..3]
            .iter()
            .map(|bit| bit.as_ref().unwrap().clone()),
    );
    weighted_bits.push(high_bits.corrections_lsb_first[3].clone());
    let ks = trace.iter().filter(|point| point.small_key).count() as u64;
    Arm {
        name,
        trace,
        weighted_bits,
        top_residual,
        pbs: counter.load(Ordering::Relaxed),
        ks,
        frozen_control_identical: Some(identical),
    }
}

fn single_arm(full: &Lwe, sk: &ServerKey, drop_first: bool) -> Arm {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A125 requires classic BSK"),
    };
    let counter = AtomicU64::new(0);
    let mut trace = Vec::new();
    snapshot(
        &mut trace,
        "score.full",
        full,
        false,
        Expectation::Residual {
            delta_log: 52,
            removed: 0,
        },
    );
    let (bits, top_residual) = traced_extract(
        full,
        bsk,
        &sk.key_switching_key,
        52,
        0,
        8,
        8,
        "full",
        &mut trace,
        &counter,
        drop_first,
    );
    let mut weighted_bits = Vec::new();
    for bit in 0..8usize {
        let output = if bit < 3 {
            let rescaled = scaled(&bits.corrections_lsb_first[bit], 8);
            snapshot(
                &mut trace,
                format!("full.correction_x256_b{bit}"),
                &rescaled,
                false,
                Expectation::Bit {
                    bit: bit as u32,
                    delta_log: 60 + bit as u32,
                },
            );
            rescaled
        } else if bit < 7 {
            bits.canonical_bits_lsb_first[bit].as_ref().unwrap().clone()
        } else {
            bits.corrections_lsb_first[7].clone()
        };
        weighted_bits.push(output);
    }
    let ks = trace.iter().filter(|point| point.small_key).count() as u64;
    Arm {
        name: if drop_first {
            "negative_drop_first_correction"
        } else {
            "single_full_reuse_x256"
        },
        trace,
        weighted_bits,
        top_residual,
        pbs: counter.load(Ordering::Relaxed),
        ks,
        frozen_control_identical: None,
    }
}

/// One new PBS consumes the retained full.ks_b1 ciphertext. The original full
/// extraction, x256 snapshots and residual stay exactly as single_arm produced them.
fn repaired_b1_arm(full: &Lwe, sk: &ServerKey) -> Arm {
    let mut arm = single_arm(full, sk, false);
    let retained = arm
        .trace
        .iter()
        .find(|point| point.stage == "full.ks_b1")
        .unwrap();
    assert!(retained.small_key);
    let small = retained.ciphertext.clone();
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A165 requires classic BSK"),
    };
    let extra_pbs = AtomicU64::new(0);
    let direct = correction_from_small_bit(
        &small,
        &accumulator(bsk, 61, false),
        bsk,
        full.lwe_size(),
        1u64 << 60,
        &extra_pbs,
    );
    assert!(direct.boolean.is_none());
    snapshot_raw_correction(&mut arm.trace, "repair_b1", 1, 61, &direct.correction);
    snapshot(
        &mut arm.trace,
        "repair_b1.pbs_correction_b1",
        &direct.correction,
        false,
        Expectation::Bit {
            bit: 1,
            delta_log: 61,
        },
    );
    arm.weighted_bits[1] = direct.correction;
    arm.pbs += extra_pbs.load(Ordering::Relaxed);
    assert_eq!((arm.pbs, arm.ks), (9, 8));
    arm.name = "single_full_direct_b1";
    arm
}

/// Extend the complete unchanged b1 repair. The consumed b0 output changes;
/// its original full-scale residual correction and all later small inputs do not.
fn repaired_b0_b1_arm(full: &Lwe, sk: &ServerKey) -> Arm {
    let mut arm = repaired_b1_arm(full, sk);
    let retained = arm
        .trace
        .iter()
        .find(|point| point.stage == "full.ks_b0")
        .unwrap();
    assert!(retained.small_key);
    let small = retained.ciphertext.clone();
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A169 requires classic BSK"),
    };
    let extra_pbs = AtomicU64::new(0);
    let direct = correction_from_small_bit(
        &small,
        &accumulator(bsk, 60, false),
        bsk,
        full.lwe_size(),
        1u64 << 59,
        &extra_pbs,
    );
    assert!(direct.boolean.is_none());
    snapshot_raw_correction(&mut arm.trace, "repair_b0", 0, 60, &direct.correction);
    snapshot(
        &mut arm.trace,
        "repair_b0.pbs_correction_b0",
        &direct.correction,
        false,
        Expectation::Bit {
            bit: 0,
            delta_log: 60,
        },
    );
    arm.weighted_bits[0] = direct.correction;
    arm.pbs += extra_pbs.load(Ordering::Relaxed);
    assert_eq!((arm.pbs, arm.ks), (10, 8));
    arm.name = "single_full_direct_b0_b1";
    arm
}

fn boundary_targets(stage: &str) -> Result<Vec<u64>, String> {
    let values = match stage {
        "smoke" => vec![0, 1, 7, 8, 15, 16, 17, 127, 128, 255, 256, 1023, 1024, 4095],
        "boundary" => {
            let mut values: BTreeSet<_> = (0..16).collect();
            for bit in 4..=11 {
                let edge = 1 << bit;
                values.extend([edge - 1, edge, edge + 1]);
            }
            values.insert(4095);
            values.into_iter().collect()
        }
        "exhaustive" => (0..4096).collect(),
        _ => return Err(format!("unknown stage: {stage}")),
    };
    Ok(values)
}

fn digest(ciphertext: &Lwe) -> String {
    let mut hash = Sha256::new();
    for word in ciphertext.as_ref() {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn decode(phase: u64, log: u32) -> u64 {
    phase.wrapping_add(1u64 << (log - 1)) >> log
}

// Frozen A66 target-one raw body: N=2048; coefficients [64,192) equal Delta59.
// This client-only scalar phase observer assumes an exact candidate, ideal KS,
// and zero coefficientwise modulus-switch displacement. It is NOT a PBS run or
// an integrated correctness certificate. The actual consumer is a later gate.
fn a50_target_one_from_scalar_phase(phase: u64) -> i64 {
    let rotation = (((phase as u128) * 4096 + (1u128 << 63)) >> 64) as usize % 4096;
    let value = i64::from((64..192).contains(&(rotation % 2048)));
    if rotation >= 2048 {
        -value
    } else {
        value
    }
}

fn emit(mut record: Value) {
    record
        .as_object_mut()
        .unwrap()
        .insert("schema".into(), json!(A169_SCHEMA));
    println!("{record}");
}

include!("actual_consumer.rs");

pub fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut stage = "smoke".to_string();
    let mut keysets = 1usize;
    let mut execute = false;
    let mut expected_binary_sha256 = None;
    for arg in args {
        if arg == "--run" {
            execute = true;
        } else if let Some(value) = arg.strip_prefix("--stage=") {
            stage = value.to_owned();
        } else if let Some(value) = arg.strip_prefix("--keysets=") {
            keysets = value.parse().map_err(|_| "invalid keysets")?;
        } else if let Some(value) = arg.strip_prefix("--expected-binary-sha256=") {
            expected_binary_sha256 = Some(value.to_owned());
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    if stage != "smoke" || keysets != 1 {
        return Err("A169 is preregistered for smoke and exactly one keyset".into());
    }
    let targets = boundary_targets(&stage)?;
    a175_emit(
        json!({"record":"consumer_plan","stage":stage,"keysets":keysets,
        "producer_schema":A169_SCHEMA,"consumer_arms":["baseline_dual","single_full_direct_b0_b1"],
        "scores":28,"consumer_states_per_arm_per_score":28,"consumer_calls":1568,
        "candidate_encryptions":784,"consumer_ks":1568,"consumer_traced_br":1568,
        "consumer_stock_br":1568,"consumer_samples":3136,
        "producer_br":1988,"producer_ks":1792,"producer_samples_including_score_extraction":2884,
        "total_br":5124,"total_ks":3360,"total_samples":6020,"total_records":17703,
        "candidate_provenance":"fresh_client_lwe_not_prior_selector_round",
        "first_key_only":true,"automatic_retry":false,"automatic_expansion":false,
        "native_zero_mask_branch_retained":true,"stock_equivalence_required":true,
        "p_fail_certified":false,"latency_claim_allowed":false}),
    );
    emit(
        json!({"record":"plan","stage":stage,"keysets":keysets,"scores_per_scene":targets.len(),"scenes":2,"arms":["baseline_dual","shift_initial_only","single_full_reuse_x256","single_full_direct_b1","single_full_direct_b0_b1","negative_drop_first_correction"],"pbs_per_score":[11,11,8,9,10,8],"ks_per_score":[8,8,8,8,8,8],"repair_pair_records_per_score":2,"frozen_control_extra_pbs_per_split":7,"frozen_control_extra_ks_per_split":8,"diagnostic_only":true,"latency_claim_allowed":false,"p_fail_certified":false,"whole_exact_id_validated":false}),
    );
    if !execute {
        return Ok(());
    }
    if std::env::var("A185_RUN_ACK").as_deref() != Ok(A169_ACK)
        || std::env::var("A185_SOURCE_SHA256").as_deref() != Ok(A169_SOURCE.trim())
        || std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("1")
    {
        return Err(
            "A169 source/runner acknowledgment and one requested Rayon thread required".into(),
        );
    }
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    if !binary
        .components()
        .any(|component| component.as_os_str() == "target-a185-private-helper-only")
    {
        return Err("execution requires isolated target-a185-private-helper-only".into());
    }
    let binary_bytes = std::fs::read(&binary).map_err(|e| e.to_string())?;
    let binary_sha256 = format!("{:x}", Sha256::digest(binary_bytes));
    if expected_binary_sha256.as_deref() != Some(binary_sha256.as_str()) {
        return Err(
            "--run requires independently supplied matching --expected-binary-sha256".into(),
        );
    }
    emit(json!({"record":"provenance","binary_sha256":binary_sha256,
        "source_manifest_sha256":A169_SOURCE.trim(),
        "source_sha256":format!("{:x}",Sha256::digest(include_bytes!("diagnostic.rs"))),
        "frozen_helpers_sha256":format!("{:x}",Sha256::digest(include_bytes!("frozen_extract.rs"))),
        "lock_sha256":format!("{:x}",Sha256::digest(include_bytes!("../Cargo.lock"))),
        "parameter_fingerprint":"b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1"}));
    let mut consumer_failure_counts = [[0usize; 6]; 2];
    let mut consumer_case_failures = [0usize; 2];
    let mut failures = [0usize; 5];
    let mut native_decode_failures = [0usize; 5];
    let mut consumer_phase_failures = [0usize; 5];
    let mut negatives_detected = [0usize; 2];
    let mut cases = 0usize;
    let mut repair_pair_failures = 0usize;
    let mut repair_b0_pair_failures = 0usize;
    for keyset in 0..keysets {
        let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let server = ServerKey::new(&client);
        let (glwe_secret, small_secret, parameters) = client.into_raw_parts();
        let big_secret = glwe_secret.as_lwe_secret_key();
        let modulus = CiphertextModulus::new_native();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        emit(
            json!({"record":"keyset","keyset":keyset,"params":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64","key_material_persisted":false,"fresh_keyset":true}),
        );
        a175_key_record(&server, keyset);
        for scene in ["sparse_nonzero", "dense_nonzero"] {
            let mut probe = vec![0i64; PROBE_DIM];
            let mut template = vec![0i64; PROBE_DIM];
            if scene == "sparse_nonzero" {
                probe[0] = 3;
                template[0] = -2;
            } else {
                for (i, value) in probe.iter_mut().enumerate() {
                    *value = if i % 2 == 0 { 1 } else { -1 };
                }
                template[..113].fill(3);
                template[113] = 1;
            }
            let probe_norm: i64 = probe.iter().map(|x| x * x).sum();
            let template_norm: i64 = template.iter().map(|x| x * x).sum();
            let dot: i64 = probe.iter().zip(&template).map(|(a, b)| a * b).sum();
            assert!(probe_norm <= 1024 && probe_norm > 0 && template_norm > 0);
            for &x in &targets {
                let mut plaintext = vec![0u64; glwe_secret.polynomial_size().0];
                for i in 0..PROBE_DIM {
                    plaintext[i] = (probe[i] as u64).wrapping_shl(52);
                    plaintext[LOW_OFFSET + i] = (probe[i] as u64).wrapping_shl(60);
                }
                let mut packed = GlweCiphertext::new(
                    0,
                    glwe_secret.glwe_dimension().to_glwe_size(),
                    glwe_secret.polynomial_size(),
                    modulus,
                );
                encrypt_glwe_ciphertext(
                    &glwe_secret,
                    &mut packed,
                    &PlaintextList::from_container(plaintext),
                    parameters.glwe_noise_distribution(),
                    &mut generator,
                );
                let mut polynomial = vec![0u64; glwe_secret.polynomial_size().0];
                for i in 0..PROBE_DIM {
                    polynomial[PROBE_DIM - 1 - i] = (-2 * template[i]) as u64;
                }
                let polynomial = Polynomial::from_container(polynomial);
                let mut product =
                    GlweCiphertext::new(0, packed.glwe_size(), packed.polynomial_size(), modulus);
                for (mut output, input) in product
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(packed.as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
                }
                let score_at = |degree: usize, log: u32| {
                    let mut score =
                        LweCiphertext::new(0, big_secret.lwe_dimension().to_lwe_size(), modulus);
                    extract_lwe_sample_from_glwe_ciphertext(
                        &product,
                        &mut score,
                        MonomialDegree(degree),
                    );
                    // Public affine offset targets a score center without suppressing actual product noise.
                    lwe_ciphertext_plaintext_add_assign(
                        &mut score,
                        Plaintext(((x as i64 + 2 * dot) as u64).wrapping_shl(log)),
                    );
                    score
                };
                let full = score_at(PROBE_DIM - 1, FULL_DELTA_LOG);
                let low = score_at(LOW_OFFSET + PROBE_DIM - 1, LOW_DELTA_LOG);
                assert!(full.get_mask().as_ref().iter().any(|word| *word != 0));
                assert!(low.get_mask().as_ref().iter().any(|word| *word != 0));
                let arms = [
                    split_arm(&full, &low, &server, "baseline_dual"),
                    split_arm(&full, &scaled(&full, 8), &server, "shift_initial_only"),
                    single_arm(&full, &server, false),
                    repaired_b1_arm(&full, &server),
                    repaired_b0_b1_arm(&full, &server),
                    single_arm(&full, &server, true),
                ];
                // Original six producer arms are complete. Encrypt each registered
                // candidate once and share that same ciphertext between the two consumers.
                // These are fresh client LWEs, not outputs of preceding selector rounds.
                let mut actual_consumers = Vec::new();
                for bit in 0..8usize {
                    let level = 7 - bit;
                    for candidate_state in -(level as i64 % 4)..=1 {
                        let encrypted_candidate = allocate_and_encrypt_new_lwe_ciphertext(
                            &big_secret,
                            Plaintext((candidate_state as u64).wrapping_shl(59)),
                            parameters.glwe_noise_distribution(),
                            modulus,
                            &mut generator,
                        );
                        for arm_index in [0usize, 4usize] {
                            let multiplier = if bit == 2 { 1i64 } else { -1i64 };
                            let (
                                input,
                                switched,
                                output,
                                receipt,
                                stock_glwe_identical,
                                stock_output_identical,
                                traced_glwe_sha256,
                                stock_glwe_sha256,
                                stock_output_sha256,
                            ) = a175_consume(
                                &encrypted_candidate,
                                &arms[arm_index].weighted_bits[bit],
                                multiplier,
                                &server,
                            );
                            actual_consumers.push(A175Consumer {
                                arm_index,
                                bit,
                                candidate_state,
                                candidate: encrypted_candidate.clone(),
                                input,
                                switched,
                                output,
                                receipt,
                                stock_glwe_identical,
                                stock_output_identical,
                                traced_glwe_sha256,
                                stock_glwe_sha256,
                                stock_output_sha256,
                            });
                        }
                    }
                }
                // All producer and actual-consumer server work is complete before client decryption.
                let original = &arms[2];
                let repair = &arms[3];
                let old_trace_identical = repair.trace.len() == original.trace.len() + 2
                    && original.trace.iter().zip(&repair.trace).all(|(a, b)| {
                        a.stage == b.stage
                            && a.small_key == b.small_key
                            && same_lwe(&a.ciphertext, &b.ciphertext)
                    });
                let top_identical = same_lwe(&original.top_residual, &repair.top_residual);
                let other_weighted_identical = (0..8)
                    .filter(|&bit| bit != 1)
                    .all(|bit| same_lwe(&original.weighted_bits[bit], &repair.weighted_bits[bit]));
                let retained_small = repair
                    .trace
                    .iter()
                    .find(|point| point.stage == "full.ks_b1")
                    .unwrap();
                let direct_trace = repair
                    .trace
                    .iter()
                    .find(|point| point.stage == "repair_b1.pbs_correction_b1")
                    .unwrap();
                let direct_output_consumed =
                    same_lwe(&repair.weighted_bits[1], &direct_trace.ciphertext);
                let pair_pass = old_trace_identical
                    && top_identical
                    && other_weighted_identical
                    && direct_output_consumed
                    && original.pbs == 8
                    && repair.pbs == 9
                    && original.ks == 8
                    && repair.ks == 8;
                repair_pair_failures += usize::from(!pair_pass);
                emit(
                    json!({"record":"repair_pair","keyset":keyset,"scene":scene,"x":x,
                    "original_arm":original.name,"repair_arm":repair.name,
                    "old_trace_byte_identical":old_trace_identical,"top_byte_identical":top_identical,
                    "other_weighted_byte_identical":other_weighted_identical,
                    "direct_output_consumed":direct_output_consumed,"pass":pair_pass,
                    "retained_small_input_sha256":digest(&retained_small.ciphertext),
                    "direct_weighted_b1_sha256":digest(&repair.weighted_bits[1]),
                    "original_x256_b1_sha256":digest(&original.weighted_bits[1]),
                    "additional_pbs":1,"additional_ks":0,"full_residual_correction_retained":true}),
                );

                // A second comparison retains the entire A165 b1 repair as the control.
                let original_b1 = &arms[3];
                let repair_b0_b1 = &arms[4];
                let old_b1_trace_identical = repair_b0_b1.trace.len()
                    == original_b1.trace.len() + 2
                    && original_b1
                        .trace
                        .iter()
                        .zip(&repair_b0_b1.trace)
                        .all(|(a, b)| {
                            a.stage == b.stage
                                && a.small_key == b.small_key
                                && same_lwe(&a.ciphertext, &b.ciphertext)
                        });
                let b0_top_identical =
                    same_lwe(&original_b1.top_residual, &repair_b0_b1.top_residual);
                let b0_other_weighted_identical = (1..8).all(|bit| {
                    same_lwe(
                        &original_b1.weighted_bits[bit],
                        &repair_b0_b1.weighted_bits[bit],
                    )
                });
                let b0_small = repair_b0_b1
                    .trace
                    .iter()
                    .find(|point| point.stage == "full.ks_b0")
                    .unwrap();
                let b1_small = repair_b0_b1
                    .trace
                    .iter()
                    .find(|point| point.stage == "full.ks_b1")
                    .unwrap();
                let b0_direct_trace = repair_b0_b1
                    .trace
                    .iter()
                    .find(|point| point.stage == "repair_b0.pbs_correction_b0")
                    .unwrap();
                let b0_direct_consumed =
                    same_lwe(&repair_b0_b1.weighted_bits[0], &b0_direct_trace.ciphertext);
                let b0_pair_pass = old_b1_trace_identical
                    && b0_top_identical
                    && b0_other_weighted_identical
                    && b0_direct_consumed
                    && original_b1.pbs == 9
                    && repair_b0_b1.pbs == 10
                    && original_b1.ks == 8
                    && repair_b0_b1.ks == 8;
                repair_b0_pair_failures += usize::from(!b0_pair_pass);
                emit(
                    json!({"record":"repair_pair_b0","keyset":keyset,"scene":scene,"x":x,
                    "original_arm":original_b1.name,"repair_arm":repair_b0_b1.name,
                    "old_b1_trace_byte_identical":old_b1_trace_identical,
                    "top_byte_identical":b0_top_identical,"other_weighted_byte_identical":b0_other_weighted_identical,
                    "direct_output_consumed":b0_direct_consumed,"pass":b0_pair_pass,
                    "retained_small_input_sha256":digest(&b0_small.ciphertext),
                    "retained_b1_small_input_sha256":digest(&b1_small.ciphertext),
                    "direct_weighted_b0_sha256":digest(&repair_b0_b1.weighted_bits[0]),
                    "original_x256_b0_sha256":digest(&original_b1.weighted_bits[0]),
                    "original_direct_b1_sha256":digest(&original_b1.weighted_bits[1]),
                    "preserved_direct_b1_sha256":digest(&repair_b0_b1.weighted_bits[1]),
                    "original_top_sha256":digest(&original_b1.top_residual),
                    "repair_top_sha256":digest(&repair_b0_b1.top_residual),
                    "additional_pbs":1,"additional_ks":0,"full_residual_corrections_retained":true}),
                );
                // The client now inspects every arm. No branch above depends on these decrypted values.
                for (arm_index, arm) in arms.iter().enumerate() {
                    let mut bit_mismatches = 0;
                    let mut consumer_phase_mismatches = 0usize;
                    for point in &arm.trace {
                        let phase = if point.small_key {
                            decrypt_lwe_ciphertext(&small_secret, &point.ciphertext).0
                        } else {
                            decrypt_lwe_ciphertext(&big_secret, &point.ciphertext).0
                        };
                        let expected = point.expectation.word(x);
                        let error = phase.wrapping_sub(expected) as i64;
                        emit(
                            json!({"record":"phase","keyset":keyset,"scene":scene,"x":x,"arm":arm.name,"stage":point.stage,"small_key":point.small_key,"expected_torus":expected.to_string(),"phase":phase.to_string(),"signed_error":error.to_string(),"error_in_delta":error as f64/(1u64<<point.expectation.delta_log()) as f64,"ciphertext_sha256":digest(&point.ciphertext)}),
                        );
                    }
                    for (bit, ciphertext) in arm.weighted_bits.iter().enumerate() {
                        let log = if bit < 3 { 60 + bit as u32 } else { 59 };
                        let phase = decrypt_lwe_ciphertext(&big_secret, ciphertext).0;
                        let actual = decode(phase, log);
                        let expected = (x >> bit) & 1;
                        bit_mismatches += usize::from(actual != expected);
                        let weight = if bit < 3 { 1u64 << (bit + 1) } else { 1 };
                        let expected_p16 = expected * weight;
                        let p16_error = phase.wrapping_sub(expected_p16 << 59) as i64;
                        let level = 7 - bit;
                        let source_multiplier = [-1i64, -1, -1, -1, -1, 1, -1, -1][level];
                        // Before each four-level refresh, reachable candidates are
                        // -(level % 4)..=1. Probe both live and inactive states.
                        for candidate in -(level as i64 % 4)..=1 {
                            let input = (candidate as u64)
                                .wrapping_shl(59)
                                .wrapping_add(phase.wrapping_mul(source_multiplier as u64));
                            let observed = a50_target_one_from_scalar_phase(input);
                            let wanted = i64::from(candidate == 1 && expected == 0);
                            consumer_phase_mismatches += usize::from(observed != wanted);
                            emit(json!({"record":"consumer_scalar_phase","keyset":keyset,
                                "scene":scene,"x":x,"arm":arm.name,"bit":bit,"level":level,
                                "candidate":candidate,"actual":observed,"expected":wanted,
                                "pass":observed==wanted,"input_torus":input.to_string(),
                                "ideal_candidate_and_keyswitch":true,
                                "coefficientwise_modulus_switch_error_assumed_zero":true,
                                "actual_pbs_executed":false}));
                        }
                        emit(json!({"record":"weighted_p16_margin","keyset":keyset,
                            "scene":scene,"x":x,"arm":arm.name,"bit":bit,
                            "expected_p16":expected_p16,"actual_p16":decode(phase,59),
                            "signed_error":p16_error.to_string(),
                            "error_in_delta59":p16_error as f64/(1u64<<59) as f64,
                            "inside_open_half_slot":p16_error.unsigned_abs() < (1u64<<58),
                            "composed_noise_margin_certified":false}));
                        emit(
                            json!({"record":"weighted_bit","keyset":keyset,"scene":scene,"x":x,"arm":arm.name,"bit":bit,"delta_log":log,"expected":expected,"actual":actual,"pass":actual==expected,"signed_error":(phase.wrapping_sub(expected<<log) as i64).to_string()}),
                        );
                    }
                    let top_phase = decrypt_lwe_ciphertext(&big_secret, &arm.top_residual).0;
                    let top = decode(top_phase, 60);
                    let native_decode_pass = bit_mismatches == 0 && top == x >> 8;
                    let consumer_phase_pass = consumer_phase_mismatches == 0;
                    let passed = native_decode_pass
                        && consumer_phase_pass
                        && arm.frozen_control_identical != Some(false);
                    let actual_low_sha256 = arm
                        .trace
                        .iter()
                        .find(|point| point.stage == "score.low")
                        .map(|point| digest(&point.ciphertext));
                    if arm_index < 5 {
                        failures[arm_index] += usize::from(!passed);
                        native_decode_failures[arm_index] += usize::from(!native_decode_pass);
                        consumer_phase_failures[arm_index] += usize::from(!consumer_phase_pass);
                    } else {
                        negatives_detected[0] += usize::from(!passed);
                    }
                    emit(
                        json!({"record":"case","keyset":keyset,"scene":scene,"x":x,"arm":arm.name,"pass":passed,"native_decode_pass":native_decode_pass,"consumer_scalar_phase_pass":consumer_phase_pass,"consumer_scalar_phase_mismatches":consumer_phase_mismatches,"bit_mismatches":bit_mismatches,"top_signed_error":(top_phase.wrapping_sub((x>>8)<<60) as i64).to_string(),"top_actual":top,"top_expected":x>>8,"pbs":arm.pbs,"ks":arm.ks,"frozen_control_byte_identical":arm.frozen_control_identical,"input_full_sha256":digest(&full),"input_low_sha256":actual_low_sha256,"source_packed_low_sha256":digest(&low),"nontrivial_product":true,"public_score_offset_diagnostic":true}),
                    );
                }
                let bad_phase = decrypt_lwe_ciphertext(
                    &big_secret,
                    &arms[2]
                        .trace
                        .iter()
                        .find(|p| p.stage == "full.pbs_correction_b0")
                        .unwrap()
                        .ciphertext,
                )
                .0;
                let missing_rescale_detected = decode(bad_phase, 60) != (x & 1);
                negatives_detected[1] += usize::from(missing_rescale_detected);
                emit(
                    json!({"record":"negative_missing_rescale","keyset":keyset,"scene":scene,"x":x,"detected":missing_rescale_detected}),
                );
                let mut local_failures = [[0usize; 6]; 2];
                for consumer in &actual_consumers {
                    let arm_slot = usize::from(consumer.arm_index == 4);
                    let gates = a175_observe(
                        consumer,
                        &arms[consumer.arm_index].weighted_bits[consumer.bit],
                        &big_secret,
                        &small_secret,
                        &server,
                        keyset,
                        scene,
                        x,
                    );
                    for (index, gate) in gates.into_iter().enumerate() {
                        local_failures[arm_slot][index] += usize::from(!gate);
                        consumer_failure_counts[arm_slot][index] += usize::from(!gate);
                    }
                }
                for arm in 0..2 {
                    consumer_case_failures[arm] +=
                        usize::from(local_failures[arm].iter().any(|n| *n != 0));
                }
                a175_emit(
                    json!({"record":"consumer_case","keyset":keyset,"scene":scene,"x":x,
                    "consumers":56,"candidate_encryptions":28,"failure_counts":local_failures,
                    "gate_order":["candidate_native","actual_address","output_at_actual_address","semantic_output","stock_equivalence","observer_closure"],
                    "all_consumer_gates_pass":local_failures.iter().flatten().all(|n|*n==0)}),
                );
                cases += 1;
            }
        }
    }
    let controls_valid = failures[0] == 0 && negatives_detected.iter().all(|count| *count > 0);
    let repair_gate_pass = controls_valid && repair_pair_failures == 0 && failures[3] == 0;
    let repair_b0_b1_gate_pass = controls_valid
        && repair_pair_failures == 0
        && repair_b0_pair_failures == 0
        && failures[4] == 0;
    emit(
        json!({"record":"summary","status":if controls_valid {"A169_DIAGNOSTIC_COMPLETE"}else{"INVALID_CONTROLS"},
        "cases":cases,"positive_arm_order":["baseline_dual","shift_initial_only","single_full_reuse_x256","single_full_direct_b1","single_full_direct_b0_b1"],
        "failures_baseline_shift_single_b1_b0_b1":failures,
        "native_decode_failures_baseline_shift_single_b1_b0_b1":native_decode_failures,
        "consumer_scalar_phase_failures_baseline_shift_single_b1_b0_b1":consumer_phase_failures,
        "both_original_candidates_native_decode_pass":native_decode_failures[1..3].iter().all(|count| *count == 0),
        "both_original_candidates_consumer_scalar_phase_pass":consumer_phase_failures[1..3].iter().all(|count| *count == 0),
        "both_original_candidates_all_checks_pass":failures[1..3].iter().all(|count| *count == 0),
        "repair_native_decode_pass":native_decode_failures[3] == 0,
        "repair_consumer_scalar_phase_pass":consumer_phase_failures[3] == 0,
        "repair_all_checks_pass":failures[3] == 0,
        "repair_pair_failures":repair_pair_failures,"repair_gate_pass":repair_gate_pass,
        "repair_b0_pair_failures":repair_b0_pair_failures,
        "repair_b0_b1_native_decode_pass":native_decode_failures[4] == 0,
        "repair_b0_b1_consumer_scalar_phase_pass":consumer_phase_failures[4] == 0,
        "repair_b0_b1_all_checks_pass":failures[4] == 0,
        "repair_b0_b1_gate_pass":repair_b0_b1_gate_pass,
        "negative_detections_drop_rescale":negatives_detected,"controls_valid":controls_valid,
        "p_fail_certified":false,"whole_exact_id_validated":false,"latency_claim_allowed":false}),
    );
    let actual_consumer_gate_pass = consumer_failure_counts.iter().flatten().all(|n| *n == 0);
    let complete_gate_pass = repair_b0_b1_gate_pass && actual_consumer_gate_pass;
    a175_emit(
        json!({"record":"consumer_summary","status":if complete_gate_pass {"PASS_A175_ACTUAL_CONSUMER"} else {"FAIL_A175_ACTUAL_CONSUMER"},
        "cases":cases,"consumer_calls":cases*56,"candidate_encryptions":cases*28,
        "producer_gate_pass":repair_b0_b1_gate_pass,"actual_consumer_gate_pass":actual_consumer_gate_pass,
        "complete_gate_pass":complete_gate_pass,"failure_counts":consumer_failure_counts,
        "case_failures":consumer_case_failures,"total_br":cases*183,"total_ks":cases*120,
        "total_samples":cases*215,"process_id":std::process::id(),
        "candidate_is_previous_selector_output":false,"full_exact_id_validated":false,
        "actual_p_fail":null,"latency_claim_allowed":false}),
    );
    if !complete_gate_pass {
        return Err("A175 complete first-key gate failed; preserve every producer/consumer outcome without retry".into());
    }
    if !repair_b0_b1_gate_pass {
        return Err("A169 b0+b1 repair or control gate failed; all prior outcomes retained".into());
    }
    Ok(())
}
