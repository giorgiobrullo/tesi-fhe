use selector_four_core_20260920::{
    raw_threshold_probe::{Arm, Mode, Output, Pair},
    service::{generate_bundle, EvaluationKeys},
};
use serde::Deserialize;
use serde_json::json;
use std::time::Instant;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::{client_key::atomic_pattern::AtomicPatternClientKey, ClientKey, ServerKey};

const DELTA: u64 = 1 << 59;
const PROBE: &str = "raw-threshold-parallel9-stage.20261005.v1";
const ARMS: [(&str, Arm); 3] = [
    ("current_parallel", Arm::Baseline),
    ("raw_sequential_branches", Arm::Raw),
    ("raw_parallel9", Arm::RawParallel9),
];
const TIMED_CASES: [&str; 3] = ["U-left-inclusive", "U-right-inclusive", "U-tie-reject"];
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[derive(Deserialize)]
struct Case {
    name: String,
    score_left: u16,
    score_right: u16,
    tau_left: u16,
    tau_right: u16,
    id_left: u16,
    id_right: u16,
    expected: u16,
}

fn lanes(score: u16, id: u16, tau: u16) -> [u64; 9] {
    [
        u64::from(score >> 8),
        u64::from((score >> 4) & 15),
        u64::from(score & 15),
        u64::from(id % 15),
        u64::from((id / 15) % 15),
        0,
        u64::from(tau >> 8),
        u64::from((tau >> 4) & 15),
        u64::from(tau & 15),
    ]
}

fn clear_oracle(case: &Case) -> u16 {
    let (score, threshold, id) = if case.score_left <= case.score_right {
        (case.score_left, case.tau_left, case.id_left)
    } else {
        (case.score_right, case.tau_right, case.id_right)
    };
    if score <= threshold {
        id
    } else {
        0
    }
}

fn mode(case: &Case) -> Mode {
    if case.name.starts_with("U-") {
        Mode::Uniform {
            sentinel: case.tau_left + 1,
        }
    } else {
        Mode::Mixed
    }
}

fn decode_id<KeyCont: Container<Element = u64>>(
    key: &LweSecretKey<KeyCont>,
    digits: &[LweCiphertextOwned<u64>; 3],
) -> Result<u16, String> {
    let decoded: [u64; 3] = std::array::from_fn(|lane| {
        let plaintext = decrypt_lwe_ciphertext(key, &digits[lane]).0;
        plaintext.wrapping_add(DELTA / 2) >> 59
    });
    if decoded.iter().any(|&digit| digit >= 15) || decoded[2] != 0 {
        return Err("final base15 decoder rejected a digit".into());
    }
    u16::try_from(decoded[0] + 15 * decoded[1]).map_err(|_| "final ID range".into())
}

fn verify<KeyCont: Container<Element = u64>>(
    key: &LweSecretKey<KeyCont>,
    output: &Output,
    expected: u16,
) -> Result<u16, String> {
    let id = decode_id(key, &output.digits)?;
    if id != expected {
        return Err("final ID differs from the independent frozen oracle".into());
    }
    Ok(id)
}

fn main() -> Result<(), String> {
    let cases: Vec<Case> = serde_json::from_str(include_str!("../raw_threshold_cases.json"))
        .map_err(|_| "invalid public fixture")?;
    if cases.len() != 14 {
        return Err("expected exactly 14 preregistered cases".into());
    }
    for case in &cases {
        if case.score_left > 4095
            || case.score_right > 4095
            || case.tau_left > 4095
            || case.tau_right > 4095
            || case.id_left >= 120
            || case.id_right >= 120
            || clear_oracle(case) != case.expected
            || (case.name.starts_with("U-")
                && (case.tau_left != case.tau_right || case.tau_left == 4095))
            || (!case.name.starts_with("U-") && !case.name.starts_with("M-"))
        {
            return Err("public fixture violates its fixed contract".into());
        }
    }
    // Match the current service: fixed FFT first, then its global16-thread pool, then keys.
    setup_custom_fft_plan(Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    ));
    rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build_global()
        .map_err(|_| "global16-thread initialization failed")?;
    if rayon::current_num_threads() != 16 {
        return Err("query pool must have16 workers".into());
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"fresh_key_generation","key_families":1,
        "rayon_threads":16,"fft_policy":"user-provided-dif4-polynomial2048-base1024-v1"})
    );
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let keys = EvaluationKeys::from_bundle(generate_bundle(&client, ServerKey::new(&client))?)?;
    let (glwe, _small, params, _wopbs) = match client.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return Err("standard Gaussian client required".into()),
    };
    let big = glwe.as_lwe_secret_key();
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut fixtures = Vec::with_capacity(14);
    for case in cases {
        let mut encrypt = |digits: [u64; 9]| -> [LweCiphertextOwned<u64>; 9] {
            std::array::from_fn(|lane| {
                if lane == 5 {
                    allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big.lwe_dimension().to_lwe_size(),
                        Plaintext(0),
                        CiphertextModulus::new_native(),
                    )
                } else {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &big,
                        Plaintext(digits[lane] * DELTA),
                        params.glwe_noise_distribution(),
                        CiphertextModulus::new_native(),
                        &mut generator,
                    )
                }
            })
        };
        let pair = Pair {
            left: encrypt(lanes(case.score_left, case.id_left, case.tau_left)),
            right: encrypt(lanes(case.score_right, case.id_right, case.tau_right)),
        };
        let nontrivial = pair
            .left
            .iter()
            .chain(&pair.right)
            .enumerate()
            .all(|(index, lane)| {
                index % 9 == 5 || lane.as_ref()[..2048].iter().any(|&word| word != 0)
            });
        if !nontrivial {
            return Err("a required input mask is trivial".into());
        }
        fixtures.push((case, pair));
    }

    let mut correctness_outputs = 0;
    for (case, pair) in &fixtures {
        let mut arm_results = Vec::with_capacity(3);
        for (label, arm) in ARMS {
            let output = keys.raw_threshold_stage_pair(pair, mode(case), arm)?;
            let id = verify(&big, &output, case.expected)?;
            correctness_outputs += 1;
            arm_results.push(
                json!({"arm":label,"id":id,"counts":output.counts,"scheduling":output.scheduling}),
            );
        }
        println!(
            "{}",
            json!({"probe":PROBE,"stage":"correctness","case":case.name,"pass":true,
            "all_required_input_masks_nontrivial":true,"arms":arm_results})
        );
    }
    if correctness_outputs != 42 {
        return Err("correctness gate requires42 final IDs".into());
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"correctness_complete","decoded_id_outputs":42,"pass":true})
    );

    // Only after every fresh encrypted case passes: bounded balanced paired stage measurements.
    let timed: Vec<_> = fixtures
        .iter()
        .filter(|(case, _)| TIMED_CASES.contains(&case.name.as_str()))
        .collect();
    if timed.len() != 3 {
        return Err("three fixed uniform cost fixtures required".into());
    }
    let mut warmup_outputs = 0;
    for (case, pair) in &timed {
        for (_, arm) in ARMS {
            let output = keys.raw_threshold_stage_pair(pair, mode(case), arm)?;
            verify(&big, &output, case.expected)?;
            warmup_outputs += 1;
        }
    }
    let mut timed_outputs = 0;
    for (case, pair) in timed {
        for repeat in 0..2 {
            for (order_index, order) in ORDERS.into_iter().enumerate() {
                let mut duration_ns = [0u64; 3];
                let mut ids = [0u16; 3];
                for arm_index in order {
                    let started = Instant::now();
                    let output =
                        keys.raw_threshold_stage_pair(pair, mode(case), ARMS[arm_index].1)?;
                    duration_ns[arm_index] = u64::try_from(started.elapsed().as_nanos())
                        .map_err(|_| "stage duration out of range")?;
                    ids[arm_index] = verify(&big, &output, case.expected)?;
                    timed_outputs += 1;
                }
                println!(
                    "{}",
                    json!({"probe":PROBE,"stage":"paired_cost","case":case.name,
                    "repeat":repeat,"order_index":order_index,"arm_order":order,
                    "arm_duration_ns":duration_ns,"final_ids":ids,"pass":true})
                );
            }
        }
    }
    if warmup_outputs != 9 || timed_outputs != 108 {
        return Err("bounded cost loop counts changed".into());
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"complete","pass":true,"correctness_id_outputs":42,
        "warmup_id_outputs":9,"timed_id_outputs":108,"decoded_id_outputs":159,
        "timing_boundary":"diagnostic evaluation including setup/affine/selectors/route checks; excludes keygen/encryption/decode/stdout; no Head/fullquery/e2e"})
    );
    Ok(())
}
