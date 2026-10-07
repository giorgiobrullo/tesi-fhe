use selector_four_core_20260920::{
    raw_threshold_probe::{Arm, Mode, Pair},
    service::{generate_bundle, EvaluationKeys},
};
use serde::Deserialize;
use serde_json::json;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::{client_key::atomic_pattern::AtomicPatternClientKey, ClientKey, ServerKey};

const DELTA: u64 = 1 << 59;
const PROBE: &str = "raw-threshold-pair-stage.20261005.v1";

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

fn decode_id<KeyCont: Container<Element = u64>>(
    key: &LweSecretKey<KeyCont>,
    digits: &[LweCiphertextOwned<u64>; 3],
) -> Result<u16, String> {
    let decoded: [u64; 3] = std::array::from_fn(|lane| {
        let plaintext = decrypt_lwe_ciphertext(key, &digits[lane]).0;
        plaintext.wrapping_add(DELTA / 2) >> 59
    });
    if decoded.iter().any(|&digit| digit >= 15) || decoded[2] != 0 {
        return Err("final base15 ID decoder rejected a digit".into());
    }
    let id = decoded[0] + 15 * decoded[1] + 225 * decoded[2];
    u16::try_from(id).map_err(|_| "final ID exceeds the decoder range".into())
}

fn main() -> Result<(), String> {
    let cases: Vec<Case> = serde_json::from_str(include_str!("../raw_threshold_cases.json"))
        .map_err(|_| "invalid public case fixture")?;
    if cases.len() != 14 {
        return Err("the preregistered fixture must contain exactly 14 cases".into());
    }
    // Check the independent oracle before generating a key or evaluating a circuit.
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
            return Err("public case fixture violates its preregistered contract".into());
        }
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"fresh_key_generation","key_families":1})
    );
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let ordinary = ServerKey::new(&client);
    let keys = EvaluationKeys::from_bundle(generate_bundle(&client, ordinary)?)?;
    let (glwe, _small, params, _wopbs) = match client.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return Err("fresh client must use the standard Gaussian family".into()),
    };
    let big = glwe.as_lwe_secret_key();
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut all_pass = true;
    let mut outputs = 0;
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
        let mode = if case.name.starts_with("U-") {
            Mode::Uniform {
                sentinel: case.tau_left + 1,
            }
        } else {
            Mode::Mixed
        };
        // Both arms borrow these exact fresh ciphertext objects and the same evaluation keys.
        let baseline = keys.raw_threshold_stage_pair(&pair, mode, Arm::Baseline)?;
        let alternative = keys.raw_threshold_stage_pair(&pair, mode, Arm::Raw)?;
        let baseline_id = decode_id(&big, &baseline.digits);
        let alternative_id = decode_id(&big, &alternative.digits);
        outputs += 2;
        let pass = nontrivial
            && baseline_id.as_ref() == Ok(&case.expected)
            && alternative_id.as_ref() == Ok(&case.expected);
        all_pass &= pass;
        println!(
            "{}",
            json!({
                "probe":PROBE,"case":case.name,"baseline_id":baseline_id.ok(),
                "alternative_id":alternative_id.ok(),"pass":pass,
                "all_required_input_masks_nontrivial":nontrivial,
                "baseline_counts":baseline.counts,"alternative_counts":alternative.counts,
            })
        );
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"complete","decoded_id_outputs":outputs,"pass":all_pass})
    );
    if !all_pass || outputs != 28 {
        return Err("fresh paired stage correctness failed".into());
    }
    Ok(())
}
