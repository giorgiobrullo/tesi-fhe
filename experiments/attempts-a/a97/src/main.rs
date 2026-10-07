//! A97: minimal materialization gate for the EvalAuto primitive needed by A92.
//!
//! This intentionally validates one primitive before implementing Chen packing:
//! a polynomial-message GGSW encrypting sigma_d(s), coefficient automorphisms,
//! and a full-Fourier external product composed only from public TFHE-rs 0.11.3
//! core APIs.  No secret or ciphertext is serialized.

use std::env;
use std::time::Instant;
use tfhe::core_crypto::algorithms::ggsw_encryption::ggsw_encryption_multiplicative_factor;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_mul;
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::ClientKey;

const POLYNOMIAL_SIZE: usize = 2_048;
const GLWE_DIMENSION: usize = 1;
const DECOMPOSITION_BASE_LOG: usize = 23;
const DECOMPOSITION_LEVEL_COUNT: usize = 1;
const VALIDATION_DELTA_LOG: u32 = 56;
const AUTOMORPHISM_DEGREES: [usize; 10] = [3, 5, 9, 33, 65, 129, 257, 513, 1025, 2049];

type Glwe = GlweCiphertextOwned<u64>;
type FourierKey = FourierGgswCiphertext<aligned_vec::ABox<[c64]>>;

#[derive(Clone, Copy)]
struct Args {
    run: bool,
    fresh_keysets: usize,
    trials_per_degree: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut run = false;
    let mut fresh_keysets = 3usize;
    let mut trials_per_degree = 4usize;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--run" => run = true,
            "--fresh-keysets" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --fresh-keysets".to_string())?;
                fresh_keysets = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid fresh-keysets: {raw}"))?;
                if fresh_keysets == 0 {
                    return Err("fresh-keysets must be positive".into());
                }
            }
            "--trials-per-degree" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --trials-per-degree".to_string())?;
                trials_per_degree = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid trials-per-degree: {raw}"))?;
                if trials_per_degree == 0 {
                    return Err("trials-per-degree must be positive".into());
                }
            }
            "-h" | "--help" => {
                println!(
                    "usage: a97_chen_evalauto_materialization [--run] [--fresh-keysets N] [--trials-per-degree N]"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(Args {
        run,
        fresh_keysets,
        trials_per_degree,
    })
}

fn automorphism_slice(input: &[u64], degree: usize) -> Vec<u64> {
    assert_eq!(input.len(), POLYNOMIAL_SIZE);
    assert!(degree % 2 == 1 && degree < 2 * POLYNOMIAL_SIZE);
    let mut output = vec![0u64; POLYNOMIAL_SIZE];
    for (exponent, &coefficient) in input.iter().enumerate() {
        let product = exponent * degree;
        let index = product % POLYNOMIAL_SIZE;
        let signed = if (product / POLYNOMIAL_SIZE) % 2 == 0 {
            coefficient
        } else {
            coefficient.wrapping_neg()
        };
        output[index] = output[index].wrapping_add(signed);
    }
    output
}

/// Independent inverse-map oracle for sigma_d in Z/(2^64)[X]/(X^N+1).
///
/// Unlike `automorphism_slice`, this maps every destination coefficient back
/// through d^{-1} modulo 2N and then uses the anti-periodic lift. It is kept
/// structurally separate so the expected output does not reuse the tested
/// forward scatter implementation.
fn automorphism_oracle_inverse(input: &[u64], degree: usize) -> Vec<u64> {
    assert_eq!(input.len(), POLYNOMIAL_SIZE);
    let two_n = 2 * POLYNOMIAL_SIZE;
    assert!(degree % 2 == 1 && degree < two_n);
    let inverse = (1..two_n)
        .step_by(2)
        .find(|candidate| degree * candidate % two_n == 1)
        .expect("every odd degree is invertible modulo 2N");
    (0..POLYNOMIAL_SIZE)
        .map(|destination| {
            let source = destination * inverse % two_n;
            if source < POLYNOMIAL_SIZE {
                input[source]
            } else {
                input[source - POLYNOMIAL_SIZE].wrapping_neg()
            }
        })
        .collect()
}

fn encrypt_polynomial_ggsw(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    message: &[u64],
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> GgswCiphertextOwned<u64> {
    assert_eq!(message.len(), POLYNOMIAL_SIZE);
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::new_native();
    let base_log = DecompositionBaseLog(DECOMPOSITION_BASE_LOG);
    let level_count = DecompositionLevelCount(DECOMPOSITION_LEVEL_COUNT);
    let mut output = GgswCiphertext::new(
        0u64,
        glwe_size,
        polynomial_size,
        base_log,
        level_count,
        modulus,
    );
    let message_poly = Polynomial::from_container(message);
    let key_polynomials = glwe_secret_key.as_polynomial_list();

    for (output_index, mut level_matrix) in output.iter_mut().enumerate() {
        let level = DecompositionLevel(level_count.0 - output_index);
        let negative_gadget =
            ggsw_encryption_multiplicative_factor(modulus, level, base_log, Cleartext(1u64));
        let last_row = level_matrix.glwe_size().0 - 1;
        for (row_index, mut row) in level_matrix.as_mut_glwe_list().iter_mut().enumerate() {
            let mut plaintext = Polynomial::new(0u64, polynomial_size);
            if row_index < last_row {
                polynomial_wrapping_mul(
                    &mut plaintext,
                    &key_polynomials.get(row_index),
                    &message_poly,
                );
                plaintext
                    .as_mut()
                    .iter_mut()
                    .for_each(|value| *value = value.wrapping_mul(negative_gadget));
            } else {
                plaintext.as_mut().copy_from_slice(message);
                let positive_gadget = negative_gadget.wrapping_neg();
                plaintext
                    .as_mut()
                    .iter_mut()
                    .for_each(|value| *value = value.wrapping_mul(positive_gadget));
            }
            encrypt_glwe_ciphertext(
                glwe_secret_key,
                &mut row,
                &PlaintextList::from_container(plaintext.into_container()),
                noise_distribution,
                generator,
            );
        }
    }
    output
}

fn generate_eval_auto_key(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    degree: usize,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> FourierKey {
    let secret_polynomials = glwe_secret_key.as_polynomial_list();
    let secret = secret_polynomials.get(0);
    let automorphed_secret = automorphism_slice(secret.as_ref(), degree);
    let standard = encrypt_polynomial_ggsw(
        glwe_secret_key,
        &automorphed_secret,
        noise_distribution,
        generator,
    );
    let mut fourier = FourierGgswCiphertext::new(
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        DecompositionBaseLog(DECOMPOSITION_BASE_LOG),
        DecompositionLevelCount(DECOMPOSITION_LEVEL_COUNT),
    );
    convert_standard_ggsw_ciphertext_to_fourier(&standard, &mut fourier);
    fourier
}

fn eval_auto(input: &Glwe, degree: usize, key: &FourierKey) -> Glwe {
    let polynomial_size = input.polynomial_size();
    let glwe_size = input.glwe_size();
    let modulus = input.ciphertext_modulus();
    assert_eq!(glwe_size.0, 2);

    let (input_mask, input_body) = input.get_mask_and_body();
    let automorphed_mask = automorphism_slice(input_mask.as_ref(), degree);
    let automorphed_body = automorphism_slice(input_body.as_ref(), degree);

    let mut output = GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
    output
        .get_mut_body()
        .as_mut()
        .copy_from_slice(&automorphed_body);

    let mut negative_mask_as_trivial_glwe =
        GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
    negative_mask_as_trivial_glwe
        .get_mut_body()
        .as_mut()
        .iter_mut()
        .zip(automorphed_mask)
        .for_each(|(destination, value)| *destination = value.wrapping_neg());
    add_external_product_assign(&mut output, key, &negative_mask_as_trivial_glwe);
    output
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn validation_plaintext(seed: u64) -> Vec<u64> {
    let mut state = seed;
    let delta = 1u64 << VALIDATION_DELTA_LOG;
    (0..POLYNOMIAL_SIZE)
        .map(|index| {
            let random = xorshift64(&mut state);
            let symbol = if index % 31 == 0 {
                (random % 15) as i64 - 7
            } else {
                0
            };
            (symbol as u64).wrapping_mul(delta)
        })
        .collect()
}

fn centered_abs_error(observed: u64, expected: u64) -> u64 {
    let signed = observed.wrapping_sub(expected) as i64;
    signed.unsigned_abs()
}

fn run(args: Args) {
    assert_eq!(PARAMS.glwe_dimension.0, GLWE_DIMENSION);
    assert_eq!(PARAMS.polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(PARAMS.pbs_base_log.0, DECOMPOSITION_BASE_LOG);
    assert_eq!(PARAMS.pbs_level.0, DECOMPOSITION_LEVEL_COUNT);

    let mut total_cases = 0usize;
    let mut total_coefficients = 0usize;
    let mut total_mismatches = 0usize;
    let mut global_max_abs_error = 0u64;
    let total_started = Instant::now();

    for keyset in 0..args.fresh_keysets {
        let key_started = Instant::now();
        let client_key = ClientKey::new(PARAMS);
        let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        println!(
            "KEY,keyset={},client_generation_s={:.6},ephemeral=true,secret_material_persisted=false",
            keyset + 1,
            key_started.elapsed().as_secs_f64()
        );

        for &degree in &AUTOMORPHISM_DEGREES {
            let key_started = Instant::now();
            let key = generate_eval_auto_key(
                &glwe_secret_key,
                degree,
                client_params.glwe_noise_distribution(),
                &mut generator,
            );
            let key_s = key_started.elapsed().as_secs_f64();
            let mut degree_eval_s = 0.0;
            let mut degree_max_abs_error = 0u64;
            let mut degree_mismatches = 0usize;

            for trial in 0..args.trials_per_degree {
                let plaintext = validation_plaintext(
                    0xA970_0000_0000_0001u64
                        ^ (keyset as u64).rotate_left(31)
                        ^ (degree as u64).rotate_left(17)
                        ^ trial as u64,
                );
                let expected = automorphism_oracle_inverse(&plaintext, degree);
                assert_eq!(
                    automorphism_slice(&plaintext, degree),
                    expected,
                    "forward automorphism disagrees with independent inverse-map oracle"
                );
                let mut input = GlweCiphertext::new(
                    0u64,
                    glwe_secret_key.glwe_dimension().to_glwe_size(),
                    glwe_secret_key.polynomial_size(),
                    CiphertextModulus::new_native(),
                );
                encrypt_glwe_ciphertext(
                    &glwe_secret_key,
                    &mut input,
                    &PlaintextList::from_container(plaintext),
                    client_params.glwe_noise_distribution(),
                    &mut generator,
                );

                let eval_started = Instant::now();
                let output = std::hint::black_box(eval_auto(
                    std::hint::black_box(&input),
                    degree,
                    std::hint::black_box(&key),
                ));
                degree_eval_s += eval_started.elapsed().as_secs_f64();

                let mut decrypted = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
                decrypt_glwe_ciphertext(&glwe_secret_key, &output, &mut decrypted);
                for (&observed, &wanted) in decrypted.as_ref().iter().zip(&expected) {
                    let error = centered_abs_error(observed, wanted);
                    degree_max_abs_error = degree_max_abs_error.max(error);
                    if error >= (1u64 << (VALIDATION_DELTA_LOG - 1)) {
                        degree_mismatches += 1;
                    }
                }
                total_cases += 1;
                total_coefficients += POLYNOMIAL_SIZE;
            }
            total_mismatches += degree_mismatches;
            global_max_abs_error = global_max_abs_error.max(degree_max_abs_error);
            println!(
                "DEGREE,keyset={},degree={degree},trials={},keygen_s={key_s:.6},eval_total_s={degree_eval_s:.6},eval_mean_s={:.9},max_abs_phase_error={},decode_mismatches={degree_mismatches},timing_includes_wrapper_scratch_allocation=true",
                keyset + 1,
                args.trials_per_degree,
                degree_eval_s / args.trials_per_degree as f64,
                degree_max_abs_error,
            );
        }
    }

    println!(
        "RESULT,status={},fresh_keysets={},cases={total_cases},coefficients={total_coefficients},decode_mismatches={total_mismatches},max_abs_phase_error={global_max_abs_error},delta_log={VALIDATION_DELTA_LOG},wall_s={:.6},runtime_frontier_promoted=false,chen_packing_proven=false,composed_pfail_proven=false",
        if total_mismatches == 0 {
            if args.fresh_keysets == 1 {
                "PASS_SAMPLED_SINGLE_KEY_EVALAUTO_COMPONENT"
            } else {
                "PASS_SAMPLED_FRESH_KEY_EVALAUTO_COMPONENT"
            }
        } else {
            "FAIL_SAMPLED_EVALAUTO_COMPONENT"
        },
        args.fresh_keysets,
        total_started.elapsed().as_secs_f64(),
    );
    assert_eq!(total_mismatches, 0, "A97 EvalAuto decode mismatch");
}

fn main() {
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("error: {error}");
        std::process::exit(2);
    });
    println!(
        "PLAN,artifact=A97,tfhe=0.11.3,params=A44-p16,glwe_dimension={GLWE_DIMENSION},polynomial_size={POLYNOMIAL_SIZE},decomposition_base_log={DECOMPOSITION_BASE_LOG},decomposition_level_count={DECOMPOSITION_LEVEL_COUNT},degrees=3|5|9|33|65|129|257|513|1025|2049,validation_delta_log={VALIDATION_DELTA_LOG},fresh_keysets={},trials_per_degree={},independent_inverse_oracle=true,run={}",
        args.fresh_keysets, args.trials_per_degree, args.run
    );
    if !args.run {
        println!("STATUS,STATIC_ONLY_USE_--run_FOR_COMPONENT_FHE");
        return;
    }
    run(args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_automorphism_matches_independent_oracle_for_all_odd_degrees() {
        let input = validation_plaintext(0xA970_A970_1357_2468);
        for degree in (1..2 * POLYNOMIAL_SIZE).step_by(2) {
            assert_eq!(
                automorphism_slice(&input, degree),
                automorphism_oracle_inverse(&input, degree),
                "degree {degree}"
            );
        }
    }

    #[test]
    fn automorphism_composed_with_inverse_recovers_input() {
        let input = validation_plaintext(0xA970_A970_89AB_CDEF);
        for &degree in &AUTOMORPHISM_DEGREES {
            let two_n = 2 * POLYNOMIAL_SIZE;
            let inverse = (1..two_n)
                .step_by(2)
                .find(|candidate| degree * candidate % two_n == 1)
                .expect("odd degree inverse");
            assert_eq!(
                automorphism_slice(&automorphism_slice(&input, degree), inverse),
                input,
                "degree {degree}, inverse {inverse}"
            );
        }
    }

    #[test]
    fn centered_error_treats_both_wrap_directions_symmetrically() {
        assert_eq!(centered_abs_error(7, 5), 2);
        assert_eq!(centered_abs_error(5, 7), 2);
        assert_eq!(centered_abs_error(1, u64::MAX), 2);
        assert_eq!(centered_abs_error(u64::MAX, 1), 2);
    }
}
