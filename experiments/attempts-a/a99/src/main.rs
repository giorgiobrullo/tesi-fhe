//! A99: materialization gate for grouped normalization in the A92 Chen node.
//!
//! Scope of the first runtime gate:
//! eight real big-LWE ciphertexts -> inverse embedding -> Chen pack -> seven
//! retained trace stages -> one public width-127 kernel -> clear-position sample
//! extraction and client decryption.  The encrypted selector-control blind
//! rotation, score comparison, full tournament, and composed p_fail are not in
//! this binary and must not be inferred from a passing component result.

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::time::{Duration, Instant};

use tfhe::core_crypto::algorithms::ggsw_encryption::ggsw_encryption_multiplicative_factor;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_mul;
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::ClientKey;

const POLYNOMIAL_SIZE: usize = 2_048;
const GLWE_DIMENSION: usize = 1;
const LWE_DIMENSION: usize = GLWE_DIMENSION * POLYNOMIAL_SIZE;

const SCORE_DELTA_LOG: u32 = 59;
const ID_DELTA_LOG: u32 = 56;
const BOX_SIZE: isize = 128;
const LEFT_CONTROL: isize = 4;
const RIGHT_CONTROL: isize = 12;
const SAMPLE_STEP: isize = 256;
const STRICT_RADIUS: isize = 63;

const PACK_DEGREES: [usize; 3] = [3, 5, 9];
const TRACE_DEGREES: [usize; 7] = [33, 65, 129, 257, 513, 1025, 2049];
const AUTOMORPHISM_DEGREES: [usize; 10] = [3, 5, 9, 33, 65, 129, 257, 513, 1025, 2049];
const MAX_FRESH_KEYSETS: usize = 16;
const MAX_TRIALS_PER_KEYSET: usize = 64;

type Glwe = GlweCiphertextOwned<u64>;
type Lwe = LweCiphertextOwned<u64>;
type FourierKey = FourierGgswCiphertext<aligned_vec::ABox<[c64]>>;

#[derive(Clone, Debug)]
struct Args {
    run: bool,
    ack_component_only: bool,
    fresh_keysets: usize,
    trials_per_keyset: usize,
    auto_params: Vec<AutoParams>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AutoParams {
    name: &'static str,
    base_log: usize,
    level_count: usize,
}

impl AutoParams {
    const PBS_23X1: Self = Self {
        name: "23x1",
        base_log: 23,
        level_count: 1,
    };
    const TRACE_8X5: Self = Self {
        name: "8x5",
        base_log: 8,
        level_count: 5,
    };
    const TRACE_7X6: Self = Self {
        name: "7x6",
        base_log: 7,
        level_count: 6,
    };
    const ALL: [Self; 3] = [Self::PBS_23X1, Self::TRACE_8X5, Self::TRACE_7X6];

    fn parse(raw: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.name == raw)
            .ok_or_else(|| format!("unknown EvalAuto parameter set: {raw}"))
    }

    fn ten_key_fourier_bytes(self) -> usize {
        // Full Fourier GGSW: l * (k+1)^2 * (N/2) complex f64 values.
        10 * self.level_count
            * (GLWE_DIMENSION + 1).pow(2)
            * (POLYNOMIAL_SIZE / 2)
            * std::mem::size_of::<c64>()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rounding {
    Floor,
    Nearest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    G1Floor,
    G2Floor,
    G2Nearest,
}

impl Arm {
    const ALL: [Self; 3] = [Self::G1Floor, Self::G2Floor, Self::G2Nearest];

    fn name(self) -> &'static str {
        match self {
            Self::G1Floor => "g1-floor",
            Self::G2Floor => "g2-floor",
            Self::G2Nearest => "g2-nearest",
        }
    }
}

#[derive(Clone)]
struct Fixture {
    left: [u64; 4],
    right: [u64; 4],
    label: &'static str,
}

impl Fixture {
    fn slot_words(&self) -> [u64; 8] {
        [
            self.right[2].wrapping_neg(),
            self.right[3].wrapping_neg(),
            self.left[0],
            self.left[1],
            self.left[2],
            self.left[3],
            self.right[0],
            self.right[1],
        ]
    }
}

#[derive(Default)]
struct ArmTotals {
    cases: usize,
    failed_cases: usize,
    robust_tuples: usize,
    robust_words: usize,
    tuple_decode_failures: usize,
    word_decode_failures: usize,
    extraction_consistency_failures: usize,
    maximum_post_kernel_certified_error: u64,
    maximum_robust_word_error: u64,
    maximum_ingress_lwe_error: u64,
    ingress_lwe_decode_failures: usize,
    stage_evalauto_calls: usize,
    maximum_incremental_evalauto_error: u64,
    stage_audit_replay_mismatches: usize,
    stage_call_count_failures: usize,
    pack_trace_time: Duration,
    kernel_time: Duration,
    client_audit_time: Duration,
    stage_audit_time: Duration,
}

struct Outcome {
    robust_tuples: usize,
    robust_words: usize,
    tuple_decode_failures: usize,
    word_decode_failures: usize,
    extraction_consistency_failures: usize,
    maximum_post_kernel_certified_error: u64,
    maximum_robust_word_error: u64,
    maximum_ingress_lwe_error: u64,
    ingress_lwe_decode_failures: usize,
    stage_evalauto_calls: usize,
    maximum_incremental_evalauto_error: u64,
    stage_audit_replay_mismatches: usize,
    stage_call_count_failures: usize,
    pack_trace_time: Duration,
    kernel_time: Duration,
    client_audit_time: Duration,
    stage_audit_time: Duration,
}

#[derive(Clone, Debug)]
struct EvalAutoObservation {
    degree: usize,
    call_index: usize,
    maximum_incremental_error: u64,
}

#[derive(Default)]
struct EvalAutoAudit {
    observations: Vec<EvalAutoObservation>,
}

impl EvalAutoAudit {
    fn record(&mut self, degree: usize, maximum_incremental_error: u64) {
        self.observations.push(EvalAutoObservation {
            degree,
            call_index: self.observations.len() + 1,
            maximum_incremental_error,
        });
    }

    fn maximum_incremental_error(&self) -> u64 {
        self.observations
            .iter()
            .map(|observation| observation.maximum_incremental_error)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy)]
struct AuditMode<'a> {
    secret_key: &'a GlweSecretKeyOwned<u64>,
    sink: &'a RefCell<EvalAutoAudit>,
}

struct PrimitiveOutcome {
    input_maximum_error: u64,
    incremental_evalauto_maximum_error: u64,
    total_maximum_error: u64,
    input_decode_failures: usize,
    output_decode_failures: usize,
    eval_time: Duration,
}

fn parse_positive_bounded(raw: &str, name: &str, maximum: usize) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("invalid {name}: {raw}"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be in 1..={maximum}"));
    }
    Ok(value)
}

fn parse_args_from<I>(arguments: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut run = false;
    let mut ack_component_only = false;
    let mut fresh_keysets = 3usize;
    let mut trials_per_keyset = 2usize;
    let mut auto_params = AutoParams::ALL.to_vec();
    let mut seen_run = false;
    let mut seen_ack = false;
    let mut seen_fresh = false;
    let mut seen_trials = false;
    let mut seen_params = false;
    let mut args = arguments.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--run" if !seen_run => {
                seen_run = true;
                run = true;
            }
            "--ack-component-only" if !seen_ack => {
                seen_ack = true;
                ack_component_only = true;
            }
            "--fresh-keysets" if !seen_fresh => {
                seen_fresh = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --fresh-keysets".to_string())?;
                fresh_keysets = parse_positive_bounded(&raw, "fresh-keysets", MAX_FRESH_KEYSETS)?;
            }
            "--trials-per-keyset" if !seen_trials => {
                seen_trials = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --trials-per-keyset".to_string())?;
                trials_per_keyset =
                    parse_positive_bounded(&raw, "trials-per-keyset", MAX_TRIALS_PER_KEYSET)?;
            }
            "--auto-params" if !seen_params => {
                seen_params = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --auto-params".to_string())?;
                let mut parsed = Vec::new();
                for item in raw.split(',') {
                    let candidate = AutoParams::parse(item)?;
                    if !parsed.contains(&candidate) {
                        parsed.push(candidate);
                    }
                }
                if parsed.is_empty() {
                    return Err("auto-params must contain at least one parameter set".into());
                }
                auto_params = parsed;
            }
            "-h" | "--help" => {
                println!(
                    "usage: a99_chen_grouped_runtime [--run --ack-component-only] [--fresh-keysets N] [--trials-per-keyset N] [--auto-params 23x1,8x5,7x6]"
                );
                std::process::exit(0);
            }
            "--run"
            | "--ack-component-only"
            | "--fresh-keysets"
            | "--trials-per-keyset"
            | "--auto-params" => return Err(format!("duplicate argument: {arg}")),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if run != ack_component_only {
        return Err(
            "runtime requires both --run and --ack-component-only; neither is needed for dry-plan"
                .to_string(),
        );
    }
    Ok(Args {
        run,
        ack_component_only,
        fresh_keysets,
        trials_per_keyset,
        auto_params,
    })
}

fn encode(value: u64, delta_log: u32) -> u64 {
    value.wrapping_mul(1u64 << delta_log)
}

fn fixture(trial: usize) -> Fixture {
    match trial % 3 {
        0 => Fixture {
            // Equal score keys make the separate reference decision tie-left;
            // code 0 exercises the reject/sentinel payload representation.
            left: [encode(0, 59), encode(7, 59), encode(15, 59), encode(0, 56)],
            right: [
                encode(0, 59),
                encode(7, 59),
                encode(15, 59),
                encode(127, 56),
            ],
            label: "tie-left-reject0-id127",
        },
        1 => Fixture {
            left: [encode(1, 59), encode(2, 59), encode(3, 59), encode(17, 56)],
            right: [encode(4, 59), encode(5, 59), encode(6, 59), encode(91, 56)],
            label: "mixed-scales-a92",
        },
        _ => Fixture {
            left: [encode(15, 59), encode(0, 59), encode(8, 59), encode(63, 56)],
            right: [encode(2, 59), encode(14, 59), encode(1, 59), encode(64, 56)],
            label: "mixed-boundaries",
        },
    }
}

fn centered_abs_error(observed: u64, expected: u64) -> u64 {
    (observed.wrapping_sub(expected) as i64).unsigned_abs()
}

fn shifted_word(word: u64, shift: u32, rounding: Rounding) -> u64 {
    assert!(shift > 0 && shift < 64);
    match rounding {
        Rounding::Floor => word >> shift,
        Rounding::Nearest => {
            let divisor = 1u128 << shift;
            let small_modulus = 1u128 << (64 - shift);
            (((u128::from(word) + divisor / 2) / divisor) % small_modulus) as u64
        }
    }
}

fn normalize_lwe_assign(input: &mut Lwe, shift: u32, rounding: Rounding) {
    for coefficient in input.as_mut() {
        *coefficient = shifted_word(*coefficient, shift, rounding);
    }
}

fn normalize_glwe_assign(input: &mut Glwe, shift: u32, rounding: Rounding) {
    for coefficient in input.as_mut() {
        *coefficient = shifted_word(*coefficient, shift, rounding);
    }
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
/// Keeping this separate from the forward scatter prevents the stage-noise
/// audit from certifying an indexing bug by repeating the implementation.
fn automorphism_oracle_inverse(input: &[u64], degree: usize) -> Vec<u64> {
    assert_eq!(input.len(), POLYNOMIAL_SIZE);
    let two_n = 2 * POLYNOMIAL_SIZE;
    assert!(degree % 2 == 1 && degree < two_n);
    let inverse = (1..two_n)
        .step_by(2)
        .find(|candidate| degree * candidate % two_n == 1)
        .expect("odd automorphism degree must be invertible modulo 2N");
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

fn decrypt_glwe_phase(input: &Glwe, secret_key: &GlweSecretKeyOwned<u64>) -> Vec<u64> {
    let mut plaintext = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    decrypt_glwe_ciphertext(secret_key, input, &mut plaintext);
    plaintext.into_container()
}

fn maximum_centered_error(observed: &[u64], expected: &[u64]) -> u64 {
    assert_eq!(observed.len(), expected.len());
    observed
        .iter()
        .zip(expected)
        .map(|(&actual, &wanted)| centered_abs_error(actual, wanted))
        .max()
        .unwrap_or(0)
}

fn encrypt_polynomial_ggsw(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    message: &[u64],
    auto_params: AutoParams,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> GgswCiphertextOwned<u64> {
    assert_eq!(message.len(), POLYNOMIAL_SIZE);
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::new_native();
    let base_log = DecompositionBaseLog(auto_params.base_log);
    let level_count = DecompositionLevelCount(auto_params.level_count);
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
    auto_params: AutoParams,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> FourierKey {
    let secret_polynomials = glwe_secret_key.as_polynomial_list();
    let secret = secret_polynomials.get(0);
    let automorphed_secret = automorphism_slice(secret.as_ref(), degree);
    let standard = encrypt_polynomial_ggsw(
        glwe_secret_key,
        &automorphed_secret,
        auto_params,
        noise_distribution,
        generator,
    );
    let mut fourier = FourierGgswCiphertext::new(
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        DecompositionBaseLog(auto_params.base_log),
        DecompositionLevelCount(auto_params.level_count),
    );
    convert_standard_ggsw_ciphertext_to_fourier(&standard, &mut fourier);
    fourier
}

fn eval_auto_core(input: &Glwe, degree: usize, key: &FourierKey) -> Glwe {
    let (input_mask, input_body) = input.get_mask_and_body();
    let automorphed_mask = automorphism_slice(input_mask.as_ref(), degree);
    let automorphed_body = automorphism_slice(input_body.as_ref(), degree);
    let mut output = GlweCiphertext::new(
        0u64,
        input.glwe_size(),
        input.polynomial_size(),
        input.ciphertext_modulus(),
    );
    output
        .get_mut_body()
        .as_mut()
        .copy_from_slice(&automorphed_body);

    let mut negative_mask_as_trivial_glwe = GlweCiphertext::new(
        0u64,
        input.glwe_size(),
        input.polynomial_size(),
        input.ciphertext_modulus(),
    );
    negative_mask_as_trivial_glwe
        .get_mut_body()
        .as_mut()
        .iter_mut()
        .zip(automorphed_mask)
        .for_each(|(destination, value)| *destination = value.wrapping_neg());
    add_external_product_assign(&mut output, key, &negative_mask_as_trivial_glwe);
    output
}

fn eval_auto(input: &Glwe, degree: usize, key: &FourierKey, audit: Option<AuditMode<'_>>) -> Glwe {
    let actual_input_phase = audit.map(|mode| decrypt_glwe_phase(input, mode.secret_key));
    let output = eval_auto_core(input, degree, key);
    if let (Some(mode), Some(input_phase)) = (audit, actual_input_phase) {
        let expected_from_actual = automorphism_oracle_inverse(&input_phase, degree);
        let actual_output_phase = decrypt_glwe_phase(&output, mode.secret_key);
        mode.sink.borrow_mut().record(
            degree,
            maximum_centered_error(&actual_output_phase, &expected_from_actual),
        );
    }
    output
}

fn lwe_to_glwe_constant(input: &Lwe) -> Glwe {
    assert_eq!(input.lwe_size().to_lwe_dimension().0, LWE_DIMENSION);
    let mut output = GlweCiphertext::new(
        0u64,
        GlweDimension(GLWE_DIMENSION).to_glwe_size(),
        PolynomialSize(POLYNOMIAL_SIZE),
        input.ciphertext_modulus(),
    );
    let (lwe_mask, lwe_body) = input.get_mask_and_body();
    let (mut glwe_mask, mut glwe_body) = output.get_mut_mask_and_body();
    let source = lwe_mask.as_ref();
    let destination = glwe_mask.as_mut();
    destination[0] = source[0];
    for index in 1..POLYNOMIAL_SIZE {
        destination[index] = source[POLYNOMIAL_SIZE - index].wrapping_neg();
    }
    *glwe_body.as_mut().get_mut(0).expect("constant coefficient") = *lwe_body.data;
    output
}

fn monomial_mul_assign(input: &mut Glwe, degree: usize) {
    assert!(degree < POLYNOMIAL_SIZE);
    for component in input.as_mut().chunks_exact_mut(POLYNOMIAL_SIZE) {
        let source = component.to_vec();
        component.fill(0);
        for (index, value) in source.into_iter().enumerate() {
            let exponent = index + degree;
            if exponent < POLYNOMIAL_SIZE {
                component[exponent] = component[exponent].wrapping_add(value);
            } else {
                component[exponent - POLYNOMIAL_SIZE] =
                    component[exponent - POLYNOMIAL_SIZE].wrapping_sub(value);
            }
        }
    }
}

fn key<'a>(keys: &'a HashMap<usize, FourierKey>, degree: usize) -> &'a FourierKey {
    keys.get(&degree).expect("missing frozen automorphism key")
}

fn merge_unnormalized(
    even: &Glwe,
    odd: &Glwe,
    subtree_count: usize,
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    let mut shifted_odd = odd.clone();
    monomial_mul_assign(&mut shifted_odd, POLYNOMIAL_SIZE / subtree_count);
    let mut difference = even.clone();
    glwe_ciphertext_sub_assign(&mut difference, &shifted_odd);
    let mut output = eval_auto(
        &difference,
        subtree_count + 1,
        key(keys, subtree_count + 1),
        audit,
    );
    glwe_ciphertext_add_assign(&mut output, even);
    glwe_ciphertext_add_assign(&mut output, &shifted_odd);
    output
}

fn merge_g1_floor(
    even: &Glwe,
    odd: &Glwe,
    subtree_count: usize,
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    // Faithful TFHEpp order: shift the odd branch first, then unsigned /2 on
    // both branch ciphertexts.  Negacyclic sign changes do not commute with
    // canonical unsigned floor division.
    let mut even_half = even.clone();
    let mut odd_half = odd.clone();
    monomial_mul_assign(&mut odd_half, POLYNOMIAL_SIZE / subtree_count);
    normalize_glwe_assign(&mut even_half, 1, Rounding::Floor);
    normalize_glwe_assign(&mut odd_half, 1, Rounding::Floor);
    let mut difference = even_half.clone();
    glwe_ciphertext_sub_assign(&mut difference, &odd_half);
    let mut output = eval_auto(
        &difference,
        subtree_count + 1,
        key(keys, subtree_count + 1),
        audit,
    );
    glwe_ciphertext_add_assign(&mut output, &even_half);
    glwe_ciphertext_add_assign(&mut output, &odd_half);
    output
}

fn pack_g1_floor(
    inputs: &[Glwe],
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    assert!(inputs.len().is_power_of_two() && !inputs.is_empty());
    if inputs.len() == 1 {
        return inputs[0].clone();
    }
    let even_inputs: Vec<_> = inputs.iter().step_by(2).cloned().collect();
    let odd_inputs: Vec<_> = inputs.iter().skip(1).step_by(2).cloned().collect();
    let even = pack_g1_floor(&even_inputs, keys, audit);
    let odd = pack_g1_floor(&odd_inputs, keys, audit);
    merge_g1_floor(&even, &odd, inputs.len(), keys, audit)
}

fn first_two_pack_levels_unnormalized(
    inputs: &[Glwe],
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Vec<Glwe> {
    assert_eq!(inputs.len(), 8);
    // Match the exact even/odd recursive partition used by pack_g1_floor.
    // The deepest subtrees are (0,4), (2,6), (1,5), (3,7), not adjacent
    // input pairs. Grouping changes normalization boundaries only; it must not
    // change the Chen permutation.
    let bottom = [
        merge_unnormalized(&inputs[0], &inputs[4], 2, keys, audit),
        merge_unnormalized(&inputs[2], &inputs[6], 2, keys, audit),
        merge_unnormalized(&inputs[1], &inputs[5], 2, keys, audit),
        merge_unnormalized(&inputs[3], &inputs[7], 2, keys, audit),
    ];
    vec![
        merge_unnormalized(&bottom[0], &bottom[1], 4, keys, audit),
        merge_unnormalized(&bottom[2], &bottom[3], 4, keys, audit),
    ]
}

fn trace_step_unnormalized(
    input: &mut Glwe,
    degree: usize,
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) {
    let transformed = eval_auto(input, degree, key(keys, degree), audit);
    glwe_ciphertext_add_assign(input, &transformed);
}

fn run_g1_floor(
    inputs: &[Lwe],
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    let embedded: Vec<_> = inputs.iter().map(lwe_to_glwe_constant).collect();
    let mut output = pack_g1_floor(&embedded, keys, audit);
    for degree in TRACE_DEGREES {
        normalize_glwe_assign(&mut output, 1, Rounding::Floor);
        trace_step_unnormalized(&mut output, degree, keys, audit);
    }
    output
}

fn run_g2(
    inputs: &[Lwe],
    rounding: Rounding,
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    // Frozen schedule [2,2,2,2,2].  Block 1 starts on eight input LWEs and
    // spans the bottom (degree 3) and middle (degree 5) packing layers.
    let embedded: Vec<_> = inputs
        .iter()
        .map(|input| {
            let mut shifted = input.clone();
            normalize_lwe_assign(&mut shifted, 2, rounding);
            lwe_to_glwe_constant(&shifted)
        })
        .collect();
    let mut middle = first_two_pack_levels_unnormalized(&embedded, keys, audit);

    // Block 2 starts on the two live GLWEs, then spans top packing degree 9
    // and the first retained trace degree 33.
    for branch in &mut middle {
        normalize_glwe_assign(branch, 2, rounding);
    }
    let mut output = merge_unnormalized(&middle[0], &middle[1], 8, keys, audit);
    trace_step_unnormalized(&mut output, TRACE_DEGREES[0], keys, audit);

    // Three two-stage trace blocks: (65,129), (257,513), (1025,2049).
    for degrees in TRACE_DEGREES[1..].chunks_exact(2) {
        normalize_glwe_assign(&mut output, 2, rounding);
        for &degree in degrees {
            trace_step_unnormalized(&mut output, degree, keys, audit);
        }
    }
    output
}

fn run_arm(
    inputs: &[Lwe],
    arm: Arm,
    keys: &HashMap<usize, FourierKey>,
    audit: Option<AuditMode<'_>>,
) -> Glwe {
    match arm {
        Arm::G1Floor => run_g1_floor(inputs, keys, audit),
        Arm::G2Floor => run_g2(inputs, Rounding::Floor, keys, audit),
        Arm::G2Nearest => run_g2(inputs, Rounding::Nearest, keys, audit),
    }
}

fn mul_public_width127_kernel(input: &Glwe) -> Glwe {
    let mut output = GlweCiphertext::new(
        0u64,
        input.glwe_size(),
        input.polynomial_size(),
        input.ciphertext_modulus(),
    );
    for (source, destination) in input
        .as_ref()
        .chunks_exact(POLYNOMIAL_SIZE)
        .zip(output.as_mut().chunks_exact_mut(POLYNOMIAL_SIZE))
    {
        for (index, &value) in source.iter().enumerate() {
            for offset in -STRICT_RADIUS..=STRICT_RADIUS {
                let exponent = index as isize + offset;
                let cycle = exponent.div_euclid(POLYNOMIAL_SIZE as isize);
                let target = exponent.rem_euclid(POLYNOMIAL_SIZE as isize) as usize;
                if cycle & 1 == 0 {
                    destination[target] = destination[target].wrapping_add(value);
                } else {
                    destination[target] = destination[target].wrapping_sub(value);
                }
            }
        }
    }
    output
}

#[cfg(test)]
fn add_kernel_word(output: &mut [u64], center: isize, word: u64) {
    for offset in -STRICT_RADIUS..=STRICT_RADIUS {
        let exponent = center + offset;
        let cycle = exponent.div_euclid(POLYNOMIAL_SIZE as isize);
        let target = exponent.rem_euclid(POLYNOMIAL_SIZE as isize) as usize;
        if cycle & 1 == 0 {
            output[target] = output[target].wrapping_add(word);
        } else {
            output[target] = output[target].wrapping_sub(word);
        }
    }
}

#[cfg(test)]
fn ideal_post_kernel(fixture: &Fixture) -> Vec<u64> {
    let mut output = vec![0u64; POLYNOMIAL_SIZE];
    for (index, &word) in fixture.left.iter().enumerate() {
        add_kernel_word(
            &mut output,
            LEFT_CONTROL * BOX_SIZE + index as isize * SAMPLE_STEP,
            word,
        );
    }
    for (index, &word) in fixture.right.iter().enumerate() {
        add_kernel_word(
            &mut output,
            RIGHT_CONTROL * BOX_SIZE + index as isize * SAMPLE_STEP,
            word,
        );
    }
    output
}

fn virtual_sample(word: u64, virtual_degree: isize) -> u64 {
    let cycle = virtual_degree.div_euclid(POLYNOMIAL_SIZE as isize);
    if cycle & 1 == 0 {
        word
    } else {
        word.wrapping_neg()
    }
}

fn evaluate_output(
    output: &Glwe,
    fixture: &Fixture,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
) -> Outcome {
    let audit_started = Instant::now();
    let mut decrypted = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    decrypt_glwe_ciphertext(glwe_secret_key, output, &mut decrypted);

    let equivalent_lwe_key = glwe_secret_key.as_lwe_secret_key();
    let mut extracted = LweCiphertext::new(
        0u64,
        equivalent_lwe_key.lwe_dimension().to_lwe_size(),
        output.ciphertext_modulus(),
    );
    let mut robust_tuples = 0usize;
    let mut robust_words = 0usize;
    let mut tuple_decode_failures = 0usize;
    let mut word_decode_failures = 0usize;
    let mut extraction_consistency_failures = 0usize;
    let mut maximum_robust_word_error = 0u64;
    let mut maximum_post_kernel_certified_error = 0u64;

    for (control, expected_tuple) in [
        (LEFT_CONTROL, &fixture.left),
        (RIGHT_CONTROL, &fixture.right),
    ] {
        for error in -STRICT_RADIUS..=STRICT_RADIUS {
            let mut tuple_failed = false;
            for (index, &expected) in expected_tuple.iter().enumerate() {
                let virtual_degree = control * BOX_SIZE + error + index as isize * SAMPLE_STEP;
                let degree = virtual_degree.rem_euclid(POLYNOMIAL_SIZE as isize) as usize;
                extract_lwe_sample_from_glwe_ciphertext(
                    output,
                    &mut extracted,
                    MonomialDegree(degree),
                );
                let raw = decrypt_lwe_ciphertext(&equivalent_lwe_key, &extracted).0;
                let observed = virtual_sample(raw, virtual_degree);
                let from_full_decryption =
                    virtual_sample(decrypted.as_ref()[degree], virtual_degree);
                if observed != from_full_decryption {
                    extraction_consistency_failures += 1;
                }
                let absolute_error = centered_abs_error(observed, expected);
                maximum_post_kernel_certified_error = maximum_post_kernel_certified_error
                    .max(centered_abs_error(from_full_decryption, expected));
                maximum_robust_word_error = maximum_robust_word_error.max(absolute_error);
                let delta_log = if index < 3 {
                    SCORE_DELTA_LOG
                } else {
                    ID_DELTA_LOG
                };
                if absolute_error >= (1u64 << (delta_log - 1)) {
                    word_decode_failures += 1;
                    tuple_failed = true;
                }
                robust_words += 1;
            }
            if tuple_failed {
                tuple_decode_failures += 1;
            }
            robust_tuples += 1;
        }
    }

    Outcome {
        robust_tuples,
        robust_words,
        tuple_decode_failures,
        word_decode_failures,
        extraction_consistency_failures,
        maximum_post_kernel_certified_error,
        maximum_robust_word_error,
        maximum_ingress_lwe_error: 0,
        ingress_lwe_decode_failures: 0,
        stage_evalauto_calls: 0,
        maximum_incremental_evalauto_error: 0,
        stage_audit_replay_mismatches: 0,
        stage_call_count_failures: 0,
        pack_trace_time: Duration::ZERO,
        kernel_time: Duration::ZERO,
        client_audit_time: audit_started.elapsed(),
        stage_audit_time: Duration::ZERO,
    }
}

fn encrypt_inputs(
    fixture: &Fixture,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Vec<Lwe> {
    let equivalent_lwe_key = glwe_secret_key.as_lwe_secret_key();
    fixture
        .slot_words()
        .into_iter()
        .map(|word| {
            let mut output = LweCiphertext::new(
                0u64,
                equivalent_lwe_key.lwe_dimension().to_lwe_size(),
                CiphertextModulus::new_native(),
            );
            encrypt_lwe_ciphertext(
                &equivalent_lwe_key,
                &mut output,
                Plaintext(word),
                noise_distribution,
                generator,
            );
            output
        })
        .collect()
}

fn ingress_lwe_audit(
    inputs: &[Lwe],
    fixture: &Fixture,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
) -> (u64, usize) {
    const SLOT_DELTA_LOGS: [u32; 8] = [59, 56, 59, 59, 59, 56, 59, 59];
    let equivalent_lwe_key = glwe_secret_key.as_lwe_secret_key();
    let mut maximum_error = 0u64;
    let mut decode_failures = 0usize;
    for ((input, expected), delta_log) in
        inputs.iter().zip(fixture.slot_words()).zip(SLOT_DELTA_LOGS)
    {
        let observed = decrypt_lwe_ciphertext(&equivalent_lwe_key, input).0;
        let error = centered_abs_error(observed, expected);
        maximum_error = maximum_error.max(error);
        if error >= (1u64 << (delta_log - 1)) {
            decode_failures += 1;
        }
    }
    (maximum_error, decode_failures)
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn primitive_plaintext(seed: u64) -> Vec<u64> {
    let mut state = seed;
    let delta = 1u64 << ID_DELTA_LOG;
    (0..POLYNOMIAL_SIZE)
        .map(|index| {
            let random = xorshift64(&mut state);
            let symbol = if index % 31 == 0 {
                (random % 127) as i64 - 63
            } else {
                0
            };
            (symbol as u64).wrapping_mul(delta)
        })
        .collect()
}

fn audit_evalauto_primitive(
    degree: usize,
    key: &FourierKey,
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    seed: u64,
) -> PrimitiveOutcome {
    let message = primitive_plaintext(seed);
    let expected_total = automorphism_oracle_inverse(&message, degree);
    assert_eq!(
        automorphism_slice(&message, degree),
        expected_total,
        "forward automorphism disagrees with independent oracle"
    );
    let mut input = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        CiphertextModulus::new_native(),
    );
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut input,
        &PlaintextList::from_container(message.clone()),
        noise_distribution,
        generator,
    );
    let actual_input = decrypt_glwe_phase(&input, glwe_secret_key);
    let expected_from_actual = automorphism_oracle_inverse(&actual_input, degree);
    let eval_started = Instant::now();
    let output = std::hint::black_box(eval_auto_core(
        std::hint::black_box(&input),
        degree,
        std::hint::black_box(key),
    ));
    let eval_time = eval_started.elapsed();
    let actual_output = decrypt_glwe_phase(&output, glwe_secret_key);
    let input_maximum_error = maximum_centered_error(&actual_input, &message);
    let incremental_evalauto_maximum_error =
        maximum_centered_error(&actual_output, &expected_from_actual);
    let total_maximum_error = maximum_centered_error(&actual_output, &expected_total);
    let threshold = 1u64 << (ID_DELTA_LOG - 1);
    PrimitiveOutcome {
        input_maximum_error,
        incremental_evalauto_maximum_error,
        total_maximum_error,
        input_decode_failures: actual_input
            .iter()
            .zip(&message)
            .filter(|&(&actual, &wanted)| centered_abs_error(actual, wanted) >= threshold)
            .count(),
        output_decode_failures: actual_output
            .iter()
            .zip(&expected_total)
            .filter(|&(&actual, &wanted)| centered_abs_error(actual, wanted) >= threshold)
            .count(),
        eval_time,
    }
}

fn accumulate(total: &mut ArmTotals, outcome: &Outcome) {
    total.cases += 1;
    if outcome.tuple_decode_failures != 0
        || outcome.word_decode_failures != 0
        || outcome.extraction_consistency_failures != 0
        || outcome.ingress_lwe_decode_failures != 0
        || outcome.stage_audit_replay_mismatches != 0
        || outcome.stage_call_count_failures != 0
    {
        total.failed_cases += 1;
    }
    total.robust_tuples += outcome.robust_tuples;
    total.robust_words += outcome.robust_words;
    total.tuple_decode_failures += outcome.tuple_decode_failures;
    total.word_decode_failures += outcome.word_decode_failures;
    total.extraction_consistency_failures += outcome.extraction_consistency_failures;
    total.maximum_post_kernel_certified_error = total
        .maximum_post_kernel_certified_error
        .max(outcome.maximum_post_kernel_certified_error);
    total.maximum_robust_word_error = total
        .maximum_robust_word_error
        .max(outcome.maximum_robust_word_error);
    total.maximum_ingress_lwe_error = total
        .maximum_ingress_lwe_error
        .max(outcome.maximum_ingress_lwe_error);
    total.ingress_lwe_decode_failures += outcome.ingress_lwe_decode_failures;
    total.stage_evalauto_calls += outcome.stage_evalauto_calls;
    total.maximum_incremental_evalauto_error = total
        .maximum_incremental_evalauto_error
        .max(outcome.maximum_incremental_evalauto_error);
    total.stage_audit_replay_mismatches += outcome.stage_audit_replay_mismatches;
    total.stage_call_count_failures += outcome.stage_call_count_failures;
    total.pack_trace_time += outcome.pack_trace_time;
    total.kernel_time += outcome.kernel_time;
    total.client_audit_time += outcome.client_audit_time;
    total.stage_audit_time += outcome.stage_audit_time;
}

fn empirical_upper_95_zero_failures(cases: usize, failures: usize) -> String {
    if cases == 0 || failures != 0 {
        return "NA".to_string();
    }
    let upper = 1.0 - 0.05f64.powf(1.0 / cases as f64);
    format!("{upper:.9}")
}

fn run(args: Args) {
    assert_eq!(PARAMS.glwe_dimension.0, GLWE_DIMENSION);
    assert_eq!(PARAMS.polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(PARAMS.pbs_base_log.0, AutoParams::PBS_23X1.base_log);
    assert_eq!(PARAMS.pbs_level.0, AutoParams::PBS_23X1.level_count);
    assert_eq!(PACK_DEGREES, [3, 5, 9]);
    let total_started = Instant::now();
    let mut all_parameter_sets_passed = true;

    for auto_params in &args.auto_params {
        assert!(auto_params.base_log * auto_params.level_count <= 64);
        let mut totals: HashMap<&'static str, ArmTotals> = Arm::ALL
            .into_iter()
            .map(|arm| (arm.name(), ArmTotals::default()))
            .collect();
        let mut primitive_cases = 0usize;
        let mut primitive_coefficients = 0usize;
        let mut primitive_input_decode_failures = 0usize;
        let mut primitive_output_decode_failures = 0usize;
        let mut primitive_input_maximum_error = 0u64;
        let mut primitive_incremental_maximum_error = 0u64;
        let mut primitive_total_maximum_error = 0u64;
        let mut primitive_eval_time = Duration::ZERO;

        for keyset in 0..args.fresh_keysets {
            let key_started = Instant::now();
            let client_key = ClientKey::new(PARAMS);
            let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
            let mut seeder_box = new_seeder();
            let seeder = seeder_box.as_mut();
            let mut generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let mut keys = HashMap::new();
            for degree in AUTOMORPHISM_DEGREES {
                keys.insert(
                    degree,
                    generate_eval_auto_key(
                        &glwe_secret_key,
                        degree,
                        *auto_params,
                        client_params.glwe_noise_distribution(),
                        &mut generator,
                    ),
                );
            }
            println!(
                "KEY,auto_params={},keyset={},key_and_client_generation_s={:.6},automorphism_keys=10,full_fourier_key_bytes={},full_fourier_key_mib={:.6},ephemeral=true,secret_material_persisted=false,cross_parameter_pairing=false",
                auto_params.name,
                keyset + 1,
                key_started.elapsed().as_secs_f64(),
                auto_params.ten_key_fourier_bytes(),
                auto_params.ten_key_fourier_bytes() as f64 / (1024.0 * 1024.0),
            );

            // The primitive audit gives the requested three-way attribution on
            // a canonical encrypted GLWE message: encryption input error,
            // EvalAuto-only error against sigma(actual input phase), and total
            // error against sigma(message). It is separate from the composed
            // packing audit because inverse-embedded LWEs contain non-message
            // coefficients before the retained trace projection.
            for &degree in &AUTOMORPHISM_DEGREES {
                let primitive = audit_evalauto_primitive(
                    degree,
                    key(&keys, degree),
                    &glwe_secret_key,
                    client_params.glwe_noise_distribution(),
                    &mut generator,
                    0xA990_0000_0000_0001u64
                        ^ (keyset as u64).rotate_left(31)
                        ^ (degree as u64).rotate_left(17)
                        ^ ((auto_params.base_log as u64) << 8)
                        ^ auto_params.level_count as u64,
                );
                println!(
                    "PRIMITIVE_AUDIT,auto_params={},keyset={},degree={},delta_log={},input_error_vs_message_max={},incremental_evalauto_error_vs_sigma_actual_input_max={},total_error_vs_sigma_message_max={},input_decode_failures={},output_decode_failures={},coefficients={},eval_s={:.9},component_only=true",
                    auto_params.name,
                    keyset + 1,
                    degree,
                    ID_DELTA_LOG,
                    primitive.input_maximum_error,
                    primitive.incremental_evalauto_maximum_error,
                    primitive.total_maximum_error,
                    primitive.input_decode_failures,
                    primitive.output_decode_failures,
                    POLYNOMIAL_SIZE,
                    primitive.eval_time.as_secs_f64(),
                );
                primitive_cases += 1;
                primitive_coefficients += POLYNOMIAL_SIZE;
                primitive_input_decode_failures += primitive.input_decode_failures;
                primitive_output_decode_failures += primitive.output_decode_failures;
                primitive_input_maximum_error =
                    primitive_input_maximum_error.max(primitive.input_maximum_error);
                primitive_incremental_maximum_error = primitive_incremental_maximum_error
                    .max(primitive.incremental_evalauto_maximum_error);
                primitive_total_maximum_error =
                    primitive_total_maximum_error.max(primitive.total_maximum_error);
                primitive_eval_time += primitive.eval_time;
            }

            for trial in 0..args.trials_per_keyset {
                let fixture = fixture(keyset * args.trials_per_keyset + trial);
                let encryption_started = Instant::now();
                let inputs = encrypt_inputs(
                    &fixture,
                    &glwe_secret_key,
                    client_params.glwe_noise_distribution(),
                    &mut generator,
                );
                let encryption_time = encryption_started.elapsed();
                let (maximum_ingress_lwe_error, ingress_lwe_decode_failures) =
                    ingress_lwe_audit(&inputs, &fixture, &glwe_secret_key);

                // Rotate order deterministically so timing is not tied to one
                // fixed arm order. The separately replayed stage audit is
                // deliberately outside pack_trace_time.
                for offset in 0..Arm::ALL.len() {
                    let arm = Arm::ALL[(keyset + trial + offset) % Arm::ALL.len()];
                    let pack_started = Instant::now();
                    let packed = std::hint::black_box(run_arm(
                        std::hint::black_box(&inputs),
                        arm,
                        std::hint::black_box(&keys),
                        None,
                    ));
                    let pack_trace_time = pack_started.elapsed();
                    let kernel_started = Instant::now();
                    let post_kernel = std::hint::black_box(mul_public_width127_kernel(
                        std::hint::black_box(&packed),
                    ));
                    let kernel_time = kernel_started.elapsed();
                    let mut outcome = evaluate_output(&post_kernel, &fixture, &glwe_secret_key);

                    let stage_sink = RefCell::new(EvalAutoAudit::default());
                    let stage_audit_started = Instant::now();
                    let audited_packed = run_arm(
                        &inputs,
                        arm,
                        &keys,
                        Some(AuditMode {
                            secret_key: &glwe_secret_key,
                            sink: &stage_sink,
                        }),
                    );
                    let stage_audit_time = stage_audit_started.elapsed();
                    let stage_audit = stage_sink.into_inner();
                    let replay_mismatches = usize::from(audited_packed.as_ref() != packed.as_ref());
                    let call_count_failures = usize::from(stage_audit.observations.len() != 14);
                    for observation in &stage_audit.observations {
                        println!(
                            "STAGE_AUDIT_CALL,auto_params={},keyset={},trial={},arm={},call_index={},degree={},incremental_evalauto_error_vs_sigma_actual_input_max={},message_reference_available=false,client_decryption_untimed=true",
                            auto_params.name,
                            keyset + 1,
                            trial + 1,
                            arm.name(),
                            observation.call_index,
                            observation.degree,
                            observation.maximum_incremental_error,
                        );
                    }

                    outcome.maximum_ingress_lwe_error = maximum_ingress_lwe_error;
                    outcome.ingress_lwe_decode_failures = ingress_lwe_decode_failures;
                    outcome.stage_evalauto_calls = stage_audit.observations.len();
                    outcome.maximum_incremental_evalauto_error =
                        stage_audit.maximum_incremental_error();
                    outcome.stage_audit_replay_mismatches = replay_mismatches;
                    outcome.stage_call_count_failures = call_count_failures;
                    outcome.pack_trace_time = pack_trace_time;
                    outcome.kernel_time = kernel_time;
                    outcome.stage_audit_time = stage_audit_time;
                    println!(
                        "CASE,auto_params={},keyset={},trial={},fixture={},arm={},input_encrypt_s={:.6},pack_trace_s={:.6},kernel_s={:.6},post_kernel_client_audit_s={:.6},stage_audit_replay_s={:.6},ingress_lwe_error_vs_message_max={},ingress_lwe_decode_failures={},stage_evalauto_calls={},stage_call_count_failures={},stage_replay_ciphertext_mismatches={},stage_incremental_evalauto_error_vs_sigma_actual_input_max={},robust_tuples={},robust_words={},tuple_decode_failures={},word_decode_failures={},extraction_consistency_failures={},max_post_kernel_certified_coefficient_total_error_vs_message={},max_robust_word_total_error_vs_message={},full_selector_included=false",
                        auto_params.name,
                        keyset + 1,
                        trial + 1,
                        fixture.label,
                        arm.name(),
                        encryption_time.as_secs_f64(),
                        outcome.pack_trace_time.as_secs_f64(),
                        outcome.kernel_time.as_secs_f64(),
                        outcome.client_audit_time.as_secs_f64(),
                        outcome.stage_audit_time.as_secs_f64(),
                        outcome.maximum_ingress_lwe_error,
                        outcome.ingress_lwe_decode_failures,
                        outcome.stage_evalauto_calls,
                        outcome.stage_call_count_failures,
                        outcome.stage_audit_replay_mismatches,
                        outcome.maximum_incremental_evalauto_error,
                        outcome.robust_tuples,
                        outcome.robust_words,
                        outcome.tuple_decode_failures,
                        outcome.word_decode_failures,
                        outcome.extraction_consistency_failures,
                        outcome.maximum_post_kernel_certified_error,
                        outcome.maximum_robust_word_error,
                    );
                    accumulate(totals.get_mut(arm.name()).expect("arm total"), &outcome);
                }
            }
        }

        let primitive_status =
            if primitive_input_decode_failures == 0 && primitive_output_decode_failures == 0 {
                "PASS_SAMPLED_PRIMITIVE_ATTRIBUTION"
            } else {
                "FAIL_SAMPLED_PRIMITIVE_ATTRIBUTION"
            };
        println!(
            "PRIMITIVE_RESULT,auto_params={},status={},cases={},coefficients={},input_decode_failures={},output_decode_failures={},input_error_vs_message_max={},incremental_evalauto_error_vs_sigma_actual_input_max={},total_error_vs_sigma_message_max={},eval_total_s={:.6},eval_mean_s={:.9},component_only=true,composed_pfail_proven=false",
            auto_params.name,
            primitive_status,
            primitive_cases,
            primitive_coefficients,
            primitive_input_decode_failures,
            primitive_output_decode_failures,
            primitive_input_maximum_error,
            primitive_incremental_maximum_error,
            primitive_total_maximum_error,
            primitive_eval_time.as_secs_f64(),
            primitive_eval_time.as_secs_f64() / primitive_cases as f64,
        );

        for arm in Arm::ALL {
            let total = totals.get(arm.name()).expect("arm total");
            let status = if total.failed_cases == 0 {
                "PASS_SAMPLED_POST_KERNEL_COMPONENT"
            } else {
                "FAIL_SAMPLED_POST_KERNEL_COMPONENT"
            };
            println!(
                "ARM_RESULT,auto_params={},arm={},status={},cases={},failed_cases={},robust_tuples={},robust_words={},tuple_decode_failures={},word_decode_failures={},extraction_consistency_failures={},ingress_lwe_decode_failures={},stage_call_count_failures={},stage_replay_ciphertext_mismatches={},max_ingress_lwe_error_vs_message={},max_incremental_evalauto_error_vs_sigma_actual_input={},max_post_kernel_certified_coefficient_total_error_vs_message={},max_robust_word_total_error_vs_message={},pack_trace_total_s={:.6},pack_trace_mean_s={:.9},kernel_total_s={:.6},kernel_mean_s={:.9},post_kernel_client_audit_total_s={:.6},stage_audit_replay_total_s={:.6},empirical_component_case_pfail_upper95_if_zero={},component_only=true,full_selector_proven=false,composed_pfail_proven=false,runtime_frontier_promoted=false",
                auto_params.name,
                arm.name(),
                status,
                total.cases,
                total.failed_cases,
                total.robust_tuples,
                total.robust_words,
                total.tuple_decode_failures,
                total.word_decode_failures,
                total.extraction_consistency_failures,
                total.ingress_lwe_decode_failures,
                total.stage_call_count_failures,
                total.stage_audit_replay_mismatches,
                total.maximum_ingress_lwe_error,
                total.maximum_incremental_evalauto_error,
                total.maximum_post_kernel_certified_error,
                total.maximum_robust_word_error,
                total.pack_trace_time.as_secs_f64(),
                total.pack_trace_time.as_secs_f64() / total.cases as f64,
                total.kernel_time.as_secs_f64(),
                total.kernel_time.as_secs_f64() / total.cases as f64,
                total.client_audit_time.as_secs_f64(),
                total.stage_audit_time.as_secs_f64(),
                empirical_upper_95_zero_failures(total.cases, total.failed_cases),
            );
            if total.failed_cases != 0 {
                all_parameter_sets_passed = false;
            }
        }
        if primitive_input_decode_failures != 0 || primitive_output_decode_failures != 0 {
            all_parameter_sets_passed = false;
        }
    }

    println!(
        "RESULT,status={},auto_parameter_sets={},fresh_keysets_per_parameter_set={},trials_per_keyset={},wall_s={:.6},cross_parameter_pairing=false,causal_cross_parameter_comparison_allowed=false,tie_first_decision_encrypted=false,reject0_and_id_payloads_exercised=true,encrypted_control_br_included=false,full_selector_proven=false,full_tournament_proven=false,composed_pfail_proven=false,runtime_frontier_promoted=false",
        if all_parameter_sets_passed {
            "PASS_SAMPLED_COMPONENT_ARMS_REPORTED_SEPARATELY"
        } else {
            "FAIL_SAMPLED_COMPONENT"
        },
        args.auto_params
            .iter()
            .map(|parameter| parameter.name)
            .collect::<Vec<_>>()
            .join("|"),
        args.fresh_keysets,
        args.trials_per_keyset,
        total_started.elapsed().as_secs_f64(),
    );
    assert!(
        all_parameter_sets_passed,
        "A99 sampled component failure; inspect per-parameter and per-arm records"
    );
}

fn main() {
    let args = parse_args_from(env::args().skip(1)).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        std::process::exit(2);
    });
    let parameter_names = args
        .auto_params
        .iter()
        .map(|parameter| parameter.name)
        .collect::<Vec<_>>()
        .join("|");
    println!(
        "PLAN,artifact=A99,tfhe=0.11.3,params=A44-p16,glwe_dimension=1,polynomial_size=2048,evalauto_parameter_sets={},arms=g1-floor|g2-floor|g2-nearest,g2_schedule=2+2+2+2+2,packing_degrees=3|5|9,partial_trace_degrees=33|65|129|257|513|1025|2049,kernel_width=127,rotation_error_radius=63,clear_position_sampling=true,stage_actual_phase_audit_separate_from_timing=true,cross_parameter_pairing=false,causal_cross_parameter_comparison_allowed=false,encrypted_control_br_included=false,fresh_keysets={},trials_per_keyset={},run={},ack_component_only={}",
        parameter_names,
        args.fresh_keysets,
        args.trials_per_keyset,
        args.run,
        args.ack_component_only
    );
    if !args.run {
        println!("STATUS,STATIC_PLAN_ONLY_USE_--run_--ack-component-only_AFTER_EXPLICIT_FHE_GATE");
        return;
    }
    run(args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_shift_handles_wrap_and_half_ties_without_inverse() {
        assert_eq!(shifted_word(0, 2, Rounding::Nearest), 0);
        assert_eq!(shifted_word(1, 2, Rounding::Nearest), 0);
        assert_eq!(shifted_word(2, 2, Rounding::Nearest), 1);
        assert_eq!(shifted_word(u64::MAX, 2, Rounding::Nearest), 0);
        assert_eq!(shifted_word(u64::MAX - 1, 2, Rounding::Nearest), 0);
        assert_eq!(shifted_word(u64::MAX, 2, Rounding::Floor), (1u64 << 62) - 1);
    }

    #[test]
    fn fixture_slot_map_matches_a92_d2() {
        let fixture = fixture(1);
        assert_eq!(
            fixture.slot_words(),
            [
                fixture.right[2].wrapping_neg(),
                fixture.right[3].wrapping_neg(),
                fixture.left[0],
                fixture.left[1],
                fixture.left[2],
                fixture.left[3],
                fixture.right[0],
                fixture.right[1],
            ]
        );
    }

    #[test]
    fn kernel_geometry_retains_both_robust_cells() {
        let fixture = fixture(1);
        let body = ideal_post_kernel(&fixture);
        for (control, expected) in [(LEFT_CONTROL, fixture.left), (RIGHT_CONTROL, fixture.right)] {
            for error in -STRICT_RADIUS..=STRICT_RADIUS {
                for (index, word) in expected.into_iter().enumerate() {
                    let virtual_degree = control * BOX_SIZE + error + index as isize * SAMPLE_STEP;
                    let stored = body[virtual_degree.rem_euclid(POLYNOMIAL_SIZE as isize) as usize];
                    assert_eq!(virtual_sample(stored, virtual_degree), word);
                }
            }
        }
    }

    #[test]
    fn frozen_stage_counts_are_not_flat_path_counts() {
        assert_eq!(PACK_DEGREES.len() + TRACE_DEGREES.len(), 10);
        assert_eq!(7 + TRACE_DEGREES.len(), 14);
        assert_eq!(2 * 7 + TRACE_DEGREES.len(), 21);
        assert_eq!(8 + 2 + 1 + 1 + 1, 13);
    }

    #[test]
    fn forward_automorphism_matches_independent_oracle() {
        let input = primitive_plaintext(0xA990_A990_1357_2468);
        for degree in (1..2 * POLYNOMIAL_SIZE).step_by(2) {
            assert_eq!(
                automorphism_slice(&input, degree),
                automorphism_oracle_inverse(&input, degree),
                "degree {degree}"
            );
        }
    }

    #[test]
    fn parameter_sets_and_full_fourier_storage_are_frozen() {
        assert_eq!(std::mem::size_of::<c64>(), 16);
        assert_eq!(AutoParams::parse("23x1"), Ok(AutoParams::PBS_23X1));
        assert_eq!(AutoParams::parse("8x5"), Ok(AutoParams::TRACE_8X5));
        assert_eq!(AutoParams::parse("7x6"), Ok(AutoParams::TRACE_7X6));
        assert!(AutoParams::parse("8x1").is_err());
        assert_eq!(AutoParams::PBS_23X1.ten_key_fourier_bytes(), 655_360);
        assert_eq!(AutoParams::TRACE_8X5.ten_key_fourier_bytes(), 3_276_800);
        assert_eq!(AutoParams::TRACE_7X6.ten_key_fourier_bytes(), 3_932_160);
    }

    #[test]
    fn runtime_cli_is_bounded_and_fail_closed() {
        assert!(parse_args_from(Vec::<String>::new()).is_ok());
        assert!(parse_args_from(vec!["--run".to_string()]).is_err());
        assert!(parse_args_from(vec!["--ack-component-only".to_string()]).is_err());
        assert!(parse_args_from(vec![
            "--run".to_string(),
            "--ack-component-only".to_string(),
            "--fresh-keysets".to_string(),
            "1".to_string(),
            "--trials-per-keyset".to_string(),
            "1".to_string(),
        ])
        .is_ok());
        assert!(parse_args_from(vec![
            "--run".to_string(),
            "--run".to_string(),
            "--ack-component-only".to_string(),
        ])
        .is_err());
        assert!(parse_args_from(vec![
            "--fresh-keysets".to_string(),
            (MAX_FRESH_KEYSETS + 1).to_string(),
        ])
        .is_err());
        assert!(parse_args_from(vec![
            "--trials-per-keyset".to_string(),
            (MAX_TRIALS_PER_KEYSET + 1).to_string(),
        ])
        .is_err());
    }
}
