//! A101: paired single-EvalAuto component gate for full and pseudo GGSW.
//!
//! This crate intentionally does not implement Chen packing, the grouped trace,
//! or the encrypted selector. Runtime work is fail-closed behind both `--run`
//! and `--ack-component-only`; a dry plan is the default.

use std::env;
use std::mem::size_of;
use std::time::Instant;

use tfhe::core_crypto::algorithms::ggsw_encryption::ggsw_encryption_multiplicative_factor;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_mul;
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::ClientKey;

const POLYNOMIAL_SIZE: usize = 2_048;
const GLWE_DIMENSION: usize = 1;
const VALIDATION_DELTA_LOG: u32 = 56;
const AUTOMORPHISM_DEGREES: [usize; 10] = [3, 5, 9, 33, 65, 129, 257, 513, 1025, 2049];
const MAX_FRESH_KEYSETS: usize = 16;
const MAX_WARMUPS: usize = 1_000;
const MAX_TRIALS_PER_DEGREE: usize = 10_000;

type Glwe = GlweCiphertextOwned<u64>;
type FullFourierKey = FourierGgswCiphertext<aligned_vec::ABox<[c64]>>;
type PseudoFourierKey = PseudoFourierGgswCiphertext<aligned_vec::ABox<[c64]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecompositionConfig {
    label: &'static str,
    base_log: usize,
    level_count: usize,
}

const DECOMPOSITION_CONFIGS: [DecompositionConfig; 3] = [
    DecompositionConfig {
        label: "23x1",
        base_log: 23,
        level_count: 1,
    },
    DecompositionConfig {
        label: "8x5",
        base_log: 8,
        level_count: 5,
    },
    DecompositionConfig {
        label: "7x6",
        base_log: 7,
        level_count: 6,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Args {
    run: bool,
    ack_component_only: bool,
    parameter_filter: String,
    fresh_keysets: usize,
    warmups: usize,
    trials_per_degree: usize,
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

fn parse_nonnegative_bounded(raw: &str, name: &str, maximum: usize) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("invalid {name}: {raw}"))?;
    if value > maximum {
        return Err(format!("{name} must be in 0..={maximum}"));
    }
    Ok(value)
}

fn parse_args_from<I>(arguments: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = Args {
        run: false,
        ack_component_only: false,
        parameter_filter: "all".to_string(),
        fresh_keysets: 1,
        warmups: 2,
        trials_per_degree: 8,
    };
    let mut seen_run = false;
    let mut seen_ack = false;
    let mut seen_params = false;
    let mut seen_fresh = false;
    let mut seen_warmups = false;
    let mut seen_trials = false;
    let mut args = arguments.into_iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--run" if !seen_run => {
                seen_run = true;
                parsed.run = true;
            }
            "--ack-component-only" if !seen_ack => {
                seen_ack = true;
                parsed.ack_component_only = true;
            }
            "--params" if !seen_params => {
                seen_params = true;
                parsed.parameter_filter = args
                    .next()
                    .ok_or_else(|| "missing value after --params".to_string())?;
                if parsed.parameter_filter != "all"
                    && !DECOMPOSITION_CONFIGS
                        .iter()
                        .any(|config| config.label == parsed.parameter_filter)
                {
                    return Err(format!(
                        "unsupported params {}; expected all|23x1|8x5|7x6",
                        parsed.parameter_filter
                    ));
                }
            }
            "--fresh-keysets" if !seen_fresh => {
                seen_fresh = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --fresh-keysets".to_string())?;
                parsed.fresh_keysets =
                    parse_positive_bounded(&raw, "fresh-keysets", MAX_FRESH_KEYSETS)?;
            }
            "--warmups" if !seen_warmups => {
                seen_warmups = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --warmups".to_string())?;
                parsed.warmups = parse_nonnegative_bounded(&raw, "warmups", MAX_WARMUPS)?;
            }
            "--trials-per-degree" if !seen_trials => {
                seen_trials = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value after --trials-per-degree".to_string())?;
                parsed.trials_per_degree =
                    parse_positive_bounded(&raw, "trials-per-degree", MAX_TRIALS_PER_DEGREE)?;
            }
            "-h" | "--help" => {
                println!(
                    "usage: a101_pseudo_ggsw_evalauto_preflight [--params all|23x1|8x5|7x6] [--fresh-keysets N] [--warmups N] [--trials-per-degree N] [--run --ack-component-only]"
                );
                std::process::exit(0);
            }
            "--run"
            | "--ack-component-only"
            | "--params"
            | "--fresh-keysets"
            | "--warmups"
            | "--trials-per-degree" => {
                return Err(format!("duplicate argument: {argument}"));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }

    if parsed.run != parsed.ack_component_only {
        return Err(
            "runtime requires both --run and --ack-component-only; neither is needed for dry-plan"
                .to_string(),
        );
    }
    Ok(parsed)
}

fn selected_configs(args: &Args) -> Vec<DecompositionConfig> {
    DECOMPOSITION_CONFIGS
        .iter()
        .copied()
        .filter(|config| args.parameter_filter == "all" || args.parameter_filter == config.label)
        .collect()
}

fn automorphism_slice_assign(input: &[u64], output: &mut [u64], degree: usize) {
    assert_eq!(input.len(), POLYNOMIAL_SIZE);
    assert_eq!(output.len(), POLYNOMIAL_SIZE);
    assert!(degree % 2 == 1 && degree < 2 * POLYNOMIAL_SIZE);
    output.fill(0);
    for (exponent, &coefficient) in input.iter().enumerate() {
        let product = exponent * degree;
        let destination = product % POLYNOMIAL_SIZE;
        let signed = if (product / POLYNOMIAL_SIZE) % 2 == 0 {
            coefficient
        } else {
            coefficient.wrapping_neg()
        };
        output[destination] = output[destination].wrapping_add(signed);
    }
}

fn automorphism_slice(input: &[u64], degree: usize) -> Vec<u64> {
    let mut output = vec![0u64; POLYNOMIAL_SIZE];
    automorphism_slice_assign(input, &mut output, degree);
    output
}

/// Independent inverse-map oracle for sigma_d in Z/(2^64)[X]/(X^N+1).
///
/// This gathers each destination through d^-1 mod 2N rather than reusing the
/// forward scatter used by both implementation arms.
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

fn automorphism_glwe_assign(input: &Glwe, output: &mut Glwe, degree: usize) {
    assert_eq!(input.polynomial_size().0, POLYNOMIAL_SIZE);
    assert_eq!(input.glwe_size(), output.glwe_size());
    assert_eq!(input.ciphertext_modulus(), output.ciphertext_modulus());
    for (input_polynomial, output_polynomial) in input
        .as_ref()
        .chunks_exact(POLYNOMIAL_SIZE)
        .zip(output.as_mut().chunks_exact_mut(POLYNOMIAL_SIZE))
    {
        automorphism_slice_assign(input_polynomial, output_polynomial, degree);
    }
}

fn encrypt_polynomial_ggsw(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    message: &[u64],
    config: DecompositionConfig,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> GgswCiphertextOwned<u64> {
    assert_eq!(message.len(), POLYNOMIAL_SIZE);
    assert!(config.base_log * config.level_count < u64::BITS as usize);
    let glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::new_native();
    let base_log = DecompositionBaseLog(config.base_log);
    let level_count = DecompositionLevelCount(config.level_count);
    let mut output = GgswCiphertext::new(
        0u64,
        glwe_size,
        polynomial_size,
        base_log,
        level_count,
        modulus,
    );
    let message_polynomial = Polynomial::from_container(message);
    let key_polynomials = glwe_secret_key.as_polynomial_list();

    for (output_index, mut level_matrix) in output.iter_mut().enumerate() {
        let level = DecompositionLevel(level_count.0 - output_index);
        let negative_gadget =
            ggsw_encryption_multiplicative_factor(modulus, level, base_log, Cleartext(1u64));
        let final_row = level_matrix.glwe_size().0 - 1;
        for (row_index, mut row) in level_matrix.as_mut_glwe_list().iter_mut().enumerate() {
            let mut plaintext = Polynomial::new(0u64, polynomial_size);
            if row_index < final_row {
                polynomial_wrapping_mul(
                    &mut plaintext,
                    &key_polynomials.get(row_index),
                    &message_polynomial,
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

#[derive(Clone, Copy, Debug)]
struct KeyBytes {
    standard: usize,
    fourier: usize,
}

fn expected_key_bytes(config: DecompositionConfig) -> (KeyBytes, KeyBytes) {
    let levels = config.level_count;
    let scalar_bytes = size_of::<u64>();
    let complex_bytes = size_of::<c64>();
    let fourier_polynomial_size = POLYNOMIAL_SIZE / 2;
    let glwe_size = GLWE_DIMENSION + 1;
    let full = KeyBytes {
        standard: levels * glwe_size * glwe_size * POLYNOMIAL_SIZE * scalar_bytes,
        fourier: levels * glwe_size * glwe_size * fourier_polynomial_size * complex_bytes,
    };
    let pseudo = KeyBytes {
        standard: levels * GLWE_DIMENSION * glwe_size * POLYNOMIAL_SIZE * scalar_bytes,
        fourier: levels * GLWE_DIMENSION * glwe_size * fourier_polynomial_size * complex_bytes,
    };
    (full, pseudo)
}

fn generate_full_eval_auto_key(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    degree: usize,
    config: DecompositionConfig,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> (FullFourierKey, KeyBytes) {
    let secret_polynomials = glwe_secret_key.as_polynomial_list();
    let secret = secret_polynomials.get(0);
    let automorphed_secret = automorphism_slice(secret.as_ref(), degree);
    let standard = encrypt_polynomial_ggsw(
        glwe_secret_key,
        &automorphed_secret,
        config,
        noise_distribution,
        generator,
    );
    let standard_bytes = standard.as_ref().len() * size_of::<u64>();
    let mut fourier = FourierGgswCiphertext::new(
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        glwe_secret_key.polynomial_size(),
        DecompositionBaseLog(config.base_log),
        DecompositionLevelCount(config.level_count),
    );
    convert_standard_ggsw_ciphertext_to_fourier(&standard, &mut fourier);
    let fourier_bytes = fourier.as_view().data().len() * size_of::<c64>();
    let actual = KeyBytes {
        standard: standard_bytes,
        fourier: fourier_bytes,
    };
    assert_eq!(actual.standard, expected_key_bytes(config).0.standard);
    assert_eq!(actual.fourier, expected_key_bytes(config).0.fourier);
    (fourier, actual)
}

fn generate_pseudo_eval_auto_key(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    degree: usize,
    config: DecompositionConfig,
    noise_distribution: DynamicDistribution<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> (PseudoFourierKey, KeyBytes) {
    let secret_polynomials = glwe_secret_key.as_polynomial_list();
    let secret = secret_polynomials.get(0);
    let automorphed_secret = automorphism_slice(secret.as_ref(), degree);
    let input_secret_key =
        GlweSecretKey::from_container(automorphed_secret, glwe_secret_key.polynomial_size());
    let input_glwe_size = input_secret_key.glwe_dimension().to_glwe_size();
    let output_glwe_size = glwe_secret_key.glwe_dimension().to_glwe_size();
    let mut standard = PseudoGgswCiphertext::new(
        0u64,
        input_glwe_size,
        output_glwe_size,
        glwe_secret_key.polynomial_size(),
        DecompositionBaseLog(config.base_log),
        DecompositionLevelCount(config.level_count),
        CiphertextModulus::new_native(),
    );
    encrypt_pseudo_ggsw_ciphertext(
        glwe_secret_key,
        &input_secret_key,
        &mut standard,
        noise_distribution,
        generator,
    );
    let standard_bytes = standard.as_ref().len() * size_of::<u64>();
    let mut fourier = PseudoFourierGgswCiphertext::new(
        input_glwe_size,
        output_glwe_size,
        glwe_secret_key.polynomial_size(),
        DecompositionBaseLog(config.base_log),
        DecompositionLevelCount(config.level_count),
    );
    convert_standard_pseudo_ggsw_ciphertext_to_fourier(&standard, &mut fourier);
    let fourier_bytes = fourier.as_view().data().len() * size_of::<c64>();
    let actual = KeyBytes {
        standard: standard_bytes,
        fourier: fourier_bytes,
    };
    assert_eq!(actual.standard, expected_key_bytes(config).1.standard);
    assert_eq!(actual.fourier, expected_key_bytes(config).1.fourier);
    (fourier, actual)
}

struct FullWorkspace {
    automorphed: Glwe,
    negative_mask: Glwe,
    output: Glwe,
    buffers: ComputationBuffers,
    scratch_requirement_bytes: usize,
}

impl FullWorkspace {
    fn new(glwe_size: GlweSize, polynomial_size: PolynomialSize, fft: FftView<'_>) -> Self {
        let modulus = CiphertextModulus::new_native();
        let scratch_requirement_bytes =
            add_external_product_assign_mem_optimized_requirement::<u64>(
                glwe_size,
                polynomial_size,
                fft,
            )
            .expect("valid full external-product scratch requirement")
            .unaligned_bytes_required();
        let mut buffers = ComputationBuffers::new();
        buffers.resize(scratch_requirement_bytes);
        Self {
            automorphed: GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus),
            negative_mask: GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus),
            output: GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus),
            buffers,
            scratch_requirement_bytes,
        }
    }

    fn apply(&mut self, input: &Glwe, degree: usize, key: &FullFourierKey, fft: FftView<'_>) {
        automorphism_glwe_assign(input, &mut self.automorphed, degree);
        self.output.as_mut().fill(0);
        self.output
            .get_mut_body()
            .as_mut()
            .copy_from_slice(self.automorphed.get_body().as_ref());
        self.negative_mask.as_mut().fill(0);
        self.negative_mask
            .get_mut_body()
            .as_mut()
            .iter_mut()
            .zip(self.automorphed.get_mask().as_ref())
            .for_each(|(destination, &mask)| *destination = mask.wrapping_neg());
        add_external_product_assign_mem_optimized(
            &mut self.output,
            key,
            &self.negative_mask,
            fft,
            self.buffers.stack(),
        );
    }
}

struct PseudoWorkspace {
    automorphed: Glwe,
    output: Glwe,
    buffers: ComputationBuffers,
    scratch_requirement_bytes: usize,
}

impl PseudoWorkspace {
    fn new(glwe_size: GlweSize, polynomial_size: PolynomialSize, fft: FftView<'_>) -> Self {
        let modulus = CiphertextModulus::new_native();
        let scratch_requirement_bytes =
            glwe_fast_keyswitch_requirement::<u64>(glwe_size, polynomial_size, fft)
                .expect("valid pseudo fast-keyswitch scratch requirement")
                .unaligned_bytes_required();
        let mut buffers = ComputationBuffers::new();
        buffers.resize(scratch_requirement_bytes);
        Self {
            automorphed: GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus),
            output: GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus),
            buffers,
            scratch_requirement_bytes,
        }
    }

    fn apply(&mut self, input: &Glwe, degree: usize, key: &PseudoFourierKey, fft: FftView<'_>) {
        automorphism_glwe_assign(input, &mut self.automorphed, degree);
        glwe_fast_keyswitch(
            &mut self.output,
            key,
            &self.automorphed,
            fft,
            self.buffers.stack(),
        );
    }
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

fn decode_symbol(value: u64) -> i128 {
    let centered = (value as i64) as i128;
    let delta = 1i128 << VALIDATION_DELTA_LOG;
    if centered >= 0 {
        (centered + delta / 2) / delta
    } else {
        -((-centered + delta / 2) / delta)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Observation {
    input_max: u64,
    full_incremental_max: u64,
    full_total_max: u64,
    pseudo_incremental_max: u64,
    pseudo_total_max: u64,
    input_decode_mismatches: usize,
    full_decode_mismatches: usize,
    pseudo_decode_mismatches: usize,
    cross_arm_decode_mismatches: usize,
}

impl Observation {
    fn any_mismatch(self) -> bool {
        self.input_decode_mismatches != 0
            || self.full_decode_mismatches != 0
            || self.pseudo_decode_mismatches != 0
            || self.cross_arm_decode_mismatches != 0
    }

    fn absorb(&mut self, other: Self) {
        self.input_max = self.input_max.max(other.input_max);
        self.full_incremental_max = self.full_incremental_max.max(other.full_incremental_max);
        self.full_total_max = self.full_total_max.max(other.full_total_max);
        self.pseudo_incremental_max = self
            .pseudo_incremental_max
            .max(other.pseudo_incremental_max);
        self.pseudo_total_max = self.pseudo_total_max.max(other.pseudo_total_max);
        self.input_decode_mismatches += other.input_decode_mismatches;
        self.full_decode_mismatches += other.full_decode_mismatches;
        self.pseudo_decode_mismatches += other.pseudo_decode_mismatches;
        self.cross_arm_decode_mismatches += other.cross_arm_decode_mismatches;
    }
}

fn observe(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    plaintext: &[u64],
    input: &Glwe,
    full_output: &Glwe,
    pseudo_output: &Glwe,
    degree: usize,
) -> Observation {
    let mut input_phase = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    let mut full_phase = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    let mut pseudo_phase = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    decrypt_glwe_ciphertext(glwe_secret_key, input, &mut input_phase);
    decrypt_glwe_ciphertext(glwe_secret_key, full_output, &mut full_phase);
    decrypt_glwe_ciphertext(glwe_secret_key, pseudo_output, &mut pseudo_phase);

    let expected_message = automorphism_oracle_inverse(plaintext, degree);
    let expected_from_actual_input = automorphism_oracle_inverse(input_phase.as_ref(), degree);
    let mut result = Observation::default();
    for index in 0..POLYNOMIAL_SIZE {
        result.input_max = result.input_max.max(centered_abs_error(
            input_phase.as_ref()[index],
            plaintext[index],
        ));
        result.full_incremental_max = result.full_incremental_max.max(centered_abs_error(
            full_phase.as_ref()[index],
            expected_from_actual_input[index],
        ));
        result.full_total_max = result.full_total_max.max(centered_abs_error(
            full_phase.as_ref()[index],
            expected_message[index],
        ));
        result.pseudo_incremental_max = result.pseudo_incremental_max.max(centered_abs_error(
            pseudo_phase.as_ref()[index],
            expected_from_actual_input[index],
        ));
        result.pseudo_total_max = result.pseudo_total_max.max(centered_abs_error(
            pseudo_phase.as_ref()[index],
            expected_message[index],
        ));

        let wanted_symbol = decode_symbol(expected_message[index]);
        let input_symbol = decode_symbol(input_phase.as_ref()[index]);
        let full_symbol = decode_symbol(full_phase.as_ref()[index]);
        let pseudo_symbol = decode_symbol(pseudo_phase.as_ref()[index]);
        result.input_decode_mismatches +=
            usize::from(input_symbol != decode_symbol(plaintext[index]));
        result.full_decode_mismatches += usize::from(full_symbol != wanted_symbol);
        result.pseudo_decode_mismatches += usize::from(pseudo_symbol != wanted_symbol);
        result.cross_arm_decode_mismatches += usize::from(full_symbol != pseudo_symbol);
    }
    result
}

#[derive(Debug, Default)]
struct Aggregate {
    observation: Observation,
    measured_cases: usize,
    full_ns: Vec<u128>,
    pseudo_ns: Vec<u128>,
}

fn median(values: &[u128]) -> u128 {
    assert!(!values.is_empty());
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2
    }
}

fn full_arm_runs_first(
    keyset: usize,
    config_index: usize,
    degree_index: usize,
    iteration: usize,
) -> bool {
    (keyset + config_index + degree_index + iteration) % 2 == 0
}

fn run(args: &Args, configs: &[DecompositionConfig]) {
    assert_eq!(PARAMS.glwe_dimension.0, GLWE_DIMENSION);
    assert_eq!(PARAMS.polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(size_of::<u64>(), 8);
    assert_eq!(size_of::<c64>(), 16);

    let polynomial_size = PolynomialSize(POLYNOMIAL_SIZE);
    let glwe_size = GlweDimension(GLWE_DIMENSION).to_glwe_size();
    let fft = Fft::new(polynomial_size);
    let mut full_workspace = FullWorkspace::new(glwe_size, polynomial_size, fft.as_view());
    let mut pseudo_workspace = PseudoWorkspace::new(glwe_size, polynomial_size, fft.as_view());
    println!(
        "WORKSPACE,full_scratch_requirement_bytes={},pseudo_scratch_requirement_bytes={},fft_reused=true,scratch_reused=true,outputs_reused=true",
        full_workspace.scratch_requirement_bytes, pseudo_workspace.scratch_requirement_bytes
    );

    let mut aggregates: Vec<Aggregate> = configs.iter().map(|_| Aggregate::default()).collect();
    let total_started = Instant::now();

    for keyset in 0..args.fresh_keysets {
        let client_started = Instant::now();
        let client_key = ClientKey::new(PARAMS);
        let (glwe_secret_key, _small_secret_key, client_parameters) = client_key.into_raw_parts();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        println!(
            "KEYSET,keyset={},client_generation_ns={},ephemeral=true,secret_material_persisted=false",
            keyset + 1,
            client_started.elapsed().as_nanos()
        );

        for (config_index, &config) in configs.iter().enumerate() {
            let (expected_full_bytes, expected_pseudo_bytes) = expected_key_bytes(config);
            assert_eq!(
                expected_full_bytes.standard,
                2 * expected_pseudo_bytes.standard
            );
            assert_eq!(
                expected_full_bytes.fourier,
                2 * expected_pseudo_bytes.fourier
            );

            for (degree_index, &degree) in AUTOMORPHISM_DEGREES.iter().enumerate() {
                let full_key_started = Instant::now();
                let (full_key, full_bytes) = generate_full_eval_auto_key(
                    &glwe_secret_key,
                    degree,
                    config,
                    client_parameters.glwe_noise_distribution(),
                    &mut generator,
                );
                let full_keygen_ns = full_key_started.elapsed().as_nanos();
                let pseudo_key_started = Instant::now();
                let (pseudo_key, pseudo_bytes) = generate_pseudo_eval_auto_key(
                    &glwe_secret_key,
                    degree,
                    config,
                    client_parameters.glwe_noise_distribution(),
                    &mut generator,
                );
                let pseudo_keygen_ns = pseudo_key_started.elapsed().as_nanos();
                println!(
                    "KEY,param={},keyset={},degree={},full_standard_bytes={},full_fourier_bytes={},pseudo_standard_bytes={},pseudo_fourier_bytes={},full_keygen_ns={},pseudo_keygen_ns={},same_secret=true,same_decomposition=true,key_ciphertext_randomness_independent=true,keygen_order=full_then_pseudo",
                    config.label,
                    keyset + 1,
                    degree,
                    full_bytes.standard,
                    full_bytes.fourier,
                    pseudo_bytes.standard,
                    pseudo_bytes.fourier,
                    full_keygen_ns,
                    pseudo_keygen_ns
                );

                let total_iterations = args.warmups + args.trials_per_degree;
                for iteration in 0..total_iterations {
                    let is_warmup = iteration < args.warmups;
                    let phase_index = if is_warmup {
                        iteration
                    } else {
                        iteration - args.warmups
                    };
                    let plaintext_seed = 0xA101_0000_0000_0001u64
                        ^ (keyset as u64).rotate_left(43)
                        ^ (config.base_log as u64).rotate_left(37)
                        ^ (config.level_count as u64).rotate_left(29)
                        ^ (degree as u64).rotate_left(17)
                        ^ (iteration as u64);
                    let plaintext = validation_plaintext(plaintext_seed);
                    assert_eq!(
                        automorphism_slice(&plaintext, degree),
                        automorphism_oracle_inverse(&plaintext, degree),
                        "forward implementation must agree with independent oracle"
                    );
                    let mut input = GlweCiphertext::new(
                        0u64,
                        glwe_size,
                        polynomial_size,
                        CiphertextModulus::new_native(),
                    );
                    encrypt_glwe_ciphertext(
                        &glwe_secret_key,
                        &mut input,
                        &PlaintextList::from_container(plaintext.clone()),
                        client_parameters.glwe_noise_distribution(),
                        &mut generator,
                    );

                    let full_first =
                        full_arm_runs_first(keyset, config_index, degree_index, iteration);
                    let (full_ns, pseudo_ns) = if full_first {
                        let started = Instant::now();
                        full_workspace.apply(
                            std::hint::black_box(&input),
                            degree,
                            std::hint::black_box(&full_key),
                            fft.as_view(),
                        );
                        std::hint::black_box(&full_workspace.output);
                        let full_ns = started.elapsed().as_nanos();
                        let started = Instant::now();
                        pseudo_workspace.apply(
                            std::hint::black_box(&input),
                            degree,
                            std::hint::black_box(&pseudo_key),
                            fft.as_view(),
                        );
                        std::hint::black_box(&pseudo_workspace.output);
                        (full_ns, started.elapsed().as_nanos())
                    } else {
                        let started = Instant::now();
                        pseudo_workspace.apply(
                            std::hint::black_box(&input),
                            degree,
                            std::hint::black_box(&pseudo_key),
                            fft.as_view(),
                        );
                        std::hint::black_box(&pseudo_workspace.output);
                        let pseudo_ns = started.elapsed().as_nanos();
                        let started = Instant::now();
                        full_workspace.apply(
                            std::hint::black_box(&input),
                            degree,
                            std::hint::black_box(&full_key),
                            fft.as_view(),
                        );
                        std::hint::black_box(&full_workspace.output);
                        (started.elapsed().as_nanos(), pseudo_ns)
                    };

                    let observation = observe(
                        &glwe_secret_key,
                        &plaintext,
                        &input,
                        &full_workspace.output,
                        &pseudo_workspace.output,
                        degree,
                    );
                    let record = if is_warmup { "WARMUP" } else { "SAMPLE" };
                    println!(
                        "{record},param={},keyset={},degree={},index={},plaintext_seed={:#018x},first_arm={},full_ns={},pseudo_ns={},input_max={},full_incremental_max={},full_total_max={},pseudo_incremental_max={},pseudo_total_max={},input_decode_mismatches={},full_decode_mismatches={},pseudo_decode_mismatches={},cross_arm_decode_mismatches={},same_encrypted_input=true,decryption_outside_timing=true",
                        config.label,
                        keyset + 1,
                        degree,
                        phase_index + 1,
                        plaintext_seed,
                        if full_first { "full" } else { "pseudo" },
                        full_ns,
                        pseudo_ns,
                        observation.input_max,
                        observation.full_incremental_max,
                        observation.full_total_max,
                        observation.pseudo_incremental_max,
                        observation.pseudo_total_max,
                        observation.input_decode_mismatches,
                        observation.full_decode_mismatches,
                        observation.pseudo_decode_mismatches,
                        observation.cross_arm_decode_mismatches
                    );
                    assert!(
                        !observation.any_mismatch(),
                        "A101 decoded-message gate failed for {} degree {}",
                        config.label,
                        degree
                    );
                    if !is_warmup {
                        aggregates[config_index].observation.absorb(observation);
                        aggregates[config_index].measured_cases += 1;
                        aggregates[config_index].full_ns.push(full_ns);
                        aggregates[config_index].pseudo_ns.push(pseudo_ns);
                    }
                }
            }
        }
    }

    for (&config, aggregate) in configs.iter().zip(&aggregates) {
        let observation = aggregate.observation;
        println!(
            "RESULT,param={},status={},measured_cases={},coefficients={},full_median_ns={},pseudo_median_ns={},input_max={},full_incremental_max={},full_total_max={},pseudo_incremental_max={},pseudo_total_max={},input_decode_mismatches={},full_decode_mismatches={},pseudo_decode_mismatches={},cross_arm_decode_mismatches={},component_only=true,speedup_claimed=false,pfail_claimed=false,chen_packing_proven=false,grouped_trace_proven=false,selector_proven=false,promotion=false",
            config.label,
            if observation.any_mismatch() {
                "FAIL_SAMPLED_SINGLE_EVALAUTO_COMPONENT"
            } else {
                "PASS_SAMPLED_SINGLE_EVALAUTO_COMPONENT"
            },
            aggregate.measured_cases,
            aggregate.measured_cases * POLYNOMIAL_SIZE,
            median(&aggregate.full_ns),
            median(&aggregate.pseudo_ns),
            observation.input_max,
            observation.full_incremental_max,
            observation.full_total_max,
            observation.pseudo_incremental_max,
            observation.pseudo_total_max,
            observation.input_decode_mismatches,
            observation.full_decode_mismatches,
            observation.pseudo_decode_mismatches,
            observation.cross_arm_decode_mismatches
        );
        assert!(!observation.any_mismatch(), "A101 aggregate mismatch");
    }
    println!(
        "FINAL,status=PASS_SAMPLED_SINGLE_EVALAUTO_COMPONENTS,wall_ns={},component_only=true,speedup_claimed=false,pfail_claimed=false,composed_promotion=false",
        total_started.elapsed().as_nanos()
    );
}

fn main() {
    let args = parse_args_from(env::args().skip(1)).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        std::process::exit(2);
    });
    let configs = selected_configs(&args);
    let calls_per_arm = configs.len()
        * args.fresh_keysets
        * AUTOMORPHISM_DEGREES.len()
        * (args.warmups + args.trials_per_degree);
    println!(
        "PLAN,artifact=A101,tfhe=0.11.3,params=A44-p16,glwe_dimension={GLWE_DIMENSION},polynomial_size={POLYNOMIAL_SIZE},decompositions={},degrees=3|5|9|33|65|129|257|513|1025|2049,validation_delta_log={VALIDATION_DELTA_LOG},fresh_keysets={},warmups={},trials_per_degree={},calls_per_arm={},independent_inverse_oracle=true,same_input_pairing=true,alternating_order=true,order_basis=keyset_plus_config_index_plus_degree_index_plus_iteration,reused_fft=true,reused_scratch=true,component_only=true,run={}",
        configs
            .iter()
            .map(|config| config.label)
            .collect::<Vec<_>>()
            .join("|"),
        args.fresh_keysets,
        args.warmups,
        args.trials_per_degree,
        calls_per_arm,
        args.run
    );
    for &config in &configs {
        let (full, pseudo) = expected_key_bytes(config);
        println!(
            "SIZE_PLAN,param={},full_standard_bytes={},full_fourier_bytes={},pseudo_standard_bytes={},pseudo_fourier_bytes={},pseudo_to_full_ratio=1/2,exact_container_payload_only=true",
            config.label, full.standard, full.fourier, pseudo.standard, pseudo.fourier
        );
    }
    if !args.run {
        println!("STATUS,DRY_PLAN_ONLY_USE_--run_--ack-component-only_FOR_COMPONENT_FHE");
        return;
    }
    run(&args, &configs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_automorphism_matches_independent_oracle_for_all_odd_degrees() {
        let input = validation_plaintext(0xA101_A101_1357_2468);
        for degree in (1..2 * POLYNOMIAL_SIZE).step_by(2) {
            assert_eq!(
                automorphism_slice(&input, degree),
                automorphism_oracle_inverse(&input, degree),
                "degree {degree}"
            );
        }
    }

    #[test]
    fn automorphism_composed_with_inverse_recovers_input_for_gate_degrees() {
        let input = validation_plaintext(0xA101_A101_89AB_CDEF);
        for &degree in &AUTOMORPHISM_DEGREES {
            let inverse = (1..2 * POLYNOMIAL_SIZE)
                .step_by(2)
                .find(|candidate| degree * candidate % (2 * POLYNOMIAL_SIZE) == 1)
                .expect("odd degree inverse");
            assert_eq!(
                automorphism_slice(&automorphism_slice(&input, degree), inverse),
                input,
                "degree {degree}, inverse {inverse}"
            );
        }
    }

    #[test]
    fn exact_payload_sizes_are_half_for_pseudo() {
        assert_eq!(size_of::<u64>(), 8);
        assert_eq!(size_of::<c64>(), 16);
        for config in DECOMPOSITION_CONFIGS {
            let (full, pseudo) = expected_key_bytes(config);
            assert_eq!(full.standard, 65_536 * config.level_count);
            assert_eq!(full.fourier, 65_536 * config.level_count);
            assert_eq!(pseudo.standard, 32_768 * config.level_count);
            assert_eq!(pseudo.fourier, 32_768 * config.level_count);
            assert_eq!(full.standard, 2 * pseudo.standard);
            assert_eq!(full.fourier, 2 * pseudo.fourier);
        }
    }

    #[test]
    fn runtime_cli_is_fail_closed() {
        assert!(parse_args_from(Vec::<String>::new()).is_ok());
        assert!(parse_args_from(vec!["--run".to_string()]).is_err());
        assert!(parse_args_from(vec!["--ack-component-only".to_string()]).is_err());
        assert!(parse_args_from(vec![
            "--run".to_string(),
            "--ack-component-only".to_string(),
            "--params".to_string(),
            "8x5".to_string(),
        ])
        .is_ok());
        assert!(parse_args_from(vec![
            "--run".to_string(),
            "--run".to_string(),
            "--ack-component-only".to_string(),
        ])
        .is_err());
        assert!(parse_args_from(vec!["--params".to_string(), "invented".to_string(),]).is_err());
    }

    #[test]
    fn centered_error_and_decode_handle_both_wrap_directions() {
        assert_eq!(centered_abs_error(7, 5), 2);
        assert_eq!(centered_abs_error(5, 7), 2);
        assert_eq!(centered_abs_error(1, u64::MAX), 2);
        assert_eq!(centered_abs_error(u64::MAX, 1), 2);
        let delta = 1u64 << VALIDATION_DELTA_LOG;
        assert_eq!(decode_symbol(3 * delta), 3);
        assert_eq!(decode_symbol((-3i64 as u64).wrapping_mul(delta)), -3);
    }

    #[test]
    fn minimal_smoke_balances_arm_order_across_registered_degrees() {
        let order: Vec<bool> = AUTOMORPHISM_DEGREES
            .iter()
            .enumerate()
            .map(|(degree_index, _)| full_arm_runs_first(0, 0, degree_index, 0))
            .collect();
        assert_eq!(order.iter().filter(|&&full_first| full_first).count(), 5);
        assert_eq!(order.iter().filter(|&&full_first| !full_first).count(), 5);
        assert!(order.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
