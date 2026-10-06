//! Diagnostic harness for the isolated A52 canonical high-score lane.
//!
//! Without `--run`, this executable performs only clear/static assertions and prints a plan.  A
//! future explicit `--run` generates one ephemeral key in memory, encrypts a fresh four-lane GLWE
//! for every selected boundary, performs the public-template convolution, extracts degree 2047,
//! and evaluates the one-KS/one-PBS A52 component.  It never serializes keys or ciphertexts.

use a52_canonical_high_lane_prototype::{
    a52_parameter_and_layout_fingerprint_sha256, canonical_high_digit, clear_canonical_high_digit,
    validate_a52_binding_text, validate_a52_server_key, validate_a52_static_layout, A52_BINDING,
    A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256, A52_PARAMS_ID, A52_PER_TEMPLATE_COUNTS,
    CANONICAL_HIGH_LANE_END, CANONICAL_HIGH_LANE_OFFSET, CANONICAL_HIGH_SAMPLE_DEGREE,
    CANONICAL_SCORE_DELTA_LOG, FULL_DELTA_LOG, FULL_LANE_OFFSET, LOW_DELTA_LOG, LOW_LANE_OFFSET,
    MID_DELTA_LOG, MID_LANE_OFFSET, P16_DELTA_LOG, POLYNOMIAL_SIZE, PROBE_DIM, SCORE_DOMAIN_SIZE,
};
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const ACTIVE_COORDINATES: [usize; 3] = [0, 255, 511];
const SMALL_CASES: [u64; 15] = [
    0, 1, 127, 128, 254, 255, 256, 257, 2_047, 2_048, 3_838, 3_839, 3_840, 4_094, 4_095,
];

type Glwe = GlweCiphertextOwned<u64>;
type Lwe = LweCiphertextOwned<u64>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Arguments {
    run: bool,
    small_only: bool,
    all_centers: bool,
    explicit_cases: Vec<u64>,
}

fn parse_arguments() -> Arguments {
    let mut parsed = Arguments {
        run: false,
        small_only: false,
        all_centers: false,
        explicit_cases: Vec::new(),
    };
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--run" => parsed.run = true,
            "--small-only" => parsed.small_only = true,
            "--all-centers" => parsed.all_centers = true,
            _ => {
                let value = argument
                    .strip_prefix("--case=")
                    .unwrap_or_else(|| panic!("unknown A52 argument: {argument}"));
                let score = value
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("invalid A52 score: {value}"));
                assert!(score < SCORE_DOMAIN_SIZE, "A52 score outside 0..4095");
                parsed.explicit_cases.push(score);
            }
        }
    }
    let selectors = usize::from(parsed.small_only)
        + usize::from(parsed.all_centers)
        + usize::from(!parsed.explicit_cases.is_empty());
    assert!(selectors <= 1, "choose only one A52 fixture selector");
    parsed
}

fn boundary_cases() -> Vec<u64> {
    let mut cases = Vec::with_capacity(32);
    for high in 0..16u64 {
        cases.push(high << 8);
        cases.push((high << 8) + 255);
    }
    cases.sort_unstable();
    cases.dedup();
    cases
}

fn selected_cases(arguments: &Arguments) -> Vec<u64> {
    if !arguments.explicit_cases.is_empty() {
        return arguments.explicit_cases.clone();
    }
    if arguments.all_centers {
        return (0..SCORE_DOMAIN_SIZE).collect();
    }
    if arguments.small_only {
        return SMALL_CASES.to_vec();
    }
    boundary_cases()
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn dot(left: &[i64], right: &[i64]) -> i64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum()
}

fn fixture_vectors(active_coordinate: usize) -> (Vec<i64>, Vec<i64>) {
    assert!(ACTIVE_COORDINATES.contains(&active_coordinate));
    let mut probe = vec![0i64; PROBE_DIM];
    probe[active_coordinate] = 1;
    probe[(active_coordinate + 1) % PROBE_DIM] = -2;
    probe[(active_coordinate + 257) % PROBE_DIM] = 3;
    let mut template = vec![0i64; PROBE_DIM];
    template[active_coordinate] = 1;
    assert_eq!(squared_norm(&probe), 14);
    assert_eq!(squared_norm(&template), 1);
    assert_eq!(dot(&probe, &template), 1);
    (probe, template)
}

fn encrypt_four_lane_probe(
    probe: &[i64],
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= 1_024);
    assert_eq!(CANONICAL_HIGH_LANE_END, POLYNOMIAL_SIZE);
    assert_eq!(glwe_secret_key.polynomial_size().0, POLYNOMIAL_SIZE);

    let mut plaintext = vec![0u64; POLYNOMIAL_SIZE];
    for (coordinate, &value) in probe.iter().enumerate() {
        plaintext[FULL_LANE_OFFSET + coordinate] =
            (value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_LANE_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOW_DELTA_LOG);
        plaintext[MID_LANE_OFFSET + coordinate] =
            (value.rem_euclid(256) as u64).wrapping_mul(1u64 << MID_DELTA_LOG);
        plaintext[CANONICAL_HIGH_LANE_OFFSET + coordinate] =
            (value as u64).wrapping_mul(1u64 << CANONICAL_SCORE_DELTA_LOG);
    }

    let mut encrypted = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        PolynomialSize(POLYNOMIAL_SIZE),
        modulus,
    );
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    encrypted
}

fn extract_normalized_canonical_score(
    packed_probe: &Glwe,
    template: &[i64],
    execution_lower: i64,
) -> Lwe {
    assert_eq!(template.len(), PROBE_DIM);
    assert!(template.iter().all(|value| (-3..=3).contains(value)));
    assert_eq!(packed_probe.polynomial_size().0, POLYNOMIAL_SIZE);
    assert_eq!(CANONICAL_HIGH_SAMPLE_DEGREE, POLYNOMIAL_SIZE - 1);

    let mut template_polynomial = vec![0u64; POLYNOMIAL_SIZE];
    for (coordinate, &value) in template.iter().enumerate() {
        template_polynomial[PROBE_DIM - 1 - coordinate] = (-2 * value) as u64;
    }
    let template_polynomial = Polynomial::from_container(template_polynomial);
    let mut product = GlweCiphertext::new(
        0u64,
        packed_probe.glwe_size(),
        packed_probe.polynomial_size(),
        packed_probe.ciphertext_modulus(),
    );
    for (mut output, input) in product
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(packed_probe.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_mul_assign(&mut output, &input, &template_polynomial);
    }

    let mut score = LweCiphertext::new(
        0u64,
        product
            .glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(product.polynomial_size())
            .to_lwe_size(),
        product.ciphertext_modulus(),
    );
    extract_lwe_sample_from_glwe_ciphertext(
        &product,
        &mut score,
        MonomialDegree(CANONICAL_HIGH_SAMPLE_DEGREE),
    );
    let public_term = squared_norm(template)
        .checked_sub(execution_lower)
        .expect("A52 public score term overflow");
    assert!(
        public_term >= 0,
        "A52 fixture public term must be nonnegative"
    );
    lwe_ciphertext_plaintext_add_assign(
        &mut score,
        Plaintext((public_term as u64) << CANONICAL_SCORE_DELTA_LOG),
    );
    score
}

fn decode_lwe(
    secret_key: &LweSecretKeyView<'_, u64>,
    ciphertext: &Lwe,
    delta_log: u32,
    mask: u64,
) -> u64 {
    (decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (delta_log - 1))
        >> delta_log)
        & mask
}

fn validate_static_contract() {
    validate_a52_static_layout().expect("A52 static layout");
    validate_a52_binding_text(A52_BINDING).expect("A52 binding");
    assert_eq!(
        a52_parameter_and_layout_fingerprint_sha256(),
        A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256
    );
    assert_eq!(PARAMS.message_modulus.0, 4);
    assert_eq!(PARAMS.carry_modulus.0, 4);
    assert_eq!(PARAMS.max_noise_level.get(), 5);
    assert_eq!(PARAMS.polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(PARAMS.lwe_dimension.0, 879);
    for score in 0..SCORE_DOMAIN_SIZE {
        assert_eq!(clear_canonical_high_digit(score, 0), Ok(score >> 8));
        assert_eq!(
            clear_canonical_high_digit(score, (1i64 << 50) - 1),
            Ok(score >> 8)
        );
        assert_eq!(
            clear_canonical_high_digit(score, -((1i64 << 50) - 1)),
            Ok(score >> 8)
        );
    }
}

fn main() {
    validate_static_contract();
    let arguments = parse_arguments();
    let cases = selected_cases(&arguments);
    if !arguments.run {
        println!(
            "PLAN,variant=a52_canonical_high_lane,compiled=false,fhe_validated=false,cases_if_run={},lane_offset={},sample_degree={},input_delta_log={},output_delta_log={},per_template_BR={},per_template_KS={},per_template_marginals={},params_id={},fingerprint_sha256={},keys_generated=false",
            cases.len(),
            CANONICAL_HIGH_LANE_OFFSET,
            CANONICAL_HIGH_SAMPLE_DEGREE,
            CANONICAL_SCORE_DELTA_LOG,
            P16_DELTA_LOG,
            A52_PER_TEMPLATE_COUNTS.blind_rotations,
            A52_PER_TEMPLATE_COUNTS.classical_key_switches,
            A52_PER_TEMPLATE_COUNTS.output_marginals,
            A52_PARAMS_ID,
            A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256,
        );
        return;
    }

    let key_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    validate_a52_server_key(A52_BINDING, &server_key).expect("A52 server-key binding");
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!(
        "KEY,generation_s={:.6},ephemeral=true,secret_material_persisted=false,params_id={},fingerprint_sha256={}",
        key_started.elapsed().as_secs_f64(),
        A52_PARAMS_ID,
        A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256,
    );

    for (case_index, &translated_score) in cases.iter().enumerate() {
        let active_coordinate = ACTIVE_COORDINATES[case_index % ACTIVE_COORDINATES.len()];
        let (probe, template) = fixture_vectors(active_coordinate);
        let raw_score = squared_norm(&template) - 2 * dot(&probe, &template);
        let execution_lower = raw_score - translated_score as i64;
        assert_eq!(raw_score - execution_lower, translated_score as i64);
        let packed_probe = encrypt_four_lane_probe(
            &probe,
            &glwe_secret_key,
            client_params.glwe_noise_distribution(),
            modulus,
            &mut generator,
        );
        let score = extract_normalized_canonical_score(&packed_probe, &template, execution_lower);
        let decoded_score = decode_lwe(&big_secret_key, &score, CANONICAL_SCORE_DELTA_LOG, 0x1fff);
        assert_eq!(decoded_score, translated_score, "A52 score-lane boundary");

        let started = Instant::now();
        let high = canonical_high_digit(A52_BINDING, &server_key, &score)
            .expect("A52 high-digit evaluation rejected valid input");
        let decoded_high = decode_lwe(&big_secret_key, &high, P16_DELTA_LOG, 0x1f);
        assert_eq!(decoded_high, translated_score >> 8, "A52 high digit");
        println!(
            "PASS,score={},high={},active_coordinate={},BR=1,KS=1,marginals=1,eval_s={:.6}",
            translated_score,
            decoded_high,
            active_coordinate,
            started.elapsed().as_secs_f64(),
        );
    }
    println!(
        "SUMMARY,status=PASS,cases={},keys=ephemeral_in_memory,secret_material_persisted=false,component_only=true,integration_validated=false,pfail_claim=false",
        cases.len(),
    );
}
