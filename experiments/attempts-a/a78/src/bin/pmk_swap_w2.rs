//! A78 PMK swap w2 micro-gate, implemented from Bergerat et al., Algorithm 9.
//!
//! STATUS: UNCOMPILED_STATIC_DRAFT (2026-09-02).
//! This file was deliberately written without invoking cargo, rustc, key generation, or FHE
//! execution while another benchmark owned the machine. Its presence is not build evidence and
//! none of the assertions below have run yet.
//!
//! The security boundary is intentional:
//! - the client generates two GLWE secret keys with distinct generator draws;
//! - an authorized client/dealer uses both secrets to encrypt one public swap PMK;
//! - the online server function receives only the Fourier PMK, public parameters, and ciphertext;
//! - only the client verification function receives the secret keys or decrypts.
//!
//! tfhe-rs 1.7 exposes an identity-only CM-GGSW helper. The local helper below follows that
//! source row for row, but applies the public permutation to the entire plaintext phase vector
//! before `encrypt_cm_glwe_ciphertext_assign`. Swapping only encrypted bodies is not equivalent.

use std::mem::{size_of, size_of_val};

use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    cm_add_external_product_assign, cm_add_external_product_assign_requirement, CmApParams,
    CM_PARAM_2_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;

const LANES: usize = 2;
const FRESH_KEYSETS: usize = 3;
const MESSAGE_DELTA: u64 = 1u64 << 60;
const TORUS_TOLERANCE: u64 = 1u64 << 57;
const EXPECTED_PMK_BYTES: usize = 100 * 1024;
const FOURIER_C64_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LanePermutation {
    /// Public convention used throughout this gate: output[destination] = input[source].
    destination_to_source: [usize; LANES],
}

impl LanePermutation {
    fn checked(destination_to_source: [usize; LANES]) -> Self {
        let mut seen = [false; LANES];
        for source in destination_to_source {
            assert!(source < LANES, "permutation source is outside the lane range");
            assert!(!seen[source], "permutation is not injective");
            seen[source] = true;
        }
        assert!(seen.into_iter().all(|is_present| is_present));
        Self {
            destination_to_source,
        }
    }

    fn swap() -> Self {
        Self::checked([1, 0])
    }

    fn source_for_destination(self, destination: usize) -> usize {
        self.destination_to_source[destination]
    }

    fn destination_for_source(self, source: usize) -> usize {
        self.destination_to_source
            .iter()
            .position(|candidate| *candidate == source)
            .expect("checked permutation must contain every source")
    }

    fn apply_polynomial_lanes(self, input: &[u64], polynomial_size: usize) -> Vec<u64> {
        assert_eq!(input.len(), LANES * polynomial_size);
        let mut output = vec![0u64; input.len()];
        for destination in 0..LANES {
            let source = self.source_for_destination(destination);
            output[destination * polynomial_size..(destination + 1) * polynomial_size]
                .copy_from_slice(
                    &input[source * polynomial_size..(source + 1) * polynomial_size],
                );
        }
        output
    }
}

struct ClientSecretKeyset {
    lane_glwe_secret_keys: Vec<GlweSecretKeyOwned<u64>>,
}

#[derive(Default)]
struct ServerAudit {
    permutation_external_products: usize,
    intermediate_decryptions: usize,
}

struct GateCase {
    name: &'static str,
    input: Vec<u64>,
    identity_must_fail: bool,
}

fn assert_gate_parameters(params: CmApParams) {
    assert_eq!(params.cm_dimension.0, LANES);
    assert_eq!(params.precision, 2);
    assert_eq!(params.glwe_dimension.0, 3);
    assert_eq!(params.polynomial_size.0, 512);
    assert_eq!(params.level_bs.0, 1);
    assert_eq!(params.base_log_bs.0, 17);
    assert!(params.ciphertext_modulus.is_native_modulus());
}

fn expected_standard_pmk_elements(params: CmApParams) -> usize {
    let matrix_side = params.glwe_dimension.0 + params.cm_dimension.0;
    params.level_bs.0 * matrix_side * matrix_side * params.polynomial_size.0
}

fn expected_fourier_pmk_elements(params: CmApParams) -> usize {
    let matrix_side = params.glwe_dimension.0 + params.cm_dimension.0;
    params.level_bs.0 * matrix_side * matrix_side * (params.polynomial_size.0 / 2)
}

fn client_generate_secret_keyset(
    params: CmApParams,
    secret_generator: &mut SecretRandomGenerator<DefaultRandomGenerator>,
) -> ClientSecretKeyset {
    // Separate calls advance the CSPRNG and sample independent binary key realizations. The
    // equality assertion below is only a defensive realization check; it does not by itself
    // constitute a proof of statistical independence.
    let lane_glwe_secret_keys = (0..LANES)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                secret_generator,
            )
        })
        .collect::<Vec<_>>();

    for key in &lane_glwe_secret_keys {
        assert_eq!(key.glwe_dimension(), params.glwe_dimension);
        assert_eq!(key.polynomial_size(), params.polynomial_size);
        assert!(key.as_ref().iter().all(|coefficient| *coefficient <= 1));
    }
    let differing_coefficients = lane_glwe_secret_keys[0]
        .as_ref()
        .iter()
        .zip(lane_glwe_secret_keys[1].as_ref())
        .filter(|(left, right)| left != right)
        .count();
    assert!(
        differing_coefficients > 0,
        "reject the negligible event of identical lane-key realizations"
    );

    ClientSecretKeyset {
        lane_glwe_secret_keys,
    }
}

/// Client/dealer-only PMK generation.
///
/// This is the identity helper from tfhe-rs 1.7 with `rho` applied to every row's plaintext
/// phase vector before encryption. For `destination_to_source`, the generated external product
/// implements `output[destination] = input[source]` while retaining the original independent
/// target key matrix.
fn authorized_dealer_generate_unit_permutation_pmk(
    client: &ClientSecretKeyset,
    permutation: LanePermutation,
    params: CmApParams,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> CmGgswCiphertextOwned<u64> {
    assert_eq!(client.lane_glwe_secret_keys.len(), LANES);

    let mut output = CmGgswCiphertext::new(
        0u64,
        params.glwe_dimension,
        params.cm_dimension,
        params.polynomial_size,
        params.base_log_bs,
        params.level_bs,
        params.ciphertext_modulus,
    );

    let decomposition_base_log = output.decomposition_base_log();
    let decomposition_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();
    assert!(matches!(
        ciphertext_modulus.kind(),
        CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo
    ));

    for (level_index, mut level_matrix) in output.iter_mut().enumerate() {
        let decomposition_level =
            DecompositionLevel(decomposition_level_count.0 - level_index);
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomposition_level,
            decomposition_base_log,
            Cleartext(1u64),
        );
        let first_body_row = level_matrix.glwe_dimension().0;
        assert_eq!(first_body_row, params.glwe_dimension.0);

        for (row_index, mut row_as_cm_glwe) in level_matrix
            .as_mut_cm_glwe_list()
            .iter_mut()
            .enumerate()
        {
            {
                let mut bodies = row_as_cm_glwe.get_mut_bodies();
                bodies.as_mut().fill(0u64);

                if row_index < first_body_row {
                    // Identity phase row:
                    //   [factor*S_0[row], factor*S_1[row]].
                    // PMK phase row after rho:
                    //   destination d receives factor*S_source[d][row].
                    for destination in 0..LANES {
                        let source = permutation.source_for_destination(destination);
                        let source_polynomial_list =
                            client.lane_glwe_secret_keys[source].as_polynomial_list();
                        let source_polynomial = source_polynomial_list.get(row_index);
                        let mut destination_body = bodies.get_mut(destination);
                        destination_body
                            .as_mut()
                            .copy_from_slice(source_polynomial.as_ref());
                        for coefficient in destination_body.as_mut() {
                            *coefficient = coefficient.wrapping_mul(factor);
                        }
                    }
                } else {
                    // Identity phase row g+j has -factor in source lane j. Applying rho moves
                    // that coefficient to the unique destination d for which rho(d)=j.
                    let source_body_lane = row_index - first_body_row;
                    assert!(source_body_lane < LANES);
                    let destination = permutation.destination_for_source(source_body_lane);
                    bodies.get_mut(destination).as_mut()[0] = factor.wrapping_neg();
                }
            }

            // The encryption target remains [S_0, S_1]. Only the row plaintext phases above
            // were permuted. The original two secret keys are never equated or mixed.
            encrypt_cm_glwe_ciphertext_assign(
                &client.lane_glwe_secret_keys,
                &mut row_as_cm_glwe,
                params.glwe_noise_distribution,
                encryption_generator,
            );
        }
    }

    output
}

fn client_encrypt_cm_glwe(
    client: &ClientSecretKeyset,
    input: &[u64],
    params: CmApParams,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> CmGlweCiphertextOwned<u64> {
    assert_eq!(input.len(), LANES * params.polynomial_size.0);
    let plaintext = PlaintextList::from_container(input);
    let mut ciphertext = CmGlweCiphertext::new(
        0u64,
        params.glwe_dimension,
        params.cm_dimension,
        params.polynomial_size,
        params.ciphertext_modulus,
    );
    encrypt_cm_glwe_ciphertext(
        &client.lane_glwe_secret_keys,
        &mut ciphertext,
        &plaintext,
        params.glwe_noise_distribution,
        encryption_generator,
    );
    ciphertext
}

/// Online server boundary: there is intentionally no secret-key parameter and no decryption.
fn server_apply_permutation_pmk(
    input: &CmGlweCiphertextOwned<u64>,
    permutation_pmk: FourierCmGgswCiphertextView<'_>,
    params: CmApParams,
    fft: &Fft,
    scratch: &mut ComputationBuffers,
    audit: &mut ServerAudit,
) -> CmGlweCiphertextOwned<u64> {
    assert_eq!(input.glwe_dimension(), params.glwe_dimension);
    assert_eq!(input.cm_dimension(), params.cm_dimension);
    assert_eq!(input.polynomial_size(), params.polynomial_size);
    assert_eq!(permutation_pmk.glwe_dimension(), params.glwe_dimension);
    assert_eq!(permutation_pmk.cm_dimension(), params.cm_dimension);
    assert_eq!(permutation_pmk.polynomial_size(), params.polynomial_size);
    assert_eq!(
        permutation_pmk.decomposition_base_log(),
        params.base_log_bs
    );
    assert_eq!(
        permutation_pmk.decomposition_level_count(),
        params.level_bs
    );

    let mut output = CmGlweCiphertext::new(
        0u64,
        params.glwe_dimension,
        params.cm_dimension,
        params.polynomial_size,
        params.ciphertext_modulus,
    );
    cm_add_external_product_assign(
        output.as_mut_view(),
        permutation_pmk,
        input.as_view(),
        fft.as_view(),
        scratch.stack(),
    );
    audit.permutation_external_products += 1;
    output
}

fn client_decrypt_cm_glwe(
    client: &ClientSecretKeyset,
    ciphertext: &CmGlweCiphertextOwned<u64>,
    params: CmApParams,
) -> Vec<u64> {
    let mut plaintext = PlaintextList::new(
        0u64,
        PlaintextCount(LANES * params.polynomial_size.0),
    );
    decrypt_cm_glwe_ciphertext(
        &client.lane_glwe_secret_keys,
        ciphertext,
        &mut plaintext,
    );
    plaintext.as_ref().to_vec()
}

fn torus_distance(left: u64, right: u64) -> u64 {
    let difference = left.wrapping_sub(right);
    difference.min(difference.wrapping_neg())
}

fn assert_polynomial_lanes_close(actual: &[u64], expected: &[u64], case_name: &str) {
    assert_eq!(actual.len(), expected.len());
    for (coefficient_index, (&actual_value, &expected_value)) in
        actual.iter().zip(expected).enumerate()
    {
        let distance = torus_distance(actual_value, expected_value);
        assert!(
            distance < TORUS_TOLERANCE,
            "{case_name}: coefficient {coefficient_index} has torus error {distance}, tolerance {TORUS_TOLERANCE}"
        );
    }
}

fn is_polynomial_lane_vector_close(actual: &[u64], expected: &[u64]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(&left, &right)| torus_distance(left, right) < TORUS_TOLERANCE)
}

fn constant_boolean_pair(bits: [u64; LANES], polynomial_size: usize) -> Vec<u64> {
    let mut encoded = Vec::with_capacity(LANES * polynomial_size);
    for bit in bits {
        assert!(bit <= 1);
        encoded.extend(std::iter::repeat(bit * MESSAGE_DELTA).take(polynomial_size));
    }
    encoded
}

fn gate_cases(polynomial_size: usize) -> Vec<GateCase> {
    let mut alternating = vec![0u64; LANES * polynomial_size];
    for coefficient in 0..polynomial_size {
        alternating[coefficient] = u64::from(coefficient % 2 != 0) * MESSAGE_DELTA;
        alternating[polynomial_size + coefficient] =
            u64::from(coefficient % 2 == 0) * MESSAGE_DELTA;
    }

    vec![
        GateCase {
            name: "boolean_00",
            input: constant_boolean_pair([0, 0], polynomial_size),
            identity_must_fail: false,
        },
        GateCase {
            name: "boolean_01",
            input: constant_boolean_pair([0, 1], polynomial_size),
            identity_must_fail: true,
        },
        GateCase {
            name: "boolean_10",
            input: constant_boolean_pair([1, 0], polynomial_size),
            identity_must_fail: true,
        },
        GateCase {
            name: "boolean_11",
            input: constant_boolean_pair([1, 1], polynomial_size),
            identity_must_fail: false,
        },
        GateCase {
            name: "alternating_lane_markers",
            input: alternating,
            identity_must_fail: true,
        },
    ]
}

fn main() {
    eprintln!(
        "STATUS=UNCOMPILED_STATIC_DRAFT source_date=2026-09-02; a successful future run may supersede this marker"
    );

    let params = CM_PARAM_2_2_MINUS_64;
    assert_gate_parameters(params);
    let swap = LanePermutation::swap();
    assert_eq!(swap.apply_polynomial_lanes(&[17, 23], 1), [23, 17]);

    let expected_standard_elements = expected_standard_pmk_elements(params);
    let expected_fourier_elements = expected_fourier_pmk_elements(params);
    assert_eq!(
        expected_standard_elements * size_of::<u64>(),
        EXPECTED_PMK_BYTES
    );
    assert_eq!(
        expected_fourier_elements * FOURIER_C64_BYTES,
        EXPECTED_PMK_BYTES
    );

    let cases = gate_cases(params.polynomial_size.0);
    let mut total_external_products = 0usize;
    let mut total_negative_identity_rejections = 0usize;

    for keyset_index in 0..FRESH_KEYSETS {
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let client = client_generate_secret_keyset(params, &mut secret_generator);
        let permutation_pmk_standard = authorized_dealer_generate_unit_permutation_pmk(
            &client,
            swap,
            params,
            &mut encryption_generator,
        );
        assert_eq!(
            permutation_pmk_standard.as_ref().len(),
            expected_standard_elements
        );
        assert_eq!(
            size_of_val(permutation_pmk_standard.as_ref()),
            EXPECTED_PMK_BYTES
        );

        // Public server-side setup: converting an evaluation key to Fourier form requires no
        // secret. The coefficient key can be discarded after this conversion.
        let fft = Fft::new(params.polynomial_size);
        let mut permutation_pmk_fourier = FourierCmGgswCiphertext::new(
            params.glwe_dimension,
            params.cm_dimension,
            params.polynomial_size,
            params.base_log_bs,
            params.level_bs,
        );
        let mut conversion_scratch = ComputationBuffers::new();
        conversion_scratch.resize(fft.as_view().forward_scratch().unaligned_bytes_required());
        permutation_pmk_fourier
            .as_mut_view()
            .fill_with_forward_fourier(
                permutation_pmk_standard.as_view(),
                fft.as_view(),
                conversion_scratch.stack(),
            );
        assert_eq!(
            permutation_pmk_fourier.as_view().data().len(),
            expected_fourier_elements
        );
        assert_eq!(
            size_of_val(permutation_pmk_fourier.as_view().data()),
            EXPECTED_PMK_BYTES
        );
        drop(permutation_pmk_standard);

        let external_product_requirement = cm_add_external_product_assign_requirement::<u64>(
            params.glwe_dimension,
            params.cm_dimension,
            params.polynomial_size,
            fft.as_view(),
        );
        let mut server_scratch = ComputationBuffers::new();
        server_scratch.resize(external_product_requirement.unaligned_bytes_required());
        assert!(
            server_scratch
                .stack()
                .can_hold(external_product_requirement),
            "server scratch must satisfy the exact tfhe-rs external-product requirement"
        );
        let mut server_audit = ServerAudit::default();

        for case in &cases {
            let input_ciphertext = client_encrypt_cm_glwe(
                &client,
                &case.input,
                params,
                &mut encryption_generator,
            );
            let output_ciphertext = server_apply_permutation_pmk(
                &input_ciphertext,
                permutation_pmk_fourier.as_view(),
                params,
                &fft,
                &mut server_scratch,
                &mut server_audit,
            );

            // Verification decrypts only after the online server boundary has returned its final
            // ciphertext. There is no intermediate client/server round trip.
            let decrypted = client_decrypt_cm_glwe(&client, &output_ciphertext, params);
            let expected = swap.apply_polynomial_lanes(&case.input, params.polynomial_size.0);
            assert_polynomial_lanes_close(&decrypted, &expected, case.name);

            // Test-sensitivity control: on non-symmetric inputs, accepting the identity mapping
            // must fail. This needs no second (identity) PMK and keeps the production ledger at
            // exactly one stored PMK.
            if case.identity_must_fail {
                assert!(
                    !is_polynomial_lane_vector_close(&decrypted, &case.input),
                    "{}: output accidentally also satisfies the unpermuted identity map",
                    case.name
                );
                total_negative_identity_rejections += 1;
            }
        }

        assert_eq!(
            server_audit.permutation_external_products,
            cases.len(),
            "exactly one permutation external product is allowed per input ciphertext"
        );
        assert_eq!(server_audit.intermediate_decryptions, 0);
        total_external_products += server_audit.permutation_external_products;

        println!(
            "keyset={} cases={} mismatches=0 pmk_count=1 pmk_bytes={} external_products={} external_products_per_ciphertext=1 server_intermediate_decryptions=0",
            keyset_index + 1,
            cases.len(),
            EXPECTED_PMK_BYTES,
            server_audit.permutation_external_products,
        );
    }

    assert_eq!(total_external_products, FRESH_KEYSETS * cases.len());
    assert_eq!(
        total_negative_identity_rejections,
        FRESH_KEYSETS * cases.iter().filter(|case| case.identity_must_fail).count()
    );
    println!(
        "gate=PMK_SWAP_W2 result=PASS fresh_keysets={} cases_per_keyset={} checked_plaintext_coefficients={} total_external_products={} negative_identity_rejections={} note=NO_TIMING_AND_NO_PFAIL_CLAIM",
        FRESH_KEYSETS,
        cases.len(),
        FRESH_KEYSETS * cases.len() * LANES * params.polynomial_size.0,
        total_external_products,
        total_negative_identity_rejections,
    );
}
