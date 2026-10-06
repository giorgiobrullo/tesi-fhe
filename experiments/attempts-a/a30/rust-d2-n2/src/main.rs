//! Isolated A30 gate: Cong-style D2 encrypted-payload selector, N=2 shape.
//!
//! This crate intentionally does not contain the score-to-limb bridge or the
//! lexicographic comparator.  It observes the previously unknown causal cost of
//! PFKS + encrypted accumulator assembly + dynamic PBS.  See README.md.

use dyn_stack::{GlobalPodBuffer, PodStack};
use sha2::{Digest, Sha256};
use std::env;
use std::mem::size_of;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_assign;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomial;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const RUN_ACK_ENV: &str = "A30_RUN_FHE";
const RUN_ACK_VALUE: &str = "I_ACKNOWLEDGE_A30_D2_N2_FHE";
const PARAMS_FINGERPRINT: &str =
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1";
const SELECTOR_MODULUS: usize = 16;
const BOOL_DELTA: u64 = 1u64 << 59;
const ID_DELTA: u64 = 1u64 << 56;
const LEFT_CONTROL: u64 = 4;
const RIGHT_CONTROL: u64 = 12;
const PFPKS_BASE_LOG: DecompositionBaseLog = DecompositionBaseLog(23);
const PFPKS_LEVEL: DecompositionLevelCount = DecompositionLevelCount(1);

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
type Poly = PolynomialOwned<u64>;

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    node0_select_right: bool,
    root_select_right: bool,
    expected_code: u64,
}

impl Fixture {
    fn from_env() -> Self {
        match env::var("A30_FIXTURE").as_deref().unwrap_or("id1") {
            // [sentinel, ID1] -> ID1; [ID1, ID2] -> ID1.
            "id1" => Self {
                name: "id1",
                node0_select_right: true,
                root_select_right: false,
                expected_code: 1,
            },
            // [sentinel, ID1] -> ID1; [ID1, ID2] -> ID2.
            "id2" => Self {
                name: "id2",
                node0_select_right: true,
                root_select_right: true,
                expected_code: 2,
            },
            // [sentinel, ID1] -> sentinel; [sentinel, ID2] -> sentinel.
            "reject" => Self {
                name: "reject",
                node0_select_right: false,
                root_select_right: false,
                expected_code: 0,
            },
            // Comparator policy is injected here: equality must choose the left ID1.
            // This fixture checks selector propagation, not the absent comparator.
            "tie_left" => Self {
                name: "tie_left",
                node0_select_right: true,
                root_select_right: false,
                expected_code: 1,
            },
            other => panic!("unsupported A30_FIXTURE={other:?}; use id1, id2, reject, or tie_left"),
        }
    }
}

#[derive(Default)]
struct CallMetrics {
    role: &'static str,
    pfks_calls: usize,
    control_ks_calls: usize,
    blind_rotations: usize,
    sample_extractions: usize,
    allocation_ns: u128,
    pfks_left_ns: u128,
    pfks_right_ns: u128,
    spread_left_ns: u128,
    spread_right_ns: u128,
    sum_ns: u128,
    control_ks_ns: u128,
    blind_rotate_ns: u128,
    sample_extract_ns: u128,
    total_ns: u128,
}

impl CallMetrics {
    fn accumulator_build_ns(&self) -> u128 {
        self.pfks_left_ns
            + self.pfks_right_ns
            + self.spread_left_ns
            + self.spread_right_ns
            + self.sum_ns
    }

    fn emit(&self, fixture: &str, call_index: usize) {
        println!(
            "{{\"record\":\"d2_call\",\"fixture\":\"{}\",\"call_index\":{},\"role\":\"{}\",\"pfks_calls\":{},\"control_ks_calls\":{},\"blind_rotations\":{},\"sample_extractions\":{},\"allocation_ns\":{},\"pfks_left_ns\":{},\"pfks_right_ns\":{},\"spread_left_ns\":{},\"spread_right_ns\":{},\"sum_ns\":{},\"accumulator_build_ns\":{},\"control_ks_ns\":{},\"blind_rotate_ns\":{},\"sample_extract_ns\":{},\"total_ns\":{}}}",
            fixture,
            call_index,
            self.role,
            self.pfks_calls,
            self.control_ks_calls,
            self.blind_rotations,
            self.sample_extractions,
            self.allocation_ns,
            self.pfks_left_ns,
            self.pfks_right_ns,
            self.spread_left_ns,
            self.spread_right_ns,
            self.sum_ns,
            self.accumulator_build_ns(),
            self.control_ks_ns,
            self.blind_rotate_ns,
            self.sample_extract_ns,
            self.total_ns,
        );
    }
}

fn selector_masks(polynomial_size: PolynomialSize) -> (Poly, Poly) {
    assert_eq!(polynomial_size.0 % SELECTOR_MODULUS, 0);
    let half = polynomial_size.0 / 2;
    let chunk = polynomial_size.0 / SELECTOR_MODULUS;

    // This is the Cong double_glwe_acc layout.  The half-chunk negation and
    // rotation implement the standard negacyclic accumulator correction.
    let mut left = vec![1u64; half];
    left.extend(vec![0u64; half]);
    for coefficient in &mut left[..chunk / 2] {
        *coefficient = coefficient.wrapping_neg();
    }
    left.rotate_left(chunk / 2);

    let mut right = vec![0u64; half];
    right.extend(vec![1u64; half]);
    for coefficient in &mut right[..chunk / 2] {
        *coefficient = coefficient.wrapping_neg();
    }
    right.rotate_left(chunk / 2);

    (
        Polynomial::from_container(left),
        Polynomial::from_container(right),
    )
}

fn polynomial_fft_wrapping_mul<OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<LhsCont>,
    rhs: &Polynomial<RhsCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    OutputCont: ContainerMut<Element = u64>,
    LhsCont: Container<Element = u64>,
    RhsCont: Container<Element = u64>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    let mut fourier_lhs = FourierPolynomial::new(lhs.polynomial_size());
    let mut fourier_rhs = FourierPolynomial::new(rhs.polynomial_size());

    fft.forward_as_torus(
        fourier_lhs.as_mut_view(),
        lhs.as_view(),
        &mut *stack,
    );
    fft.forward_as_integer(
        fourier_rhs.as_mut_view(),
        rhs.as_view(),
        &mut *stack,
    );
    for (left, right) in fourier_lhs.data.iter_mut().zip(fourier_rhs.data.iter()) {
        *left *= *right;
    }
    fft.backward_as_torus(
        output.as_mut_view(),
        fourier_lhs.as_view(),
        &mut *stack,
    );
}

fn spread_glwe(
    input: &Glwe,
    mask: &Poly,
    fft: FftView<'_>,
    stack: &mut PodStack,
) -> Glwe {
    let mut output = GlweCiphertext::new(
        0u64,
        input.glwe_size(),
        input.polynomial_size(),
        input.ciphertext_modulus(),
    );
    for (mut output_poly, input_poly) in output
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(input.as_polynomial_list().iter())
    {
        polynomial_fft_wrapping_mul(
            &mut output_poly,
            &input_poly,
            mask,
            fft,
            &mut *stack,
        );
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn d2_select(
    role: &'static str,
    left_payload: &Lwe,
    right_payload: &Lwe,
    encrypted_control: &Lwe,
    pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
    left_mask: &Poly,
    right_mask: &Poly,
    fft: FftView<'_>,
    stack: &mut PodStack,
) -> (Lwe, CallMetrics) {
    let total_started = Instant::now();
    let modulus = left_payload.ciphertext_modulus();
    assert_eq!(right_payload.ciphertext_modulus(), modulus);
    assert_eq!(encrypted_control.ciphertext_modulus(), modulus);

    let started = Instant::now();
    let mut left_glwe = GlweCiphertext::new(
        0u64,
        pfpksk.output_glwe_size(),
        pfpksk.output_polynomial_size(),
        modulus,
    );
    let mut right_glwe = left_glwe.clone();
    let mut allocation_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
        pfpksk,
        &mut left_glwe,
        left_payload,
    );
    let pfks_left_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
        pfpksk,
        &mut right_glwe,
        right_payload,
    );
    let pfks_right_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let mut accumulator = spread_glwe(&left_glwe, left_mask, fft, &mut *stack);
    let spread_left_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let right_accumulator = spread_glwe(&right_glwe, right_mask, fft, &mut *stack);
    let spread_right_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    for (mut left, right) in accumulator
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(right_accumulator.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_assign(&mut left, &right);
    }
    let sum_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let mut small_control = LweCiphertext::new(
        0u64,
        ksk.output_key_lwe_dimension().to_lwe_size(),
        modulus,
    );
    allocation_ns += started.elapsed().as_nanos();
    let started = Instant::now();
    keyswitch_lwe_ciphertext(ksk, encrypted_control, &mut small_control);
    let control_ks_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    blind_rotate_assign(&small_control, &mut accumulator, bsk);
    let blind_rotate_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let mut output = LweCiphertext::new(
        0u64,
        bsk.output_lwe_dimension().to_lwe_size(),
        modulus,
    );
    allocation_ns += started.elapsed().as_nanos();
    let started = Instant::now();
    extract_lwe_sample_from_glwe_ciphertext(
        &accumulator,
        &mut output,
        MonomialDegree(0),
    );
    let sample_extract_ns = started.elapsed().as_nanos();

    (
        output,
        CallMetrics {
            role,
            pfks_calls: 2,
            control_ks_calls: 1,
            blind_rotations: 1,
            sample_extractions: 1,
            allocation_ns,
            pfks_left_ns,
            pfks_right_ns,
            spread_left_ns,
            spread_right_ns,
            sum_ns,
            control_ks_ns,
            blind_rotate_ns,
            sample_extract_ns,
            total_ns: total_started.elapsed().as_nanos(),
        },
    )
}

fn hash_lwe(ciphertext: &Lwe) -> String {
    let mut hasher = Sha256::new();
    for coefficient in ciphertext.as_ref() {
        hasher.update(coefficient.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn decode_and_error(
    secret_key: &LweSecretKeyView<'_, u64>,
    ciphertext: &Lwe,
    expected: u64,
    delta: u64,
) -> (u64, f64) {
    let phase = decrypt_lwe_ciphertext(secret_key, ciphertext).0;
    let decoded = phase.wrapping_add(delta / 2) / delta;
    let expected_phase = expected.wrapping_mul(delta);
    let signed_error = phase.wrapping_sub(expected_phase) as i64;
    (decoded, signed_error as f64 / delta as f64)
}

fn main() {
    if env::var(RUN_ACK_ENV).as_deref() != Ok(RUN_ACK_VALUE) {
        println!(
            "{{\"record\":\"plan\",\"status\":\"NO_FHE_GUARD\",\"variant\":\"a30_d2_n2_isolated\",\"required_env\":\"{}={}\",\"observable_dynamic_outputs\":5,\"observable_pfks_calls\":10,\"full_pipeline_counts_observed\":false}}",
            RUN_ACK_ENV, RUN_ACK_VALUE
        );
        return;
    }

    let fixture = Fixture::from_env();
    let process_id = std::process::id();
    let rayon_threads = env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".to_string());
    let modulus = CiphertextModulus::<u64>::new_native();

    let keygen_started = Instant::now();
    let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server_key = ServerKey::new(&client_key);
    let base_keygen_ns = keygen_started.elapsed().as_nanos();
    let (glwe_secret_key, _small_secret_key, parameters) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let polynomial_size = glwe_secret_key.polynomial_size();

    let bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("A30 D2 requires the A44 classic bootstrap key"),
    };
    assert_eq!(bsk.polynomial_size(), polynomial_size);
    assert_eq!(bsk.output_lwe_dimension(), big_secret_key.lwe_dimension());
    assert_eq!(
        server_key.key_switching_key.input_key_lwe_dimension(),
        big_secret_key.lwe_dimension()
    );

    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let pfpksk_started = Instant::now();
    let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
        0u64,
        PFPKS_BASE_LOG,
        PFPKS_LEVEL,
        big_secret_key.lwe_dimension(),
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
        modulus,
    );
    let mut identity_polynomial = Polynomial::new(0u64, polynomial_size);
    identity_polynomial[0] = u64::MAX;
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big_secret_key,
        &glwe_secret_key,
        &mut pfpksk,
        parameters.glwe_noise_distribution(),
        &mut encryption_generator,
        |value| value.wrapping_neg(),
        &identity_polynomial,
    );
    let pfpksk_keygen_ns = pfpksk_started.elapsed().as_nanos();
    let pfpksk_bytes = pfpksk.as_ref().len() * size_of::<u64>();

    let public_setup_started = Instant::now();
    let (left_mask, right_mask) = selector_masks(polynomial_size);
    let fft = Fft::new(polynomial_size);
    let fft_view = fft.as_view();
    let fft_requirement = fft_view
        .forward_scratch()
        .expect("forward FFT scratch overflow")
        .and(
            fft_view
                .backward_scratch()
                .expect("backward FFT scratch overflow"),
        );
    let mut fft_memory = GlobalPodBuffer::new(fft_requirement);
    let fft_stack = PodStack::new(&mut fft_memory);
    let public_setup_ns = public_setup_started.elapsed().as_nanos();

    let encryption_started = Instant::now();
    let mut encrypt_big = |value: u64, delta: u64| {
        let mut ciphertext = LweCiphertext::new(
            0u64,
            big_secret_key.lwe_dimension().to_lwe_size(),
            modulus,
        );
        encrypt_lwe_ciphertext(
            &big_secret_key,
            &mut ciphertext,
            Plaintext(value.wrapping_mul(delta)),
            parameters.glwe_noise_distribution(),
            &mut encryption_generator,
        );
        ciphertext
    };

    let payload_scales = [BOOL_DELTA, BOOL_DELTA, BOOL_DELTA, ID_DELTA];
    let sentinel_values = [4u64, 0, 0, 0];
    let gallery1_values = [0u64, 0, 5, 1];
    let sentinel: Vec<Lwe> = sentinel_values
        .iter()
        .zip(payload_scales)
        .map(|(&value, delta)| encrypt_big(value, delta))
        .collect();
    let gallery1: Vec<Lwe> = gallery1_values
        .iter()
        .zip(payload_scales)
        .map(|(&value, delta)| encrypt_big(value, delta))
        .collect();
    let gallery2_id = encrypt_big(2, ID_DELTA);
    let node0_control = encrypt_big(
        if fixture.node0_select_right {
            RIGHT_CONTROL
        } else {
            LEFT_CONTROL
        },
        BOOL_DELTA,
    );
    let root_control = encrypt_big(
        if fixture.root_select_right {
            RIGHT_CONTROL
        } else {
            LEFT_CONTROL
        },
        BOOL_DELTA,
    );
    let input_encryption_ns = encryption_started.elapsed().as_nanos();

    println!(
        "{{\"record\":\"meta\",\"variant\":\"a30_d2_n2_isolated\",\"fixture\":\"{}\",\"process_id\":{},\"rayon_threads_env\":\"{}\",\"tfhe_version\":\"0.11.3\",\"params_fingerprint\":\"{}\",\"pfpks_base_log\":{},\"pfpks_level\":{},\"selector_modulus\":{},\"left_control\":{},\"right_control\":{},\"base_keygen_ns\":{},\"pfpks_keygen_ns\":{},\"pfpksk_bytes\":{},\"public_setup_ns\":{},\"input_encryption_ns\":{},\"keygen_in_query_latency\":false,\"bridge_present\":false,\"comparator_present\":false}}",
        fixture.name,
        process_id,
        rayon_threads,
        PARAMS_FINGERPRINT,
        PFPKS_BASE_LOG.0,
        PFPKS_LEVEL.0,
        SELECTOR_MODULUS,
        LEFT_CONTROL,
        RIGHT_CONTROL,
        base_keygen_ns,
        pfpksk_keygen_ns,
        pfpksk_bytes,
        public_setup_ns,
        input_encryption_ns,
    );

    let query_started = Instant::now();
    let mut node0_outputs = Vec::with_capacity(4);
    let mut calls = Vec::with_capacity(5);
    for (index, role) in ["node0_top", "node0_middle", "node0_low", "node0_id"]
        .into_iter()
        .enumerate()
    {
        let (output, metrics) = d2_select(
            role,
            &sentinel[index],
            &gallery1[index],
            &node0_control,
            &pfpksk,
            &server_key.key_switching_key,
            bsk,
            &left_mask,
            &right_mask,
            fft_view,
            &mut *fft_stack,
        );
        node0_outputs.push(output);
        calls.push(metrics);
    }
    let (root_id, root_metrics) = d2_select(
        "root_id",
        &node0_outputs[3],
        &gallery2_id,
        &root_control,
        &pfpksk,
        &server_key.key_switching_key,
        bsk,
        &left_mask,
        &right_mask,
        fft_view,
        &mut *fft_stack,
    );
    calls.push(root_metrics);
    let query_ns = query_started.elapsed().as_nanos();

    for (index, call) in calls.iter().enumerate() {
        call.emit(fixture.name, index);
    }

    let expected_node0 = if fixture.node0_select_right {
        gallery1_values
    } else {
        sentinel_values
    };
    let mut intermediate_pass = true;
    let mut max_abs_phase_error = 0.0f64;
    for index in 0..4 {
        let (decoded, error) = decode_and_error(
            &big_secret_key,
            &node0_outputs[index],
            expected_node0[index],
            payload_scales[index],
        );
        intermediate_pass &= decoded == expected_node0[index];
        max_abs_phase_error = max_abs_phase_error.max(error.abs());
    }
    let (actual_code, root_phase_error) = decode_and_error(
        &big_secret_key,
        &root_id,
        fixture.expected_code,
        ID_DELTA,
    );
    max_abs_phase_error = max_abs_phase_error.max(root_phase_error.abs());
    let output_nontrivial = root_id.get_mask().as_ref().iter().any(|&word| word != 0);
    let semantics_pass = intermediate_pass
        && actual_code == fixture.expected_code
        && output_nontrivial
        && max_abs_phase_error < 0.5;
    let observed_pfks_calls: usize = calls.iter().map(|call| call.pfks_calls).sum();
    let observed_control_ks: usize = calls.iter().map(|call| call.control_ks_calls).sum();
    let observed_blind_rotations: usize = calls.iter().map(|call| call.blind_rotations).sum();
    let observed_sample_extractions: usize =
        calls.iter().map(|call| call.sample_extractions).sum();
    let counters_pass = calls.len() == 5
        && observed_pfks_calls == 10
        && observed_control_ks == 5
        && observed_blind_rotations == 5
        && observed_sample_extractions == 5;

    println!(
        "{{\"record\":\"summary\",\"variant\":\"a30_d2_n2_isolated\",\"fixture\":\"{}\",\"query_ns\":{},\"observable_dynamic_outputs\":{},\"observable_pfks_calls\":{},\"observable_control_ks\":{},\"observable_blind_rotations\":{},\"observable_sample_extractions\":{},\"projected_full_pipeline_pbs\":39,\"projected_full_pipeline_classic_ks\":33,\"projected_full_pipeline_marginals\":53,\"full_pipeline_counts_observed\":false,\"expected_code\":{},\"actual_code\":{},\"intermediate_pass\":{},\"output_nontrivial\":{},\"max_abs_normalized_phase_error\":{:.12},\"root_ciphertext_sha256\":\"{}\",\"counters_pass\":{},\"semantics_pass\":{}}}",
        fixture.name,
        query_ns,
        calls.len(),
        observed_pfks_calls,
        observed_control_ks,
        observed_blind_rotations,
        observed_sample_extractions,
        fixture.expected_code,
        actual_code,
        intermediate_pass,
        output_nontrivial,
        max_abs_phase_error,
        hash_lwe(&root_id),
        counters_pass,
        semantics_pass,
    );

    assert!(counters_pass, "D2 N=2 must execute exactly five dynamic outputs");
    assert!(semantics_pass, "D2 N=2 selector gate failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn negacyclic_sample(body: &[u64], rotation: usize) -> u64 {
        let value = body[rotation % body.len()];
        if (rotation / body.len()) % 2 == 0 {
            value
        } else {
            value.wrapping_neg()
        }
    }

    #[test]
    fn cong_masks_select_left_then_right_on_all_p16_centers() {
        let polynomial_size = PolynomialSize(2048);
        let (left_mask, right_mask) = selector_masks(polynomial_size);
        let left_value = 17u64;
        let right_value = 29u64;
        let body: Vec<u64> = left_mask
            .as_ref()
            .iter()
            .zip(right_mask.as_ref())
            .map(|(&left, &right)| {
                left_value
                    .wrapping_mul(left)
                    .wrapping_add(right_value.wrapping_mul(right))
            })
            .collect();
        let chunk = polynomial_size.0 / SELECTOR_MODULUS;
        for slot in 0..SELECTOR_MODULUS {
            let expected = if slot < SELECTOR_MODULUS / 2 {
                left_value
            } else {
                right_value
            };
            assert_eq!(negacyclic_sample(&body, slot * chunk), expected);
        }
        assert_eq!(negacyclic_sample(&body, LEFT_CONTROL as usize * chunk), left_value);
        assert_eq!(
            negacyclic_sample(&body, RIGHT_CONTROL as usize * chunk),
            right_value
        );
    }

    #[test]
    fn fixture_policies_have_exact_codes() {
        for (name, expected) in [("id1", 1), ("id2", 2), ("reject", 0), ("tie_left", 1)] {
            env::set_var("A30_FIXTURE", name);
            assert_eq!(Fixture::from_env().expected_code, expected);
        }
        env::remove_var("A30_FIXTURE");
    }
}
