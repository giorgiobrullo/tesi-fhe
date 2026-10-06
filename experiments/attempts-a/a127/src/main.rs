//! A127: direct-window PFKS versus frozen convolution and scalar D2 controls.
//!
//! The component receives an encrypted left/right control.  It deliberately
//! excludes score bridging, comparison, tournament composition, and open-set
//! threshold logic.  No runtime claim follows until the preregistered gate is
//! compiled and executed in three authorized clean, fresh-key processes.
//! The convolution/scalar datapaths are copied byte-for-byte from A120/A108.
//! A127 adds direct-window PFKS and coefficientwise modulus-switch support audit.

#![recursion_limit = "256"]

use serde_json::json;
use std::io::{self, Write};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use dyn_stack::{GlobalPodBuffer, PodStack};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::mem::size_of;
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_assign;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomial;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const ARTIFACT: &str = "A127";
const RUN_ACK_ENV: &str = "A127_RUN_FHE";
const RUN_ACK_VALUE: &str = "I_ACKNOWLEDGE_A127_DIRECT_WINDOW_PFKS_FHE";
const PREREG_ACK_ENV: &str = "A127_PREREGISTRATION_SHA256";
const PREREG_SHA256: &str =
    "2bbc55173731fd3f79b91e4bfa3dc3eed3ede835850634cab07b1a490acd27d4";
const PARAMS_FINGERPRINT: &str =
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1";

const POLYNOMIAL_SIZE: usize = 2_048;
const GLWE_SIZE: usize = 2;
const SELECTOR_MODULUS: usize = 16;
const BOX_SIZE: usize = POLYNOMIAL_SIZE / SELECTOR_MODULUS;
const STRICT_RADIUS: isize = BOX_SIZE as isize / 2 - 1;
const INTERIOR_OFFSET: isize = 48;
const INTERIOR_GUARD_BAND: isize = STRICT_RADIUS - INTERIOR_OFFSET;
const OUTPUTS: usize = 4;
const BRANCHES: usize = 2;
const PACKED_TERMS: usize = OUTPUTS * BRANCHES;
const LEFT_CONTROL: u64 = 4;
const RIGHT_CONTROL: u64 = 12;
const SCORE_DELTA: u64 = 1u64 << 59;
const ID_DELTA: u64 = 1u64 << 56;
const TORUS_PER_BLIND_ROTATION_DEGREE: u64 = 1u64 << 52;
const PAYLOAD_DELTAS: [u64; OUTPUTS] = [SCORE_DELTA, SCORE_DELTA, SCORE_DELTA, ID_DELTA];
const LANE_NAMES: [&str; OUTPUTS] = ["score_top", "score_middle", "score_low", "id"];

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
type Poly = PolynomialOwned<u64>;

#[derive(Clone, Copy)]
struct PfksParameters {
    label: &'static str,
    base_log: usize,
    level_count: usize,
}

impl PfksParameters {
    const P24X1: Self = Self {
        label: "24x1",
        base_log: 24,
        level_count: 1,
    };

    fn parse(label: &str) -> Option<Self> {
        match label {
            "24x1" => Some(Self::P24X1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    contract_role: &'static str,
    left: [u64; OUTPUTS],
    right: [u64; OUTPUTS],
    control: u64,
    requested_control_degree_error: isize,
}

impl Fixture {
    fn expected(&self) -> [u64; OUTPUTS] {
        match self.control {
            LEFT_CONTROL => self.left,
            RIGHT_CONTROL => self.right,
            _ => unreachable!("fixture controls are statically bounded"),
        }
    }

    fn control_phase(&self) -> u64 {
        let center = self.control.wrapping_mul(SCORE_DELTA);
        let magnitude = self.requested_control_degree_error.unsigned_abs() as u64
            * TORUS_PER_BLIND_ROTATION_DEGREE;
        if self.requested_control_degree_error < 0 {
            center.wrapping_sub(magnitude)
        } else {
            center.wrapping_add(magnitude)
        }
    }
}

const FIXTURES: [Fixture; 8] = [
    Fixture {
        name: "left_zero_vs_clipped_max",
        contract_role: "left_control_and_mixed_scale_extrema",
        left: [0, 0, 0, 1],
        right: [4, 15, 15, 127],
        control: LEFT_CONTROL,
        requested_control_degree_error: -INTERIOR_OFFSET,
    },
    Fixture {
        name: "right_zero_vs_clipped_max",
        contract_role: "right_control_and_mixed_scale_extrema",
        left: [4, 15, 15, 127],
        right: [0, 0, 0, 1],
        control: RIGHT_CONTROL,
        requested_control_degree_error: INTERIOR_OFFSET,
    },
    Fixture {
        name: "accept_threshold_left",
        contract_role: "score_1023_beats_sentinel_1024",
        left: [3, 15, 15, 127],
        right: [4, 0, 0, 0],
        control: LEFT_CONTROL,
        requested_control_degree_error: INTERIOR_OFFSET,
    },
    Fixture {
        name: "accept_threshold_right",
        contract_role: "score_1023_beats_sentinel_1024",
        left: [4, 0, 0, 0],
        right: [3, 15, 15, 127],
        control: RIGHT_CONTROL,
        requested_control_degree_error: -INTERIOR_OFFSET,
    },
    Fixture {
        name: "reject_sentinel_tie_left",
        contract_role: "score_1024_clips_to_sentinel_and_tie_left_keeps_id_zero",
        left: [4, 0, 0, 0],
        right: [4, 0, 0, 127],
        control: LEFT_CONTROL,
        requested_control_degree_error: 0,
    },
    Fixture {
        name: "reject_clipped_left",
        contract_role: "sentinel_beats_clipped_score_above_threshold",
        left: [4, 0, 0, 0],
        right: [4, 15, 15, 127],
        control: LEFT_CONTROL,
        requested_control_degree_error: -INTERIOR_OFFSET,
    },
    Fixture {
        name: "score_tie_left",
        contract_role: "equal_score_tie_left_keeps_first_id",
        left: [3, 14, 7, 3],
        right: [3, 14, 7, 127],
        control: LEFT_CONTROL,
        requested_control_degree_error: INTERIOR_OFFSET,
    },
    Fixture {
        name: "right_low_nibble_boundary",
        contract_role: "score_15_on_right_beats_score_16_on_left",
        left: [0, 1, 0, 126],
        right: [0, 0, 15, 127],
        control: RIGHT_CONTROL,
        requested_control_degree_error: 0,
    },
];

enum Action {
    Plan,
    Run(PfksParameters),
}

fn parse_args_from<I>(arguments: I) -> Result<Action, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = arguments.into_iter().collect();
    if args.is_empty() {
        return Ok(Action::Plan);
    }
    if args.len() != 3 || args[0] != "--run-authorized" || args[1] != "--pfks" {
        return Err(
            "expected no arguments, or exactly: --run-authorized --pfks 24x1"
                .to_string(),
        );
    }
    let parameters = PfksParameters::parse(&args[2])
        .ok_or_else(|| format!("unsupported preregistered PFKS parameter {:?}", args[2]))?;
    Ok(Action::Run(parameters))
}

fn emit_invalid(reason: &str) -> ! {
    let escaped = json_escape(reason);
    println!(
        "{{\"record\":\"invalid\",\"artifact\":\"{}\",\"status\":\"NO_FHE\",\"reason\":\"{}\"}}",
        ARTIFACT, escaped
    );
    std::process::exit(2);
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(&mut escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn check_runtime_authorization() -> Result<(), String> {
    if env::var(RUN_ACK_ENV).as_deref() != Ok(RUN_ACK_VALUE) {
        return Err(format!("missing exact authorization {RUN_ACK_ENV}={RUN_ACK_VALUE}"));
    }
    if env::var(PREREG_ACK_ENV).as_deref() != Ok(PREREG_SHA256) {
        return Err(format!(
            "missing exact preregistration acknowledgement {PREREG_ACK_ENV}={PREREG_SHA256}"
        ));
    }
    Ok(())
}

#[derive(Default)]
struct SelectorMetrics {
    pfks_calls: usize,
    logical_glwe_public_mask_spreads: usize,
    scalar_polynomial_fft_multiplications: usize,
    glwe_additions: usize,
    control_ks_calls: usize,
    blind_rotations: usize,
    sample_extractions: usize,
    constant_glwe_allocations: usize,
    spread_glwe_allocations: usize,
    small_lwe_allocations: usize,
    output_lwe_allocations: usize,
    peak_live_dynamic_glwe_ciphertexts: usize,
    constant_glwe_allocation_ns: [u128; PACKED_TERMS],
    spread_glwe_allocation_ns: [u128; PACKED_TERMS],
    pfks_ns: [u128; PACKED_TERMS],
    spread_ns: [u128; PACKED_TERMS],
    glwe_add_ns: [u128; PACKED_TERMS - 1],
    control_lwe_allocation_ns: u128,
    control_ks_ns: u128,
    blind_rotate_ns: u128,
    output_lwe_allocation_ns: [u128; OUTPUTS],
    sample_extract_ns: [u128; OUTPUTS],
    total_ns: u128,
}

impl SelectorMetrics {
    fn counters_pass(&self) -> bool {
        self.pfks_calls == 8
            && self.logical_glwe_public_mask_spreads == 8
            && self.scalar_polynomial_fft_multiplications == 16
            && self.glwe_additions == 7
            && self.control_ks_calls == 1
            && self.blind_rotations == 1
            && self.sample_extractions == 4
            && self.constant_glwe_allocations == 8
            && self.spread_glwe_allocations == 8
            && self.small_lwe_allocations == 1
            && self.output_lwe_allocations == 4
            && self.peak_live_dynamic_glwe_ciphertexts == 3
    }

    fn accumulator_build_ns(&self) -> u128 {
        self.constant_glwe_allocation_ns.iter().sum::<u128>()
            + self.spread_glwe_allocation_ns.iter().sum::<u128>()
            + self.pfks_ns.iter().sum::<u128>()
            + self.spread_ns.iter().sum::<u128>()
            + self.glwe_add_ns.iter().sum::<u128>()
    }
}

#[derive(Default)]
struct ScalarD2Metrics {
    pfks_calls: usize,
    logical_glwe_public_mask_spreads: usize,
    scalar_polynomial_fft_multiplications: usize,
    glwe_additions: usize,
    control_ks_calls: usize,
    blind_rotations: usize,
    sample_extractions: usize,
    constant_glwe_allocation_ns: [u128; PACKED_TERMS],
    spread_glwe_allocation_ns: [u128; PACKED_TERMS],
    pfks_ns: [u128; PACKED_TERMS],
    spread_ns: [u128; PACKED_TERMS],
    glwe_add_ns: [u128; OUTPUTS],
    control_lwe_allocation_ns: [u128; OUTPUTS],
    control_ks_ns: [u128; OUTPUTS],
    blind_rotate_ns: [u128; OUTPUTS],
    output_lwe_allocation_ns: [u128; OUTPUTS],
    sample_extract_ns: [u128; OUTPUTS],
    total_ns: u128,
}

impl ScalarD2Metrics {
    fn counters_pass(&self) -> bool {
        self.pfks_calls == 8
            && self.logical_glwe_public_mask_spreads == 8
            && self.scalar_polynomial_fft_multiplications == 16
            && self.glwe_additions == 4
            && self.control_ks_calls == 4
            && self.blind_rotations == 4
            && self.sample_extractions == 4
    }

    fn accumulator_build_ns(&self) -> u128 {
        self.constant_glwe_allocation_ns.iter().sum::<u128>()
            + self.spread_glwe_allocation_ns.iter().sum::<u128>()
            + self.pfks_ns.iter().sum::<u128>()
            + self.spread_ns.iter().sum::<u128>()
            + self.glwe_add_ns.iter().sum::<u128>()
    }
}

fn signed_cell_mask(polynomial_size: PolynomialSize, virtual_center: usize) -> Poly {
    assert_eq!(polynomial_size.0, POLYNOMIAL_SIZE);
    let ring_size = polynomial_size.0 as isize;
    let mut coefficients = vec![0u64; polynomial_size.0];
    for error in -STRICT_RADIUS..=STRICT_RADIUS {
        let virtual_degree = virtual_center as isize + error;
        let cycles = virtual_degree.div_euclid(ring_size);
        let index = virtual_degree.rem_euclid(ring_size) as usize;
        let coefficient = if cycles.rem_euclid(2) == 0 {
            1u64
        } else {
            u64::MAX
        };
        assert!(coefficients[index] == 0 || coefficients[index] == coefficient);
        coefficients[index] = coefficient;
    }
    assert_eq!(
        coefficients.iter().filter(|&&word| word != 0).count(),
        (2 * STRICT_RADIUS + 1) as usize
    );
    Polynomial::from_container(coefficients)
}

fn packed_selector_masks(polynomial_size: PolynomialSize) -> Vec<Poly> {
    let mut masks = Vec::with_capacity(PACKED_TERMS);
    for control in [LEFT_CONTROL, RIGHT_CONTROL] {
        for lane in 0..OUTPUTS {
            let center = control as usize * BOX_SIZE + lane * BOX_SIZE;
            masks.push(signed_cell_mask(polynomial_size, center));
        }
    }
    masks
}

fn a30_scalar_selector_masks(polynomial_size: PolynomialSize) -> (Poly, Poly) {
    assert_eq!(polynomial_size.0 % SELECTOR_MODULUS, 0);
    let half = polynomial_size.0 / 2;
    let chunk = polynomial_size.0 / SELECTOR_MODULUS;

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
    fft.forward_as_torus(fourier_lhs.as_mut_view(), lhs.as_view(), &mut *stack);
    fft.forward_as_integer(fourier_rhs.as_mut_view(), rhs.as_view(), &mut *stack);
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
) -> (Glwe, u128, u128) {
    let allocation_started = Instant::now();
    let mut output = GlweCiphertext::new(
        0u64,
        input.glwe_size(),
        input.polynomial_size(),
        input.ciphertext_modulus(),
    );
    let allocation_ns = allocation_started.elapsed().as_nanos();
    let multiply_started = Instant::now();
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
    (output, allocation_ns, multiply_started.elapsed().as_nanos())
}

#[allow(clippy::too_many_arguments)]
fn scalar_d2_select_tuple(
    left_payloads: &[Lwe],
    right_payloads: &[Lwe],
    encrypted_control: &Lwe,
    pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
    left_mask: &Poly,
    right_mask: &Poly,
    fft: FftView<'_>,
    stack: &mut PodStack,
) -> ([Lwe; OUTPUTS], [Lwe; OUTPUTS], ScalarD2Metrics) {
    assert_eq!(left_payloads.len(), OUTPUTS);
    assert_eq!(right_payloads.len(), OUTPUTS);
    let modulus = encrypted_control.ciphertext_modulus();
    let total_started = Instant::now();
    let mut metrics = ScalarD2Metrics::default();
    let mut outputs = Vec::with_capacity(OUTPUTS);
    let mut switched_controls = Vec::with_capacity(OUTPUTS);

    for lane in 0..OUTPUTS {
        let left_term = 2 * lane;
        let right_term = left_term + 1;

        let allocation_started = Instant::now();
        let mut left_glwe = GlweCiphertext::new(
            0u64,
            pfpksk.output_glwe_size(),
            pfpksk.output_polynomial_size(),
            modulus,
        );
        metrics.constant_glwe_allocation_ns[left_term] =
            allocation_started.elapsed().as_nanos();
        let pfks_started = Instant::now();
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            pfpksk,
            &mut left_glwe,
            &left_payloads[lane],
        );
        metrics.pfks_ns[left_term] = pfks_started.elapsed().as_nanos();
        metrics.pfks_calls += 1;
        let (mut accumulator, allocation_ns, spread_ns) =
            spread_glwe(&left_glwe, left_mask, fft, &mut *stack);
        metrics.spread_glwe_allocation_ns[left_term] = allocation_ns;
        metrics.spread_ns[left_term] = spread_ns;
        metrics.logical_glwe_public_mask_spreads += 1;
        metrics.scalar_polynomial_fft_multiplications += GLWE_SIZE;

        let allocation_started = Instant::now();
        let mut right_glwe = GlweCiphertext::new(
            0u64,
            pfpksk.output_glwe_size(),
            pfpksk.output_polynomial_size(),
            modulus,
        );
        metrics.constant_glwe_allocation_ns[right_term] =
            allocation_started.elapsed().as_nanos();
        let pfks_started = Instant::now();
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            pfpksk,
            &mut right_glwe,
            &right_payloads[lane],
        );
        metrics.pfks_ns[right_term] = pfks_started.elapsed().as_nanos();
        metrics.pfks_calls += 1;
        let (right_accumulator, allocation_ns, spread_ns) =
            spread_glwe(&right_glwe, right_mask, fft, &mut *stack);
        metrics.spread_glwe_allocation_ns[right_term] = allocation_ns;
        metrics.spread_ns[right_term] = spread_ns;
        metrics.logical_glwe_public_mask_spreads += 1;
        metrics.scalar_polynomial_fft_multiplications += GLWE_SIZE;

        let add_started = Instant::now();
        for (mut output_poly, input_poly) in accumulator
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(right_accumulator.as_polynomial_list().iter())
        {
            polynomial_wrapping_add_assign(&mut output_poly, &input_poly);
        }
        metrics.glwe_add_ns[lane] = add_started.elapsed().as_nanos();
        metrics.glwe_additions += 1;

        let control_allocation_started = Instant::now();
        let mut small_control = LweCiphertext::new(
            0u64,
            ksk.output_key_lwe_dimension().to_lwe_size(),
            modulus,
        );
        metrics.control_lwe_allocation_ns[lane] =
            control_allocation_started.elapsed().as_nanos();
        let control_ks_started = Instant::now();
        keyswitch_lwe_ciphertext(ksk, encrypted_control, &mut small_control);
        metrics.control_ks_ns[lane] = control_ks_started.elapsed().as_nanos();
        metrics.control_ks_calls += 1;

        let blind_rotate_started = Instant::now();
        blind_rotate_assign(&small_control, &mut accumulator, bsk);
        metrics.blind_rotate_ns[lane] = blind_rotate_started.elapsed().as_nanos();
        metrics.blind_rotations += 1;

        let output_allocation_started = Instant::now();
        let mut output = LweCiphertext::new(
            0u64,
            bsk.output_lwe_dimension().to_lwe_size(),
            modulus,
        );
        metrics.output_lwe_allocation_ns[lane] =
            output_allocation_started.elapsed().as_nanos();
        let extraction_started = Instant::now();
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut output,
            MonomialDegree(0),
        );
        metrics.sample_extract_ns[lane] = extraction_started.elapsed().as_nanos();
        metrics.sample_extractions += 1;
        outputs.push(output);
        switched_controls.push(small_control);
    }

    metrics.total_ns = total_started.elapsed().as_nanos();
    let outputs: [Lwe; OUTPUTS] = outputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly four scalar D2 outputs are constructed"));
    let switched_controls: [Lwe; OUTPUTS] = switched_controls
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly four scalar controls are constructed"));
    (outputs, switched_controls, metrics)
}

#[allow(clippy::too_many_arguments)]
fn packed_d2_select(
    left_payloads: &[Lwe],
    right_payloads: &[Lwe],
    encrypted_control: &Lwe,
    pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
    masks: &[Poly],
    fft: FftView<'_>,
    stack: &mut PodStack,
) -> ([Lwe; OUTPUTS], Lwe, SelectorMetrics) {
    assert_eq!(left_payloads.len(), OUTPUTS);
    assert_eq!(right_payloads.len(), OUTPUTS);
    assert_eq!(masks.len(), PACKED_TERMS);
    let modulus = encrypted_control.ciphertext_modulus();
    assert!(left_payloads
        .iter()
        .chain(right_payloads)
        .all(|payload| payload.ciphertext_modulus() == modulus));

    let total_started = Instant::now();
    let mut metrics = SelectorMetrics::default();
    let mut accumulator: Option<Glwe> = None;
    let payloads = left_payloads.iter().chain(right_payloads.iter());
    for (term_index, (payload, mask)) in payloads.zip(masks.iter()).enumerate() {
        let allocation_started = Instant::now();
        let mut constant_glwe = GlweCiphertext::new(
            0u64,
            pfpksk.output_glwe_size(),
            pfpksk.output_polynomial_size(),
            modulus,
        );
        metrics.constant_glwe_allocation_ns[term_index] =
            allocation_started.elapsed().as_nanos();
        metrics.constant_glwe_allocations += 1;

        let pfks_started = Instant::now();
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            pfpksk,
            &mut constant_glwe,
            payload,
        );
        metrics.pfks_ns[term_index] = pfks_started.elapsed().as_nanos();
        metrics.pfks_calls += 1;

        let (spread, spread_allocation_ns, spread_ns) =
            spread_glwe(&constant_glwe, mask, fft, &mut *stack);
        metrics.spread_glwe_allocation_ns[term_index] = spread_allocation_ns;
        metrics.spread_ns[term_index] = spread_ns;
        metrics.spread_glwe_allocations += 1;
        metrics.logical_glwe_public_mask_spreads += 1;
        metrics.scalar_polynomial_fft_multiplications += GLWE_SIZE;

        if let Some(current) = accumulator.as_mut() {
            let add_started = Instant::now();
            for (mut output_poly, input_poly) in current
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(spread.as_polynomial_list().iter())
            {
                polynomial_wrapping_add_assign(&mut output_poly, &input_poly);
            }
            metrics.glwe_add_ns[metrics.glwe_additions] = add_started.elapsed().as_nanos();
            metrics.glwe_additions += 1;
            metrics.peak_live_dynamic_glwe_ciphertexts =
                metrics.peak_live_dynamic_glwe_ciphertexts.max(3);
        } else {
            accumulator = Some(spread);
            metrics.peak_live_dynamic_glwe_ciphertexts =
                metrics.peak_live_dynamic_glwe_ciphertexts.max(2);
        }
    }
    let mut accumulator = accumulator.expect("the packed selector has eight terms");

    let control_allocation_started = Instant::now();
    let mut small_control = LweCiphertext::new(
        0u64,
        ksk.output_key_lwe_dimension().to_lwe_size(),
        modulus,
    );
    metrics.control_lwe_allocation_ns = control_allocation_started.elapsed().as_nanos();
    metrics.small_lwe_allocations = 1;

    let control_ks_started = Instant::now();
    keyswitch_lwe_ciphertext(ksk, encrypted_control, &mut small_control);
    metrics.control_ks_ns = control_ks_started.elapsed().as_nanos();
    metrics.control_ks_calls = 1;

    let blind_rotate_started = Instant::now();
    blind_rotate_assign(&small_control, &mut accumulator, bsk);
    metrics.blind_rotate_ns = blind_rotate_started.elapsed().as_nanos();
    metrics.blind_rotations = 1;

    let mut outputs = Vec::with_capacity(OUTPUTS);
    for lane in 0..OUTPUTS {
        let allocation_started = Instant::now();
        let mut output = LweCiphertext::new(
            0u64,
            bsk.output_lwe_dimension().to_lwe_size(),
            modulus,
        );
        metrics.output_lwe_allocation_ns[lane] = allocation_started.elapsed().as_nanos();
        metrics.output_lwe_allocations += 1;

        let extraction_started = Instant::now();
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut output,
            MonomialDegree(lane * BOX_SIZE),
        );
        metrics.sample_extract_ns[lane] = extraction_started.elapsed().as_nanos();
        metrics.sample_extractions += 1;
        outputs.push(output);
    }
    metrics.total_ns = total_started.elapsed().as_nanos();
    let outputs: [Lwe; OUTPUTS] = outputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly four outputs are constructed"));
    (outputs, small_control, metrics)
}

fn hash_lwe(ciphertext: &Lwe) -> String {
    let mut hasher = Sha256::new();
    for coefficient in ciphertext.as_ref() {
        hasher.update(coefficient.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn lwe_bitwise_equal(left: &Lwe, right: &Lwe) -> bool {
    left.ciphertext_modulus() == right.ciphertext_modulus() && left.as_ref() == right.as_ref()
}

#[derive(Clone, Copy)]
struct PhaseAudit {
    phase: u64,
    decoded: u64,
    signed_error: i64,
    absolute_error: u64,
    half_slot_pass: bool,
    decode_pass: bool,
}

fn phase_audit(
    secret_key: &LweSecretKeyView<'_, u64>,
    ciphertext: &Lwe,
    expected: u64,
    delta: u64,
) -> PhaseAudit {
    let phase = decrypt_lwe_ciphertext(secret_key, ciphertext).0;
    let decoded = phase.wrapping_add(delta / 2) / delta;
    let expected_phase = expected.wrapping_mul(delta);
    let signed_error = phase.wrapping_sub(expected_phase) as i64;
    let absolute_error = signed_error.unsigned_abs();
    PhaseAudit {
        phase,
        decoded,
        signed_error,
        absolute_error,
        half_slot_pass: absolute_error < delta / 2,
        decode_pass: decoded == expected,
    }
}

fn modulus_switch_degree(phase: u64) -> usize {
    let two_n = 2 * POLYNOMIAL_SIZE;
    ((((phase as u128) * (two_n as u128) + (1u128 << 63)) >> 64) as usize) % two_n
}

fn centered_degree_error(observed: usize, expected: usize) -> isize {
    let modulus = 2 * POLYNOMIAL_SIZE;
    let forward = (observed + modulus - expected) % modulus;
    if forward > modulus / 2 {
        forward as isize - modulus as isize
    } else {
        forward as isize
    }
}

fn classify_case(
    control_support_pass: bool,
    prerequisite_gate_pass: bool,
    packed_semantic_gate_pass: bool,
) -> &'static str {
    if !control_support_pass {
        "support_invalid"
    } else if !prerequisite_gate_pass {
        "inconclusive_inside_support"
    } else if !packed_semantic_gate_pass {
        "packed_semantic_failure_inside_support"
    } else {
        "pass"
    }
}

#[derive(Default)]
struct DirectMetrics {
    pfks_calls: usize,
    monomial_rotations: usize,
    polynomial_signed_permutations: usize,
    glwe_additions: usize,
    control_ks_calls: usize,
    blind_rotations: usize,
    sample_extractions: usize,
    pfks_ns: [u128; PACKED_TERMS],
    rotations_ns: [u128; PACKED_TERMS],
    build_ns: u128,
    control_ks_ns: u128,
    blind_rotate_ns: u128,
    extract_ns: u128,
    total_ns: u128,
}

impl DirectMetrics {
    fn counters_pass(&self) -> bool {
        self.pfks_calls == 8
            && self.monomial_rotations == 8
            && self.polynomial_signed_permutations == 16
            && self.glwe_additions == 7
            && self.control_ks_calls == 1
            && self.blind_rotations == 1
            && self.sample_extractions == 4
    }
}

fn direct_window_d2_select(
    left: &[Lwe],
    right: &[Lwe],
    encrypted_control: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe; OUTPUTS], Lwe, DirectMetrics) {
    assert_eq!(left.len(), OUTPUTS);
    assert_eq!(right.len(), OUTPUTS);
    let started = Instant::now();
    let mut metrics = DirectMetrics::default();
    let modulus = encrypted_control.ciphertext_modulus();
    let mut accumulator: Option<Glwe> = None;
    let build_started = Instant::now();
    for (index, payload) in left.iter().chain(right).enumerate() {
        let mut term = GlweCiphertext::new(
            0u64,
            window_key.output_glwe_size(),
            window_key.output_polynomial_size(),
            modulus,
        );
        let pfks_started = Instant::now();
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            window_key,
            &mut term,
            payload,
        );
        metrics.pfks_ns[index] = pfks_started.elapsed().as_nanos();
        metrics.pfks_calls += 1;
        let branch = if index < OUTPUTS { LEFT_CONTROL } else { RIGHT_CONTROL };
        let center = (branch as usize + index % OUTPUTS) * BOX_SIZE;
        let rotation_started = Instant::now();
        for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
            polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial, MonomialDegree(center));
            metrics.polynomial_signed_permutations += 1;
        }
        metrics.rotations_ns[index] = rotation_started.elapsed().as_nanos();
        metrics.monomial_rotations += 1;
        if let Some(accumulator) = accumulator.as_mut() {
            for (target, value) in accumulator.as_mut().iter_mut().zip(term.as_ref()) {
                *target = target.wrapping_add(*value);
            }
            metrics.glwe_additions += 1;
        } else {
            accumulator = Some(term);
        }
    }
    let mut accumulator = accumulator.expect("eight payloads fill the accumulator");
    metrics.build_ns = build_started.elapsed().as_nanos();
    let mut control = LweCiphertext::new(0u64, ksk.output_key_lwe_dimension().to_lwe_size(), modulus);
    let ks_started = Instant::now();
    keyswitch_lwe_ciphertext(ksk, encrypted_control, &mut control);
    metrics.control_ks_ns = ks_started.elapsed().as_nanos();
    metrics.control_ks_calls = 1;
    let br_started = Instant::now();
    blind_rotate_assign(&control, &mut accumulator, bsk);
    metrics.blind_rotate_ns = br_started.elapsed().as_nanos();
    metrics.blind_rotations = 1;
    let extract_started = Instant::now();
    let outputs = std::array::from_fn(|lane| {
        let mut output = LweCiphertext::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), modulus);
        extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut output, MonomialDegree(lane * BOX_SIZE));
        metrics.sample_extractions += 1;
        output
    });
    metrics.extract_ns = extract_started.elapsed().as_nanos();
    metrics.total_ns = started.elapsed().as_nanos();
    (outputs, control, metrics)
}

/// Exact effective phase used by the stock binary-key blind rotation. Rounding
/// the decrypted phase once would omit the mask's modulus-switch error.
fn effective_rotation_degree(control: &Lwe, secret: &LweSecretKeyView<'_, u64>) -> usize {
    let size = PolynomialSize(POLYNOMIAL_SIZE);
    let modulus = 2 * POLYNOMIAL_SIZE;
    let body = pbs_modulus_switch(*control.get_body().data, size) % modulus;
    let mask = control.get_mask().as_ref().iter().zip(secret.as_ref()).fold(0usize, |sum, (&a, &s)| {
        assert!(s <= 1, "effective rotation audit assumes the pinned binary secret");
        (sum + pbs_modulus_switch(a, size) * s as usize) % modulus
    });
    (body + modulus - mask) % modulus
}

fn emit(value: serde_json::Value) {
    println!("{value}");
    io::stdout().flush().expect("flush research result record");
}

fn nontrivial(ciphertext: &Lwe) -> bool {
    ciphertext.get_mask().as_ref().iter().any(|&word| word != 0)
}

fn audit_json(audit: PhaseAudit, ciphertext: &Lwe, delta: u64) -> serde_json::Value {
    json!({
        "decoded": audit.decoded, "phase": audit.phase,
        "signed_error": audit.signed_error, "absolute_error": audit.absolute_error,
        "half_slot_limit_exclusive": delta / 2, "half_slot_pass": audit.half_slot_pass,
        "decode_pass": audit.decode_pass, "nontrivial": nontrivial(ciphertext),
        "sha256": hash_lwe(ciphertext)
    })
}

fn lane_pass(audit: PhaseAudit, ciphertext: &Lwe) -> bool {
    audit.decode_pass && audit.half_slot_pass && nontrivial(ciphertext)
}

fn arm_order(fixture: usize, offset: usize) -> [usize; 3] {
    const ORDERS: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    ORDERS[(fixture + 2 * offset) % ORDERS.len()]
}

fn run(parameters: PfksParameters) -> Result<(), String> {
    let order_offset: usize = env::var("A127_ORDER_OFFSET").unwrap_or_else(|_| "0".into())
        .parse().map_err(|_| "A127_ORDER_OFFSET must be 0, 1 or 2")?;
    if order_offset > 2 { return Err("A127_ORDER_OFFSET must be 0, 1 or 2".into()); }
    if env::var("RAYON_NUM_THREADS").as_deref() != Ok("1") {
        return Err("A127 first gate requires RAYON_NUM_THREADS=1".into());
    }
    let modulus = CiphertextModulus::<u64>::new_native();
    let key_started = Instant::now();
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server = ServerKey::new(&client);
    let base_keygen_ns = key_started.elapsed().as_nanos();
    let (glwe_secret, small_secret, shortint_parameters) = client.into_raw_parts();
    let big_secret = glwe_secret.as_lwe_secret_key();
    let polynomial_size = glwe_secret.polynomial_size();
    assert_eq!(polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(glwe_secret.glwe_dimension().to_glwe_size().0, GLWE_SIZE);
    let bsk = match &server.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err("requires pinned A44 classic BSK".into()),
    };
    assert_eq!(bsk.output_lwe_dimension(), big_secret.lwe_dimension());
    assert_eq!(server.key_switching_key.input_key_lwe_dimension(), big_secret.lwe_dimension());
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let new_pfks_key = || LwePrivateFunctionalPackingKeyswitchKey::new(
        0u64, DecompositionBaseLog(parameters.base_log), DecompositionLevelCount(parameters.level_count),
        big_secret.lwe_dimension(), glwe_secret.glwe_dimension().to_glwe_size(), polynomial_size, modulus,
    );
    let mut constant_key = new_pfks_key();
    let mut negative_identity = Polynomial::new(0u64, polynomial_size);
    negative_identity[0] = u64::MAX;
    let key_started = Instant::now();
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big_secret, &glwe_secret, &mut constant_key, shortint_parameters.glwe_noise_distribution(),
        &mut generator, |value| value.wrapping_neg(), &negative_identity,
    );
    let constant_keygen_ns = key_started.elapsed().as_nanos();
    let mut window_key = new_pfks_key();
    let base_window = signed_cell_mask(polynomial_size, 0);
    let key_started = Instant::now();
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big_secret, &glwe_secret, &mut window_key, shortint_parameters.glwe_noise_distribution(),
        &mut generator, |value| value, &base_window,
    );
    let window_keygen_ns = key_started.elapsed().as_nanos();
    let masks = packed_selector_masks(polynomial_size);
    let (scalar_left, scalar_right) = a30_scalar_selector_masks(polynomial_size);
    let fft = Fft::new(polynomial_size);
    let fft_view = fft.as_view();
    let requirement = fft_view.forward_scratch().expect("FFT scratch")
        .and(fft_view.backward_scratch().expect("FFT scratch"));
    let mut memory = GlobalPodBuffer::new(requirement);
    let stack = PodStack::new(&mut memory);
    emit(json!({
        "record": "meta", "artifact": ARTIFACT, "process_id": std::process::id(),
        "order_offset": order_offset, "tfhe_version": "0.11.3", "pfks": parameters.label,
        "params_fingerprint": PARAMS_FINGERPRINT, "preregistration_sha256": PREREG_SHA256,
        "base_keygen_ns": base_keygen_ns, "constant_keygen_ns": constant_keygen_ns,
        "window_keygen_ns": window_keygen_ns, "pfpks_key_bytes_each": constant_key.as_ref().len() * size_of::<u64>(),
        "same_base_keys_and_inputs": true, "functional_keys_independently_encrypted": true,
        "noise": "nonzero A44 Gaussian", "support_gate": "coefficientwise_modulus_switch_effective_degree",
        "comparator_present": false, "tournament_present": false, "keys_ephemeral": true,
        "secret_material_persisted": false, "timing_scope": "diagnostic single observation per fixture"
    }));
    let mut direct_passed = 0;
    let mut convolution_passed = 0;
    let mut scalar_passed = 0;
    let mut effective_support_failures = 0;
    let mut phase_only_support_disagreements = 0;
    for (fixture_index, fixture) in FIXTURES.into_iter().enumerate() {
        let mut encrypt = |phase| {
            let mut ciphertext = LweCiphertext::new(0u64, big_secret.lwe_dimension().to_lwe_size(), modulus);
            encrypt_lwe_ciphertext(&big_secret, &mut ciphertext, Plaintext(phase),
                shortint_parameters.glwe_noise_distribution(), &mut generator);
            ciphertext
        };
        let left: Vec<Lwe> = fixture.left.iter().zip(PAYLOAD_DELTAS).map(|(&x, delta)| encrypt(x.wrapping_mul(delta))).collect();
        let right: Vec<Lwe> = fixture.right.iter().zip(PAYLOAD_DELTAS).map(|(&x, delta)| encrypt(x.wrapping_mul(delta))).collect();
        let control = encrypt(fixture.control_phase());
        let order = arm_order(fixture_index, order_offset);
        let mut direct = None;
        let mut convolution = None;
        let mut scalar = None;
        for arm in order {
            match arm {
                0 => direct = Some(direct_window_d2_select(&left, &right, &control, &window_key, &server.key_switching_key, bsk)),
                1 => convolution = Some(packed_d2_select(&left, &right, &control, &constant_key,
                    &server.key_switching_key, bsk, &masks, fft_view, &mut *stack)),
                2 => scalar = Some(scalar_d2_select_tuple(&left, &right, &control, &constant_key,
                    &server.key_switching_key, bsk, &scalar_left, &scalar_right, fft_view, &mut *stack)),
                _ => unreachable!(),
            }
        }
        let (direct_outputs, direct_control, direct_metrics) = direct.expect("direct arm timed");
        let (convolution_outputs, convolution_control, convolution_metrics) = convolution.expect("convolution arm timed");
        let (scalar_outputs, scalar_controls, scalar_metrics) = scalar.expect("scalar arm timed");
        // No secret-key diagnostic, hash, or result output ran until all three arm timers stopped.
        let expected = fixture.expected();
        let mut ingress_ok = true;
        for ((ciphertext, &value), delta) in left.iter().zip(&fixture.left).chain(right.iter().zip(&fixture.right))
            .zip(PAYLOAD_DELTAS.into_iter().chain(PAYLOAD_DELTAS)) {
            let audit = phase_audit(&big_secret, ciphertext, value, delta);
            ingress_ok &= audit.decode_pass && audit.half_slot_pass;
        }
        let input_control_audit = phase_audit(&big_secret, &control, fixture.control, SCORE_DELTA);
        ingress_ok &= input_control_audit.decode_pass && input_control_audit.half_slot_pass;
        let controls_equal = lwe_bitwise_equal(&direct_control, &convolution_control)
            && scalar_controls.iter().all(|c| lwe_bitwise_equal(&direct_control, c));
        let control_audit = phase_audit(&small_secret.as_view(), &direct_control, fixture.control, SCORE_DELTA);
        let control_ok = control_audit.decode_pass && control_audit.half_slot_pass && controls_equal;
        let effective_degree = effective_rotation_degree(&direct_control, &small_secret.as_view());
        let effective_error = centered_degree_error(effective_degree, fixture.control as usize * BOX_SIZE);
        let phase_degree = modulus_switch_degree(control_audit.phase);
        let phase_error = centered_degree_error(phase_degree, fixture.control as usize * BOX_SIZE);
        let support_ok = effective_error.abs() <= STRICT_RADIUS;
        let phase_support_ok = phase_error.abs() <= STRICT_RADIUS;
        effective_support_failures += usize::from(!support_ok);
        phase_only_support_disagreements += usize::from(support_ok != phase_support_ok);
        let mut direct_ok = true;
        let mut convolution_ok = true;
        let mut scalar_ok = true;
        for lane in 0..OUTPUTS {
            let delta = PAYLOAD_DELTAS[lane];
            let d = phase_audit(&big_secret, &direct_outputs[lane], expected[lane], delta);
            let c = phase_audit(&big_secret, &convolution_outputs[lane], expected[lane], delta);
            let s = phase_audit(&big_secret, &scalar_outputs[lane], expected[lane], delta);
            direct_ok &= lane_pass(d, &direct_outputs[lane]) && d.decoded == s.decoded;
            convolution_ok &= lane_pass(c, &convolution_outputs[lane]) && c.decoded == s.decoded;
            scalar_ok &= lane_pass(s, &scalar_outputs[lane]);
            emit(json!({
                "record": "lane", "fixture": fixture.name, "lane": lane, "lane_name": LANE_NAMES[lane],
                "delta_log": if lane == 3 {56} else {59}, "expected": expected[lane],
                "direct": audit_json(d, &direct_outputs[lane], delta),
                "convolution": audit_json(c, &convolution_outputs[lane], delta),
                "scalar": audit_json(s, &scalar_outputs[lane], delta), "diagnostics_after_all_arm_timers": true
            }));
        }
        let prerequisites = ingress_ok && control_ok && scalar_ok && scalar_metrics.counters_pass();
        let direct_class = classify_case(support_ok, prerequisites && direct_metrics.counters_pass(), direct_ok);
        let convolution_class = classify_case(support_ok, prerequisites && convolution_metrics.counters_pass(), convolution_ok);
        direct_passed += usize::from(direct_class == "pass");
        convolution_passed += usize::from(convolution_class == "pass");
        scalar_passed += usize::from(scalar_ok && scalar_metrics.counters_pass());
        emit(json!({
            "record": "case", "fixture": fixture.name, "fixture_index": fixture_index,
            "contract_role": fixture.contract_role, "arm_order": order, "requested_control_error": fixture.requested_control_degree_error,
            "actual_effective_rotation_degree": effective_degree, "actual_effective_rotation_error": effective_error,
            "rounded_decrypted_phase_degree_diagnostic": phase_degree, "rounded_decrypted_phase_error_diagnostic": phase_error,
            "support_ok": support_ok, "phase_only_support_ok_diagnostic": phase_support_ok,
            "ingress_ok": ingress_ok, "post_ks_controls_bitwise_equal": controls_equal,
            "control_phase_audit": audit_json(control_audit, &direct_control, SCORE_DELTA),
            "scalar_ok": scalar_ok, "prerequisites_ok": prerequisites,
            "direct_class": direct_class, "convolution_class": convolution_class,
            "direct_total_ns": direct_metrics.total_ns, "direct_build_ns": direct_metrics.build_ns,
            "direct_pfks_ns": direct_metrics.pfks_ns, "direct_rotation_ns": direct_metrics.rotations_ns,
            "direct_control_ks_ns": direct_metrics.control_ks_ns, "direct_blind_rotate_ns": direct_metrics.blind_rotate_ns,
            "direct_extract_ns": direct_metrics.extract_ns, "direct_counters_pass": direct_metrics.counters_pass(),
            "direct_pfks": direct_metrics.pfks_calls, "direct_monomial_rotations": direct_metrics.monomial_rotations,
            "direct_polynomial_signed_permutations": direct_metrics.polynomial_signed_permutations,
            "direct_glwe_additions": direct_metrics.glwe_additions, "direct_control_ks": direct_metrics.control_ks_calls,
            "direct_blind_rotations": direct_metrics.blind_rotations, "direct_extractions": direct_metrics.sample_extractions,
            "convolution_total_ns": convolution_metrics.total_ns, "convolution_build_ns": convolution_metrics.accumulator_build_ns(),
            "convolution_pfks_ns": convolution_metrics.pfks_ns, "convolution_spread_ns": convolution_metrics.spread_ns,
            "convolution_counters_pass": convolution_metrics.counters_pass(),
            "scalar_total_ns": scalar_metrics.total_ns, "scalar_build_ns": scalar_metrics.accumulator_build_ns(),
            "scalar_pfks_ns": scalar_metrics.pfks_ns, "scalar_spread_ns": scalar_metrics.spread_ns,
            "scalar_counters_pass": scalar_metrics.counters_pass(), "performance_interpretation_allowed": false
        }));
    }
    let pass = direct_passed == FIXTURES.len();
    emit(json!({
        "record": "summary", "artifact": ARTIFACT, "process_id": std::process::id(),
        "status": if pass {"PASS_DIRECT_SINGLE_KEY_COMPONENT"} else {"FAIL_DIRECT_COMPONENT"},
        "fixture_cases": FIXTURES.len(), "direct_passed": direct_passed,
        "convolution_passed": convolution_passed, "scalar_passed": scalar_passed,
        "effective_support_failures": effective_support_failures,
        "phase_only_support_disagreements": phase_only_support_disagreements,
        "fresh_keysets": 1, "minimum_fresh_processes": 3, "order_offset": order_offset,
        "comparator_present": false, "tournament_present": false, "p_fail_proven": false,
        "runtime_frontier_promoted": false, "performance_interpretation_allowed": false
    }));
    if pass { Ok(()) } else { Err(format!("direct arm passed {direct_passed}/{} cases", FIXTURES.len())) }
}

fn main() {
    let action = parse_args_from(env::args().skip(1)).unwrap_or_else(|e| emit_invalid(&e));
    match action {
        Action::Plan => emit(json!({
            "record": "plan", "artifact": ARTIFACT, "status": "NO_FHE", "preregistration_sha256": PREREG_SHA256,
            "arms": ["direct_window", "convolution_a108", "scalar_d2"], "pfks": "24x1",
            "fixtures": 8, "fresh_processes": 3, "support": [-63,63], "requested_offsets": [-48,0,48],
            "direct_counters": {"pfks":8,"monomial_rotations":8,"polynomial_permutations":16,"glwe_add":7,"ks":1,"br":1,"extract":4}
        })),
        Action::Run(parameters) => {
            check_runtime_authorization().unwrap_or_else(|e| emit_invalid(&e));
            if let Err(error) = run(parameters) {
                emit(json!({"record":"fatal", "artifact":ARTIFACT, "reason":error, "performance_interpretation_allowed":false}));
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_window_matches_all_frozen_masks() {
        let masks = packed_selector_masks(PolynomialSize(POLYNOMIAL_SIZE));
        for (index, expected) in masks.iter().enumerate() {
            let mut window = signed_cell_mask(PolynomialSize(POLYNOMIAL_SIZE), 0);
            let branch = if index < OUTPUTS {LEFT_CONTROL} else {RIGHT_CONTROL};
            polynomial_wrapping_monic_monomial_mul_assign(&mut window,
                MonomialDegree((branch as usize + index % OUTPUTS) * BOX_SIZE));
            assert_eq!(window.as_ref(), expected.as_ref());
        }
    }

    #[test]
    fn real_modulus_switch_rounding_is_not_rounding_the_phase() {
        // Two half-degree mask coefficients round upward separately; their sum is exact.
        let modulus = CiphertextModulus::new_native();
        let secret = LweSecretKey::from_container(vec![1u64,1]);
        let ct = LweCiphertext::from_container(vec![1u64<<51,1u64<<51,1u64<<52],modulus);
        assert_eq!(decrypt_lwe_ciphertext(&secret,&ct).0,0);
        assert_eq!(effective_rotation_degree(&ct,&secret.as_view()),4095);
        assert_eq!(modulus_switch_degree(0),0);
    }

    #[test]
    fn three_process_orders_balance_all_six_permutations() {
        let mut counts = std::collections::BTreeMap::new();
        for offset in 0..3 {
            for fixture in 0..8 { *counts.entry(arm_order(fixture,offset)).or_insert(0) += 1; }
        }
        assert_eq!(counts.len(),6);
        assert!(counts.values().all(|&n|n==4));
    }

    #[test]
    fn reference_masks_select_all_lanes_including_guard_edges() {
        let masks = packed_selector_masks(PolynomialSize(POLYNOMIAL_SIZE));
        let payloads = [0u64,15,7,127,4,0,3,1];
        for branch in 0..2 {
            let control = if branch==0 {LEFT_CONTROL} else {RIGHT_CONTROL};
            for error in -STRICT_RADIUS..=STRICT_RADIUS {
                for lane in 0..OUTPUTS {
                    let virtual_degree = (control as isize + lane as isize)*BOX_SIZE as isize + error;
                    let cycles=virtual_degree.div_euclid(POLYNOMIAL_SIZE as isize);
                    let index=virtual_degree.rem_euclid(POLYNOMIAL_SIZE as isize) as usize;
                    let mut value=0u64;
                    for (mask,payload) in masks.iter().zip(payloads) {
                        let coefficient=if cycles.rem_euclid(2)==0 {mask[index]} else {mask[index].wrapping_neg()};
                        value=value.wrapping_add(coefficient.wrapping_mul(payload));
                    }
                    assert_eq!(value,payloads[branch*4+lane]);
                }
            }
        }
    }
}
