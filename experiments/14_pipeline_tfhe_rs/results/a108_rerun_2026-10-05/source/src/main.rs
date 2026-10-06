//! A108: source-only k=4 packed-D2 PFKS selector component.
//!
//! The component receives an encrypted left/right control.  It deliberately
//! excludes score bridging, comparison, tournament composition, and open-set
//! threshold logic.  No runtime claim follows until the preregistered gate is
//! compiled and executed in an authorized clean window.

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

const ARTIFACT: &str = "A108";
const RUN_ACK_ENV: &str = "A108_RUN_FHE";
const RUN_ACK_VALUE: &str = "I_ACKNOWLEDGE_A108_PACKED_D2_K4_FHE";
const PREREG_ACK_ENV: &str = "A108_PREREGISTRATION_SHA256";
const PREREG_SHA256: &str =
    "b12dbbb9c2e81de20f54070dba2a48c9f5a6f64c351f26f2889a7e8d5d899ce6";
const PARAMS_FINGERPRINT: &str =
    "b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1";

const POLYNOMIAL_SIZE: usize = 2_048;
const GLWE_SIZE: usize = 2;
const SELECTOR_MODULUS: usize = 16;
const BOX_SIZE: usize = POLYNOMIAL_SIZE / SELECTOR_MODULUS;
const STRICT_RADIUS: isize = BOX_SIZE as isize / 2 - 1;
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
    const P23X1: Self = Self {
        label: "23x1",
        base_log: 23,
        level_count: 1,
    };
    const P24X1: Self = Self {
        label: "24x1",
        base_log: 24,
        level_count: 1,
    };
    const P16X2: Self = Self {
        label: "16x2",
        base_log: 16,
        level_count: 2,
    };
    const P12X3: Self = Self {
        label: "12x3",
        base_log: 12,
        level_count: 3,
    };
    const P10X4: Self = Self {
        label: "10x4",
        base_log: 10,
        level_count: 4,
    };

    fn parse(label: &str) -> Option<Self> {
        match label {
            "23x1" => Some(Self::P23X1),
            "24x1" => Some(Self::P24X1),
            "16x2" => Some(Self::P16X2),
            "12x3" => Some(Self::P12X3),
            "10x4" => Some(Self::P10X4),
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
        requested_control_degree_error: -63,
    },
    Fixture {
        name: "right_zero_vs_clipped_max",
        contract_role: "right_control_and_mixed_scale_extrema",
        left: [4, 15, 15, 127],
        right: [0, 0, 0, 1],
        control: RIGHT_CONTROL,
        requested_control_degree_error: 63,
    },
    Fixture {
        name: "accept_threshold_left",
        contract_role: "score_1023_beats_sentinel_1024",
        left: [3, 15, 15, 127],
        right: [4, 0, 0, 0],
        control: LEFT_CONTROL,
        requested_control_degree_error: 63,
    },
    Fixture {
        name: "accept_threshold_right",
        contract_role: "score_1023_beats_sentinel_1024",
        left: [4, 0, 0, 0],
        right: [3, 15, 15, 127],
        control: RIGHT_CONTROL,
        requested_control_degree_error: -63,
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
        requested_control_degree_error: -63,
    },
    Fixture {
        name: "score_tie_left",
        contract_role: "equal_score_tie_left_keeps_first_id",
        left: [3, 14, 7, 3],
        right: [3, 14, 7, 127],
        control: LEFT_CONTROL,
        requested_control_degree_error: 63,
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
            "expected no arguments, or exactly: --run-authorized --pfks <23x1|24x1|16x2|12x3|10x4>"
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

fn json_u128_array(values: &[u128]) -> String {
    values
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn json_sha_array(outputs: &[Lwe; OUTPUTS]) -> String {
    outputs
        .iter()
        .map(|output| format!("\"{}\"", hash_lwe(output)))
        .collect::<Vec<_>>()
        .join(",")
}

fn run(parameters: PfksParameters) -> Result<(), String> {
    assert_eq!(POLYNOMIAL_SIZE, 2_048);
    assert_eq!(BOX_SIZE, 128);
    assert_eq!(STRICT_RADIUS, 63);
    assert!(parameters.base_log * parameters.level_count <= 64);
    let modulus = CiphertextModulus::<u64>::new_native();
    let process_id = std::process::id();
    let rayon_threads = json_escape(
        &env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".to_string()),
    );

    let base_keygen_started = Instant::now();
    let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server_key = ServerKey::new(&client_key);
    let base_keygen_ns = base_keygen_started.elapsed().as_nanos();
    let (glwe_secret_key, small_secret_key, shortint_parameters) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let polynomial_size = glwe_secret_key.polynomial_size();
    assert_eq!(polynomial_size.0, POLYNOMIAL_SIZE);
    assert_eq!(glwe_secret_key.glwe_dimension().to_glwe_size().0, GLWE_SIZE);

    let bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err("A108 requires the pinned A44 classic bootstrap key".to_string()),
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

    let pfpks_keygen_started = Instant::now();
    let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
        0u64,
        DecompositionBaseLog(parameters.base_log),
        DecompositionLevelCount(parameters.level_count),
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
        shortint_parameters.glwe_noise_distribution(),
        &mut encryption_generator,
        |value| value.wrapping_neg(),
        &identity_polynomial,
    );
    let pfpks_keygen_ns = pfpks_keygen_started.elapsed().as_nanos();
    let pfpks_words = pfpksk.as_ref().len();
    let pfpks_bytes = pfpks_words * size_of::<u64>();

    let public_setup_started = Instant::now();
    let masks = packed_selector_masks(polynomial_size);
    let (scalar_left_mask, scalar_right_mask) = a30_scalar_selector_masks(polynomial_size);
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

    println!(
        "{{\"record\":\"meta\",\"artifact\":\"{}\",\"variant\":\"packed_d2_k4_vs_scalar_a30_d2\",\"component_only\":true,\"process_id\":{},\"rayon_threads_env\":\"{}\",\"tfhe_version\":\"0.11.3\",\"params_fingerprint\":\"{}\",\"preregistration_sha256\":\"{}\",\"pfks_parameter\":\"{}\",\"pfks_base_log\":{},\"pfks_level_count\":{},\"polynomial_size\":{},\"glwe_size\":{},\"selector_modulus\":{},\"box_size\":{},\"error_support_min\":{},\"error_support_max\":{},\"score_delta_log\":59,\"id_delta_log\":56,\"base_keygen_ns\":{},\"pfpks_keygen_ns\":{},\"public_setup_ns\":{},\"keygen_in_selector_latency\":false,\"input_encryption_in_selector_latency\":false,\"client_audit_in_selector_latency\":false,\"logical_cryptographic_key_containers_live\":5,\"key_container_kinds\":\"glwe_secret|small_lwe_secret|fourier_bsk|classic_ksk|pfpksk\",\"glwe_secret_words\":{},\"small_lwe_secret_words\":{},\"pfpks_words\":{},\"pfpks_bytes\":{},\"packed_public_mask_polynomial_containers\":8,\"scalar_reference_public_mask_polynomial_containers\":2,\"packed_public_mask_nonzero_terms\":1016,\"allocator_peak_rss_measured\":false,\"scalar_reference_present\":true,\"comparator_present\":false,\"tournament_present\":false,\"threshold_logic_present\":false}}",
        ARTIFACT,
        process_id,
        rayon_threads,
        PARAMS_FINGERPRINT,
        PREREG_SHA256,
        parameters.label,
        parameters.base_log,
        parameters.level_count,
        polynomial_size.0,
        glwe_secret_key.glwe_dimension().to_glwe_size().0,
        SELECTOR_MODULUS,
        BOX_SIZE,
        -STRICT_RADIUS,
        STRICT_RADIUS,
        base_keygen_ns,
        pfpks_keygen_ns,
        public_setup_ns,
        glwe_secret_key.as_ref().len(),
        small_secret_key.as_ref().len(),
        pfpks_words,
        pfpks_bytes,
    );

    let mut failed_cases = 0usize;
    let mut failed_output_lanes = 0usize;
    let mut ingress_decode_failures = 0usize;
    let mut switched_control_failures = 0usize;
    let mut maximum_output_absolute_error = 0u64;
    let mut maximum_scalar_output_absolute_error = 0u64;
    let mut maximum_ingress_absolute_error = 0u64;
    let mut maximum_switched_control_absolute_error = 0u64;
    let mut total_selector_ns = 0u128;
    let mut total_scalar_reference_ns = 0u128;
    let mut packed_scalar_ciphertext_bitwise_equal_lanes = 0usize;

    for (fixture_index, fixture) in FIXTURES.into_iter().enumerate() {
        let encryption_started = Instant::now();
        let mut encrypt_phase = |phase: u64| {
            let mut ciphertext = LweCiphertext::new(
                0u64,
                big_secret_key.lwe_dimension().to_lwe_size(),
                modulus,
            );
            encrypt_lwe_ciphertext(
                &big_secret_key,
                &mut ciphertext,
                Plaintext(phase),
                shortint_parameters.glwe_noise_distribution(),
                &mut encryption_generator,
            );
            ciphertext
        };
        let left: Vec<Lwe> = fixture
            .left
            .iter()
            .zip(PAYLOAD_DELTAS)
            .map(|(&value, delta)| encrypt_phase(value.wrapping_mul(delta)))
            .collect();
        let right: Vec<Lwe> = fixture
            .right
            .iter()
            .zip(PAYLOAD_DELTAS)
            .map(|(&value, delta)| encrypt_phase(value.wrapping_mul(delta)))
            .collect();
        let encrypted_control = encrypt_phase(fixture.control_phase());
        let input_encryption_ns = encryption_started.elapsed().as_nanos();

        let packed_result;
        let scalar_result;
        let arm_order;
        if fixture_index % 2 == 0 {
            arm_order = "packed_then_scalar";
            packed_result = packed_d2_select(
                &left,
                &right,
                &encrypted_control,
                &pfpksk,
                &server_key.key_switching_key,
                bsk,
                &masks,
                fft_view,
                &mut *fft_stack,
            );
            scalar_result = scalar_d2_select_tuple(
                &left,
                &right,
                &encrypted_control,
                &pfpksk,
                &server_key.key_switching_key,
                bsk,
                &scalar_left_mask,
                &scalar_right_mask,
                fft_view,
                &mut *fft_stack,
            );
        } else {
            arm_order = "scalar_then_packed";
            scalar_result = scalar_d2_select_tuple(
                &left,
                &right,
                &encrypted_control,
                &pfpksk,
                &server_key.key_switching_key,
                bsk,
                &scalar_left_mask,
                &scalar_right_mask,
                fft_view,
                &mut *fft_stack,
            );
            packed_result = packed_d2_select(
                &left,
                &right,
                &encrypted_control,
                &pfpksk,
                &server_key.key_switching_key,
                bsk,
                &masks,
                fft_view,
                &mut *fft_stack,
            );
        }
        let (packed_outputs, switched_control, metrics) = packed_result;
        let (scalar_outputs, scalar_switched_controls, scalar_metrics) = scalar_result;
        total_selector_ns += metrics.total_ns;
        total_scalar_reference_ns += scalar_metrics.total_ns;

        // The first secret-key operation for this case is deliberately after
        // both the packed and scalar D2 arms have stopped every server timer.
        let client_audit_started = Instant::now();
        let mut case_ingress_decode_failures = 0usize;
        let mut case_max_ingress_error = 0u64;
        for ((ciphertext, &expected), delta) in left
            .iter()
            .zip(fixture.left.iter())
            .chain(right.iter().zip(fixture.right.iter()))
            .zip(PAYLOAD_DELTAS.into_iter().chain(PAYLOAD_DELTAS))
        {
            let audit = phase_audit(&big_secret_key, ciphertext, expected, delta);
            case_ingress_decode_failures += usize::from(!(audit.decode_pass && audit.half_slot_pass));
            case_max_ingress_error = case_max_ingress_error.max(audit.absolute_error);
        }
        let control_audit = phase_audit(
            &big_secret_key,
            &encrypted_control,
            fixture.control,
            SCORE_DELTA,
        );
        case_ingress_decode_failures +=
            usize::from(!(control_audit.decode_pass && control_audit.half_slot_pass));
        case_max_ingress_error = case_max_ingress_error.max(control_audit.absolute_error);
        let small_secret_key_view = small_secret_key.as_view();
        let switched_control_audit = phase_audit(
            &small_secret_key_view,
            &switched_control,
            fixture.control,
            SCORE_DELTA,
        );
        let switched_controls_bitwise_equal = scalar_switched_controls
            .iter()
            .all(|control| lwe_bitwise_equal(&switched_control, control));
        let switched_control_gate_pass = switched_control_audit.decode_pass
            && switched_control_audit.half_slot_pass
            && switched_controls_bitwise_equal;
        switched_control_failures += usize::from(!switched_control_gate_pass);
        maximum_switched_control_absolute_error = maximum_switched_control_absolute_error
            .max(switched_control_audit.absolute_error);
        let observed_control_degree = modulus_switch_degree(switched_control_audit.phase);
        let expected_control_degree = fixture.control as usize * BOX_SIZE;
        let control_degree_error =
            centered_degree_error(observed_control_degree, expected_control_degree);
        let control_support_pass = (-STRICT_RADIUS..=STRICT_RADIUS).contains(&control_degree_error);

        let expected = fixture.expected();
        let mut output_gate_pass = true;
        let mut case_max_output_error = 0u64;
        let mut case_max_scalar_output_error = 0u64;
        let mut nontrivial_packed_outputs = 0usize;
        let mut nontrivial_scalar_outputs = 0usize;
        let mut case_ciphertext_bitwise_equal_lanes = 0usize;
        for lane in 0..OUTPUTS {
            let packed_audit = phase_audit(
                &big_secret_key,
                &packed_outputs[lane],
                expected[lane],
                PAYLOAD_DELTAS[lane],
            );
            let scalar_audit = phase_audit(
                &big_secret_key,
                &scalar_outputs[lane],
                expected[lane],
                PAYLOAD_DELTAS[lane],
            );
            let packed_nontrivial = packed_outputs[lane]
                .get_mask()
                .as_ref()
                .iter()
                .any(|&word| word != 0);
            let scalar_nontrivial = scalar_outputs[lane]
                .get_mask()
                .as_ref()
                .iter()
                .any(|&word| word != 0);
            nontrivial_packed_outputs += usize::from(packed_nontrivial);
            nontrivial_scalar_outputs += usize::from(scalar_nontrivial);
            let decoded_equal = packed_audit.decoded == scalar_audit.decoded;
            let ciphertext_bitwise_equal =
                lwe_bitwise_equal(&packed_outputs[lane], &scalar_outputs[lane]);
            case_ciphertext_bitwise_equal_lanes += usize::from(ciphertext_bitwise_equal);
            let lane_pass = packed_audit.decode_pass
                && packed_audit.half_slot_pass
                && scalar_audit.decode_pass
                && scalar_audit.half_slot_pass
                && decoded_equal
                && packed_nontrivial
                && scalar_nontrivial;
            output_gate_pass &= lane_pass;
            failed_output_lanes += usize::from(!lane_pass);
            case_max_output_error = case_max_output_error.max(packed_audit.absolute_error);
            case_max_scalar_output_error =
                case_max_scalar_output_error.max(scalar_audit.absolute_error);
            println!(
                "{{\"record\":\"paired_lane_audit\",\"artifact\":\"{}\",\"fixture\":\"{}\",\"lane\":{},\"lane_name\":\"{}\",\"delta_log\":{},\"expected\":{},\"packed_decoded\":{},\"packed_phase\":{},\"packed_signed_phase_error\":{},\"packed_absolute_phase_error\":{},\"scalar_decoded\":{},\"scalar_phase\":{},\"scalar_signed_phase_error\":{},\"scalar_absolute_phase_error\":{},\"half_slot_limit_exclusive\":{},\"packed_half_slot_pass\":{},\"scalar_half_slot_pass\":{},\"packed_decode_pass\":{},\"scalar_decode_pass\":{},\"decrypted_integer_outputs_equal\":{},\"packed_ciphertext_nontrivial\":{},\"scalar_ciphertext_nontrivial\":{},\"ciphertext_bitwise_equal_diagnostic\":{},\"ciphertext_bitwise_equality_is_gate\":false,\"lane_gate_pass\":{},\"audit_after_both_arm_timers\":true}}",
                ARTIFACT,
                fixture.name,
                lane,
                LANE_NAMES[lane],
                if lane == OUTPUTS - 1 { 56 } else { 59 },
                expected[lane],
                packed_audit.decoded,
                packed_audit.phase,
                packed_audit.signed_error,
                packed_audit.absolute_error,
                scalar_audit.decoded,
                scalar_audit.phase,
                scalar_audit.signed_error,
                scalar_audit.absolute_error,
                PAYLOAD_DELTAS[lane] / 2,
                packed_audit.half_slot_pass,
                scalar_audit.half_slot_pass,
                packed_audit.decode_pass,
                scalar_audit.decode_pass,
                decoded_equal,
                packed_nontrivial,
                scalar_nontrivial,
                ciphertext_bitwise_equal,
                lane_pass,
            );
        }
        let client_audit_ns = client_audit_started.elapsed().as_nanos();
        ingress_decode_failures += case_ingress_decode_failures;
        maximum_ingress_absolute_error =
            maximum_ingress_absolute_error.max(case_max_ingress_error);
        maximum_output_absolute_error = maximum_output_absolute_error.max(case_max_output_error);
        maximum_scalar_output_absolute_error =
            maximum_scalar_output_absolute_error.max(case_max_scalar_output_error);
        packed_scalar_ciphertext_bitwise_equal_lanes += case_ciphertext_bitwise_equal_lanes;
        let counters_pass = metrics.counters_pass();
        let scalar_counters_pass = scalar_metrics.counters_pass();
        let case_pass = counters_pass
            && scalar_counters_pass
            && output_gate_pass
            && case_ingress_decode_failures == 0
            && switched_control_gate_pass
            && control_support_pass
            && nontrivial_packed_outputs == OUTPUTS
            && nontrivial_scalar_outputs == OUTPUTS;
        failed_cases += usize::from(!case_pass);

        println!(
            "{{\"record\":\"scalar_reference\",\"artifact\":\"{}\",\"fixture\":\"{}\",\"arm_order\":\"{}\",\"scalar_selector_total_ns\":{},\"scalar_accumulator_build_ns\":{},\"constant_glwe_allocation_ns\":[{}],\"pfks_ns\":[{}],\"spread_glwe_allocation_ns\":[{}],\"spread_ns\":[{}],\"glwe_add_ns\":[{}],\"control_lwe_allocation_ns\":[{}],\"control_ks_ns\":[{}],\"blind_rotate_ns\":[{}],\"output_lwe_allocation_ns\":[{}],\"sample_extract_ns\":[{}],\"payload_pfks\":{},\"logical_glwe_public_mask_spreads\":{},\"public_polynomial_multiplications\":{},\"scalar_polynomial_fft_multiplications\":{},\"glwe_additions\":{},\"control_key_switches\":{},\"blind_rotations\":{},\"sample_extractions\":{},\"output_ciphertext_sha256\":[{}],\"counters_pass\":{},\"derived_from_a30_scalar_d2\":true}}",
            ARTIFACT,
            fixture.name,
            arm_order,
            scalar_metrics.total_ns,
            scalar_metrics.accumulator_build_ns(),
            json_u128_array(&scalar_metrics.constant_glwe_allocation_ns),
            json_u128_array(&scalar_metrics.pfks_ns),
            json_u128_array(&scalar_metrics.spread_glwe_allocation_ns),
            json_u128_array(&scalar_metrics.spread_ns),
            json_u128_array(&scalar_metrics.glwe_add_ns),
            json_u128_array(&scalar_metrics.control_lwe_allocation_ns),
            json_u128_array(&scalar_metrics.control_ks_ns),
            json_u128_array(&scalar_metrics.blind_rotate_ns),
            json_u128_array(&scalar_metrics.output_lwe_allocation_ns),
            json_u128_array(&scalar_metrics.sample_extract_ns),
            scalar_metrics.pfks_calls,
            scalar_metrics.logical_glwe_public_mask_spreads,
            scalar_metrics.logical_glwe_public_mask_spreads,
            scalar_metrics.scalar_polynomial_fft_multiplications,
            scalar_metrics.glwe_additions,
            scalar_metrics.control_ks_calls,
            scalar_metrics.blind_rotations,
            scalar_metrics.sample_extractions,
            json_sha_array(&scalar_outputs),
            scalar_counters_pass,
        );

        println!(
            "{{\"record\":\"packed_case\",\"artifact\":\"{}\",\"fixture\":\"{}\",\"contract_role\":\"{}\",\"injected_control\":{},\"requested_control_degree_error\":{},\"expected_branch\":\"{}\",\"input_encryption_ns\":{},\"selector_total_ns\":{},\"accumulator_build_ns\":{},\"constant_glwe_allocation_ns\":[{}],\"pfks_ns\":[{}],\"spread_glwe_allocation_ns\":[{}],\"spread_ns\":[{}],\"glwe_add_ns\":[{}],\"control_lwe_allocation_ns\":{},\"control_ks_ns\":{},\"blind_rotate_ns\":{},\"output_lwe_allocation_ns\":[{}],\"sample_extract_ns\":[{}],\"client_audit_ns\":{},\"payload_pfks\":{},\"logical_glwe_public_mask_spreads\":{},\"public_polynomial_multiplications\":{},\"scalar_polynomial_fft_multiplications\":{},\"glwe_additions\":{},\"control_key_switches\":{},\"blind_rotations\":{},\"sample_extractions\":{},\"input_big_lwe_ciphertexts\":9,\"internal_small_lwe_ciphertexts\":1,\"output_big_lwe_ciphertexts\":4,\"source_level_logical_peak_live_dynamic_glwe_ciphertexts\":{},\"allocator_peak_rss_measured\":false,\"switched_control_phase\":{},\"switched_control_signed_phase_error\":{},\"switched_control_absolute_phase_error\":{},\"switched_control_decode_pass\":{},\"switched_control_half_slot_pass\":{},\"switched_control_gate_pass\":{},\"switched_control_ciphertext_sha256\":\"{}\",\"actual_control_degree\":{},\"expected_control_degree\":{},\"control_degree_error\":{},\"control_support_pass\":{},\"ingress_decode_failures\":{},\"maximum_ingress_absolute_phase_error\":{},\"maximum_output_absolute_phase_error\":{},\"nontrivial_outputs\":{},\"output_ciphertext_sha256\":[{}],\"counters_pass\":{},\"component_case_pass\":{},\"comparator_present\":false,\"exact_id_pipeline_present\":false}}",
            ARTIFACT,
            fixture.name,
            fixture.contract_role,
            fixture.control,
            fixture.requested_control_degree_error,
            if fixture.control == LEFT_CONTROL { "left" } else { "right" },
            input_encryption_ns,
            metrics.total_ns,
            metrics.accumulator_build_ns(),
            json_u128_array(&metrics.constant_glwe_allocation_ns),
            json_u128_array(&metrics.pfks_ns),
            json_u128_array(&metrics.spread_glwe_allocation_ns),
            json_u128_array(&metrics.spread_ns),
            json_u128_array(&metrics.glwe_add_ns),
            metrics.control_lwe_allocation_ns,
            metrics.control_ks_ns,
            metrics.blind_rotate_ns,
            json_u128_array(&metrics.output_lwe_allocation_ns),
            json_u128_array(&metrics.sample_extract_ns),
            client_audit_ns,
            metrics.pfks_calls,
            metrics.logical_glwe_public_mask_spreads,
            metrics.logical_glwe_public_mask_spreads,
            metrics.scalar_polynomial_fft_multiplications,
            metrics.glwe_additions,
            metrics.control_ks_calls,
            metrics.blind_rotations,
            metrics.sample_extractions,
            metrics.peak_live_dynamic_glwe_ciphertexts,
            switched_control_audit.phase,
            switched_control_audit.signed_error,
            switched_control_audit.absolute_error,
            switched_control_audit.decode_pass,
            switched_control_audit.half_slot_pass,
            switched_control_gate_pass,
            hash_lwe(&switched_control),
            observed_control_degree,
            expected_control_degree,
            control_degree_error,
            control_support_pass,
            case_ingress_decode_failures,
            case_max_ingress_error,
            case_max_output_error,
            nontrivial_packed_outputs,
            json_sha_array(&packed_outputs),
            counters_pass,
            case_pass,
        );
        println!(
            "{{\"record\":\"pair_audit\",\"artifact\":\"{}\",\"fixture\":\"{}\",\"arm_order\":\"{}\",\"post_ks_controls_bitwise_equal\":{},\"post_ks_control_bitwise_equality_is_gate\":true,\"packed_scalar_ciphertext_bitwise_equal_lanes\":{},\"output_ciphertext_bitwise_equality_is_gate\":false,\"decrypted_integer_output_gate_pass\":{},\"packed_nontrivial_outputs\":{},\"scalar_nontrivial_outputs\":{},\"maximum_packed_output_absolute_phase_error\":{},\"maximum_scalar_output_absolute_phase_error\":{},\"packed_output_ciphertext_sha256\":[{}],\"scalar_output_ciphertext_sha256\":[{}],\"packed_counters_pass\":{},\"scalar_counters_pass\":{},\"component_case_pass\":{},\"comparison_after_both_arm_timers\":true}}",
            ARTIFACT,
            fixture.name,
            arm_order,
            switched_controls_bitwise_equal,
            case_ciphertext_bitwise_equal_lanes,
            output_gate_pass,
            nontrivial_packed_outputs,
            nontrivial_scalar_outputs,
            case_max_output_error,
            case_max_scalar_output_error,
            json_sha_array(&packed_outputs),
            json_sha_array(&scalar_outputs),
            counters_pass,
            scalar_counters_pass,
            case_pass,
        );
    }

    let status = if failed_cases == 0 {
        "PASS_COMPONENT_CORRECTNESS_SINGLE_KEY_DIAGNOSTIC_TIMING_ONLY"
    } else {
        "FAIL_COMPONENT_GATE_NO_PERFORMANCE_INTERPRETATION"
    };
    println!(
        "{{\"record\":\"summary\",\"artifact\":\"{}\",\"status\":\"{}\",\"pfks_parameter\":\"{}\",\"fresh_keysets_in_process\":1,\"fixture_cases\":{},\"failed_cases\":{},\"failed_output_lanes\":{},\"ingress_decode_failures\":{},\"switched_control_failures\":{},\"total_packed_payload_pfks\":{},\"total_packed_logical_glwe_public_mask_spreads\":{},\"total_packed_public_polynomial_multiplications\":{},\"total_packed_scalar_polynomial_fft_multiplications\":{},\"total_packed_glwe_additions\":{},\"total_packed_control_key_switches\":{},\"total_packed_blind_rotations\":{},\"total_packed_sample_extractions\":{},\"total_scalar_reference_payload_pfks\":{},\"total_scalar_reference_logical_glwe_public_mask_spreads\":{},\"total_scalar_reference_public_polynomial_multiplications\":{},\"total_scalar_reference_scalar_polynomial_fft_multiplications\":{},\"total_scalar_reference_glwe_additions\":{},\"total_scalar_reference_control_key_switches\":{},\"total_scalar_reference_blind_rotations\":{},\"total_scalar_reference_sample_extractions\":{},\"maximum_ingress_absolute_phase_error\":{},\"maximum_switched_control_absolute_phase_error\":{},\"maximum_packed_output_absolute_phase_error\":{},\"maximum_scalar_output_absolute_phase_error\":{},\"packed_scalar_ciphertext_bitwise_equal_lanes_diagnostic\":{},\"output_ciphertext_bitwise_equality_is_gate\":false,\"packed_selector_total_ns\":{},\"scalar_reference_total_ns\":{},\"timing_decision_role\":\"diagnostic_until_multikey_causal_gate\",\"correlated_output_p_fail_claim\":false,\"scalar_d2_reference_present\":true,\"comparator_present\":false,\"tournament_present\":false,\"threshold_logic_present\":false,\"exact_id_pipeline_present\":false,\"runtime_frontier_promoted\":false}}",
        ARTIFACT,
        status,
        parameters.label,
        FIXTURES.len(),
        failed_cases,
        failed_output_lanes,
        ingress_decode_failures,
        switched_control_failures,
        FIXTURES.len() * 8,
        FIXTURES.len() * 8,
        FIXTURES.len() * 8,
        FIXTURES.len() * 16,
        FIXTURES.len() * 7,
        FIXTURES.len(),
        FIXTURES.len(),
        FIXTURES.len() * 4,
        FIXTURES.len() * 8,
        FIXTURES.len() * 8,
        FIXTURES.len() * 8,
        FIXTURES.len() * 16,
        FIXTURES.len() * 4,
        FIXTURES.len() * 4,
        FIXTURES.len() * 4,
        FIXTURES.len() * 4,
        maximum_ingress_absolute_error,
        maximum_switched_control_absolute_error,
        maximum_output_absolute_error,
        maximum_scalar_output_absolute_error,
        packed_scalar_ciphertext_bitwise_equal_lanes,
        total_selector_ns,
        total_scalar_reference_ns,
    );
    if failed_cases == 0 {
        Ok(())
    } else {
        Err(format!("{failed_cases} of {} fixed component cases failed", FIXTURES.len()))
    }
}

fn main() {
    let action = parse_args_from(env::args().skip(1)).unwrap_or_else(|error| emit_invalid(&error));
    match action {
        Action::Plan => {
            println!(
                "{{\"record\":\"plan\",\"artifact\":\"{}\",\"status\":\"NO_FHE_GUARD\",\"component\":\"packed_d2_k4_vs_scalar_a30_d2\",\"preregistration_sha256\":\"{}\",\"parameter_sweep\":\"23x1|24x1|16x2|12x3|10x4\",\"first_gate\":\"23x1_then_24x1\",\"fixed_fixtures\":8,\"packed_per_case_payload_pfks\":8,\"packed_per_case_public_polynomial_multiplications\":8,\"packed_per_case_control_ks\":1,\"packed_per_case_blind_rotations\":1,\"packed_per_case_sample_extractions\":4,\"scalar_reference_per_case_payload_pfks\":8,\"scalar_reference_per_case_public_polynomial_multiplications\":8,\"scalar_reference_per_case_control_ks\":4,\"scalar_reference_per_case_blind_rotations\":4,\"scalar_reference_per_case_sample_extractions\":4,\"keygen_performed\":false,\"fhe_performed\":false}}",
                ARTIFACT, PREREG_SHA256
            );
        }
        Action::Run(parameters) => {
            check_runtime_authorization().unwrap_or_else(|error| emit_invalid(&error));
            if let Err(error) = run(parameters) {
                let escaped = json_escape(&error);
                println!(
                    "{{\"record\":\"fatal\",\"artifact\":\"{}\",\"status\":\"FAIL_COMPONENT_GATE\",\"reason\":\"{}\",\"performance_interpretation_allowed\":false}}",
                    ARTIFACT, escaped
                );
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn negacyclic_sample(polynomial: &[u64], virtual_degree: usize) -> u64 {
        let cycles = virtual_degree / polynomial.len();
        let word = polynomial[virtual_degree % polynomial.len()];
        if cycles % 2 == 0 {
            word
        } else {
            word.wrapping_neg()
        }
    }

    #[test]
    fn packed_cells_select_all_four_lanes_for_both_controls_and_full_support() {
        let masks = packed_selector_masks(PolynomialSize(POLYNOMIAL_SIZE));
        let left = [1u64, 2, 3, 4];
        let right = [11u64, 12, 13, 14];
        let mut body = vec![0u64; POLYNOMIAL_SIZE];
        for (term, value) in left.into_iter().chain(right).enumerate() {
            for (target, &mask) in body.iter_mut().zip(masks[term].as_ref()) {
                *target = target.wrapping_add(value.wrapping_mul(mask));
            }
        }
        for (control, expected) in [(LEFT_CONTROL, left), (RIGHT_CONTROL, right)] {
            for error in -STRICT_RADIUS..=STRICT_RADIUS {
                for lane in 0..OUTPUTS {
                    let degree = (control as isize * BOX_SIZE as isize
                        + error
                        + (lane * BOX_SIZE) as isize) as usize;
                    assert_eq!(negacyclic_sample(&body, degree), expected[lane]);
                }
            }
        }
    }

    #[test]
    fn fixed_fixtures_cover_controls_boundary_tie_and_reject_roles() {
        assert_eq!(FIXTURES.len(), 8);
        assert!(FIXTURES.iter().any(|fixture| fixture.control == LEFT_CONTROL));
        assert!(FIXTURES.iter().any(|fixture| fixture.control == RIGHT_CONTROL));
        for control in [LEFT_CONTROL, RIGHT_CONTROL] {
            for degree_error in [-STRICT_RADIUS, STRICT_RADIUS] {
                assert!(FIXTURES.iter().any(|fixture| {
                    fixture.control == control
                        && fixture.requested_control_degree_error == degree_error
                }));
            }
        }
        for name in [
            "accept_threshold_left",
            "accept_threshold_right",
            "reject_sentinel_tie_left",
            "reject_clipped_left",
            "score_tie_left",
        ] {
            assert!(FIXTURES.iter().any(|fixture| fixture.name == name));
        }
        for fixture in FIXTURES {
            let expected = if fixture.control == LEFT_CONTROL {
                fixture.left
            } else {
                fixture.right
            };
            assert_eq!(fixture.expected(), expected);
            assert_eq!(
                centered_degree_error(
                    modulus_switch_degree(fixture.control_phase()),
                    fixture.control as usize * BOX_SIZE,
                ),
                fixture.requested_control_degree_error
            );
        }
    }

    #[test]
    fn cli_is_finite_and_fail_closed() {
        assert!(matches!(
            parse_args_from(Vec::<String>::new()).unwrap(),
            Action::Plan
        ));
        for label in ["23x1", "24x1", "16x2", "12x3", "10x4"] {
            assert!(matches!(
                parse_args_from(vec![
                    "--run-authorized".to_string(),
                    "--pfks".to_string(),
                    label.to_string()
                ])
                .unwrap(),
                Action::Run(_)
            ));
        }
        assert!(parse_args_from(vec!["--run-authorized".to_string()]).is_err());
        assert!(parse_args_from(vec![
            "--run-authorized".to_string(),
            "--pfks".to_string(),
            "23x99".to_string()
        ])
        .is_err());
        assert!(parse_args_from(vec!["--trials".to_string(), "999999".to_string()]).is_err());
    }

    #[test]
    fn degree_mapping_has_exact_p16_centers() {
        for control in [LEFT_CONTROL, RIGHT_CONTROL] {
            let phase = control * SCORE_DELTA;
            assert_eq!(modulus_switch_degree(phase), control as usize * BOX_SIZE);
            assert_eq!(
                centered_degree_error(modulus_switch_degree(phase), control as usize * BOX_SIZE),
                0
            );
        }
    }

    #[test]
    fn deliberate_selected_cell_and_folded_sign_mutations_are_detected() {
        let mut masks = packed_selector_masks(PolynomialSize(POLYNOMIAL_SIZE));
        let selected_index = LEFT_CONTROL as usize * BOX_SIZE;
        masks[0][selected_index] = masks[0][selected_index].wrapping_neg();
        let left = [SCORE_DELTA, 2 * SCORE_DELTA, 3 * SCORE_DELTA, 4 * ID_DELTA];
        let right = [11 * SCORE_DELTA, 12 * SCORE_DELTA, 13 * SCORE_DELTA, 14 * ID_DELTA];
        let mut body = vec![0u64; POLYNOMIAL_SIZE];
        for (term, value) in left.into_iter().chain(right).enumerate() {
            for (target, &mask) in body.iter_mut().zip(masks[term].as_ref()) {
                *target = target.wrapping_add(value.wrapping_mul(mask));
            }
        }
        assert_ne!(
            negacyclic_sample(&body, LEFT_CONTROL as usize * BOX_SIZE),
            left[0]
        );

        // k=4 itself does not wrap.  Exercise the same sign-aware constructor
        // at the first folded virtual center without extending runtime scope.
        let folded_center = RIGHT_CONTROL as usize * BOX_SIZE + 4 * BOX_SIZE;
        let mut folded = signed_cell_mask(PolynomialSize(POLYNOMIAL_SIZE), folded_center);
        assert_eq!(folded[0], u64::MAX);
        folded[0] = 1;
        assert_ne!(negacyclic_sample(folded.as_ref(), folded_center), 1);
    }
}
