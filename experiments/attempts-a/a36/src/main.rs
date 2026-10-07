//! Isolated FHE micro-prototype for the non-fused A36 chunked candidate update.
//!
//! The path dependency is the frozen A33 source snapshot. Its diagnostic trace supplies encrypted
//! post-b8 candidates and the exact encrypted b7..b0 sources already used by A33. This binary
//! scales those ciphertexts linearly, applies the A36 raw p=16 accumulators, and checks the final
//! ordinary 0/1 candidates against both clear semantics and frozen A33. No decrypt->reencrypt step
//! feeds the circuit: decryption is diagnostic and occurs only after A36 evaluation.
//!
//! This is deliberately not the rejected B=13 two-output fusion. Every A36 blind rotation below
//! has one sample extraction, and BR, KS, and output marginals are counted independently.

use pipeline_tfhe_rs::{
    plan_private_argmin_execution, private_argmin_with_trace, TemplateView, BOOL_DELTA_LOG,
    CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET,
    MAX_GALLERY_SIZE, PROBE_DIM, PROBE_NORM2_MAX,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const FROZEN_A33_PRIVATE_ARGMIN_SHA256: &str =
    "1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d";
const FROZEN_A33_PRIVATE_ARGMIN_SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../a33-aligned-sparse-2026-09-02/source/experiments/14_pipeline_tfhe_rs/src/private_argmin.rs"
));
const THRESHOLD: i64 = 4;
const EXECUTION_LOWER: i64 = THRESHOLD - 1023;
const P16: usize = 16;
const OR_RADIX: usize = 4;
const ACTIVE_STEP: i64 = 2;
const SOURCE_WEIGHTS: [i64; 8] = [1, 1, 1, 1, 1, 8, 4, 2];
const TARGET_WEIGHTS: [i64; 8] = [-2, -2, -2, -2, -2, 8, -4, -2];
const SOURCE_MULTIPLIERS: [i64; 8] = [-2, -2, -2, -2, -2, 1, -1, -1];
const BIT_POSITIONS: [u32; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const CHUNK_END_LEVELS: [usize; 2] = [3, 7];
const A33_N127_PBS: u64 = 4_273;
const A33_N127_KS: u64 = 3_892;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone, Copy, Debug)]
enum FixtureKind {
    Explicit(&'static [u64]),
    LastMinimum,
    LastTwoTie,
}

#[derive(Clone, Copy, Debug)]
struct FixtureSpec {
    name: &'static str,
    gallery_size: usize,
    kind: FixtureKind,
}

const N1_SCORE_255: [u64; 1] = [767];
const N2_NO_RESURRECTION: [u64; 2] = [1024, 767];
const N3_ALL_REJECT: [u64; 3] = [1024, 1024, 1024];
const N3_TIE: [u64; 3] = [519, 521, 519];
const N9_BIT_LADDER: [u64; 9] = [512, 640, 576, 544, 528, 520, 516, 514, 513];

const FIXTURES: [FixtureSpec; 7] = [
    FixtureSpec {
        name: "n1_score255",
        gallery_size: 1,
        kind: FixtureKind::Explicit(&N1_SCORE_255),
    },
    FixtureSpec {
        name: "n2_no_resurrection",
        gallery_size: 2,
        kind: FixtureKind::Explicit(&N2_NO_RESURRECTION),
    },
    FixtureSpec {
        name: "n3_all_reject",
        gallery_size: 3,
        kind: FixtureKind::Explicit(&N3_ALL_REJECT),
    },
    FixtureSpec {
        name: "n3_tie_id1_id3",
        gallery_size: 3,
        kind: FixtureKind::Explicit(&N3_TIE),
    },
    FixtureSpec {
        name: "n9_bit_ladder",
        gallery_size: 9,
        kind: FixtureKind::Explicit(&N9_BIT_LADDER),
    },
    FixtureSpec {
        name: "n127_last_min",
        gallery_size: 127,
        kind: FixtureKind::LastMinimum,
    },
    FixtureSpec {
        name: "n128_last_two_tie",
        gallery_size: 128,
        kind: FixtureKind::LastTwoTie,
    },
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrimitiveCounts {
    blind_rotations: u64,
    key_switches: u64,
    output_marginals: u64,
}

impl PrimitiveCounts {
    fn checked_sub(self, before: Self) -> Self {
        Self {
            blind_rotations: self
                .blind_rotations
                .checked_sub(before.blind_rotations)
                .expect("contatore BR non monotono"),
            key_switches: self
                .key_switches
                .checked_sub(before.key_switches)
                .expect("contatore KS non monotono"),
            output_marginals: self
                .output_marginals
                .checked_sub(before.output_marginals)
                .expect("contatore marginali non monotono"),
        }
    }

    fn plus(self, other: Self) -> Self {
        Self {
            blind_rotations: self.blind_rotations + other.blind_rotations,
            key_switches: self.key_switches + other.key_switches,
            output_marginals: self.output_marginals + other.output_marginals,
        }
    }
}

#[derive(Default)]
struct AtomicPrimitiveCounts {
    blind_rotations: AtomicU64,
    key_switches: AtomicU64,
    output_marginals: AtomicU64,
}

impl AtomicPrimitiveCounts {
    fn record_single_output_rotation(&self) {
        self.blind_rotations.fetch_add(1, Ordering::Relaxed);
        self.key_switches.fetch_add(1, Ordering::Relaxed);
        self.output_marginals.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PrimitiveCounts {
        PrimitiveCounts {
            blind_rotations: self.blind_rotations.load(Ordering::Relaxed),
            key_switches: self.key_switches.load(Ordering::Relaxed),
            output_marginals: self.output_marginals.load(Ordering::Relaxed),
        }
    }
}

struct EvalContext<'a> {
    key_switching_key: &'a LweKeyswitchKeyOwned<u64>,
    bootstrap_key: &'a FourierLweBootstrapKeyOwned,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
    counters: &'a AtomicPrimitiveCounts,
}

impl EvalContext<'_> {
    fn apply_single_output(&self, input: &Lwe, accumulator: &Glwe) -> Lwe {
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(self.key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, self.big_size, self.modulus);
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut output,
            accumulator,
            self.bootstrap_key,
        );
        self.counters.record_single_output_rotation();
        output
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct A36Instrumentation {
    zero_tests: PrimitiveCounts,
    or_reductions: PrimitiveCounts,
    boundary_canonicalizers: PrimitiveCounts,
    final_canonicalizers: PrimitiveCounts,
    total: PrimitiveCounts,
}

#[derive(Clone)]
struct EncryptedLevelTrace {
    states_before: Vec<Lwe>,
    weighted_bits: Vec<Lwe>,
    zero_test_inputs: Vec<Lwe>,
    zero_candidates: Vec<Lwe>,
    any_zero: Lwe,
    linear_states: Vec<Lwe>,
    states_after: Vec<Lwe>,
}

struct A36EncryptedOutput {
    final_candidates: Vec<Lwe>,
    levels: Vec<EncryptedLevelTrace>,
    instrumentation: A36Instrumentation,
}

#[derive(Clone, Debug)]
struct ClearLevelTrace {
    states_before: Vec<i64>,
    weighted_bits: Vec<i64>,
    zero_test_inputs: Vec<i64>,
    zero_candidates: Vec<i64>,
    any_zero: i64,
    linear_states: Vec<i64>,
    states_after: Vec<i64>,
}

fn fixture_scores(spec: FixtureSpec) -> Vec<u64> {
    let scores = match spec.kind {
        FixtureKind::Explicit(values) => values.to_vec(),
        FixtureKind::LastMinimum => {
            let mut values = vec![767; spec.gallery_size];
            *values.last_mut().expect("fixture non vuota") = 766;
            values
        }
        FixtureKind::LastTwoTie => {
            let mut values = vec![767; spec.gallery_size];
            values[spec.gallery_size - 2..].fill(512);
            values
        }
    };
    assert_eq!(scores.len(), spec.gallery_size);
    assert!(scores.iter().all(|score| *score <= 1024));
    let mut accepted_prefixes = scores
        .iter()
        .filter(|score| **score <= 1023)
        .map(|score| score >> 8);
    if let Some(prefix) = accepted_prefixes.next() {
        assert!(
            accepted_prefixes.all(|candidate| candidate == prefix),
            "le fixture isolate devono lasciare ad A36 un unico prefisso b11..b8"
        );
    }
    scores
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("scrivere in una String non puo' fallire");
    }
    encoded
}

fn assert_frozen_source_provenance() {
    assert_eq!(
        sha256_hex(FROZEN_A33_PRIVATE_ARGMIN_SOURCE),
        FROZEN_A33_PRIVATE_ARGMIN_SHA256,
        "il source A33 congelato non corrisponde all'hash auditato"
    );
}

fn expected_final_candidates(scores: &[u64]) -> Vec<u64> {
    let minimum = *scores.iter().min().expect("score non vuoti");
    if minimum > 1023 {
        return vec![0; scores.len()];
    }
    scores
        .iter()
        .map(|score| u64::from(*score == minimum))
        .collect()
}

fn expected_code(scores: &[u64]) -> u64 {
    expected_final_candidates(scores)
        .iter()
        .position(|candidate| *candidate == 1)
        .map_or(0, |index| (index + 1) as u64)
}

fn raw_active_body(polynomial_size: PolynomialSize, output_code: u64) -> Vec<u64> {
    assert_eq!(polynomial_size.0 % P16, 0);
    assert!(matches!(output_code, 1 | 2));
    let box_size = polynomial_size.0 / P16;
    let output = output_code << BOOL_DELTA_LOG;
    let mut body = vec![0u64; polynomial_size.0];
    body[box_size..3 * box_size].fill(output);
    body
}

fn raw_step2_or_body(polynomial_size: PolynomialSize) -> Vec<u64> {
    assert_eq!(polynomial_size.0 % P16, 0);
    let box_size = polynomial_size.0 / P16;
    let output = 2u64 << BOOL_DELTA_LOG;
    let mut body = vec![0u64; polynomial_size.0];
    body[box_size..9 * box_size].fill(output);
    body
}

fn allocate_raw_accumulator(context: &EvalContext<'_>, body: Vec<u64>) -> Glwe {
    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        context.bootstrap_key.glwe_size(),
        &PlaintextList::from_container(body),
        context.modulus,
    )
}

fn scale_lwe_signed(input: &Lwe, multiplier: i64) -> Lwe {
    assert_ne!(multiplier, 0);
    let mut output = input.clone();
    let magnitude = multiplier.unsigned_abs();
    if magnitude != 1 {
        lwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(magnitude));
    }
    if multiplier < 0 {
        lwe_ciphertext_opposite_assign(&mut output);
    }
    output
}

fn compact_or_step2(mut values: Vec<Lwe>, context: &EvalContext<'_>, accumulator: &Glwe) -> Lwe {
    assert!(!values.is_empty());
    while values.len() > 1 {
        values = values
            .par_chunks(OR_RADIX)
            .map(|chunk| {
                let mut sum = chunk[0].clone();
                for value in &chunk[1..] {
                    lwe_ciphertext_add_assign(&mut sum, value);
                }
                context.apply_single_output(&sum, accumulator)
            })
            .collect();
    }
    values.pop().expect("riduzione OR non vuota")
}

fn snapshot_delta(counters: &AtomicPrimitiveCounts, before: PrimitiveCounts) -> PrimitiveCounts {
    counters.snapshot().checked_sub(before)
}

fn a36_chunked_candidates(
    initial_candidates: &[Lwe],
    source_bits_by_level: &[Vec<Lwe>],
    server_key: &ServerKey,
) -> A36EncryptedOutput {
    assert!(!initial_candidates.is_empty());
    assert_eq!(source_bits_by_level.len(), BIT_POSITIONS.len());
    assert!(source_bits_by_level
        .iter()
        .all(|bits| bits.len() == initial_candidates.len()));

    let key_switching_key = &server_key.key_switching_key;
    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("A36 richiede un bootstrap key Classic"),
    };
    let counters = AtomicPrimitiveCounts::default();
    let context = EvalContext {
        key_switching_key,
        bootstrap_key,
        small_size: key_switching_key.output_key_lwe_dimension().to_lwe_size(),
        big_size: bootstrap_key.output_lwe_dimension().to_lwe_size(),
        modulus: key_switching_key.ciphertext_modulus(),
        counters: &counters,
    };
    let polynomial_size = bootstrap_key.polynomial_size();
    assert_eq!(
        polynomial_size.0, 2048,
        "layout A36 auditato per Npoly=2048"
    );
    let active_step2 = allocate_raw_accumulator(&context, raw_active_body(polynomial_size, 2));
    let final_boolean = allocate_raw_accumulator(&context, raw_active_body(polynomial_size, 1));
    let step2_or = allocate_raw_accumulator(&context, raw_step2_or_body(polynomial_size));

    // Conservativo e compatibile col ciphertext A33 corrente: 0/1 -> 0/2 via clear multiplier.
    let mut states: Vec<Lwe> = initial_candidates
        .par_iter()
        .map(|candidate| scale_lwe_signed(candidate, 2))
        .collect();
    let mut levels = Vec::with_capacity(BIT_POSITIONS.len());
    let mut instrumentation = A36Instrumentation::default();
    let total_before = counters.snapshot();

    for level in 0..BIT_POSITIONS.len() {
        let states_before = states.clone();
        let weighted_bits: Vec<Lwe> = source_bits_by_level[level]
            .par_iter()
            .map(|bit| scale_lwe_signed(bit, SOURCE_MULTIPLIERS[level]))
            .collect();
        let zero_test_inputs: Vec<Lwe> = states_before
            .par_iter()
            .zip(weighted_bits.par_iter())
            .map(|(state, bit)| {
                let mut input = state.clone();
                lwe_ciphertext_add_assign(&mut input, bit);
                input
            })
            .collect();

        let before = counters.snapshot();
        let zero_candidates: Vec<Lwe> = zero_test_inputs
            .par_iter()
            .map(|input| context.apply_single_output(input, &active_step2))
            .collect();
        instrumentation.zero_tests = instrumentation
            .zero_tests
            .plus(snapshot_delta(&counters, before));

        let before = counters.snapshot();
        let any_zero = compact_or_step2(zero_candidates.clone(), &context, &step2_or);
        instrumentation.or_reductions = instrumentation
            .or_reductions
            .plus(snapshot_delta(&counters, before));

        let linear_states: Vec<Lwe> = states_before
            .par_iter()
            .zip(zero_candidates.par_iter())
            .map(|(state, zero)| {
                let mut next = state.clone();
                lwe_ciphertext_add_assign(&mut next, zero);
                lwe_ciphertext_sub_assign(&mut next, &any_zero);
                next
            })
            .collect();

        let states_after = if level == CHUNK_END_LEVELS[0] {
            let before = counters.snapshot();
            let refreshed = linear_states
                .par_iter()
                .map(|state| context.apply_single_output(state, &active_step2))
                .collect();
            instrumentation.boundary_canonicalizers = instrumentation
                .boundary_canonicalizers
                .plus(snapshot_delta(&counters, before));
            refreshed
        } else if level == CHUNK_END_LEVELS[1] {
            let before = counters.snapshot();
            let refreshed = linear_states
                .par_iter()
                .map(|state| context.apply_single_output(state, &final_boolean))
                .collect();
            instrumentation.final_canonicalizers = instrumentation
                .final_canonicalizers
                .plus(snapshot_delta(&counters, before));
            refreshed
        } else {
            linear_states.clone()
        };

        levels.push(EncryptedLevelTrace {
            states_before,
            weighted_bits,
            zero_test_inputs,
            zero_candidates,
            any_zero,
            linear_states,
            states_after: states_after.clone(),
        });
        states = states_after;
    }

    instrumentation.total = snapshot_delta(&counters, total_before);
    assert_eq!(
        instrumentation,
        expected_instrumentation(initial_candidates.len())
    );
    A36EncryptedOutput {
        final_candidates: states,
        levels,
        instrumentation,
    }
}

fn clear_a36(initial_candidates: &[u64], scores: &[u64]) -> Vec<ClearLevelTrace> {
    assert_eq!(initial_candidates.len(), scores.len());
    assert!(initial_candidates
        .iter()
        .all(|value| matches!(*value, 0 | 1)));
    let mut states: Vec<i64> = initial_candidates
        .iter()
        .map(|candidate| 2 * (*candidate as i64))
        .collect();
    let mut levels = Vec::with_capacity(BIT_POSITIONS.len());
    for level in 0..BIT_POSITIONS.len() {
        let states_before = states.clone();
        let weighted_bits: Vec<i64> = scores
            .iter()
            .map(|score| {
                let bit = ((score >> BIT_POSITIONS[level]) & 1) as i64;
                TARGET_WEIGHTS[level] * bit
            })
            .collect();
        let zero_test_inputs: Vec<i64> = states_before
            .iter()
            .zip(&weighted_bits)
            .map(|(state, bit)| state + bit)
            .collect();
        let zero_candidates: Vec<i64> = zero_test_inputs
            .iter()
            .map(|input| {
                if *input == ACTIVE_STEP {
                    ACTIVE_STEP
                } else {
                    0
                }
            })
            .collect();
        let any_zero = if zero_candidates.iter().any(|value| *value == ACTIVE_STEP) {
            ACTIVE_STEP
        } else {
            0
        };
        let linear_states: Vec<i64> = states_before
            .iter()
            .zip(&zero_candidates)
            .map(|(state, zero)| state + zero - any_zero)
            .collect();
        let states_after = if level == CHUNK_END_LEVELS[0] {
            linear_states
                .iter()
                .map(|state| {
                    if *state == ACTIVE_STEP {
                        ACTIVE_STEP
                    } else {
                        0
                    }
                })
                .collect()
        } else if level == CHUNK_END_LEVELS[1] {
            linear_states
                .iter()
                .map(|state| i64::from(*state == ACTIVE_STEP))
                .collect()
        } else {
            linear_states.clone()
        };
        levels.push(ClearLevelTrace {
            states_before,
            weighted_bits,
            zero_test_inputs,
            zero_candidates,
            any_zero,
            linear_states,
            states_after: states_after.clone(),
        });
        states = states_after;
    }
    levels
}

fn or_reduction_count(mut items: usize) -> u64 {
    assert!(items > 0);
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(OR_RADIX);
        count += items as u64;
    }
    count
}

fn single_output_counts(rotations: u64) -> PrimitiveCounts {
    PrimitiveCounts {
        blind_rotations: rotations,
        key_switches: rotations,
        output_marginals: rotations,
    }
}

fn expected_instrumentation(gallery_size: usize) -> A36Instrumentation {
    assert!((1..=MAX_GALLERY_SIZE).contains(&gallery_size));
    let zero_tests = single_output_counts(8 * gallery_size as u64);
    let or_reductions = single_output_counts(8 * or_reduction_count(gallery_size));
    let boundary_canonicalizers = single_output_counts(gallery_size as u64);
    let final_canonicalizers = single_output_counts(gallery_size as u64);
    let total = zero_tests
        .plus(or_reductions)
        .plus(boundary_canonicalizers)
        .plus(final_canonicalizers);
    A36Instrumentation {
        zero_tests,
        or_reductions,
        boundary_canonicalizers,
        final_canonicalizers,
        total,
    }
}

fn expected_a33_low_selection(gallery_size: usize) -> PrimitiveCounts {
    single_output_counts(12 * gallery_size as u64 + 8 * or_reduction_count(gallery_size))
}

fn expected_a33_aligned_select_pbs(gallery_size: usize) -> u64 {
    let pairs = gallery_size.div_ceil(2);
    14 * gallery_size as u64
        + pairs as u64
        + 9 * or_reduction_count(gallery_size)
        + or_reduction_count(pairs)
}

fn negacyclic_division_sample(body: &[u64], rotation: usize) -> u64 {
    let value = body[rotation % body.len()];
    if (rotation / body.len()) % 2 == 0 {
        value
    } else {
        value.wrapping_neg()
    }
}

fn sample_raw_code(body: &[u64], code: i64, rotation_error: isize) -> u64 {
    let box_size = body.len() / P16;
    let modulus = 2 * body.len() as isize;
    let rotation = (code as isize * box_size as isize + rotation_error).rem_euclid(modulus);
    negacyclic_division_sample(body, rotation as usize)
}

fn static_layout_and_count_audit() {
    assert_eq!(
        SOURCE_WEIGHTS
            .into_iter()
            .zip(SOURCE_MULTIPLIERS)
            .map(|(source, multiplier)| source * multiplier)
            .collect::<Vec<_>>(),
        TARGET_WEIGHTS.to_vec()
    );
    let polynomial_size = PolynomialSize(2048);
    let box_size = polynomial_size.0 / P16;
    let active = raw_active_body(polynomial_size, 2);
    let final_boolean = raw_active_body(polynomial_size, 1);
    let step2_or = raw_step2_or_body(polynomial_size);
    let delta = 1u64 << BOOL_DELTA_LOG;
    let reachable: [&[i64]; 8] = [
        &[-2, 0, 2],
        &[-4, -2, 0, 2],
        &[-6, -4, -2, 0, 2],
        &[-8, -6, -4, -2, 0, 2],
        &[-2, 0, 2],
        &[-2, 0, 2, 6, 8, 10],
        &[-8, -6, -4, -2, 0, 2],
        &[-8, -6, -4, -2, 0, 2],
    ];
    for inputs in reachable {
        for input in inputs {
            let expected = if *input == ACTIVE_STEP { 2 * delta } else { 0 };
            for error in -(box_size as isize) + 1..box_size as isize {
                assert_eq!(sample_raw_code(&active, *input, error), expected);
            }
        }
    }
    for state in [-8, -6, -4, -2, 0, 2] {
        let expected_step2 = if state == ACTIVE_STEP { 2 * delta } else { 0 };
        let expected_final = if state == ACTIVE_STEP { delta } else { 0 };
        for error in -(box_size as isize) + 1..box_size as isize {
            assert_eq!(sample_raw_code(&active, state, error), expected_step2);
            assert_eq!(
                sample_raw_code(&final_boolean, state, error),
                expected_final
            );
        }
    }
    for count_code in [0, 2, 4, 6, 8] {
        let expected = if count_code == 0 { 0 } else { 2 * delta };
        for error in -(box_size as isize) + 1..box_size as isize {
            assert_eq!(sample_raw_code(&step2_or, count_code, error), expected);
        }
    }
    assert_eq!(sample_raw_code(&active, 18, 0), (2 * delta).wrapping_neg());
    assert!(!reachable
        .iter()
        .flat_map(|values| values.iter())
        .any(|value| value.rem_euclid(32) == 18));
    assert_eq!(sample_raw_code(&active, 2, -(box_size as isize)), 2 * delta);
    assert_eq!(sample_raw_code(&active, 2, box_size as isize), 0);

    let input_l1 = [4u64, 6, 8, 10, 3, 4, 6, 8];
    assert!(input_l1.into_iter().all(|weight| weight <= 10));
    assert_eq!(10 / 2, 5);
    assert_eq!(9f64 / 2.0, 4.5);

    let n127 = expected_instrumentation(127);
    assert_eq!(n127.zero_tests, single_output_counts(1_016));
    assert_eq!(n127.or_reductions, single_output_counts(344));
    assert_eq!(n127.boundary_canonicalizers, single_output_counts(127));
    assert_eq!(n127.final_canonicalizers, single_output_counts(127));
    assert_eq!(n127.total, single_output_counts(1_614));
    let old = expected_a33_low_selection(127);
    assert_eq!(old, single_output_counts(1_868));
    assert_eq!(old.checked_sub(n127.total), single_output_counts(254));
    assert_eq!(A33_N127_PBS - 254, 4_019);
    assert_eq!(A33_N127_KS - 254, 3_638);

    for spec in FIXTURES {
        let scores = fixture_scores(spec);
        let initial = scores
            .iter()
            .map(|score| u64::from(*score <= 1023))
            .collect::<Vec<_>>();
        let clear = clear_a36(&initial, &scores);
        assert_eq!(clear.len(), BIT_POSITIONS.len());
        assert!(clear
            .last()
            .expect("otto livelli")
            .states_after
            .iter()
            .all(|state| matches!(*state, 0 | 1)));
    }
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn clear_score(template: &[i64], probe: &[i64]) -> i64 {
    squared_norm(template)
        - 2 * template
            .iter()
            .zip(probe)
            .map(|(gallery, query)| gallery * query)
            .sum::<i64>()
}

fn remainder_terms(remainder: usize) -> &'static [i64] {
    match remainder {
        0 => &[],
        1 => &[-1, 1, 1],
        2 => &[-1, 1],
        3 => &[-1],
        4 => &[-1, -1, 1, 1],
        5 => &[-1, -1, 1],
        6 => &[-1, -1],
        7 => &[-2, 1],
        8 => &[-2],
        9 => &[-1, -1, -1],
        10 => &[-2, -1, 1],
        11 => &[-2, -1],
        12 => &[-1, -1, -1, -1],
        13 => &[-3, 1, 1],
        14 => &[-3, 1],
        _ => unreachable!("resto modulo 15 fuori intervallo"),
    }
}

fn template_for_score(score: i64) -> Vec<i64> {
    let mut template = vec![0i64; PROBE_DIM];
    let used = if score < 0 {
        let count = usize::try_from(-score).expect("score negativo non rappresentabile");
        template[..count].fill(1);
        count
    } else {
        let quotient = usize::try_from(score / 15).expect("quoziente non rappresentabile");
        let tail = remainder_terms((score % 15) as usize);
        template[..quotient].fill(-3);
        template[quotient..quotient + tail.len()].copy_from_slice(tail);
        quotient + tail.len()
    };
    assert!(used <= PROBE_DIM, "score non rappresentabile");
    template
}

fn make_gallery(scores: &[u64], probe: &[i64]) -> Vec<Vec<i64>> {
    scores
        .iter()
        .map(|translated| {
            let score = i64::try_from(*translated).expect("score fuori i64") + EXECUTION_LOWER;
            let template = template_for_score(score);
            assert_eq!(clear_score(&template, probe), score);
            template
        })
        .collect()
}

fn encrypt_packed_probe(
    probe: &[i64],
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    polynomial_size: PolynomialSize,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    assert_eq!(probe.len(), PROBE_DIM);
    assert!(probe.iter().all(|value| (-3..=3).contains(value)));
    assert!(squared_norm(probe) <= PROBE_NORM2_MAX);
    assert!(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM <= polynomial_size.0);

    let mut plaintext = vec![0u64; polynomial_size.0];
    for (coordinate, value) in probe.iter().enumerate() {
        plaintext[coordinate] = (*value as u64).wrapping_mul(1u64 << FULL_DELTA_LOG);
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOW_MOD16_DELTA_LOG);
    }
    let mut encrypted = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
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

fn decode_symbol(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (BOOL_DELTA_LOG - 1))
        >> BOOL_DELTA_LOG
}

fn decode_code(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (CODE_DELTA_LOG - 1))
        >> CODE_DELTA_LOG
}

fn decode_vector(secret_key: &LweSecretKeyView<'_, u64>, ciphertexts: &[Lwe]) -> Vec<u64> {
    ciphertexts
        .iter()
        .map(|ciphertext| decode_symbol(secret_key, ciphertext) & 31)
        .collect()
}

fn modulo32(values: &[i64]) -> Vec<u64> {
    values
        .iter()
        .map(|value| value.rem_euclid(32) as u64)
        .collect()
}

fn validate_fixture(
    spec: FixtureSpec,
    server_key: &ServerKey,
    probe: &[i64],
    packed_probe: &Glwe,
    big_secret_key: &LweSecretKeyView<'_, u64>,
) {
    let scores = fixture_scores(spec);
    let expected_candidates = expected_final_candidates(&scores);
    let expected_code = expected_code(&scores);
    let gallery = make_gallery(&scores, probe);
    let templates: Vec<TemplateView<'_>> = gallery
        .iter()
        .map(|template| TemplateView {
            template,
            norm2: squared_norm(template),
            threshold: THRESHOLD,
        })
        .collect();
    let plan = plan_private_argmin_execution(&templates).expect("planning A33 fallito");
    assert!(plan.aligned_fast_path, "{}: dispatch non A33", spec.name);
    assert_eq!(plan.execution_domain.lower, EXECUTION_LOWER);

    let fixture_started = Instant::now();
    let a33_started = Instant::now();
    let (a33_output, a33_trace) =
        private_argmin_with_trace(server_key, packed_probe, &templates, plan.execution_domain)
            .expect("core A33 congelato ha rifiutato la fixture");
    let a33_seconds = a33_started.elapsed().as_secs_f64();
    assert!(a33_trace.aligned_fast_path);
    assert_eq!(
        a33_trace.aligned_initial_candidates.len(),
        spec.gallery_size
    );
    assert_eq!(a33_trace.bridged_bits_by_level.len(), BIT_POSITIONS.len());
    assert_eq!(
        a33_output.metrics.select.pbs_count,
        expected_a33_aligned_select_pbs(spec.gallery_size)
    );

    let initial_decoded = decode_vector(big_secret_key, &a33_trace.aligned_initial_candidates);
    assert!(initial_decoded.iter().all(|value| matches!(*value, 0 | 1)));
    for level in 0..BIT_POSITIONS.len() {
        let source_decoded = decode_vector(big_secret_key, &a33_trace.bridged_bits_by_level[level]);
        let expected_source: Vec<u64> = scores
            .iter()
            .map(|score| ((score >> BIT_POSITIONS[level]) & 1) * SOURCE_WEIGHTS[level] as u64)
            .collect();
        assert_eq!(
            source_decoded, expected_source,
            "{}: scala sorgente A33 livello {}",
            spec.name, level
        );
    }

    let a36_started = Instant::now();
    let a36 = a36_chunked_candidates(
        &a33_trace.aligned_initial_candidates,
        &a33_trace.bridged_bits_by_level,
        server_key,
    );
    let a36_seconds = a36_started.elapsed().as_secs_f64();
    let clear = clear_a36(&initial_decoded, &scores);
    assert_eq!(a36.levels.len(), clear.len());

    for (level, (encrypted, expected)) in a36.levels.iter().zip(&clear).enumerate() {
        let decoded_states_before = decode_vector(big_secret_key, &encrypted.states_before);
        let decoded_weighted = decode_vector(big_secret_key, &encrypted.weighted_bits);
        let decoded_inputs = decode_vector(big_secret_key, &encrypted.zero_test_inputs);
        let decoded_zero = decode_vector(big_secret_key, &encrypted.zero_candidates);
        let decoded_any = decode_symbol(big_secret_key, &encrypted.any_zero) & 31;
        let decoded_linear = decode_vector(big_secret_key, &encrypted.linear_states);
        let decoded_after = decode_vector(big_secret_key, &encrypted.states_after);
        assert_eq!(decoded_states_before, modulo32(&expected.states_before));
        assert_eq!(decoded_weighted, modulo32(&expected.weighted_bits));
        assert_eq!(decoded_inputs, modulo32(&expected.zero_test_inputs));
        assert_eq!(decoded_zero, modulo32(&expected.zero_candidates));
        assert_eq!(decoded_any, expected.any_zero as u64);
        assert_eq!(decoded_linear, modulo32(&expected.linear_states));
        assert_eq!(decoded_after, modulo32(&expected.states_after));

        println!(
            "TRACE,case={},level={},bit={},weight={},active_before={},zero_count={},any_zero={},active_after={},input_min={},input_max={},mismatches=0",
            spec.name,
            level,
            BIT_POSITIONS[level],
            TARGET_WEIGHTS[level],
            expected
                .states_before
                .iter()
                .filter(|state| **state == ACTIVE_STEP)
                .count(),
            expected
                .zero_candidates
                .iter()
                .filter(|zero| **zero == ACTIVE_STEP)
                .count(),
            expected.any_zero,
            expected
                .states_after
                .iter()
                .filter(|state| {
                    **state
                        == if level == CHUNK_END_LEVELS[1] {
                            1
                        } else {
                            ACTIVE_STEP
                        }
                })
                .count(),
            expected
                .zero_test_inputs
                .iter()
                .min()
                .expect("input non vuoti"),
            expected
                .zero_test_inputs
                .iter()
                .max()
                .expect("input non vuoti"),
        );
    }

    let a36_final = decode_vector(big_secret_key, &a36.final_candidates);
    assert_eq!(
        a36_final, expected_candidates,
        "{}: candidati A36",
        spec.name
    );
    let a33_final = decode_vector(
        big_secret_key,
        a33_trace
            .candidates_by_level
            .last()
            .expect("candidati finali A33 assenti"),
    );
    assert_eq!(
        a33_final, expected_candidates,
        "{}: candidati A33",
        spec.name
    );
    assert_eq!(a36_final, a33_final, "{}: A36 != A33", spec.name);
    let a36_code = a36_final
        .iter()
        .position(|candidate| *candidate == 1)
        .map_or(0, |index| (index + 1) as u64);
    assert_eq!(a36_code, expected_code);
    assert_eq!(
        decode_code(big_secret_key, &a33_output.code) & 255,
        expected_code
    );
    assert_eq!(
        a36.instrumentation,
        expected_instrumentation(spec.gallery_size)
    );
    if spec.gallery_size == 127 {
        assert_eq!(a33_output.metrics.total_pbs_count, A33_N127_PBS);
        assert_eq!(a36.instrumentation.total, single_output_counts(1_614));
    }

    println!(
        "RESULT,case={},n={},code={},ties={},a36_zero_br={},a36_zero_ks={},a36_zero_marginals={},a36_or_br={},a36_or_ks={},a36_or_marginals={},a36_boundary_br={},a36_boundary_ks={},a36_boundary_marginals={},a36_final_br={},a36_final_ks={},a36_final_marginals={},a36_total_br={},a36_total_ks={},a36_total_marginals={},low_block_save_br={},low_block_save_ks={},low_block_save_marginals={},a33_source_seconds={:.6},a36_seconds={:.6},fixture_seconds={:.6},correct=true",
        spec.name,
        spec.gallery_size,
        a36_code,
        expected_candidates.iter().sum::<u64>(),
        a36.instrumentation.zero_tests.blind_rotations,
        a36.instrumentation.zero_tests.key_switches,
        a36.instrumentation.zero_tests.output_marginals,
        a36.instrumentation.or_reductions.blind_rotations,
        a36.instrumentation.or_reductions.key_switches,
        a36.instrumentation.or_reductions.output_marginals,
        a36.instrumentation.boundary_canonicalizers.blind_rotations,
        a36.instrumentation.boundary_canonicalizers.key_switches,
        a36.instrumentation.boundary_canonicalizers.output_marginals,
        a36.instrumentation.final_canonicalizers.blind_rotations,
        a36.instrumentation.final_canonicalizers.key_switches,
        a36.instrumentation.final_canonicalizers.output_marginals,
        a36.instrumentation.total.blind_rotations,
        a36.instrumentation.total.key_switches,
        a36.instrumentation.total.output_marginals,
        2 * spec.gallery_size,
        2 * spec.gallery_size,
        2 * spec.gallery_size,
        a33_seconds,
        a36_seconds,
        fixture_started.elapsed().as_secs_f64(),
    );
}

fn main() {
    assert_frozen_source_provenance();
    static_layout_and_count_audit();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|argument| argument == "--list") {
        for spec in FIXTURES {
            println!("FIXTURE,name={},n={}", spec.name, spec.gallery_size);
        }
        return;
    }

    let n127 = expected_instrumentation(127);
    if !arguments.iter().any(|argument| argument == "--run") {
        println!(
            "usage: a36_chunked_candidate_prototype --run [--small-only] [--case=NAME]\n\
             PLAN,source=a33_frozen_trace,source_sha256={},no_decrypt_reencrypt=true,fusion_b13=false,p=16,active_step=2,boundary_output=0/2,final_output=0/1,open_margin=Delta_bool,n127_zero={}/{}/{},n127_or={}/{}/{},n127_boundary={}/{}/{},n127_final={}/{}/{},n127_total={}/{}/{},n127_low_block_saving=254/254/254,n127_projected_core=4019/3638,ephemeral_key=true,secret_material_persisted=false",
            FROZEN_A33_PRIVATE_ARGMIN_SHA256,
            n127.zero_tests.blind_rotations,
            n127.zero_tests.key_switches,
            n127.zero_tests.output_marginals,
            n127.or_reductions.blind_rotations,
            n127.or_reductions.key_switches,
            n127.or_reductions.output_marginals,
            n127.boundary_canonicalizers.blind_rotations,
            n127.boundary_canonicalizers.key_switches,
            n127.boundary_canonicalizers.output_marginals,
            n127.final_canonicalizers.blind_rotations,
            n127.final_canonicalizers.key_switches,
            n127.final_canonicalizers.output_marginals,
            n127.total.blind_rotations,
            n127.total.key_switches,
            n127.total.output_marginals,
        );
        return;
    }

    let selected_name = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--case="));
    let small_only = arguments.iter().any(|argument| argument == "--small-only");
    let selected: Vec<FixtureSpec> = FIXTURES
        .into_iter()
        .filter(|spec| selected_name.map_or(true, |name| spec.name == name))
        .filter(|spec| !small_only || spec.gallery_size <= 3)
        .collect();
    assert!(!selected.is_empty(), "nessuna fixture selezionata");

    // Una sola chiave fresca, effimera e mai serializzata per l'intero harness.
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let probe = vec![1i64; PROBE_DIM];
    assert!(squared_norm(&probe) <= PROBE_NORM2_MAX);

    for spec in selected {
        let packed_probe = encrypt_packed_probe(
            &probe,
            &glwe_secret_key,
            client_params.glwe_noise_distribution(),
            polynomial_size,
            modulus,
            &mut generator,
        );
        validate_fixture(spec, &server_key, &probe, &packed_probe, &big_secret_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_layout_scales_and_counts_are_static() {
        assert_frozen_source_provenance();
        static_layout_and_count_audit();
    }

    #[test]
    fn clear_fixtures_match_exact_minimum_and_final_boolean_scale() {
        for spec in FIXTURES {
            let scores = fixture_scores(spec);
            let initial: Vec<u64> = scores
                .iter()
                .map(|score| u64::from(*score <= 1023))
                .collect();
            let trace = clear_a36(&initial, &scores);
            let final_states = &trace.last().expect("otto livelli").states_after;
            assert_eq!(
                final_states
                    .iter()
                    .map(|value| *value as u64)
                    .collect::<Vec<_>>(),
                expected_final_candidates(&scores)
            );
            assert!(final_states.iter().all(|state| matches!(*state, 0 | 1)));
        }
    }
}
