//! Latency-ready A53 adapter used by the isolated A66 copy of A62/A44.
//!
//! A66 preserves A62 semantics, wire format and primitive counts.  It prepares each raw LUT
//! accumulator once, shares immutable accumulators between independent PBS calls, and schedules
//! only dependency-free peers with Rayon.  Calls still fail closed on the frozen A44 parameter
//! identity, source provenance, explicit experimental acknowledgement, and exact counters.  The
//! adapter returns two fresh p16 roots and never performs encrypted code56 recomposition.

use super::{
    scan_counts, selector_layout, slot_lut_residue_body, A53StaticError, OutputScale,
    PrimitiveCounts, SourceGuard, A44_MAX_NOISE_LEVEL, A44_PARAMETER_CANONICAL,
    A44_PARAMETER_FINGERPRINT_SHA256, A44_PARAMS_ID, DIGIT_IDENTITY_SLOT_LUT, GROUP_OR_SLOT_LUT,
    GROUP_SIZE, LOCAL_FIRST_SLOT_LUT, MAX_GALLERY_SIZE, POLYNOMIAL_SIZE, REDUCTION_RADIX,
    SELECTOR_SECOND_SAMPLE_DEGREE, SOURCE_GUARDS,
};
use rayon::prelude::*;

pub const A66_EXPERIMENT_ACK: &str =
    "A66_LATENCY_READY_UNVALIDATED_FHE_EXPERIMENT_WITH_FRESH_A44_KEYS";
pub const A66_PFAIL_ACK: &str =
    "A66_HAS_NO_END_TO_END_PFAIL_BOUND_FOR_CUSTOM_OR_CORRELATED_LUT_OUTPUTS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendParameterContract<'a> {
    pub params_id: &'a str,
    pub canonical: &'a str,
    pub fingerprint_sha256: &'a str,
    pub polynomial_size: usize,
    pub pbs_message_modulus: usize,
    pub max_noise_level: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedSourceGuard<'a> {
    pub repository_path: &'a str,
    pub sha256: &'a str,
}

/// Frozen input digests copied into the integration boundary.  The independent Python preflight
/// hashes the repository files before this crate may be compiled or executed.
pub const A66_OBSERVED_SOURCE_GUARDS: &[ObservedSourceGuard<'static>] = &[
    ObservedSourceGuard {
        repository_path: "tmp/a38-combined-prototype/src/private_argmin.rs",
        sha256: "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a38-combined-prototype/src/lib.rs",
        sha256: "855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/src/private_argmin.rs",
        sha256: "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/src/lib.rs",
        sha256: "c31619b88e87ac73e3174281b1453433f08f8ab0cd6d7e50a79ca16539ddf434",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/Cargo.lock",
        sha256: "f0072f805e3559203affcd73dc94ca30610552a63b3cfb1da8d4e6d78aa435dd",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a50-canonical-radix15-model/a50_canonical_radix15_model.py",
        sha256: "19196d9e17a30e5197601dacf42b9416239608a99489b4a1a284f488e102c4cb",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py",
        sha256: "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/test_a53_static.py",
        sha256: "c64026b21134d6df1b0e2d2dfdf4358137a98dc6b832f5cfde2e43b50d9166ae",
    },
    ObservedSourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/README.md",
        sha256: "12c95ef11b91e1922312336ad7380b4b98ef616ddf6f9046aa05ae060053d179",
    },
];

#[derive(Clone, Copy, Debug)]
pub struct FutureFheGate<'a> {
    pub backend_parameter: BackendParameterContract<'a>,
    pub observed_sources: &'a [ObservedSourceGuard<'a>],
    pub experiment_ack: &'a str,
    pub pfail_ack: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FutureFheGateError {
    ExperimentNotAcknowledged,
    MissingPFailAcknowledgement,
    ParameterMismatch,
    GeometryMismatch,
    SourceGuardCardinality,
    MissingSourceGuard(&'static str),
    SourceDigestMismatch(&'static str),
}

pub fn validate_future_fhe_gate(gate: &FutureFheGate<'_>) -> Result<(), FutureFheGateError> {
    if gate.experiment_ack != A66_EXPERIMENT_ACK {
        return Err(FutureFheGateError::ExperimentNotAcknowledged);
    }
    if gate.pfail_ack != A66_PFAIL_ACK {
        return Err(FutureFheGateError::MissingPFailAcknowledgement);
    }
    let parameter = gate.backend_parameter;
    if parameter.params_id != A44_PARAMS_ID
        || parameter.canonical != A44_PARAMETER_CANONICAL
        || parameter.fingerprint_sha256 != A44_PARAMETER_FINGERPRINT_SHA256
    {
        return Err(FutureFheGateError::ParameterMismatch);
    }
    if parameter.polynomial_size != POLYNOMIAL_SIZE
        || parameter.pbs_message_modulus != 16
        || parameter.max_noise_level != A44_MAX_NOISE_LEVEL
    {
        return Err(FutureFheGateError::GeometryMismatch);
    }
    if gate.observed_sources.len() != SOURCE_GUARDS.len() {
        return Err(FutureFheGateError::SourceGuardCardinality);
    }
    for expected in SOURCE_GUARDS {
        let observed = gate
            .observed_sources
            .iter()
            .find(|candidate| candidate.repository_path == expected.repository_path)
            .ok_or(FutureFheGateError::MissingSourceGuard(
                expected.repository_path,
            ))?;
        if observed.sha256 != expected.sha256 {
            return Err(FutureFheGateError::SourceDigestMismatch(
                expected.repository_path,
            ));
        }
    }
    Ok(())
}

/// Thread-safe bridge implemented by the frozen A44 core in the isolated A66 copy.
///
/// `pbs_prepared` counts one BR, one KS and one marginal. `pbs_dual_prepared` consumes its
/// single-use selector accumulator, uses one switched input and one blind rotation, extracts
/// degrees zero and 1024, and counts one BR, one KS and two correlated marginals.  The shared OR,
/// local-first and digit-identity accumulators are immutable.  Plaintext additions do not alter
/// the counters.
pub trait A53FheBackend: Sync {
    type Lwe: Clone + Send + Sync;
    type Accumulator: Send + Sync;
    type Error: Send;

    fn trivial_zero(&self) -> Self::Lwe;
    fn add_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe);
    fn sub_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe);
    fn add_plaintext_assign(&self, target: &mut Self::Lwe, torus_plaintext: u64);
    fn prepare_raw_accumulator(&self, torus_body: &[u64])
        -> Result<Self::Accumulator, Self::Error>;
    fn pbs_prepared(
        &self,
        input: &Self::Lwe,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::Lwe, Self::Error>;
    fn pbs_dual_prepared(
        &self,
        input: &Self::Lwe,
        accumulator: Self::Accumulator,
        first_degree: usize,
        second_degree: usize,
    ) -> Result<(Self::Lwe, Self::Lwe), Self::Error>;
    fn counters(&self) -> PrimitiveCounts;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FutureFheError<E> {
    Gate(FutureFheGateError),
    Static(A53StaticError),
    Backend(E),
    CounterUnderflow,
    CounterMismatch {
        expected: PrimitiveCounts,
        observed: PrimitiveCounts,
    },
}

#[derive(Clone, Debug)]
pub struct A53FheOutput<Lwe> {
    /// First p16 protocol root: `code mod 15`, at `Delta=2^59`.
    pub low_digit: Lwe,
    /// Second p16 protocol root: `floor(code / 15)`, at `Delta=2^59`.
    pub high_digit: Lwe,
    pub expected_counts: PrimitiveCounts,
    pub observed_counts: PrimitiveCounts,
}

fn subtract_counts(after: PrimitiveCounts, before: PrimitiveCounts) -> Option<PrimitiveCounts> {
    Some(PrimitiveCounts {
        blind_rotations: after.blind_rotations.checked_sub(before.blind_rotations)?,
        key_switches: after.key_switches.checked_sub(before.key_switches)?,
        output_marginals: after
            .output_marginals
            .checked_sub(before.output_marginals)?,
    })
}

fn torus_plaintext(residue: u16, scale: OutputScale) -> u64 {
    (residue as u64).wrapping_mul(1u64 << scale.delta_log())
}

fn torus_body(residues: &[u16], scale: OutputScale) -> Vec<u64> {
    residues
        .iter()
        .map(|residue| torus_plaintext(*residue, scale))
        .collect()
}

/// Indexed parallel iterators preserve the outer `Vec` order. Resolving `Result` afterwards also
/// makes simultaneous backend failures select the lowest logical index deterministically.
fn collect_ordered_results<T, E>(results: Vec<Result<T, E>>) -> Result<Vec<T>, E> {
    results.into_iter().collect()
}

fn sum_lwes<B: A53FheBackend>(backend: &B, inputs: &[B::Lwe]) -> B::Lwe {
    let mut sum = backend.trivial_zero();
    for input in inputs {
        backend.add_assign(&mut sum, input);
    }
    sum
}

fn add_scaled<B: A53FheBackend>(
    backend: &B,
    target: &mut B::Lwe,
    source: &B::Lwe,
    multiplier: i32,
) {
    if multiplier >= 0 {
        for _ in 0..multiplier.unsigned_abs() {
            backend.add_assign(target, source);
        }
    } else {
        for _ in 0..multiplier.unsigned_abs() {
            backend.sub_assign(target, source);
        }
    }
}

fn or_gate<B: A53FheBackend>(
    backend: &B,
    inputs: &[B::Lwe],
    or_accumulator: Option<&B::Accumulator>,
) -> Result<B::Lwe, B::Error> {
    match inputs {
        [] => Ok(backend.trivial_zero()),
        [only] => Ok(only.clone()),
        _ => {
            debug_assert!(inputs.len() <= REDUCTION_RADIX);
            let sum = sum_lwes(backend, inputs);
            backend.pbs_prepared(
                &sum,
                or_accumulator.expect("multi-input OR requires its prepared accumulator"),
            )
        }
    }
}

fn encrypted_exclusive_prefix<B: A53FheBackend>(
    backend: &B,
    flags: &[B::Lwe],
    or_accumulator: Option<&B::Accumulator>,
) -> Result<Vec<B::Lwe>, B::Error> {
    if flags.len() <= REDUCTION_RADIX {
        return collect_ordered_results(
            (0..flags.len())
                .into_par_iter()
                .map(|index| or_gate(backend, &flags[..index], or_accumulator))
                .collect(),
        );
    }

    // All block totals at one level are peers.  The recursive call is a dependency barrier:
    // expansion cannot start until the ordered block prefixes are available.
    let totals = collect_ordered_results(
        flags
            .par_chunks(REDUCTION_RADIX)
            .map(|block| or_gate(backend, block, or_accumulator))
            .collect(),
    )?;
    let block_prefixes = encrypted_exclusive_prefix(backend, &totals, or_accumulator)?;
    collect_ordered_results(
        (0..flags.len())
            .into_par_iter()
            .map(|index| {
                let block_index = index / REDUCTION_RADIX;
                let offset = index % REDUCTION_RADIX;
                if offset == 0 {
                    return Ok(block_prefixes[block_index].clone());
                }
                let block_start = block_index * REDUCTION_RADIX;
                let mut inputs = Vec::with_capacity(offset + usize::from(block_index > 0));
                if block_index > 0 {
                    inputs.push(block_prefixes[block_index].clone());
                }
                inputs.extend(flags[block_start..block_start + offset].iter().cloned());
                or_gate(backend, &inputs, or_accumulator)
            })
            .collect(),
    )
}

fn reduce_digit<B: A53FheBackend>(
    backend: &B,
    mut digits: Vec<B::Lwe>,
    identity_accumulator: &B::Accumulator,
) -> Result<B::Lwe, B::Error> {
    debug_assert!(digits.len() >= 2);
    while digits.len() > 1 {
        digits = collect_ordered_results(
            digits
                .par_chunks(REDUCTION_RADIX)
                .map(|chunk| match chunk {
                    [only] => Ok(only.clone()),
                    _ => {
                        let sum = sum_lwes(backend, chunk);
                        backend.pbs_prepared(&sum, identity_accumulator)
                    }
                })
                .collect(),
        )?;
    }
    Ok(digits.pop().expect("non-empty digit reduction"))
}

/// Encrypted scan materialization called by the A62 exact-ID entry point in the A66 copy.
pub fn materialize_a53_scan<B: A53FheBackend>(
    gate: &FutureFheGate<'_>,
    backend: &B,
    candidates: &[B::Lwe],
) -> Result<A53FheOutput<B::Lwe>, FutureFheError<B::Error>> {
    validate_future_fhe_gate(gate).map_err(FutureFheError::Gate)?;
    if candidates.is_empty() || candidates.len() > MAX_GALLERY_SIZE {
        return Err(FutureFheError::Static(A53StaticError::GallerySize));
    }
    let before = backend.counters();
    let boolean_scale = OutputScale::BooleanDigit;
    let or_body = torus_body(
        &slot_lut_residue_body(&GROUP_OR_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );
    let local_body = torus_body(
        &slot_lut_residue_body(&LOCAL_FIRST_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );
    let identity_body = torus_body(
        &slot_lut_residue_body(&DIGIT_IDENTITY_SLOT_LUT, boolean_scale.period())
            .map_err(FutureFheError::Static)?,
        boolean_scale,
    );

    let group_count = candidates.len().div_ceil(GROUP_SIZE);
    let or_accumulator = if candidates.len() > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&or_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let local_accumulator = if candidates.len() > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&local_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let identity_accumulator = if group_count > 1 {
        Some(
            backend
                .prepare_raw_accumulator(&identity_body)
                .map_err(FutureFheError::Backend)?,
        )
    } else {
        None
    };
    let layouts = collect_ordered_results(
        candidates
            .chunks(GROUP_SIZE)
            .enumerate()
            .map(|(group_index, group)| selector_layout(group_index, group.len(), false))
            .collect(),
    )
    .map_err(FutureFheError::Static)?;
    // Selector accumulator preparation and group flags are independent after layouts/shared LUTs.
    let (selector_accumulators_result, flags_result) = rayon::join(
        || {
            collect_ordered_results(
                layouts
                    .par_iter()
                    .map(|layout| {
                        let body = torus_body(&layout.residue_body, layout.scale);
                        backend.prepare_raw_accumulator(&body)
                    })
                    .collect(),
            )
        },
        || {
            collect_ordered_results(
                candidates
                    .par_chunks(GROUP_SIZE)
                    .map(|group| or_gate(backend, group, or_accumulator.as_ref()))
                    .collect(),
            )
        },
    );
    let selector_accumulators = selector_accumulators_result.map_err(FutureFheError::Backend)?;
    let flags = flags_result.map_err(FutureFheError::Backend)?;

    // Both branches consume flags but neither consumes the other's output.
    let (local_first_result, prefixes_result) = rayon::join(
        || {
            collect_ordered_results(
                candidates
                    .par_chunks(GROUP_SIZE)
                    .zip(flags.par_iter())
                    .map(|(group, flag)| {
                        if group.len() == 1 {
                            return Ok(flag.clone());
                        }
                        let mut encoded = flag.clone();
                        add_scaled(backend, &mut encoded, &group[0], 4);
                        add_scaled(backend, &mut encoded, &group[1], 2);
                        if group.len() >= 3 {
                            add_scaled(backend, &mut encoded, &group[2], 1);
                        }
                        backend.pbs_prepared(
                            &encoded,
                            local_accumulator.as_ref().expect(
                                "multi-candidate scan prepares the local-first accumulator",
                            ),
                        )
                    })
                    .collect(),
            )
        },
        || encrypted_exclusive_prefix(backend, &flags, or_accumulator.as_ref()),
    );
    let local_first = local_first_result.map_err(FutureFheError::Backend)?;
    let prefixes = prefixes_result.map_err(FutureFheError::Backend)?;
    let selector_outputs = collect_ordered_results(
        selector_accumulators
            .into_par_iter()
            .enumerate()
            .map(|(group_index, accumulator)| {
                let layout = &layouts[group_index];
                let mut encoded = local_first[group_index].clone();
                add_scaled(
                    backend,
                    &mut encoded,
                    &prefixes[group_index],
                    -(GROUP_SIZE as i32),
                );
                let (mut low, mut high) = backend.pbs_dual_prepared(
                    &encoded,
                    accumulator,
                    0,
                    SELECTOR_SECOND_SAMPLE_DEGREE,
                )?;
                backend.add_plaintext_assign(
                    &mut low,
                    torus_plaintext(layout.offsets.low, layout.scale),
                );
                backend.add_plaintext_assign(
                    &mut high,
                    torus_plaintext(layout.offsets.high, layout.scale),
                );
                Ok((low, high))
            })
            .collect(),
    )
    .map_err(FutureFheError::Backend)?;
    let (mut low_digits, mut high_digits): (Vec<_>, Vec<_>) = selector_outputs.into_iter().unzip();

    let (low_digit, high_digit) = if flags.len() == 1 {
        (low_digits.pop().unwrap(), high_digits.pop().unwrap())
    } else {
        let identity_accumulator = identity_accumulator
            .as_ref()
            .expect("multiple groups prepare the digit accumulator");
        let (low_result, high_result) = rayon::join(
            || reduce_digit(backend, low_digits, identity_accumulator),
            || reduce_digit(backend, high_digits, identity_accumulator),
        );
        (
            low_result.map_err(FutureFheError::Backend)?,
            high_result.map_err(FutureFheError::Backend)?,
        )
    };

    let after = backend.counters();
    let observed = subtract_counts(after, before).ok_or(FutureFheError::CounterUnderflow)?;
    let expected = scan_counts(candidates.len())
        .map_err(FutureFheError::Static)?
        .total;
    if observed != expected {
        return Err(FutureFheError::CounterMismatch { expected, observed });
    }
    Ok(A53FheOutput {
        low_digit,
        high_digit,
        expected_counts: expected,
        observed_counts: observed,
    })
}

#[allow(dead_code)]
fn _source_guard_type_anchor(_: SourceGuard) {}
