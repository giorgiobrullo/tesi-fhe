//! Explicitly gated adapter for a future A44/TFHE experiment.
//!
//! This module is not compiled or enabled in A58.  It deliberately depends on a backend adapter
//! that does not exist in this directory.  A future integration must compute source hashes,
//! validate the exact A44 parameter contract, acknowledge the open custom-LUT p-fail work, and
//! expose exact BR/KS/marginal counters before this entry point accepts a run.

use super::{
    scan_counts, selector_layout, slot_lut_residue_body, A53StaticError, OutputScale,
    PrimitiveCounts, SourceGuard, A44_MAX_NOISE_LEVEL, A44_PARAMETER_CANONICAL,
    A44_PARAMETER_FINGERPRINT_SHA256, A44_PARAMS_ID, CODE_OUTPUT_PERIOD, DIGIT_IDENTITY_SLOT_LUT,
    GROUP_OR_SLOT_LUT, GROUP_SIZE, HIGH_CODE_SLOT_LUT, LOCAL_FIRST_SLOT_LUT, LOW_CODE_SLOT_LUT,
    MAX_GALLERY_SIZE, POLYNOMIAL_SIZE, REDUCTION_RADIX, SELECTOR_SECOND_SAMPLE_DEGREE,
    SOURCE_GUARDS,
};

pub const A58_EXPERIMENT_ACK: &str =
    "A58_SOURCE_ONLY_UNVALIDATED_FHE_EXPERIMENT_WITH_FRESH_A44_KEYS";
pub const A58_PFAIL_ACK: &str =
    "A58_HAS_NO_END_TO_END_PFAIL_BOUND_FOR_CUSTOM_OR_CORRELATED_LUT_OUTPUTS";

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
    if gate.experiment_ack != A58_EXPERIMENT_ACK {
        return Err(FutureFheGateError::ExperimentNotAcknowledged);
    }
    if gate.pfail_ack != A58_PFAIL_ACK {
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

/// Minimal bridge the frozen A44 core must implement in a separate integration copy.
///
/// `pbs_raw` counts one BR, one KS and one marginal. `pbs_dual_raw` uses one switched input and
/// one blind rotation, extracts degrees zero and 1024, and counts one BR, one KS, two correlated
/// marginals. Plaintext additions do not alter those counters.
pub trait A53FheBackend {
    type Lwe: Clone;
    type Error;

    fn trivial_zero(&self) -> Self::Lwe;
    fn add_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe);
    fn sub_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe);
    fn add_plaintext_assign(&self, target: &mut Self::Lwe, torus_plaintext: u64);
    fn pbs_raw(&mut self, input: &Self::Lwe, torus_body: &[u64]) -> Result<Self::Lwe, Self::Error>;
    fn pbs_dual_raw(
        &mut self,
        input: &Self::Lwe,
        torus_body: &[u64],
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
    /// The only protocol payload: one encrypted exact code (`0` or `i + 1`).
    pub code: Lwe,
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
    for _ in 0..multiplier.unsigned_abs() {
        if multiplier >= 0 {
            backend.add_assign(target, source);
        } else {
            backend.sub_assign(target, source);
        }
    }
}

fn or_gate<B: A53FheBackend>(
    backend: &mut B,
    inputs: &[B::Lwe],
    or_body: &[u64],
) -> Result<B::Lwe, B::Error> {
    match inputs {
        [] => Ok(backend.trivial_zero()),
        [only] => Ok(only.clone()),
        _ => {
            debug_assert!(inputs.len() <= REDUCTION_RADIX);
            let sum = sum_lwes(backend, inputs);
            backend.pbs_raw(&sum, or_body)
        }
    }
}

fn encrypted_exclusive_prefix<B: A53FheBackend>(
    backend: &mut B,
    flags: &[B::Lwe],
    or_body: &[u64],
) -> Result<Vec<B::Lwe>, B::Error> {
    if flags.len() <= REDUCTION_RADIX {
        let mut prefixes = Vec::with_capacity(flags.len());
        for index in 0..flags.len() {
            prefixes.push(or_gate(backend, &flags[..index], or_body)?);
        }
        return Ok(prefixes);
    }

    let mut totals = Vec::with_capacity(flags.len().div_ceil(REDUCTION_RADIX));
    for block in flags.chunks(REDUCTION_RADIX) {
        totals.push(or_gate(backend, block, or_body)?);
    }
    let block_prefixes = encrypted_exclusive_prefix(backend, &totals, or_body)?;
    let mut prefixes = Vec::with_capacity(flags.len());
    for (block_index, block) in flags.chunks(REDUCTION_RADIX).enumerate() {
        for offset in 0..block.len() {
            if offset == 0 {
                prefixes.push(block_prefixes[block_index].clone());
                continue;
            }
            let mut inputs = Vec::with_capacity(offset + usize::from(block_index > 0));
            if block_index > 0 {
                inputs.push(block_prefixes[block_index].clone());
            }
            inputs.extend(block[..offset].iter().cloned());
            prefixes.push(or_gate(backend, &inputs, or_body)?);
        }
    }
    Ok(prefixes)
}

fn reduce_digit<B: A53FheBackend>(
    backend: &mut B,
    mut digits: Vec<B::Lwe>,
    identity_body: &[u64],
    final_body: &[u64],
) -> Result<B::Lwe, B::Error> {
    debug_assert!(digits.len() >= 2);
    while digits.len() > 1 {
        let next_len = digits.len().div_ceil(REDUCTION_RADIX);
        let mut next = Vec::with_capacity(next_len);
        for chunk in digits.chunks(REDUCTION_RADIX) {
            if chunk.len() == 1 {
                next.push(chunk[0].clone());
                continue;
            }
            let sum = sum_lwes(backend, chunk);
            let body = if next_len == 1 {
                final_body
            } else {
                identity_body
            };
            next.push(backend.pbs_raw(&sum, body)?);
        }
        digits = next;
    }
    Ok(digits.pop().expect("non-empty digit reduction"))
}

/// Source-level encrypted scan materialization.  A58 never invokes this function.
pub fn materialize_a53_scan<B: A53FheBackend>(
    gate: &FutureFheGate<'_>,
    backend: &mut B,
    candidates: &[B::Lwe],
) -> Result<A53FheOutput<B::Lwe>, FutureFheError<B::Error>> {
    validate_future_fhe_gate(gate).map_err(FutureFheError::Gate)?;
    if candidates.is_empty() || candidates.len() > MAX_GALLERY_SIZE {
        return Err(FutureFheError::Static(A53StaticError::GallerySize));
    }
    let before = backend.counters();
    let boolean_scale = OutputScale::BooleanDigit;
    let exact_scale = OutputScale::ExactCode;
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
    let low_final_body = torus_body(
        &slot_lut_residue_body(&LOW_CODE_SLOT_LUT, CODE_OUTPUT_PERIOD)
            .map_err(FutureFheError::Static)?,
        exact_scale,
    );
    let high_final_body = torus_body(
        &slot_lut_residue_body(&HIGH_CODE_SLOT_LUT, CODE_OUTPUT_PERIOD)
            .map_err(FutureFheError::Static)?,
        exact_scale,
    );

    let mut flags = Vec::with_capacity(candidates.len().div_ceil(GROUP_SIZE));
    for group in candidates.chunks(GROUP_SIZE) {
        flags.push(or_gate(backend, group, &or_body).map_err(FutureFheError::Backend)?);
    }

    let mut local_first = Vec::with_capacity(flags.len());
    for (group, flag) in candidates.chunks(GROUP_SIZE).zip(&flags) {
        if group.len() == 1 {
            local_first.push(flag.clone());
            continue;
        }
        let mut encoded = flag.clone();
        add_scaled(backend, &mut encoded, &group[0], 4);
        if group.len() >= 2 {
            add_scaled(backend, &mut encoded, &group[1], 2);
        }
        if group.len() >= 3 {
            add_scaled(backend, &mut encoded, &group[2], 1);
        }
        local_first.push(
            backend
                .pbs_raw(&encoded, &local_body)
                .map_err(FutureFheError::Backend)?,
        );
    }

    let prefixes =
        encrypted_exclusive_prefix(backend, &flags, &or_body).map_err(FutureFheError::Backend)?;
    let direct = flags.len() == 1;
    let mut low_digits = Vec::with_capacity(flags.len());
    let mut high_digits = Vec::with_capacity(flags.len());
    for (group_index, ((group, local), prefix)) in candidates
        .chunks(GROUP_SIZE)
        .zip(&local_first)
        .zip(&prefixes)
        .enumerate()
    {
        let layout =
            selector_layout(group_index, group.len(), direct).map_err(FutureFheError::Static)?;
        let mut encoded = local.clone();
        add_scaled(backend, &mut encoded, prefix, -(GROUP_SIZE as i32));
        let body = torus_body(&layout.residue_body, layout.scale);
        let (mut low, mut high) = backend
            .pbs_dual_raw(&encoded, &body, 0, SELECTOR_SECOND_SAMPLE_DEGREE)
            .map_err(FutureFheError::Backend)?;
        backend.add_plaintext_assign(&mut low, torus_plaintext(layout.offsets.low, layout.scale));
        backend.add_plaintext_assign(
            &mut high,
            torus_plaintext(layout.offsets.high, layout.scale),
        );
        low_digits.push(low);
        high_digits.push(high);
    }

    let (low_code, high_code) = if direct {
        (low_digits.pop().unwrap(), high_digits.pop().unwrap())
    } else {
        (
            reduce_digit(backend, low_digits, &identity_body, &low_final_body)
                .map_err(FutureFheError::Backend)?,
            reduce_digit(backend, high_digits, &identity_body, &high_final_body)
                .map_err(FutureFheError::Backend)?,
        )
    };
    let mut code = low_code.clone();
    backend.add_assign(&mut code, &high_code);

    let after = backend.counters();
    let observed = subtract_counts(after, before).ok_or(FutureFheError::CounterUnderflow)?;
    let expected = scan_counts(candidates.len())
        .map_err(FutureFheError::Static)?
        .total;
    if observed != expected {
        return Err(FutureFheError::CounterMismatch { expected, observed });
    }
    Ok(A53FheOutput {
        code,
        expected_counts: expected,
        observed_counts: observed,
    })
}

#[allow(dead_code)]
fn _source_guard_type_anchor(_: SourceGuard) {}
