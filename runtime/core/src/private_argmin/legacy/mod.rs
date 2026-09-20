//! Earlier A29/A38/A62/A126 circuits retained for reproduction and diagnostics.
//!
//! Their operation graphs and execution order are preserved. The selected runtime uses the
//! score prefix and contracts in the parent module, not these older argmin implementations.
use super::contracts::*;
use super::domain::{
    aligned_uniform_fast_path_for_thresholds, validate_domain, ALIGNED_UNIFORM_THRESHOLD,
};
use super::input::validate_inputs;
use super::parameters::validate_a44_parameter_binding;
use crate::a53_scan::fhe::{
    materialize_a53_scan, A53FheBackend, BackendParameterContract, FutureFheError, FutureFheGate,
    A66_EXPERIMENT_ACK, A66_OBSERVED_SOURCE_GUARDS, A66_PFAIL_ACK,
};
use crate::a53_scan::{
    scan_counts as a53_scan_counts, PrimitiveCounts as A53PrimitiveCounts,
    A44_MAX_NOISE_LEVEL as A53_REQUIRED_MAX_NOISE_LEVEL,
};
use crate::compat::{blind_rotate_assign, ServerKey, ShortintBootstrappingKey};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;

mod aligned;
mod api;
mod bridge;
mod counts;
mod extraction;
mod general;
mod luts;
mod reductions;
mod scan;

use aligned::private_argmin_aligned_a38_impl;
pub use api::*;
pub use bridge::{pfks_score_bridge, PfksBridgeOutput};
use counts::*;
pub use counts::{
    a126_aligned_operation_counts, a34_aligned_operation_counts, a38_aligned_operation_counts,
    a41_aligned_operation_counts, a44_aligned_operation_counts, a62_aligned_operation_counts,
    expected_pbs_count, expected_pbs_count_for_thresholds,
};
use extraction::*;
use general::private_argmin_impl;
use luts::*;
use reductions::*;
use scan::*;

const HIGH_SCORE_BIT: u32 = 11;
const SCORE_BITS: u32 = HIGH_SCORE_BIT + 1;
const SPLIT_LOW_BITS: u32 = 3;
const LOW_EXTRACTED_BITS: u32 = 4;
const HIGH_EXTRACTED_BITS: u32 = SCORE_BITS - LOW_EXTRACTED_BITS;
const HIGH_DELTA_LOG: u32 = FULL_DELTA_LOG + LOW_EXTRACTED_BITS;
const PBS_MESSAGE_MODULUS: usize = 16;
const ALIGNED_SELECTION_HIGH_BIT: u32 = 7;
const A34_HIGH_CORRECTION_BITS: u32 = 4;
const A34_TOP_CLASSIFIER_MODULUS: usize = 16;
const A34_TOP_CLASSIFIER_CODES: [u64; 16] = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0];
const A38_REDUCTION_RADIX: usize = 5;
const A38_SCAN_GROUP_SIZE: usize = 3;
const A50_REDUCTION_RADIX: usize = 15;
const A50_SOURCE_MULTIPLIERS: [i64; 8] = [-1, -1, -1, -1, -1, 1, -1, -1];
const A38_NIBBLE_RADIX: u64 = 16;
const A38_EXPECTED_SOURCE_WEIGHTS: [u64; 8] = [1, 1, 1, 1, 1, 8, 4, 2];
const A38_SOURCE_MULTIPLIERS: [i64; 8] = [-2, -2, -2, -2, -2, 1, -1, -1];
const A38_CHUNK_END_LEVELS: [usize; 2] = [3, 7];
// Ogni ingresso e' un Booleano appena rinfrescato. Quattro contributi restano sotto il
// `max_noise_level=15` del preset A44. Il grafo resta quello A41: il margine maggiore non viene
// usato per cambiare il fan-in in questa copia.
const OR_BLOCK: usize = 4;
const FIRST_ONE_GROUP: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlignedWireFormat {
    SingleCode,
    TwoP16Digits,
    A53Radix15TwoP16Digits,
}

struct AlignedPrivateArgminOutput {
    low_nibble: Lwe,
    high_nibble: Lwe,
    code: Option<Lwe>,
    metrics: PrivateArgminMetrics,
}

fn stage_metrics(started: Instant, pbs_before: u64, pbs_count: &AtomicU64) -> StageMetrics {
    StageMetrics {
        seconds: started.elapsed().as_secs_f64(),
        pbs_count: pbs_count.load(Ordering::Relaxed) - pbs_before,
    }
}

#[cfg(test)]
mod tests;
