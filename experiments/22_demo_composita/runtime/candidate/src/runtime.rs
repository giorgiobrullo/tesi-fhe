//! Compile-time service selection. Global prototype flags change only at serialized boundaries.
use pfks_core::composite::{self, Mode};
use serde_json::{json, Value};

pub const SOURCE_SHA256: &str = include_str!("../../service-source.sha256");
pub const CORE_SOURCE_SHA256: &str = include_str!("../../core-source.sha256");
pub const MODE_NAME: &str = include_str!("../../runtime-mode.txt");

pub fn mode() -> Mode {
    let mode = Mode::parse(MODE_NAME).expect("compiled service mode");
    assert!(mode != Mode::Reference, "the new service requires a selected composite variant");
    mode
}

pub fn initialize() {
    // Key generation, upload and metadata must work before supplemental keys exist.
    // Both service variants have identical public operation counts.
    composite::begin_query(Mode::PublicParallel, false);
    assert!(matches!(mode(), Mode::PublicParallel | Mode::PublicParallelG4));
}

pub fn begin_query() {
    composite::begin_query(mode(), false);
}

pub fn metadata() -> Value {
    json!({
        "mode": MODE_NAME, "service_source_sha256": SOURCE_SHA256,
        "core_source_sha256": CORE_SOURCE_SHA256, "rayon_threads": 16,
        "fft_plan_policy": crate::FFT_PLAN_POLICY,
        "compiler_profile": "opt3-cgu1-no-lto-generic-no-pgo",
        "runtime_features": pfks_core::runtime_features(),
        "query_admission": "one_synchronous_query_per_process",
        "shared_normalizers": "both", "classic_comparators": "parallel3_cutoff4",
        "id_cuts": "both", "public_thresholds": true, "public_digits": "repack",
        "selector_parallel": true, "g4": mode().uses_g4(), "detector_only_alignment": true,
    })
}
