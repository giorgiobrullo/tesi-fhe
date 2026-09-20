//! Compile-time service selection. Global prototype flags change only at serialized boundaries.
use pfks_core::composite::{self, Mode};
use serde_json::{json, Value};

pub const SOURCE_SHA256: &str = include_str!("../../service-source.sha256");
pub const CORE_SOURCE_SHA256: &str = include_str!("../../core-source.sha256");
pub const MODE_NAME: &str = include_str!("../../runtime-mode.txt");

pub fn mode() -> Mode {
    let mode = Mode::parse(MODE_NAME).expect("compiled service mode");
    assert!(
        mode == Mode::PublicParallel,
        "the repaired service supports only ordinary public_parallel"
    );
    mode
}

pub fn initialize() {
    // Key generation, upload and metadata must work before supplemental keys exist.
    // G4 is explicitly unsupported for the refreshed selector.
    composite::begin_query(Mode::PublicParallel, false);
    assert!(matches!(
        mode(),
        Mode::PublicParallel
    ));
}

pub fn begin_query() {
    composite::begin_query(mode(), false);
}

pub fn metadata() -> Value {
    json!({
        "mode": MODE_NAME, "service_source_sha256": SOURCE_SHA256,
        "core_source_sha256": CORE_SOURCE_SHA256, "rayon_threads": 16,
        "fft_plan_policy": FFT_PLAN_POLICY,
        "compiler_profile": "opt3-cgu1-no-lto-generic-no-pgo",
        "runtime_features": pfks_core::runtime_features(),
        "query_admission": "one_synchronous_query_per_process",
        "shared_normalizers": "both", "classic_comparators": "parallel3_cutoff4",
        "id_cuts": "both", "public_thresholds": true, "public_digits": "repack",
        "selector_parallel": true, "g4": mode().uses_g4(), "detector_only_alignment": true,
    })
}

use crate::keys::PARAMS;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};

pub(crate) const FFT_PLAN_POLICY: &str = "user-provided-dif4-polynomial2048-base1024-v1";

fn install_fixed_fft_plan() -> String {
    assert_eq!(PARAMS.polynomial_size.0, 2048);
    let plan = Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    );
    let description = format!("{plan:?}");
    setup_custom_fft_plan(plan);
    description
}

pub(crate) fn initialize_process() -> Result<(), String> {
    // Install the qualified numerical policy before any key generation or loading.
    let fft_plan = install_fixed_fft_plan();
    let threads = std::env::var("RAYON_NUM_THREADS")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "RAYON_NUM_THREADS must be an integer".to_string())
        })
        .unwrap_or(Ok(16))?;
    if threads != 16 {
        return Err("this service is qualified for exactly 16 Rayon threads".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .map_err(|error| format!("initialize the service thread pool: {error}"))?;
    eprintln!("runtime: threads={threads} fft_policy={FFT_PLAN_POLICY} fft_plan={fft_plan}");
    initialize();
    Ok(())
}
