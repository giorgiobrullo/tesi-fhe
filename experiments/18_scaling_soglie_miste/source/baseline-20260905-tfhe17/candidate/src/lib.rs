pub mod a53_scan;
mod private_argmin;

pub use private_argmin::{
    a34_aligned_operation_counts, a38_aligned_operation_counts, a41_aligned_operation_counts,
    a44_aligned_operation_counts, a44_parameter_fingerprint_sha256, a62_aligned_operation_counts,
    cauchy_score_domain, clear_private_argmin, expected_pbs_count,
    expected_pbs_count_for_thresholds, plan_private_argmin_execution, private_argmin_a62,
    private_argmin_two_lwe_a44, validate_a44_parameter_binding,
    validate_a44_parameter_binding_text, A34OperationCounts, A38OperationCounts,
    A41OperationCounts, A44OperationCounts, A44ParameterBinding, A44PrivateArgminTwoLweOutput,
    A62OperationCounts, A62PrivateArgminOutput, ClearPrivateArgminResult, PrivateArgminError,
    PrivateArgminExecutionPlan, PrivateArgminMetrics, ScoreDomain, StageMetrics, TemplateView,
    A44_PARAMETER_BINDING, A44_PARAMETER_CANONICAL, A44_PARAMETER_FINGERPRINT_SHA256,
    A44_PARAMS_ID, BOOL_DELTA_LOG, CODE_DELTA_LOG, FULL_DELTA_LOG, LOW_MOD16_DELTA_LOG,
    LOW_MOD16_POLYNOMIAL_OFFSET, MAX_DOMAIN_WIDTH, MAX_GALLERY_SIZE, PROBE_DIM, PROBE_NORM2_MAX,
};

#[cfg(feature = "diagnostic-trace")]
pub use private_argmin::{
    private_argmin_a62_with_trace, private_argmin_two_lwe_a44_with_trace, PrivateArgminTrace,
};

#[cfg(feature = "diagnostic-trace")]
pub use private_argmin::private_argmin_a126_with_trace;
pub use private_argmin::{a126_aligned_operation_counts, private_argmin_a126};
