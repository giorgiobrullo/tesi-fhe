//! Shared argmin contracts and the selected packed score prefix.
//!
//! Domain planning, key/probe validation and score construction have independent modules.
//! Earlier complete argmin circuits remain in `legacy` for reproduction; this facade preserves
//! their existing internal entry points without making the current prefix depend on them.
mod contracts;
mod domain;
mod input;
mod legacy;
mod parameters;
mod score;

pub use contracts::*;
pub use domain::{cauchy_score_domain, clear_private_argmin, plan_private_argmin_execution};
pub(crate) use domain::{cauchy_score_domain_with_limit, plan_private_argmin_execution_with_limit};
pub use legacy::*;
pub use parameters::{
    a44_parameter_fingerprint_sha256, validate_a44_parameter_binding,
    validate_a44_parameter_binding_text,
};
pub use score::head_pfks_score_prefix;
pub(crate) use score::head_pfks_score_prefix_with_parallel;

#[cfg(test)]
mod test_support;
