//! Public metadata and evaluation for the one frozen uniform/mixed fast library.
pub use pfks_core::service::Counts;
use pfks_core::service::{self, EvaluationKeys, ExecutionMode, TemplateView, ThresholdMode};
use tfhe::core_crypto::prelude::{GlweCiphertextOwned, LweCiphertextOwned};

use crate::profile::QueryProfile;

pub fn endpoint_name(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::Uniform(_) => "head_mean_uniform_parallel",
        ExecutionMode::MixedWinnerThreshold => "head_mean_mixed_parallel",
    }
}

pub fn path_name(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::Uniform(_) => "fast_uniform",
        ExecutionMode::MixedWinnerThreshold => "fast_mixed_winner_threshold",
    }
}

pub fn mode_name(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::Uniform(ThresholdMode::CompareSentinel { .. }) => "uniform_sentinel",
        ExecutionMode::Uniform(ThresholdMode::AllAccept) => "uniform_all_accept",
        ExecutionMode::Uniform(ThresholdMode::AllReject) => "uniform_all_reject",
        ExecutionMode::MixedWinnerThreshold => "mixed_winner_threshold",
    }
}

pub fn sentinel_score(mode: ExecutionMode) -> Option<u16> {
    match mode {
        ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score }) => Some(score),
        _ => None,
    }
}

/// Structural work only: no gallery or runtime execution mode is inferred by this CLI route.
pub fn mode_from_cli(name: &str, sentinel: Option<&str>) -> Result<ExecutionMode, String> {
    if name == "uniform_sentinel" {
        let score: u16 = sentinel
            .ok_or("uniform_sentinel requires its explicit normalized score")?
            .parse()
            .map_err(|_| "normalized sentinel must be an integer in 1..4095")?;
        if !(1..=4095).contains(&score) {
            return Err("normalized sentinel must be an integer in 1..4095".into());
        }
        return Ok(ExecutionMode::Uniform(ThresholdMode::CompareSentinel {
            score,
        }));
    }
    if sentinel.is_some() {
        return Err("a normalized sentinel is only valid for uniform_sentinel".into());
    }
    match name {
        "uniform_all_accept" => Ok(ExecutionMode::Uniform(ThresholdMode::AllAccept)),
        "uniform_all_reject" => Ok(ExecutionMode::Uniform(ThresholdMode::AllReject)),
        "mixed_winner_threshold" => Ok(ExecutionMode::MixedWinnerThreshold),
        _ => Err("explicit uniform or mixed execution mode required".into()),
    }
}

pub fn evaluate(
    server: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[TemplateView<'_>],
    profile: QueryProfile,
) -> Result<
    (
        LweCiphertextOwned<u64>,
        LweCiphertextOwned<u64>,
        LweCiphertextOwned<u64>,
        Counts,
    ),
    String,
> {
    profile.validate_gallery(templates.len())?;
    let plan = service::plan(templates)?;
    crate::runtime::begin_query();
    let expected = pfks_core::public_digits::operation_counts(templates)?;
    let (low, middle, high, counts) = server.evaluate_public_thresholds(packed, templates, plan.execution_domain, true)?;
    if counts != expected {
        return Err("actual fast-core operation ledger differs from the derived plan".into());
    }
    Ok((low, middle, high, counts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_modes_are_explicit_and_never_guess_a_gallery() {
        for name in [
            "uniform_all_accept",
            "uniform_all_reject",
            "mixed_winner_threshold",
        ] {
            let mode = mode_from_cli(name, None).unwrap();
            assert_eq!(mode_name(mode), name);
            assert_eq!(sentinel_score(mode), None);
            assert!(mode_from_cli(name, Some("1024")).is_err());
        }
        for score in [1, 1024, 4095] {
            let text = score.to_string();
            let mode = mode_from_cli("uniform_sentinel", Some(&text)).unwrap();
            assert_eq!(sentinel_score(mode), Some(score));
            assert_eq!(mode_name(mode), "uniform_sentinel");
        }
        for value in [None, Some("0"), Some("4096"), Some("-1"), Some("x")] {
            assert!(mode_from_cli("uniform_sentinel", value).is_err());
        }
        for name in ["", "a126", "auto", "uniform", "sentinel"] {
            assert!(mode_from_cli(name, None).is_err());
        }
    }
}
