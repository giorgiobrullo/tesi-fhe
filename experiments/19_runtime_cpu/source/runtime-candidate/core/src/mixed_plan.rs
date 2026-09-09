//! Public dispatch preserves the uniform parent and selects a common domain for mixed thresholds.
use crate::general::{self, ThresholdMode};
use crate::private_argmin::{self, ScoreDomain, TemplateView};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Uniform(ThresholdMode),
    MixedWinnerThreshold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub cauchy_domain: ScoreDomain,
    pub execution_domain: ScoreDomain,
    pub aligned_fast_path: bool,
    pub threshold: Option<i64>,
    pub mode: ExecutionMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ThresholdPayload {
    pub digits: [u64; 3],
    pub below_domain: bool,
}

pub(super) fn threshold_payload(threshold: i64, domain: ScoreDomain) -> Result<ThresholdPayload, String> {
    if !domain.checked_width().is_some_and(|width| (1..=4096).contains(&width)) {
        return Err("mixed threshold requires a valid twelve-bit score domain".into());
    }
    let clamped = threshold.clamp(domain.lower, domain.upper);
    let normalized = i128::from(clamped) - i128::from(domain.lower);
    let normalized = u64::try_from(normalized).map_err(|_| "mixed threshold normalization failed")?;
    if normalized > 4095 {
        return Err("mixed threshold exceeds three nibbles".into());
    }
    Ok(ThresholdPayload {
        digits: [normalized >> 8, (normalized >> 4) & 15, normalized & 15],
        below_domain: threshold < domain.lower,
    })
}

pub(super) fn plan(templates: &[TemplateView<'_>]) -> Result<ExecutionPlan, String> {
    let original = private_argmin::plan_private_argmin_execution_with_limit(templates, general::MAX_GALLERY_SIZE)
        .map_err(|error| format!("mixed execution plan: {error:?}"))?;
    // The inherited planner has already validated nonempty size, templates, norms and domain width.
    let threshold = templates[0].threshold;
    if templates.iter().all(|entry| entry.threshold == threshold) {
        let uniform = general::plan(templates)?;
        return Ok(ExecutionPlan {
            cauchy_domain: uniform.cauchy_domain,
            execution_domain: uniform.execution_domain,
            aligned_fast_path: uniform.aligned_fast_path,
            threshold: Some(uniform.threshold),
            mode: ExecutionMode::Uniform(uniform.mode),
        });
    }
    Ok(ExecutionPlan {
        cauchy_domain: original.cauchy_domain,
        execution_domain: original.cauchy_domain,
        aligned_fast_path: false,
        threshold: None,
        mode: ExecutionMode::MixedWinnerThreshold,
    })
}
