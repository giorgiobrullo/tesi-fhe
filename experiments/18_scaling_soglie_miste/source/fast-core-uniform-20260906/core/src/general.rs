//! Uniform thresholds over an admitted twelve-bit domain, retaining aligned plans exactly.
use crate::private_argmin::{self, ScoreDomain, TemplateView};

pub const MAX_GALLERY_SIZE: usize = 15 * 15 - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdMode {
    AllReject,
    CompareSentinel { score: u16 },
    AllAccept,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniformExecutionPlan {
    pub cauchy_domain: ScoreDomain,
    pub execution_domain: ScoreDomain,
    pub aligned_fast_path: bool,
    pub threshold: i64,
    pub mode: ThresholdMode,
}

/// Select a terminal operation only after establishing a valid score domain.
pub(super) fn mode_for_domain(threshold: i64, domain: ScoreDomain) -> Result<ThresholdMode, String> {
    if !domain.checked_width().is_some_and(|width| (1..=4096).contains(&width)) {
        return Err("Head uniform domain must contain 1..4096 integer scores".into());
    }
    if threshold < domain.lower {
        return Ok(ThresholdMode::AllReject);
    }
    if threshold >= domain.upper {
        return Ok(ThresholdMode::AllAccept);
    }
    // Public branches precede arithmetic, including at both signed threshold extremes.
    let score = i128::from(threshold) - i128::from(domain.lower) + 1;
    let score = u16::try_from(score).map_err(|_| "Head sentinel score conversion failed")?;
    if !(1..=4095).contains(&score) {
        return Err("Head sentinel score must fit three nibbles".into());
    }
    Ok(ThresholdMode::CompareSentinel { score })
}

pub(super) fn sentinel_payload(mode: ThresholdMode) -> Option<[u64; 5]> {
    match mode {
        ThresholdMode::CompareSentinel { score } if (1..=4095).contains(&score) => {
            let score = u64::from(score);
            Some([score >> 8, (score >> 4) & 15, score & 15, 0, 0])
        }
        _ => None,
    }
}

pub(super) fn plan(templates: &[TemplateView<'_>]) -> Result<UniformExecutionPlan, String> {
    let plan = private_argmin::plan_private_argmin_execution_with_limit(templates, MAX_GALLERY_SIZE)
        .map_err(|error| format!("Head uniform execution plan: {error:?}"))?;
    // The existing planner has already rejected an empty or invalid gallery.
    let threshold = templates[0].threshold;
    if templates.iter().any(|entry| entry.threshold != threshold) {
        return Err("Head uniform core requires the same public threshold for every template".into());
    }
    let mode = if plan.aligned_fast_path {
        // Preserve old body offsets and terminal words, even when a public shortcut is possible.
        ThresholdMode::CompareSentinel { score: 1024 }
    } else {
        mode_for_domain(threshold, plan.execution_domain)?
    };
    Ok(UniformExecutionPlan {
        cauchy_domain: plan.cauchy_domain,
        execution_domain: plan.execution_domain,
        aligned_fast_path: plan.aligned_fast_path,
        threshold,
        mode,
    })
}
