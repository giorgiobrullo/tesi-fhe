//! General uniform-threshold admission around the unchanged five-payload prefix.
//! Same public packed/planner/domain guards as the passed service; no fixed T or lower bound.
use super::*;
use crate::private_argmin::{PrivateArgminExecutionPlan, PfksBridgeOutput, ScoreDomain, TemplateView};

pub(super) fn plan(templates: &[TemplateView<'_>]) -> Result<PrivateArgminExecutionPlan, String> {
    if templates.len() != 127 {
        return Err("PFKS circuit requires 127 candidates".into());
    }
    let plan = private_argmin::plan_private_argmin_execution(templates)
        .map_err(|error| format!("PFKS execution plan: {error:?}"))?;
    if !plan.aligned_fast_path {
        return Err("PFKS requires the planner's aligned uniform-threshold domain".into());
    }
    Ok(plan)
}

