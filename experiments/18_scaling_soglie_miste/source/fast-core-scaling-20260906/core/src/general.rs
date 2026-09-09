//! General uniform-threshold admission around the unchanged five-payload prefix.
//! Same public packed/planner/domain guards as the passed service; no fixed T or lower bound.
use crate::private_argmin::{self, PrivateArgminExecutionPlan, TemplateView};

pub const MAX_GALLERY_SIZE: usize = 15 * 15 - 1;

pub(super) fn plan(templates: &[TemplateView<'_>]) -> Result<PrivateArgminExecutionPlan, String> {
    let plan = private_argmin::plan_private_argmin_execution_with_limit(templates, MAX_GALLERY_SIZE)
        .map_err(|error| format!("PFKS execution plan: {error:?}"))?;
    if !plan.aligned_fast_path {
        return Err("PFKS requires the planner's aligned uniform-threshold domain".into());
    }
    Ok(plan)
}

