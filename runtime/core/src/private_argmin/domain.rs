//! Public score bounds, deterministic execution planning and clear result semantics.
use super::contracts::*;

pub(super) const ALIGNED_UNIFORM_THRESHOLD: i64 = 1023;

fn ceil_sqrt(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut lower = 1u64;
    let mut upper = value.min(1u64 << 32);
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let quotient_ceiling = value / middle + u64::from(!value.is_multiple_of(middle));
        if middle >= quotient_ceiling {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    lower
}

pub(super) fn template_score_bounds(norm2: i64) -> Option<(i64, i64)> {
    let product = u64::try_from(norm2)
        .ok()?
        .checked_mul(PROBE_NORM2_MAX as u64)?;
    let radius = i64::try_from(ceil_sqrt(product)).ok()?.checked_mul(2)?;
    Some((norm2.checked_sub(radius)?, norm2.checked_add(radius)?))
}

pub fn cauchy_score_domain(
    templates: &[TemplateView<'_>],
) -> Result<ScoreDomain, PrivateArgminError> {
    cauchy_score_domain_with_limit(templates, MAX_GALLERY_SIZE)
}

pub(crate) fn cauchy_score_domain_with_limit(
    templates: &[TemplateView<'_>],
    maximum: usize,
) -> Result<ScoreDomain, PrivateArgminError> {
    validate_gallery_size_with_limit(templates.len(), maximum)?;
    let mut lower = i64::MAX;
    let mut upper = i64::MIN;
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
        let (entry_lower, entry_upper) = template_score_bounds(entry.norm2)
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
        lower = lower.min(entry_lower);
        upper = upper.max(entry_upper);
    }
    let domain = ScoreDomain { lower, upper };
    validate_domain(domain)?;
    Ok(domain)
}

/// Valida la galleria e sceglie un dominio di esecuzione compatibile col dispatch stretto
/// allineato.
///
/// Il percorso allineato e' disponibile soltanto per gallerie non vuote con una soglia uniforme
/// `T`. In quel caso prova `lower = T - 1023`, senza mai restringere il dominio di Cauchy: il
/// candidato deve coprirne il limite inferiore e l'intervallo `[lower, cauchy.upper]` deve restare
/// rappresentabile nei dodici bit del core. Overflow, mancata copertura o eccessiva larghezza non
/// sono errori: selezionano deterministicamente il fallback generale sul dominio stretto.
pub fn plan_private_argmin_execution(
    templates: &[TemplateView<'_>],
) -> Result<PrivateArgminExecutionPlan, PrivateArgminError> {
    plan_private_argmin_execution_with_limit(templates, MAX_GALLERY_SIZE)
}

pub(crate) fn plan_private_argmin_execution_with_limit(
    templates: &[TemplateView<'_>],
    maximum: usize,
) -> Result<PrivateArgminExecutionPlan, PrivateArgminError> {
    let cauchy_domain = cauchy_score_domain_with_limit(templates, maximum)?;
    let uniform_threshold = templates
        .first()
        .map(|entry| entry.threshold)
        .filter(|threshold| templates.iter().all(|entry| entry.threshold == *threshold));

    if let Some(lower) =
        uniform_threshold.and_then(|threshold| threshold.checked_sub(ALIGNED_UNIFORM_THRESHOLD))
    {
        let execution_domain = ScoreDomain {
            lower,
            upper: cauchy_domain.upper,
        };
        if lower <= cauchy_domain.lower
            && execution_domain
                .checked_width()
                .is_some_and(|width| (1..=MAX_DOMAIN_WIDTH).contains(&width))
        {
            return Ok(PrivateArgminExecutionPlan {
                cauchy_domain,
                execution_domain,
                aligned_fast_path: true,
            });
        }
    }

    Ok(PrivateArgminExecutionPlan {
        cauchy_domain,
        execution_domain: cauchy_domain,
        aligned_fast_path: false,
    })
}

pub fn clear_private_argmin(
    scores: &[i64],
    templates: &[TemplateView<'_>],
) -> Result<ClearPrivateArgminResult, PrivateArgminError> {
    validate_gallery_size(templates.len())?;
    if scores.len() != templates.len() {
        return Err(PrivateArgminError::ScoreLengthMismatch {
            scores: scores.len(),
            templates: templates.len(),
        });
    }
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
    }
    let winner_index = scores
        .iter()
        .enumerate()
        .min_by_key(|(index, score)| (**score, *index))
        .map(|(index, _)| index)
        .expect("galleria validata non vuota");
    let matched = scores[winner_index] <= templates[winner_index].threshold;
    Ok(ClearPrivateArgminResult {
        winner_index,
        matched,
        code: if matched { winner_index as u64 + 1 } else { 0 },
    })
}

pub(super) fn aligned_uniform_fast_path_for_thresholds(
    thresholds: &[i64],
    domain: ScoreDomain,
) -> bool {
    let Some(&threshold) = thresholds.first() else {
        return false;
    };
    thresholds.iter().all(|&candidate| candidate == threshold)
        && threshold.checked_sub(domain.lower) == Some(ALIGNED_UNIFORM_THRESHOLD)
}

pub(super) fn validate_gallery_size(size: usize) -> Result<(), PrivateArgminError> {
    validate_gallery_size_with_limit(size, MAX_GALLERY_SIZE)
}

pub(super) fn validate_gallery_size_with_limit(
    size: usize,
    maximum: usize,
) -> Result<(), PrivateArgminError> {
    if size == 0 {
        return Err(PrivateArgminError::EmptyGallery);
    }
    if size > maximum {
        return Err(PrivateArgminError::GalleryTooLarge {
            actual: size,
            maximum,
        });
    }
    Ok(())
}

pub(super) fn validate_template(
    index: usize,
    entry: &TemplateView<'_>,
) -> Result<(), PrivateArgminError> {
    if entry.template.len() != PROBE_DIM {
        return Err(PrivateArgminError::InvalidTemplateDimension {
            index,
            actual: entry.template.len(),
        });
    }
    let mut actual = 0i64;
    for (coordinate, value) in entry.template.iter().copied().enumerate() {
        if !(-3..=3).contains(&value) {
            return Err(PrivateArgminError::InvalidTemplateCoordinate {
                index,
                coordinate,
                value,
            });
        }
        actual = actual
            .checked_add(
                value
                    .checked_mul(value)
                    .ok_or(PrivateArgminError::TemplateNormOverflow { index })?,
            )
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
    }
    if actual != entry.norm2 {
        return Err(PrivateArgminError::IncorrectTemplateNorm {
            index,
            declared: entry.norm2,
            actual,
        });
    }
    Ok(())
}

pub(super) fn validate_domain(domain: ScoreDomain) -> Result<(), PrivateArgminError> {
    if domain.lower > domain.upper {
        return Err(PrivateArgminError::InvalidDomain {
            lower: domain.lower,
            upper: domain.upper,
        });
    }
    let width = domain
        .checked_width()
        .ok_or(PrivateArgminError::InvalidDomain {
            lower: domain.lower,
            upper: domain.upper,
        })?;
    if width > MAX_DOMAIN_WIDTH {
        return Err(PrivateArgminError::DomainTooWide {
            width,
            maximum: MAX_DOMAIN_WIDTH,
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/domain.rs"]
mod tests;
