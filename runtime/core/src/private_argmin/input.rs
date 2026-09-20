//! Encrypted probe shape and public gallery admission checks.
use super::contracts::*;
use super::domain::{
    template_score_bounds, validate_domain, validate_gallery_size_with_limit, validate_template,
};
use crate::compat::{ServerKey, ShortintBootstrappingKey};

pub(super) fn validate_inputs(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(), PrivateArgminError> {
    validate_inputs_with_limit(
        server_key,
        packed_probe,
        templates,
        domain,
        MAX_GALLERY_SIZE,
    )
}

pub(super) fn validate_inputs_with_limit(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    maximum: usize,
) -> Result<(), PrivateArgminError> {
    validate_gallery_size_with_limit(templates.len(), maximum)?;
    validate_domain(domain)?;
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
        let (required_lower, required_upper) = template_score_bounds(entry.norm2)
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
        if domain.lower > required_lower || domain.upper < required_upper {
            return Err(PrivateArgminError::DomainDoesNotCoverTemplate {
                index,
                required_lower,
                required_upper,
            });
        }
    }
    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    if !packed_probe.ciphertext_modulus().is_native_modulus()
        || packed_probe.ciphertext_modulus() != server_key.ciphertext_modulus
        || packed_probe.ciphertext_modulus() != server_key.key_switching_key.ciphertext_modulus()
    {
        return Err(PrivateArgminError::InvalidProbeModulus);
    }
    let polynomial_size = bootstrap_key.polynomial_size();
    let packed_support_end = LOW_MOD16_POLYNOMIAL_OFFSET + 2 * PROBE_DIM - 2;
    if packed_probe.polynomial_size() != polynomial_size
        || packed_probe.glwe_size() != bootstrap_key.glwe_size()
        || packed_support_end >= polynomial_size.0
    {
        return Err(PrivateArgminError::InvalidProbeShape);
    }
    Ok(())
}
