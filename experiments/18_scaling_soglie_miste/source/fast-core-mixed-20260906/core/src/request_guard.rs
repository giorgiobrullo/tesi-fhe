// Key-free admission is called before the first cryptographic operation.
use super::*;

pub fn validate(packed: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain) -> Result<(), String> {
    if packed.as_ref().len() != 4096
        || packed.polynomial_size().0 != 2048
        || packed.glwe_size().0 != 2
        || !packed.ciphertext_modulus().is_native_modulus()
    {
        return Err("packed query geometry or modulus differs from the fixed profile".into());
    }
    let plan = crate::mixed_plan::plan(templates)?;
    if plan.execution_domain != domain {
        return Err("PFKS and service execution domains differ".into());
    }
    Ok(())
}

