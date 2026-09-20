//! Packed full51 score prefix used by the selected Head/PFKS runtime.
use super::contracts::*;
use super::input::validate_inputs_with_limit;
use super::parameters::validate_a44_parameter_binding;
use crate::compat::{ServerKey, ShortintBootstrappingKey};
use rayon::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;

// Exact full51 branch of the passed packed Delta51/60 prefix; unused low60 extraction omitted.
pub fn head_pfks_score_prefix(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<Vec<Lwe>, PrivateArgminError> {
    head_pfks_score_prefix_with_parallel(server_key, packed_probe, templates, domain, true)
}

pub(crate) fn head_pfks_score_prefix_with_parallel(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    parallel: bool,
) -> Result<Vec<Lwe>, PrivateArgminError> {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, server_key)?;
    validate_inputs_with_limit(
        server_key,
        packed_probe,
        templates,
        domain,
        crate::general::MAX_GALLERY_SIZE,
    )?;
    let bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
    };
    let polynomial_size = bsk.polynomial_size();
    let glwe_size = bsk.glwe_size();
    let modulus = CiphertextModulus::new_native();
    let big_size = bsk.output_lwe_dimension().to_lwe_size();
    let full_delta = 1u64 << 51;
    let make_product = |entry: &TemplateView<'_>| {
        let mut polynomial = vec![0u64; polynomial_size.0];
        for coordinate in 0..PROBE_DIM {
            polynomial[PROBE_DIM - 1 - coordinate] = (-2 * entry.template[coordinate]) as u64;
        }
        let polynomial = Polynomial::from_container(polynomial);
        let mut product = GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
        for (mut output, input) in product
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(packed_probe.as_polynomial_list().iter())
        {
            polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
        }
        product
    };
    let anchor = make_product(&templates[0]);
    let produce = |entry: &TemplateView<'_>| {
        let product = if let Some(terms) = crate::score_anchor::differences(&templates[0], entry) {
            crate::score_anchor::from_anchor(packed_probe, &anchor, &terms)
        } else {
            make_product(entry)
        };
        let extract_score = |degree: usize, delta: u64| {
            let mut score = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&product, &mut score, MonomialDegree(degree));
            lwe_ciphertext_plaintext_add_assign(
                &mut score,
                Plaintext(((entry.norm2 - domain.lower) as u64).wrapping_mul(delta)),
            );
            score
        };
        extract_score(PROBE_DIM - 1, full_delta)
    };
    let full_scores = if parallel {
        templates.par_iter().map(produce).collect()
    } else {
        templates.iter().map(produce).collect()
    };
    Ok(full_scores)
}
