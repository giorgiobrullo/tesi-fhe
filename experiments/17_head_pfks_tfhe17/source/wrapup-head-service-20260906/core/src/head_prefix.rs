// Exact full51 branch of the passed packed Delta51/60 prefix; unused low60 extraction omitted.
pub fn head_pfks_score_prefix(
    server_key: &ServerKey, packed_probe: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain,
) -> Result<Vec<Lwe>, PrivateArgminError> {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, server_key)?;
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
    };
    let polynomial_size = bsk.polynomial_size();
    let glwe_size = bsk.glwe_size();
    let modulus = CiphertextModulus::new_native();
    let big_size = bsk.output_lwe_dimension().to_lwe_size();
    let full_delta = 1u64 << 51;
    let full_scores: Vec<Lwe> = templates
        .par_iter()
        .map(|entry| {
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
            let extract_score = |degree: usize, delta: u64| {
                let mut score = LweCiphertext::new(0u64, big_size, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &product,
                    &mut score,
                    MonomialDegree(degree),
                );
                lwe_ciphertext_plaintext_add_assign(
                    &mut score,
                    Plaintext(((entry.norm2 - domain.lower) as u64).wrapping_mul(delta)),
                );
                score
            };
            extract_score(PROBE_DIM - 1, full_delta)
        })
        .collect();
    Ok(full_scores)
}
