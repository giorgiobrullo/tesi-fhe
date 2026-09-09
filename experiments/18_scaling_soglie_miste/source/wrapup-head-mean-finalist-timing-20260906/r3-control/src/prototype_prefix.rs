pub fn prototype_score_prefix(
    server_key: &ServerKey, packed_probe: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain,
) -> Result<(Vec<Lwe>, Vec<Lwe>), PrivateArgminError> {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, server_key)?;
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let (_, bsk, _, _) = standard_server_key_parts(server_key)?;
    let polynomial_size = bsk.polynomial_size();
    let glwe_size = bsk.glwe_size();
    let modulus = CiphertextModulus::new_native();
    let big_size = bsk.output_lwe_dimension().to_lwe_size();
    let full_delta = 1u64 << 51;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let score_pairs: Vec<(Lwe, Lwe)> = templates
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
            let mut full = extract_score(PROBE_DIM - 1, full_delta);
            // Public prototype-wire adapter. Do not multiply the GLWE or its low60 view.
            lwe_ciphertext_cleartext_mul_assign(&mut full, Cleartext(2));
            (full, extract_score(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM - 1, low_delta))
        })
        .collect();
    Ok(score_pairs.into_iter().unzip())
}
