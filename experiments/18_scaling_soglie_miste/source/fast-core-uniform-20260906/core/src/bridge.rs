// Included in the frozen core module to reuse its existing extraction helpers.
// This is the A30 B0 consumer: low-to-full b0..b3 and clipped A34 top mapper.
pub struct PfksBridgeOutput {
    pub tuples: Vec<[Lwe; 5]>,
    pub score_pairs: Vec<(Lwe, Lwe)>,
    pub blind_rotations: u64,
    pub key_switches_structural: u64,
    pub output_marginals_structural: u64,
}

fn pfks_top_lut(code: u64) -> u64 {
    match code {
        2 => 0,
        0 => 1,
        7 => 2,
        3 => 3,
        1 | 4 | 5 | 6 | 8 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod pfks_bridge_tests {
    use super::*;

    #[test]
    fn clipped_top_mapper_accepts_actual_a34_codes() {
        for h in 0u64..16 {
            let raw = a34_top_classifier_slot_lut(2 * (h % 8));
            let signed = if h < 8 { raw } else { raw.wrapping_neg() };
            let code = signed.wrapping_add(4) & 31;
            assert_eq!(pfks_top_lut(code), h.min(4));
        }
    }
}

pub fn pfks_score_bridge(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PfksBridgeOutput, PrivateArgminError> {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, server_key)?;
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<_> = templates.iter().map(|t| t.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    let key_switching_key = &server_key.key_switching_key;
    let bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    let polynomial_size = bsk.polynomial_size();
    assert_eq!(polynomial_size.0, 2048);
    let glwe_size = bsk.glwe_size();
    let big_size = bsk.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let pbs_count = AtomicU64::new(0);
    let make_accumulators = |delta_log: u32, count: u32, fused: std::ops::Range<u32>| {
        (0..count).map(|bit| {
            let alpha = 1u64 << (delta_log + bit - 1);
            let with_boolean = fused.contains(&bit);
            let body = if with_boolean {
                fused_correction_accumulator_body(polynomial_size, alpha, bool_delta >> 1)
            } else {
                vec![alpha.wrapping_neg(); polynomial_size.0]
            };
            let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size, &PlaintextList::from_container(body), modulus,
            );
            if with_boolean { CorrectionAccumulator::WithBoolean(accumulator) }
            else { CorrectionAccumulator::Single(accumulator) }
        }).collect::<Vec<_>>()
    };
    let low_accumulators = make_accumulators(LOW_MOD16_DELTA_LOG, 3, 0..0);
    let low_to_full_accumulators = make_accumulators(FULL_DELTA_LOG, 4, 0..4);
    let high_accumulators = make_accumulators(HIGH_DELTA_LOG, 4, 0..3);
    let classifier = generate_programmable_bootstrap_glwe_lut(
        polynomial_size, glwe_size, 16, modulus, bool_delta, a34_top_classifier_slot_lut,
    );
    let top_mapper = generate_programmable_bootstrap_glwe_lut(
        polynomial_size, glwe_size, 16, modulus, bool_delta, pfks_top_lut,
    );
    let apply_pbs = |input: &Lwe, accumulator: &Glwe| {
        let mut small = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut small);
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(&small, &mut output, accumulator, bsk);
        pbs_count.fetch_add(1, Ordering::Relaxed);
        output
    };
    let mut tuples = Vec::with_capacity(templates.len());
    let mut score_pairs = Vec::with_capacity(templates.len());
    let mut key_switches_structural = 0;
    let mut output_marginals_structural = 0;
    for (index, entry) in templates.iter().enumerate() {
        let mut polynomial = vec![0u64; polynomial_size.0];
        for coordinate in 0..PROBE_DIM {
            polynomial[PROBE_DIM - 1 - coordinate] = (-2 * entry.template[coordinate]) as u64;
        }
        let polynomial = Polynomial::from_container(polynomial);
        let mut product = GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
        for (mut output, input) in product.as_mut_polynomial_list().iter_mut()
            .zip(packed_probe.as_polynomial_list().iter()) {
            polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
        }
        let extract_score = |degree, delta: u64| {
            let mut score = LweCiphertext::new(0u64, big_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&product, &mut score, MonomialDegree(degree));
            lwe_ciphertext_plaintext_add_assign(&mut score,
                Plaintext(((entry.norm2 - domain.lower) as u64).wrapping_mul(delta)));
            score
        };
        let full = extract_score(PROBE_DIM - 1, 1u64 << FULL_DELTA_LOG);
        let low = extract_score(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM - 1, 1u64 << LOW_MOD16_DELTA_LOG);
        let low_bits = extract_bits_with_corrections(&low, bsk, key_switching_key,
            &low_accumulators, LOW_MOD16_DELTA_LOG, 4, &pbs_count);
        let low_to_full: Vec<_> = (0..4).map(|bit| {
            correction_from_small_bit(&low_bits.small_lsb_first[bit],
                &low_to_full_accumulators[bit], bsk, big_size,
                1u64 << (FULL_DELTA_LOG + bit as u32 - 1), &pbs_count)
        }).collect();
        let mut high_input = full.clone();
        for bit in &low_to_full { lwe_ciphertext_sub_assign(&mut high_input, &bit.correction); }
        let high_bits = extract_bits_with_all_corrections(&high_input, bsk,
            key_switching_key, &high_accumulators, HIGH_DELTA_LOG, 4, &pbs_count);
        let mut residual = high_input.clone();
        for correction in &high_bits.corrections_lsb_first {
            lwe_ciphertext_sub_assign(&mut residual, correction);
        }
        let mut code = apply_pbs(&residual, &classifier);
        lwe_ciphertext_plaintext_add_assign(&mut code, Plaintext(4 * bool_delta));
        let top = apply_pbs(&code, &top_mapper);
        let mut low_limb = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0), modulus);
        let mut middle_limb = low_limb.clone();
        for bit in 0..4 {
            let mut low_bit = low_to_full[bit].boolean.as_ref().expect("B0 b0..b3 ManyLUT").clone();
            let mut high_bit = if bit == 3 {
                high_bits.corrections_lsb_first[3].clone()
            } else {
                high_bits.canonical_bits_lsb_first[bit].as_ref().expect("B0 b4..b6 ManyLUT").clone()
            };
            lwe_ciphertext_cleartext_mul_assign(&mut low_bit, Cleartext(1u64 << bit));
            lwe_ciphertext_cleartext_mul_assign(&mut high_bit, Cleartext(1u64 << bit));
            lwe_ciphertext_add_assign(&mut low_limb, &low_bit);
            lwe_ciphertext_add_assign(&mut middle_limb, &high_bit);
        }
        // The public candidate index is carried directly in the final base15 output units.
        let identity = (index + 1) as u64;
        let id_low = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size,
            Plaintext((identity % 15) * bool_delta), modulus);
        let id_high = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size,
            Plaintext((identity / 15) * bool_delta), modulus);
        key_switches_structural += low_bits.small_lsb_first.len() as u64
            + high_bits.small_lsb_first.len() as u64 + 2;
        output_marginals_structural += low_bits.corrections_lsb_first.len() as u64
            + low_to_full.iter().map(|b| 1 + u64::from(b.boolean.is_some())).sum::<u64>()
            + high_bits.corrections_lsb_first.len() as u64
            + high_bits.canonical_bits_lsb_first.iter().filter(|b| b.is_some()).count() as u64 + 2;
        tuples.push([top, middle_limb, low_limb, id_low, id_high]);
        score_pairs.push((full, low));
    }
    Ok(PfksBridgeOutput { tuples, score_pairs,
        blind_rotations: pbs_count.load(Ordering::Relaxed),
        key_switches_structural, output_marginals_structural })
}
