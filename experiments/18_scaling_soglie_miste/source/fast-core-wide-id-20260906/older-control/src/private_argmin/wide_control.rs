//! Explicit wider A126 control. The inherited score/extraction/elimination prefix is retained.
//! Only admission, the three-root scan/output, ledgers and an unused-LUT overflow guard differ.
use super::*;
use crate::a53_scan::wide as wide_scan;
use crate::a53_scan::fhe::wide::materialize_a53_scan_wide;

pub const MAX_GALLERY_SIZE: usize = wide_scan::MAX_GALLERY_SIZE;
pub const ID_BASE: u64 = 15;
pub const ID_DIGITS: usize = 3;
pub const CONTRACT: &str = wide_scan::CONTRACT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuralCounts {
    pub br: u64,
    pub ks: u64,
    pub marginals: u64,
    pub initial_samples: u64,
}

pub struct A126WideOutput {
    pub low_digit: Lwe,
    pub middle_digit: Lwe,
    pub high_digit: Lwe,
    pub metrics: PrivateArgminMetrics,
    pub structural_counts: StructuralCounts,
    pub scan_expected_counts: A53PrimitiveCounts,
    pub scan_observed_counts: A53PrimitiveCounts,
    pub parameter_binding: A44ParameterBinding<'static>,
}

pub fn operation_counts(n: usize) -> Option<StructuralCounts> {
    if n == 0 || n > MAX_GALLERY_SIZE { return None; }
    let scan = wide_scan::scan_counts(n).ok()?.total;
    let reduction = reduction_pbs_forwarding_singletons(n, A50_REDUCTION_RADIX);
    let n = n as u64;
    Some(StructuralCounts {
        br: 24*n + 8*reduction - 1 + scan.blind_rotations,
        ks: 21*n + 8*reduction - 1 + scan.key_switches,
        marginals: 29*n + 8*reduction - 1 + scan.output_marginals,
        initial_samples: 2*n,
    })
}

/// Same aligned-uniform domain rule as frozen A126, with the explicit wider gallery bound.
pub fn plan(templates: &[TemplateView<'_>]) -> Result<PrivateArgminExecutionPlan, PrivateArgminError> {
    let plan = original_plan(templates)?;
    if !plan.aligned_fast_path {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    Ok(plan)
}

/// Keep the previously unused group3 table's release torus words without debug overflow.
fn unused_high_digit(identity: u64) -> u64 {
    (identity / A38_NIBBLE_RADIX) % u64::from(crate::a53_scan::BOOL_OUTPUT_PERIOD)
}

pub fn evaluate(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A126WideOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    evaluate_aligned(server_key, packed_probe, templates, domain,
        AlignedWireFormat::A53Radix15TwoP16Digits, true, None)
}

fn validate_gallery_size(size: usize) -> Result<(), PrivateArgminError> {
    if size == 0 {
        return Err(PrivateArgminError::EmptyGallery);
    }
    if size > MAX_GALLERY_SIZE {
        return Err(PrivateArgminError::GalleryTooLarge {
            actual: size,
            maximum: MAX_GALLERY_SIZE,
        });
    }
    Ok(())
}

fn validate_inputs(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(), PrivateArgminError> {
    validate_gallery_size(templates.len())?;
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
    let (key_switching_key, bootstrap_key, _, _) = standard_server_key_parts(server_key)?;
    if !packed_probe.ciphertext_modulus().is_native_modulus()
        || packed_probe.ciphertext_modulus() != server_key.ciphertext_modulus
        || packed_probe.ciphertext_modulus() != key_switching_key.ciphertext_modulus()
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

pub fn cauchy_score_domain(
    templates: &[TemplateView<'_>],
) -> Result<ScoreDomain, PrivateArgminError> {
    validate_gallery_size(templates.len())?;
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

fn original_plan(
    templates: &[TemplateView<'_>],
) -> Result<PrivateArgminExecutionPlan, PrivateArgminError> {
    let cauchy_domain = cauchy_score_domain(templates)?;
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

fn evaluate_aligned(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    wire_format: AlignedWireFormat,
    fuse_refresh: bool,
    mut trace: Option<&mut PrivateArgminTrace>,
) -> Result<A126WideOutput, PrivateArgminError> {
    debug_assert!(templates
        .iter()
        .all(|entry| entry.threshold == templates[0].threshold));
    debug_assert_eq!(
        templates[0].threshold.checked_sub(domain.lower),
        Some(ALIGNED_UNIFORM_THRESHOLD)
    );
    let total_started = Instant::now();
    let pbs_count = AtomicU64::new(0);
    let n = templates.len();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let (key_switching_key, fourier_bootstrap_key, modulus_switch_configuration, _) =
        standard_server_key_parts(server_key)?;
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    assert_eq!(polynomial_size.0 % PBS_MESSAGE_MODULUS, 0);
    assert_eq!(
        polynomial_size.0, 2048,
        "il layout raw A36 e' auditato per Npoly=2048"
    );
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let bit_positions: Vec<u32> = (0..=ALIGNED_SELECTION_HIGH_BIT).rev().collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.aligned_fast_path = true;
        trace.bit_positions_msb_first = bit_positions.clone();
    }

    let setup_started = Instant::now();
    let setup_pbs = pbs_count.load(Ordering::Relaxed);
    let make_correction_accumulator = |alpha: u64, with_boolean: bool| {
        let plaintexts = if with_boolean {
            fused_correction_accumulator_body(polynomial_size, alpha, bool_delta >> 1)
        } else {
            vec![alpha.wrapping_neg(); polynomial_size.0]
        };
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(plaintexts),
            modulus,
        );
        if with_boolean {
            CorrectionAccumulator::WithBoolean(accumulator)
        } else {
            CorrectionAccumulator::Single(accumulator)
        }
    };
    let make_correction_accumulators =
        |delta_log: u32, correction_count: u32, fused_bits: std::ops::Range<u32>| {
            (0..correction_count)
                .map(|bit_index| {
                    let alpha = 1u64 << (delta_log + bit_index - 1);
                    make_correction_accumulator(alpha, fused_bits.contains(&bit_index))
                })
                .collect::<Vec<_>>()
        };
    let low_correction_accumulators =
        make_correction_accumulators(LOW_MOD16_DELTA_LOG, LOW_EXTRACTED_BITS - 1, 0..0);
    let low_to_full_correction_accumulators =
        make_correction_accumulators(FULL_DELTA_LOG, LOW_EXTRACTED_BITS, 3..4);
    let high_correction_accumulators =
        make_correction_accumulators(HIGH_DELTA_LOG, A34_HIGH_CORRECTION_BITS, 0..3);
    let bit_weights: Vec<u64> = bit_positions
        .iter()
        .map(|bit_index| extracted_bit_weight(*bit_index))
        .collect();
    assert_eq!(
        bit_weights.as_slice(),
        A38_EXPECTED_SOURCE_WEIGHTS.as_slice()
    );
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_weights_msb_first = bit_weights.clone();
    }
    let a34_top_classifier_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        A34_TOP_CLASSIFIER_MODULUS,
        modulus,
        bool_delta,
        a34_top_classifier_slot_lut,
    );
    let a34_canonical_category_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_canonical_category_lut,
    );
    let a34_pair_category_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_pair_category_lut,
    );
    let a34_top_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_top_candidate_lut,
    );

    // A36 usa corpi raw p=16: gli stati vivi valgono 2 a Delta_bool. Il plateau OR radix-5
    // copre i soli centri raggiungibili 2,4,6,8,10 e resta a distanza dall'antipodo 18.
    let raw_accumulator = |body: Vec<u64>| {
        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(body),
            modulus,
        )
    };
    let box_size = polynomial_size.0 / PBS_MESSAGE_MODULUS;
    let mut a36_active_step2_body = vec![0u64; polynomial_size.0];
    a36_active_step2_body[box_size..3 * box_size].fill(2 * bool_delta);
    let mut a36_final_boolean_body = vec![0u64; polynomial_size.0];
    a36_final_boolean_body[box_size..3 * box_size].fill(bool_delta);
    let mut a36_radix5_or_body = vec![0u64; polynomial_size.0];
    a36_radix5_or_body[box_size..11 * box_size].fill(2 * bool_delta);
    let a36_active_step2_accumulator = raw_accumulator(a36_active_step2_body);
    let a36_final_boolean_accumulator = raw_accumulator(a36_final_boolean_body);
    let a36_radix5_or_accumulator = raw_accumulator(a36_radix5_or_body);

    // A50, richiesto dagli anchor A53 3390/3009/3930, mantiene invece stati canonici 0/1.
    // Il target-one usa l'intervallo aperto di mezzo slot attorno al centro 1; l'OR copre le
    // somme canoniche 1..=15. Entrambi richiedono il preset A44 max-noise 15.
    assert_eq!(box_size % 2, 0);
    let half_box = box_size / 2;
    let mut a50_target_one_body = vec![0u64; polynomial_size.0];
    a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);
    let mut a50_radix15_or_body = vec![0u64; polynomial_size.0];
    a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);
    let a50_target_one_accumulator = raw_accumulator(a50_target_one_body);
    let a50_radix15_or_accumulator = raw_accumulator(a50_radix15_or_body);

    assert!(!fuse_refresh || wire_format == AlignedWireFormat::A53Radix15TwoP16Digits);
    let a126_fusion_accumulator = fuse_refresh.then(|| {
        let bytes = include_bytes!("../../artifacts/fused_candidate_zero_body.u64le");
        assert_eq!(bytes.len(), polynomial_size.0 * 8);
        let body = bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        raw_accumulator(body)
    });

    let scan_or_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| u64::from((1..=A38_REDUCTION_RADIX as u64).contains(&slot)),
    );
    let scan_local_first_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| match slot {
            0 => 0,
            1 => 3,
            2 => 2,
            3 | 4 => 1,
            _ => 0,
        },
    );
    let digit_identity_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| slot,
    );
    let root_delta = match wire_format {
        AlignedWireFormat::SingleCode => code_delta,
        AlignedWireFormat::TwoP16Digits | AlignedWireFormat::A53Radix15TwoP16Digits => bool_delta,
    };
    let low_code_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        root_delta,
        |slot| slot,
    );
    let high_code_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        root_delta,
        |slot| match wire_format {
            AlignedWireFormat::SingleCode if slot <= 8 => A38_NIBBLE_RADIX * slot,
            AlignedWireFormat::TwoP16Digits | AlignedWireFormat::A53Radix15TwoP16Digits
                if slot <= 8 =>
            {
                slot
            }
            _ => 0,
        },
    );
    let scan_groups = n.div_ceil(A38_SCAN_GROUP_SIZE);
    let scan_selector_accumulators: Vec<Glwe> = (0..scan_groups)
        .map(|group| {
            let group_len = (n - group * A38_SCAN_GROUP_SIZE).min(A38_SCAN_GROUP_SIZE);
            let mut low = [0u64; 8];
            let mut high = [0u64; 8];
            for state in 1..=group_len {
                let identity_code = (A38_SCAN_GROUP_SIZE * group + state) as u64;
                low[state] = identity_code % A38_NIBBLE_RADIX;
                high[state] = unused_high_digit(identity_code);
            }
            let direct_code_scale =
                scan_groups == 1 && wire_format == AlignedWireFormat::SingleCode;
            let delta = if direct_code_scale {
                code_delta
            } else {
                bool_delta
            };
            let high = if direct_code_scale {
                high.map(|digit| A38_NIBBLE_RADIX * digit)
            } else {
                high
            };
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                delta,
                move |slot| {
                    let slot = slot as usize;
                    if slot < 8 {
                        low[slot]
                    } else {
                        high[slot - 8]
                    }
                },
            )
        })
        .collect();
    let setup_metrics = stage_metrics(setup_started, setup_pbs, &pbs_count);

    let apply_pbs = |input: &Lwe, accumulator: &Glwe| -> Lwe {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut output,
            accumulator,
            fourier_bootstrap_key,
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        output
    };

    let apply_a126_fusion = |input: &Lwe| -> (Lwe, Lwe) {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = a126_fusion_accumulator
            .as_ref()
            .expect("A126 accumulator")
            .clone();
        blind_rotate_assign_with_modulus_switch(
            &switched, &mut rotated, fourier_bootstrap_key, modulus_switch_configuration,
        );
        let mut candidate = LweCiphertext::new(0u64, big_size, modulus);
        let mut zero_candidate = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut candidate, MonomialDegree(0));
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut zero_candidate, MonomialDegree(768));
        pbs_count.fetch_add(1, Ordering::Relaxed);
        (candidate, zero_candidate)
    };
    let apply_selector_pbs = |input: &Lwe, accumulator: &Glwe| -> (Lwe, Lwe) {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = accumulator.clone();
        blind_rotate_assign_with_modulus_switch(
            &switched, &mut rotated, fourier_bootstrap_key, modulus_switch_configuration,
        );
        let mut low = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut low, MonomialDegree(0));
        let mut high = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &rotated,
            &mut high,
            MonomialDegree(polynomial_size.0 / 2),
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        (low, high)
    };
    let zero =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
    let a36_or_gate = |states: &[Lwe]| -> Lwe {
        assert!(!states.is_empty() && states.len() <= A38_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(states, &zero), &a36_radix5_or_accumulator)
    };
    let a50_or_gate = |states: &[Lwe]| -> Lwe {
        assert!(!states.is_empty() && states.len() <= A50_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(states, &zero), &a50_radix15_or_accumulator)
    };
    let scan_or_gate = |bits: &[Lwe]| -> Lwe {
        assert!(!bits.is_empty() && bits.len() <= A38_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(bits, &zero), &scan_or_accumulator)
    };
    let bridge_bit = |full: &CapturedExtractedBits,
                      low: &CapturedExtractedBits,
                      bit_index: u32|
     -> WeightedBit {
        if is_canonical_boolean_bit(bit_index) {
            return WeightedBit {
                ciphertext: full.canonical_bits_lsb_first[bit_index as usize]
                    .as_ref()
                    .expect("i bit 3..=7 sono Booleani canonici")
                    .clone(),
            };
        }
        debug_assert!(bit_index < SPLIT_LOW_BITS);
        let weight = extracted_bit_weight(bit_index);
        let correction_log = bit_source_delta(bit_index) + bit_index;
        let target_log = BOOL_DELTA_LOG + weight.ilog2();
        let mut ciphertext = low.corrections_lsb_first[bit_index as usize].clone();
        lwe_ciphertext_cleartext_mul_assign(
            &mut ciphertext,
            Cleartext(1u64 << (target_log - correction_log)),
        );
        WeightedBit { ciphertext }
    };

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
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
            (
                extract_score(PROBE_DIM - 1, full_delta),
                extract_score(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM - 1, low_delta),
            )
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.score_full = score_pairs.iter().map(|(full, _)| full.clone()).collect();
        trace.score_low_mod16 = score_pairs.iter().map(|(_, low)| low.clone()).collect();
    }
    let score_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let low_bit_count = LOW_EXTRACTED_BITS as usize;
    let low_extracted: Vec<CapturedExtractedBits> = score_pairs
        .par_iter()
        .map(|(_, low)| {
            extract_bits_with_corrections(
                low,
                fourier_bootstrap_key,
                modulus_switch_configuration,
                key_switching_key,
                &low_correction_accumulators,
                LOW_MOD16_DELTA_LOG,
                LOW_EXTRACTED_BITS,
                &pbs_count,
            )
        })
        .collect();
    let low_to_full_bits_flat: Vec<ExtractedCorrection> = (0..n * low_bit_count)
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / low_bit_count;
            let bit_index = flat % low_bit_count;
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index as u32 - 1);
            correction_from_small_bit(
                &low_extracted[gallery_index].small_lsb_first[bit_index],
                &low_to_full_correction_accumulators[bit_index],
                fourier_bootstrap_key,
                modulus_switch_configuration,
                big_size,
                alpha,
                &pbs_count,
            )
        })
        .collect();
    let high_inputs: Vec<Lwe> = score_pairs
        .par_iter()
        .enumerate()
        .map(|(gallery_index, (full_score, _))| {
            let mut residual = full_score.clone();
            let start = gallery_index * low_bit_count;
            for bit in &low_to_full_bits_flat[start..start + low_bit_count] {
                lwe_ciphertext_sub_assign(&mut residual, &bit.correction);
            }
            residual
        })
        .collect();
    let high_extracted: Vec<CapturedExtractedBits> = high_inputs
        .par_iter()
        .map(|high| {
            let mut extracted = extract_bits_with_all_corrections(
                high,
                fourier_bootstrap_key,
                modulus_switch_configuration,
                key_switching_key,
                &high_correction_accumulators,
                HIGH_DELTA_LOG,
                A34_HIGH_CORRECTION_BITS,
                &pbs_count,
            );
            // La correzione locale 3 e' il bit globale 7, gia' a Delta_bool.
            extracted.canonical_bits_lsb_first[3] =
                Some(extracted.corrections_lsb_first[3].clone());
            extracted
        })
        .collect();
    let aligned_residuals: Vec<Lwe> = high_inputs
        .par_iter()
        .zip(&high_extracted)
        .map(|(high_input, high)| {
            let mut residual = high_input.clone();
            for correction in &high.corrections_lsb_first {
                lwe_ciphertext_sub_assign(&mut residual, correction);
            }
            residual
        })
        .collect();
    let full_extracted: Vec<CapturedExtractedBits> = low_extracted
        .iter()
        .zip(&high_extracted)
        .enumerate()
        .map(|(gallery_index, (low, high))| {
            let start = gallery_index * low_bit_count;
            let mut small_lsb_first = low.small_lsb_first.clone();
            small_lsb_first.extend(high.small_lsb_first.clone());
            let mut corrections_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.correction.clone())
                .collect::<Vec<_>>();
            corrections_lsb_first.extend(high.corrections_lsb_first.clone());
            let mut canonical_bits_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.boolean.clone())
                .collect::<Vec<_>>();
            canonical_bits_lsb_first.extend(high.canonical_bits_lsb_first.clone());
            debug_assert_eq!(small_lsb_first.len(), 8);
            debug_assert_eq!(corrections_lsb_first.len(), 8);
            debug_assert_eq!(canonical_bits_lsb_first.len(), 8);
            CapturedExtractedBits {
                small_lsb_first,
                corrections_lsb_first,
                canonical_bits_lsb_first,
            }
        })
        .collect();
    let flat_bits: Vec<WeightedBit> = (0..n * bit_positions.len())
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / bit_positions.len();
            let level = flat % bit_positions.len();
            bridge_bit(
                &full_extracted[gallery_index],
                &low_extracted[gallery_index],
                bit_positions[level],
            )
        })
        .collect();
    let bits_by_level: Vec<Vec<WeightedBit>> = bit_positions
        .iter()
        .enumerate()
        .map(|(level, _)| {
            (0..n)
                .map(|index| flat_bits[index * bit_positions.len() + level].clone())
                .collect()
        })
        .collect();
    let a34_top_codes: Vec<Lwe> = aligned_residuals
        .par_iter()
        .map(|residual| apply_pbs(residual, &a34_top_classifier_accumulator))
        .collect();
    let a34_canonical_categories: Vec<Lwe> = a34_top_codes
        .par_iter()
        .map(|code| {
            let mut input = code.clone();
            lwe_ciphertext_plaintext_add_assign(
                &mut input,
                Plaintext(4u64.wrapping_mul(bool_delta)),
            );
            apply_pbs(&input, &a34_canonical_category_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.high_residuals = high_inputs.clone();
        trace.aligned_residuals = aligned_residuals.clone();
        trace.full_small_bits_lsb_first = full_extracted
            .iter()
            .map(|bits| bits.small_lsb_first.clone())
            .collect();
        trace.full_corrections_lsb_first = full_extracted
            .iter()
            .map(|bits| bits.corrections_lsb_first.clone())
            .collect();
        trace.low_small_bits_lsb_first = low_extracted
            .iter()
            .map(|bits| bits.small_lsb_first.clone())
            .collect();
        trace.low_corrections_lsb_first = low_extracted
            .iter()
            .map(|bits| bits.corrections_lsb_first.clone())
            .collect();
        trace.fused_boolean_bits_3_to_6 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[3..=6]
                    .iter()
                    .map(|bit| bit.as_ref().expect("bit A29 assente").clone())
                    .collect()
            })
            .collect();
        trace.reused_bit7 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[7]
                    .as_ref()
                    .expect("correzione b7 assente")
                    .clone()
            })
            .collect();
        trace.bridged_bits_by_level = bits_by_level
            .iter()
            .map(|bits| bits.iter().map(|bit| bit.ciphertext.clone()).collect())
            .collect();
        trace.a34_top_codes = a34_top_codes.clone();
        trace.a34_canonical_categories = a34_canonical_categories.clone();
    }
    let extract_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let mut a34_category_reduction_levels = vec![a34_canonical_categories.clone()];
    let mut category_level = a34_canonical_categories;
    while category_level.len() > 1 {
        category_level = category_level
            .par_chunks(2)
            .map(|pair| {
                if pair.len() == 1 {
                    pair[0].clone()
                } else {
                    let mut input = pair[0].clone();
                    lwe_ciphertext_add_assign(&mut input, &pair[1]);
                    apply_pbs(&input, &a34_pair_category_accumulator)
                }
            })
            .collect();
        a34_category_reduction_levels.push(category_level.clone());
    }
    let a34_global_category = category_level
        .pop()
        .expect("riduzione categoria A34-top non vuota");
    let initial_candidates: Vec<Lwe> = a34_top_codes
        .par_iter()
        .map(|code| {
            let mut input = code.clone();
            lwe_ciphertext_add_assign(&mut input, &a34_global_category);
            lwe_ciphertext_plaintext_add_assign(
                &mut input,
                Plaintext(4u64.wrapping_mul(bool_delta)),
            );
            apply_pbs(&input, &a34_top_candidate_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.a34_category_reduction_levels = a34_category_reduction_levels;
        trace.a34_global_category = Some(a34_global_category);
        trace.aligned_initial_candidates = initial_candidates.clone();
    }

    // A38 usa stati 0/2 e OR radix-5. A62 attiva la macchina canonica A50 0/1 e OR radix-15:
    // questo passaggio e' necessario, oltre alla sola scan A53, per ottenere gli anchor congelati
    // 3390/3009/3930. Entrambi i rami conservano l'argmin esatto e il primo vincitore nei tie.
    let use_a50_selection = wire_format == AlignedWireFormat::A53Radix15TwoP16Digits;
    let source_multipliers = if use_a50_selection {
        A50_SOURCE_MULTIPLIERS
    } else {
        A38_SOURCE_MULTIPLIERS
    };
    let mut candidates: Vec<Lwe> = if use_a50_selection {
        initial_candidates.clone()
    } else {
        initial_candidates
            .par_iter()
            .map(|candidate| scale_lwe_signed(candidate, 2))
            .collect()
    };
    for (level, bits) in bits_by_level.iter().enumerate() {
        let zero_candidates: Vec<Lwe> = if fuse_refresh && level == 4 {
            // bits is the positive canonical b3; weighted_bits would already negate it.
            let inputs: Vec<Lwe> = candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    let six_bits = scale_lwe_signed(&bit.ciphertext, 6);
                    lwe_ciphertext_add_assign(&mut encoded, &six_bits);
                    encoded
                })
                .collect();
            let pairs: Vec<(Lwe, Lwe)> = inputs.par_iter().map(apply_a126_fusion).collect();
            if let Some(trace) = trace.as_deref_mut() {
                trace.a126_fusion_inputs = inputs;
                trace.a126_fresh_candidates = pairs
                    .iter()
                    .map(|(candidate, _)| candidate.clone())
                    .collect();
                trace.a126_zero_candidates = pairs.iter().map(|(_, zero)| zero.clone()).collect();
            }
            candidates = pairs
                .iter()
                .map(|(candidate, _)| candidate.clone())
                .collect();
            pairs.into_iter().map(|(_, zero)| zero).collect()
        } else {
            let weighted_bits: Vec<Lwe> = bits
                .par_iter()
                .map(|bit| scale_lwe_signed(&bit.ciphertext, source_multipliers[level]))
                .collect();
            candidates
                .par_iter()
                .zip(&weighted_bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, bit);
                    if use_a50_selection {
                        apply_pbs(&encoded, &a50_target_one_accumulator)
                    } else {
                        apply_pbs(&encoded, &a36_active_step2_accumulator)
                    }
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.zero_candidates_by_level.push(zero_candidates.clone());
        }
        let mut reduced = zero_candidates.clone();
        while reduced.len() > 1 {
            reduced = if use_a50_selection {
                reduced
                    .par_chunks(A50_REDUCTION_RADIX)
                    .map(|chunk| {
                        if chunk.len() == 1 {
                            chunk[0].clone()
                        } else {
                            a50_or_gate(chunk)
                        }
                    })
                    .collect()
            } else {
                reduced
                    .par_chunks(A38_REDUCTION_RADIX)
                    .map(|chunk| a36_or_gate(chunk))
                    .collect()
            };
        }
        let any_zero = reduced.pop().expect("OR A36 non vuoto");
        let linear_candidates: Vec<Lwe> = candidates
            .par_iter()
            .zip(&zero_candidates)
            .map(|(candidate, zero_candidate)| {
                let mut next = candidate.clone();
                lwe_ciphertext_add_assign(&mut next, zero_candidate);
                lwe_ciphertext_sub_assign(&mut next, &any_zero);
                next
            })
            .collect();
        candidates = if use_a50_selection
            && A38_CHUNK_END_LEVELS.contains(&level)
            && !(fuse_refresh && level == 3)
        {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a50_target_one_accumulator))
                .collect()
        } else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[0] {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a36_active_step2_accumulator))
                .collect()
        } else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[1] {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a36_final_boolean_accumulator))
                .collect()
        } else {
            linear_candidates
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.any_zero_by_level.push(any_zero);
            trace.candidates_by_level.push(candidates.clone());
        }
    }
    let select_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let backend = A66A53CoreBackend {
        server_key, modulus, big_size, small_size, pbs_count: &pbs_count,
        scan_pbs: AtomicU64::new(0), scan_extra_output_marginals: AtomicU64::new(0),
    };
    let output = materialize_a53_scan_wide(&a66_a53_gate(), &backend, &candidates)
        .map_err(map_a53_error)?;
    let scan_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    // Preserve the empty threshold and output stages; A53 returns ready ID roots.
    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let threshold_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);
    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let output_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);
    let total_pbs_count = pbs_count.load(Ordering::Relaxed);
    let structural_counts = operation_counts(n).expect("validated wider gallery");
    assert_eq!(total_pbs_count, structural_counts.br, "adapted A126 actual BR ledger differs");
    Ok(A126WideOutput {
        low_digit: output.low_digit, middle_digit: output.middle_digit, high_digit: output.high_digit,
        structural_counts, scan_expected_counts: output.expected_counts,
        scan_observed_counts: output.observed_counts, parameter_binding: A44_PARAMETER_BINDING,
        metrics: PrivateArgminMetrics {
            setup: setup_metrics, score: score_metrics, extract: extract_metrics,
            select: select_metrics, scan: scan_metrics, threshold: threshold_metrics,
            output: output_metrics, total_seconds: total_started.elapsed().as_secs_f64(), total_pbs_count,
        },
    })
}

#[cfg(test)]
mod tests;
