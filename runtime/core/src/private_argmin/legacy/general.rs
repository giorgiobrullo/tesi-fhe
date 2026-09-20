//! Historical general argmin circuit, with its original operation order.
use super::*;

pub(super) fn private_argmin_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    mut trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        let output = private_argmin_aligned_a38_impl(
            server_key,
            packed_probe,
            templates,
            domain,
            AlignedWireFormat::SingleCode,
            false,
            trace,
        )?;
        return Ok(PrivateArgminOutput {
            code: output.code.expect("uscita single-LWE A38 assente"),
            metrics: output.metrics,
        });
    }
    let total_started = Instant::now();
    let pbs_count = AtomicU64::new(0);
    let n = templates.len();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let key_switching_key = &server_key.key_switching_key;
    let fourier_bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    assert_eq!(polynomial_size.0 % 4, 0);
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let bit_positions: Vec<u32> = (0..=HIGH_SCORE_BIT).rev().collect();
    if let Some(trace) = trace.as_deref_mut() {
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
        make_correction_accumulators(HIGH_DELTA_LOG, HIGH_EXTRACTED_BITS - 1, 0..3);
    let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (bool_delta >> 1).wrapping_neg(),
            PlaintextCount(polynomial_size.0),
        ),
        modulus,
    );

    let bit_weights: Vec<u64> = bit_positions
        .iter()
        .map(|bit_index| extracted_bit_weight(*bit_index))
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_weights_msb_first = bit_weights.clone();
    }
    let update_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        update_candidate_from_zero_lut,
    );
    let encoded_zero_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        encoded_zero_candidate_lut,
    );
    let single_zero_accumulators: Vec<Glwe> = bit_weights
        .iter()
        .map(|weight| {
            let (candidate_weight, bit_weight) = zero_layout(*weight);
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                bool_delta,
                move |value| zero_candidate_lut(value, candidate_weight, bit_weight),
            )
        })
        .collect();
    let boolean_and_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        boolean_and_lut,
    );
    let comparison_state_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        comparison_state_lut,
    );
    let comparison_accept_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        comparison_accept_tag_lut,
    );
    let output_bit_positions = output_bit_positions(n);
    let weighted_or_accumulators: Vec<Glwe> = [1u64, 2, 4]
        .into_iter()
        .map(|weight| {
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                bool_delta,
                move |value| weighted_or_lut(value, weight),
            )
        })
        .collect();
    let output_group_accumulators: Vec<Glwe> = output_bit_positions
        .chunks(3)
        .map(|positions| {
            debug_assert!(positions.windows(2).all(|pair| pair[1] == pair[0] + 1));
            let bit_offset = positions[0];
            let group_len = positions.len();
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                code_delta,
                move |value| output_group_lut(value, bit_offset, group_len),
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
    let recode_extracted_bit = |bit: &Lwe| -> Lwe {
        let mut shifted = bit.clone();
        lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(1u64 << 61));
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &shifted,
            &mut output,
            &sign_accumulator,
            fourier_bootstrap_key,
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(bool_delta >> 1));
        output
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
        let source = if bit_index < SPLIT_LOW_BITS {
            low
        } else {
            full
        };
        let weight = extracted_bit_weight(bit_index);
        if recodes_bit(bit_index) {
            return WeightedBit {
                ciphertext: recode_extracted_bit(&source.small_lsb_first[bit_index as usize]),
            };
        }
        let correction_log = bit_source_delta(bit_index) + bit_index;
        let target_log = BOOL_DELTA_LOG + weight.ilog2();
        let mut ciphertext = source.corrections_lsb_first[bit_index as usize].clone();
        lwe_ciphertext_cleartext_mul_assign(
            &mut ciphertext,
            Cleartext(1u64 << (target_log - correction_log)),
        );
        WeightedBit { ciphertext }
    };
    let or_gate = |bits: &[Lwe]| -> Lwe {
        assert!(!bits.is_empty() && bits.len() <= OR_BLOCK);
        let mut count =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
        for bit in bits {
            lwe_ciphertext_add_assign(&mut count, bit);
        }
        lwe_ciphertext_opposite_assign(&mut count);
        lwe_ciphertext_plaintext_add_assign(&mut count, Plaintext(bool_delta >> 1));
        let mut any = apply_pbs(&count, &sign_accumulator);
        lwe_ciphertext_plaintext_add_assign(&mut any, Plaintext(bool_delta >> 1));
        any
    };
    let or_reduce = |mut bits: Vec<Lwe>| -> Lwe {
        assert!(!bits.is_empty());
        while bits.len() > 1 {
            bits = bits.chunks(OR_BLOCK).map(&or_gate).collect();
        }
        bits.pop().expect("la riduzione OR parte non vuota")
    };
    let apply_sum_gate = |bits: &[&Lwe], accumulator: &Glwe| -> Lwe {
        let mut sum =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
        for bit in bits {
            lwe_ciphertext_add_assign(&mut sum, bit);
        }
        apply_pbs(&sum, accumulator)
    };
    let and_gate = |left: &Lwe, right: &Lwe| -> Lwe {
        apply_sum_gate(&[left, right], &boolean_and_accumulator)
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
    // La vista modulo 16 fornisce i bit 0..3 con il margine piu' ampio. Li convertiamo tutti
    // alla scala full e li sottraiamo prima di estrarre soltanto i bit globali 4..11.
    let low_extracted: Vec<CapturedExtractedBits> = score_pairs
        .par_iter()
        .map(|(_, low)| {
            extract_bits_with_corrections(
                low,
                fourier_bootstrap_key,
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
    if let Some(trace) = trace.as_deref_mut() {
        trace.high_residuals = high_inputs.clone();
    }
    let high_extracted: Vec<CapturedExtractedBits> = high_inputs
        .par_iter()
        .map(|high| {
            let mut extracted = extract_bits_with_corrections(
                high,
                fourier_bootstrap_key,
                key_switching_key,
                &high_correction_accumulators,
                HIGH_DELTA_LOG,
                HIGH_EXTRACTED_BITS,
                &pbs_count,
            );
            // La correzione locale 3 e' il bit globale 7 a 2^59: non serve un altro PBS.
            extracted.canonical_bits_lsb_first[3] =
                Some(extracted.corrections_lsb_first[3].clone());
            extracted
        })
        .collect();
    let full_extracted: Vec<CapturedExtractedBits> = low_extracted
        .iter()
        .zip(high_extracted)
        .enumerate()
        .map(|(gallery_index, (low, high))| {
            let start = gallery_index * low_bit_count;
            // Manteniamo la rappresentazione globale 0..11 usata dal bridge e dal trace: i primi
            // quattro slot provengono dal canale low, gli altri otto dall'estrattore high.
            let mut small_lsb_first = low.small_lsb_first.clone();
            small_lsb_first.extend(high.small_lsb_first);
            let mut corrections_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.correction.clone())
                .collect::<Vec<_>>();
            corrections_lsb_first.extend(high.corrections_lsb_first);
            let mut canonical_bits_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.boolean.clone())
                .collect::<Vec<_>>();
            canonical_bits_lsb_first.extend(high.canonical_bits_lsb_first);
            debug_assert_eq!(small_lsb_first.len(), SCORE_BITS as usize);
            debug_assert_eq!(corrections_lsb_first.len(), SCORE_BITS as usize - 1);
            debug_assert_eq!(canonical_bits_lsb_first.len(), SCORE_BITS as usize);
            CapturedExtractedBits {
                small_lsb_first,
                corrections_lsb_first,
                canonical_bits_lsb_first,
            }
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
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
                    .map(|bit| {
                        bit.as_ref()
                            .expect("i bit 3..=6 provengono da ManyLUT")
                            .clone()
                    })
                    .collect()
            })
            .collect();
        trace.reused_bit7 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[7]
                    .as_ref()
                    .expect("il bit 7 riusa la correzione")
                    .clone()
            })
            .collect();
    }
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
    if let Some(trace) = trace.as_deref_mut() {
        trace.bridged_bits_by_level = bits_by_level
            .iter()
            .map(|bits| bits.iter().map(|bit| bit.ciphertext.clone()).collect())
            .collect();
    }
    let extract_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let mut candidates: Vec<Lwe> = (0..n)
        .map(|_| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                big_size,
                Plaintext(bool_delta),
                modulus,
            )
        })
        .collect();
    let mut any_zero_bits = Vec::with_capacity(SCORE_BITS as usize);
    for (level, bits) in bits_by_level.iter().enumerate() {
        let raw_bit_weight = bit_weights[level];
        let zero_candidates: Vec<Lwe> = if level == 0 {
            assert_eq!(raw_bit_weight, 1);
            bits.par_iter()
                .map(|bit| {
                    let mut zero = bit.ciphertext.clone();
                    lwe_ciphertext_opposite_assign(&mut zero);
                    lwe_ciphertext_plaintext_add_assign(&mut zero, Plaintext(bool_delta));
                    zero
                })
                .collect()
        } else if level % 2 == 1 {
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, &bit.ciphertext);
                    apply_pbs(&encoded, &encoded_zero_candidate_accumulator)
                })
                .collect()
        } else if raw_bit_weight == 1 {
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut not_bit = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big_size,
                        Plaintext(bool_delta),
                        modulus,
                    );
                    lwe_ciphertext_sub_assign(&mut not_bit, &bit.ciphertext);
                    and_gate(candidate, &not_bit)
                })
                .collect()
        } else {
            assert!(matches!(raw_bit_weight, 2 | 4 | 8));
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, &bit.ciphertext);
                    apply_pbs(&encoded, &single_zero_accumulators[level])
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.zero_candidates_by_level.push(zero_candidates.clone());
        }
        let any_zero = compact_or(zero_candidates.clone(), &or_gate);
        any_zero_bits.push(any_zero.clone());
        candidates = if level % 2 == 0 {
            // Da un candidato Booleano c costruiamo linearmente e=-c-z+a. Gli attivi diventano
            // 15, gli inattivi 0/1; il rumore e' <=2 al MSB e <=3 negli altri livelli pari.
            candidates
                .par_iter()
                .zip(&zero_candidates)
                .map(|(candidate, zero_candidate)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, zero_candidate);
                    lwe_ciphertext_opposite_assign(&mut encoded);
                    lwe_ciphertext_add_assign(&mut encoded, &any_zero);
                    encoded
                })
                .collect()
        } else {
            // Dal candidato codificato e ricaviamo `-e+z-a`: il codice uno identifica soltanto
            // gli attivi che sopravvivono. L'ingresso contiene al massimo cinque unita' di
            // rumore, esattamente il limite del parameter set, e l'uscita torna Booleana fresca.
            candidates
                .par_iter()
                .zip(&zero_candidates)
                .map(|(candidate, zero_candidate)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_opposite_assign(&mut encoded);
                    lwe_ciphertext_add_assign(&mut encoded, zero_candidate);
                    lwe_ciphertext_sub_assign(&mut encoded, &any_zero);
                    apply_pbs(&encoded, &update_candidate_accumulator)
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.any_zero_by_level.push(any_zero);
            trace.candidates_by_level.push(candidates.clone());
        }
    }
    let select_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let zero =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
    // Lo scan opera prima su gruppi di tre candidati: un solo OR produce il flag del gruppo,
    // poi un prefisso ricorsivo radix-4 calcola quali gruppi precedenti contengono un minimo.
    // Il gate finale di ogni elemento incorpora quel prefisso e i (massimo due) predecessori
    // locali. Non serve padding e ogni input contiene al massimo quattro Booleani freschi.
    let group_flags: Vec<Lwe> = candidates
        .par_chunks(FIRST_ONE_GROUP)
        .map(|group| {
            if group.len() == 1 {
                group[0].clone()
            } else {
                or_gate(group)
            }
        })
        .collect();
    let group_prefixes = radix4_exclusive_prefix_or(&group_flags, &zero, &or_gate);
    if let Some(trace) = trace.as_deref_mut() {
        trace.group_prefixes = group_prefixes.clone();
    }
    let winners: Vec<Lwe> = (0..n)
        .into_par_iter()
        .map(|index| {
            let group = index / FIRST_ONE_GROUP;
            let group_start = group * FIRST_ONE_GROUP;
            let mut encoded = candidates[index].clone();
            lwe_ciphertext_sub_assign(&mut encoded, &group_prefixes[group]);
            for previous in &candidates[group_start..index] {
                lwe_ciphertext_sub_assign(&mut encoded, previous);
            }
            apply_pbs(&encoded, &update_candidate_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.winners = winners.clone();
    }
    let scan_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let threshold_metadata: Vec<(u64, bool)> = templates
        .iter()
        .map(|entry| {
            let below = entry.threshold < domain.lower;
            let clamped = entry.threshold.clamp(domain.lower, domain.upper);
            ((clamped - domain.lower) as u64, below)
        })
        .collect();
    // Selezionare la soglia con somme lineari accumula il rumore dei winner che cifrano zero.
    // Riduciamo quindi con OR soltanto gli indici il cui bit pubblico e' impostato. Una maschera
    // vuota e' zero pubblico; una maschera piena e' uno pubblico, perche' esiste esattamente un
    // winner. Le soglie uniformi non richiedono cosi' alcun PBS di selezione, mentre il caso
    // per-template generale conserva la stessa semantica con costo dipendente dalle maschere.
    let threshold_masks: Vec<Vec<bool>> = bit_positions
        .iter()
        .map(|bit_position| {
            threshold_metadata
                .iter()
                .map(|(threshold, _)| ((threshold >> bit_position) & 1) == 1)
                .collect()
        })
        .collect();
    let below_mask: Vec<bool> = threshold_metadata.iter().map(|(_, below)| *below).collect();
    let one =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(bool_delta), modulus);
    let select_winner_mask = |mask: &[bool]| -> Lwe {
        assert_eq!(mask.len(), n);
        let selected: Vec<Lwe> = winners[..n]
            .iter()
            .zip(mask)
            .filter(|(_, enabled)| **enabled)
            .map(|(winner, _)| winner.clone())
            .collect();
        match selected.len() {
            0 => zero.clone(),
            count if count == n => one.clone(),
            _ => or_reduce(selected),
        }
    };
    let selected_threshold_bits: Vec<Lwe> = threshold_masks
        .par_iter()
        .map(|mask| select_winner_mask(mask))
        .collect();
    let selected_below = select_winner_mask(&below_mask);
    if let Some(trace) = trace.as_deref_mut() {
        trace.selected_threshold_bits_msb_first = selected_threshold_bits.clone();
        trace.selected_below = Some(selected_below.clone());
    }
    // Stato ternario less/equal/greater codificato come 0/2/4. Sottrarre i due Booleani
    // `any_zero = !minimum_bit` e `threshold_bit` produce codici non ambigui modulo 16; una sola
    // LUT aggiorna quindi il confronto a ogni bit, invece dei quattro gate Booleani precedenti.
    let mut comparison_state = allocate_and_trivially_encrypt_new_lwe_ciphertext(
        big_size,
        Plaintext(COMPARISON_EQUAL * bool_delta),
        modulus,
    );
    for (any_zero, threshold_bit) in any_zero_bits.iter().zip(&selected_threshold_bits) {
        let mut encoded = comparison_state;
        lwe_ciphertext_sub_assign(&mut encoded, any_zero);
        lwe_ciphertext_sub_assign(&mut encoded, threshold_bit);
        comparison_state = apply_pbs(&encoded, &comparison_state_accumulator);
        if let Some(trace) = trace.as_deref_mut() {
            trace
                .comparison_state_by_level
                .push(comparison_state.clone());
        }
    }
    // `threshold >= upper` non richiede una sentinella separata: il valore viene clampato a upper
    // e ogni score valido e' gia' <= upper. Solo `threshold < lower` deve forzare il rifiuto.
    lwe_ciphertext_add_assign(&mut comparison_state, &selected_below);
    let accept_tag = apply_pbs(&comparison_state, &comparison_accept_accumulator);
    if let Some(trace) = trace.as_deref_mut() {
        trace.accept_tag = Some(accept_tag.clone());
    }
    let threshold_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    // L'ultimo OR di ogni maschera emette direttamente un digit locale fresco 1/2/4. Tre digit
    // e il tag fresco 8 dell'accettazione formano un codice non ambiguo 0..15; una sola LUT di
    // gruppo applica insieme soglia e peso assoluto del codice. La somma finale contiene al
    // massimo tre ciphertext freschi per MAX_GALLERY_SIZE=128.
    let coded_digits: Vec<Lwe> = output_bit_positions
        .par_iter()
        .map(|&bit_position| {
            let mut selected: Vec<Lwe> = winners[..n]
                .iter()
                .enumerate()
                .filter(|(index, _)| output_code_has_bit(*index, bit_position))
                .map(|(_, winner)| winner.clone())
                .collect();
            debug_assert!(!selected.is_empty());
            while selected.len() > OR_BLOCK {
                selected = selected.chunks(OR_BLOCK).map(&or_gate).collect();
            }
            let mut count = zero.clone();
            for winner in &selected {
                lwe_ciphertext_add_assign(&mut count, winner);
            }
            apply_pbs(&count, &weighted_or_accumulators[bit_position as usize % 3])
        })
        .collect();
    let code_groups: Vec<Lwe> = coded_digits
        .par_chunks(3)
        .zip(&output_group_accumulators)
        .map(|(digits, accumulator)| {
            let mut encoded = accept_tag.clone();
            for digit in digits {
                lwe_ciphertext_add_assign(&mut encoded, digit);
            }
            apply_pbs(&encoded, accumulator)
        })
        .collect();
    let mut code = zero;
    for value in &code_groups {
        lwe_ciphertext_add_assign(&mut code, value);
    }
    if let Some(trace) = trace {
        trace.coded_digits_lsb_first = coded_digits.clone();
        trace.code_groups = code_groups;
        trace.final_code = Some(code.clone());
    }
    let output_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);
    let total_pbs_count = pbs_count.load(Ordering::Relaxed);
    Ok(PrivateArgminOutput {
        code,
        metrics: PrivateArgminMetrics {
            setup: setup_metrics,
            score: score_metrics,
            extract: extract_metrics,
            select: select_metrics,
            scan: scan_metrics,
            threshold: threshold_metrics,
            output: output_metrics,
            total_seconds: total_started.elapsed().as_secs_f64(),
            total_pbs_count,
        },
    })
}
