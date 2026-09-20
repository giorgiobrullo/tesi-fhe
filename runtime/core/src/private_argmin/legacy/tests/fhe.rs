use super::*;

#[test]
#[ignore = "micro-diagnostica FHE: genera una chiave fresca e otto blind rotation"]
fn fused_blind_rotation_emits_both_expected_lwe_messages() {
    use crate::compat::{ClientKey, ServerKey};
    use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;

    let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, small_secret_key, parameters) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let fourier_bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("il test A29 richiede il BSK Classic"),
    };
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let modulus = CiphertextModulus::<u64>::new_native();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let counter = AtomicU64::new(0);
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    for bit_index in 3..=6 {
        let alpha = 1u64 << (FULL_DELTA_LOG + bit_index - 1);
        let accumulator =
            CorrectionAccumulator::WithBoolean(allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &PlaintextList::from_container(fused_correction_accumulator_body(
                    polynomial_size,
                    alpha,
                    bool_delta >> 1,
                )),
                modulus,
            ));
        for bit in [0u64, 1] {
            let mut encrypted = LweCiphertext::new(
                0u64,
                small_secret_key.lwe_dimension().to_lwe_size(),
                modulus,
            );
            encrypt_lwe_ciphertext(
                &small_secret_key,
                &mut encrypted,
                Plaintext(bit << 63),
                parameters.lwe_noise_distribution(),
                &mut generator,
            );
            let output = correction_from_small_bit(
                &encrypted,
                &accumulator,
                fourier_bootstrap_key,
                big_size,
                alpha,
                &counter,
            );
            let correction_phase = decrypt_lwe_ciphertext(&big_secret_key, &output.correction).0;
            let boolean_phase = decrypt_lwe_ciphertext(
                &big_secret_key,
                output.boolean.as_ref().expect("uscita Booleana assente"),
            )
            .0;
            let correction_log = FULL_DELTA_LOG + bit_index;
            assert_eq!(
                correction_phase.wrapping_add(1u64 << (correction_log - 1)) >> correction_log,
                bit
            );
            assert_eq!(
                boolean_phase.wrapping_add(1u64 << (BOOL_DELTA_LOG - 1)) >> BOOL_DELTA_LOG,
                bit
            );
        }
    }
    assert_eq!(counter.load(Ordering::Relaxed), 8);
}

#[test]
#[ignore = "micro-diagnostica FHE end-to-end su chiave fresca"]
fn fused_core_preserves_exact_id_ties_threshold_and_output_contract() {
    use crate::compat::{ClientKey, ServerKey};
    use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;

    let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _, parameters) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut packed_probe = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
        modulus,
    );
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut packed_probe,
        &PlaintextList::new(0u64, PlaintextCount(polynomial_size.0)),
        parameters.glwe_noise_distribution(),
        &mut generator,
    );
    let zero_template = [0i64; PROBE_DIM];
    let decode_big = |ciphertext: &Lwe, delta_log: u32| {
        decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
            .0
            .wrapping_add(1u64 << (delta_log - 1))
            >> delta_log
    };

    for x in [0u64, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 2048, 4095] {
        let template = TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: 0,
        };
        let domain = ScoreDomain {
            lower: -(x as i64),
            upper: -(x as i64) + MAX_DOMAIN_WIDTH - 1,
        };
        let mut trace = PrivateArgminTrace::default();
        let output = private_argmin_impl(
            &server_key,
            &packed_probe,
            &[template],
            domain,
            Some(&mut trace),
        )
        .unwrap();
        assert_eq!(output.metrics.total_pbs_count, 48);
        assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 1);
        assert_eq!(trace.fused_boolean_bits_3_to_6.len(), 1);
        assert_eq!(trace.fused_boolean_bits_3_to_6[0].len(), 4);
        for (offset, bit) in trace.fused_boolean_bits_3_to_6[0].iter().enumerate() {
            assert_eq!(decode_big(bit, BOOL_DELTA_LOG), (x >> (offset + 3)) & 1);
        }
        assert_eq!(trace.reused_bit7.len(), 1);
        assert_eq!(
            decode_big(&trace.reused_bit7[0], BOOL_DELTA_LOG),
            (x >> 7) & 1
        );
    }

    let tie_domain = ScoreDomain {
        lower: -10,
        upper: MAX_DOMAIN_WIDTH - 11,
    };
    for (thresholds, expected_code) in [([-1, 100], 0), ([0, -1], 1)] {
        let templates = [
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: thresholds[0],
            },
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: thresholds[1],
            },
        ];
        let output = private_argmin(&server_key, &packed_probe, &templates, tie_domain).unwrap();
        assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), expected_code);
        assert_eq!(
            output.metrics.total_pbs_count,
            expected_pbs_count_for_thresholds(2, &thresholds, tie_domain).unwrap()
        );
    }
}

#[test]
#[ignore = "micro-diagnostica FHE A34-top: genera una chiave fresca ed esegue il core completo"]
fn aligned_a34_top_core_preserves_boundaries_reject_ties_and_exact_id() {
    use crate::compat::{ClientKey, ServerKey};
    use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;

    let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _, parameters) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let polynomial_size = glwe_secret_key.polynomial_size();
    let modulus = CiphertextModulus::<u64>::new_native();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut encrypt_zero_probe = || {
        let mut packed_probe = GlweCiphertext::new(
            0u64,
            glwe_secret_key.glwe_dimension().to_glwe_size(),
            polynomial_size,
            modulus,
        );
        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut packed_probe,
            &PlaintextList::new(0u64, PlaintextCount(polynomial_size.0)),
            parameters.glwe_noise_distribution(),
            &mut generator,
        );
        packed_probe
    };
    let decode_big = |ciphertext: &Lwe, delta_log: u32| {
        decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
            .0
            .wrapping_add(1u64 << (delta_log - 1))
            >> delta_log
    };
    let zero_template = [0i64; PROBE_DIM];
    for x in [
        0u64, 256, 512, 768, 1023, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 2816, 3072, 3328,
        3584, 3840, 4095,
    ] {
        let domain = ScoreDomain {
            lower: -(x as i64),
            upper: -(x as i64) + MAX_DOMAIN_WIDTH - 1,
        };
        let threshold = domain.lower + ALIGNED_UNIFORM_THRESHOLD;
        let template = TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold,
        };
        let mut trace = PrivateArgminTrace::default();
        let output = private_argmin_impl(
            &server_key,
            &encrypt_zero_probe(),
            &[template],
            domain,
            Some(&mut trace),
        )
        .unwrap();
        let h = x >> 8;
        let accepted = x <= ALIGNED_UNIFORM_THRESHOLD as u64;
        assert!(trace.aligned_fast_path);
        assert_eq!(output.metrics.total_pbs_count, 29);
        assert_eq!(output.metrics.extract.pbs_count, 13);
        assert_eq!(output.metrics.select.pbs_count, 13);
        assert_eq!(output.metrics.scan.pbs_count, 1);
        assert_eq!(output.metrics.threshold.pbs_count, 0);
        assert_eq!(output.metrics.output.pbs_count, 2);
        assert_eq!(
            decode_big(&output.code, CODE_DELTA_LOG),
            u64::from(accepted)
        );
        assert_eq!(trace.aligned_residuals.len(), 1);
        assert_eq!(
            decode_big(&trace.aligned_residuals[0], FULL_DELTA_LOG + 8) & 15,
            h
        );
        assert_eq!(
            decode_big(&trace.a34_top_codes[0], BOOL_DELTA_LOG) & 31,
            A34_TOP_CLASSIFIER_CODES[h as usize]
        );
        let expected_category = match h {
            0 => 1,
            1 => 3,
            2 => 7,
            _ => 0,
        };
        assert_eq!(
            decode_big(&trace.a34_canonical_categories[0], BOOL_DELTA_LOG) & 31,
            expected_category
        );
        assert_eq!(
            decode_big(trace.a34_global_category.as_ref().unwrap(), BOOL_DELTA_LOG) & 31,
            expected_category
        );
        assert_eq!(
            decode_big(&trace.aligned_initial_candidates[0], BOOL_DELTA_LOG),
            u64::from(accepted)
        );
        assert!(trace.accept_tag.is_none());
        assert!(trace.selected_threshold_bits_msb_first.is_empty());
        assert!(trace.selected_below.is_none());
    }

    let mut unit_template = [0i64; PROBE_DIM];
    unit_template[0] = 1;
    let run_pair = |first: TemplateView<'_>,
                    second: TemplateView<'_>,
                    domain: ScoreDomain,
                    expected_code: u64,
                    expected_winners: [u64; 2],
                    packed_probe: Glwe| {
        let mut trace = PrivateArgminTrace::default();
        let output = private_argmin_impl(
            &server_key,
            &packed_probe,
            &[first, second],
            domain,
            Some(&mut trace),
        )
        .unwrap();
        assert!(trace.aligned_fast_path);
        assert_eq!(output.metrics.total_pbs_count, 67);
        assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), expected_code);
        assert_eq!(trace.winners.len(), 2);
        assert_eq!(
            trace
                .winners
                .iter()
                .map(|winner| decode_big(winner, BOOL_DELTA_LOG))
                .collect::<Vec<_>>(),
            expected_winners
        );
    };

    // Il primo score e' 1 (x'=1024, rifiutato), il secondo 0 (x'=1023, accettato).
    // I bit bassi del primo sono tutti zero: il test impedisce che la scorciatoia del primo
    // livello lo faccia risorgere dopo il pre-filtro.
    run_pair(
        TemplateView {
            template: &unit_template,
            norm2: 1,
            threshold: 0,
        },
        TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: 0,
        },
        ScoreDomain {
            lower: -1023,
            upper: 65,
        },
        2,
        [0, 1],
        encrypt_zero_probe(),
    );
    run_pair(
        TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: 0,
        },
        TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: 0,
        },
        ScoreDomain {
            lower: -1023,
            upper: 0,
        },
        1,
        [1, 0],
        encrypt_zero_probe(),
    );
    run_pair(
        TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: -1,
        },
        TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: -1,
        },
        ScoreDomain {
            lower: -1024,
            upper: 0,
        },
        0,
        [0, 0],
        encrypt_zero_probe(),
    );

    // La galleria primaria esercita il tail dispari della riduzione binaria e rende osservabili
    // i conteggi progettuali completi. I template non nulli propagano il rumore del probe nel
    // prodotto; tutti i punteggi sono pari a uno e ammessi, quindi il primo tie resta ID 1.
    let large_gallery = vec![
        TemplateView {
            template: &unit_template,
            norm2: 1,
            threshold: 1,
        };
        127
    ];
    let output = private_argmin(
        &server_key,
        &encrypt_zero_probe(),
        &large_gallery,
        ScoreDomain {
            lower: -1022,
            upper: 65,
        },
    )
    .unwrap();
    assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 1);
    assert_eq!(output.metrics.extract.pbs_count, 1651);
    assert_eq!(output.metrics.select.pbs_count, 2121);
    assert_eq!(output.metrics.scan.pbs_count, 222);
    assert_eq!(output.metrics.threshold.pbs_count, 0);
    assert_eq!(output.metrics.output.pbs_count, 150);
    assert_eq!(output.metrics.total_pbs_count, 4144);

    let mut max_id_gallery = vec![
        TemplateView {
            template: &unit_template,
            norm2: 1,
            threshold: 4,
        };
        127
    ];
    max_id_gallery.push(TemplateView {
        template: &zero_template,
        norm2: 0,
        threshold: 4,
    });
    let output = private_argmin(
        &server_key,
        &encrypt_zero_probe(),
        &max_id_gallery,
        ScoreDomain {
            lower: -1019,
            upper: 65,
        },
    )
    .unwrap();
    assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 128);
    assert_eq!(output.metrics.total_pbs_count, 4174);
}
