//! Fixed first composition: original fixture7, shared actual comparator, D2/scalar/D1.
use super::*;

const SOURCE_ID: &str = include_str!("../../SOURCE_DIGEST.txt");

fn plan(execute: bool) -> serde_json::Value {
    json!({"record":"plan","schema":"a191.comparator_pfks.v1","execution_requested":execute,
        "fixture_index":7,"fixture":"right_low_nibble_boundary","left":[0,1,0,126],"right":[0,0,15,127],
        "comparator_stages":["ternary/top","ternary/middle","ternary/low","final/control"],
        "selector_order":["direct_window","scalar_d2","direct_d1"],"keys":1,"cases":1,
        "records":48,"pfks":20,"ks":10,"br":10,"samples":16,
        "input_lwe_encryptions":8,"supplied_control_encryptions":0,"functional_keys":2,
        "diagnostic_extra_crypto":0,"score_to_limb_bridge":false,"tournament":false,
        "tie_or_threshold_runtime_gate":false,"timing_allowed":false,"automatic_expansion":false})
}

fn run(binary_expected: &str) -> Result<bool, String> {
    if env::var("A191_RUN_ACK").as_deref() != Ok("A191_FIRST_COMPARATOR_AUTHORIZED")
        || env::var("A191_SOURCE_SHA256").as_deref() != Ok(SOURCE_ID.trim())
        || env::var("RAYON_NUM_THREADS").as_deref() != Ok("1")
    {
        return Err("requires exact A191 authorization/source/thread environment".into());
    }
    let executable = env::current_exe().map_err(|e| e.to_string())?;
    if !executable
        .components()
        .any(|x| x.as_os_str() == "target-a191-only")
    {
        return Err("requires isolated target-a191-only".into());
    }
    let binary_hash = observer::hash_bytes(&std::fs::read(&executable).map_err(|e| e.to_string())?);
    if binary_hash != binary_expected {
        return Err("actual binary hash differs".into());
    }
    emit(plan(true));
    let parameters = PfksParameters::P24X1;
    let modulus = CiphertextModulus::<u64>::new_native();
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server = ServerKey::new(&client);
    let (glwe_secret, small_secret, params) = client.into_raw_parts();
    let big = glwe_secret.as_lwe_secret_key();
    let small = small_secret.as_view();
    assert_eq!(big.lwe_dimension().0, 2048);
    assert_eq!(small.lwe_dimension().0, 859);
    assert_eq!(glwe_secret.polynomial_size().0, 2048);
    assert_eq!(glwe_secret.glwe_dimension().0, 1);
    assert_eq!(server.key_switching_key.decomposition_base_log().0, 3);
    assert_eq!(server.key_switching_key.decomposition_level_count().0, 5);
    let bsk = match &server.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k,
        _ => return Err("classic Fourier BSK required".into()),
    };
    assert_eq!(bsk.output_lwe_dimension(), big.lwe_dimension());
    assert_eq!(
        server.key_switching_key.input_key_lwe_dimension(),
        big.lwe_dimension()
    );
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let make_key = || {
        LwePrivateFunctionalPackingKeyswitchKey::new(
            0u64,
            DecompositionBaseLog(24),
            DecompositionLevelCount(1),
            big.lwe_dimension(),
            GlweSize(2),
            PolynomialSize(2048),
            modulus,
        )
    };
    let mut constant_key = make_key();
    let mut negative_identity = Polynomial::new(0u64, PolynomialSize(2048));
    negative_identity[0] = u64::MAX;
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big,
        &glwe_secret,
        &mut constant_key,
        params.glwe_noise_distribution(),
        &mut generator,
        |v| v.wrapping_neg(),
        &negative_identity,
    );
    let mut window_key = make_key();
    let base_window = signed_cell_mask(PolynomialSize(2048), 0);
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big,
        &glwe_secret,
        &mut window_key,
        params.glwe_noise_distribution(),
        &mut generator,
        |v| v,
        &base_window,
    );
    let fixture = FIXTURES[7];
    let mut encrypt = |message| {
        let mut ct = LweCiphertext::new(0u64, big.lwe_dimension().to_lwe_size(), modulus);
        encrypt_lwe_ciphertext(
            &big,
            &mut ct,
            Plaintext(message),
            params.glwe_noise_distribution(),
            &mut generator,
        );
        ct
    };
    let left: Vec<Lwe> = fixture
        .left
        .iter()
        .zip(PAYLOAD_DELTAS)
        .map(|(&v, d)| encrypt(v.wrapping_mul(d)))
        .collect();
    let right: Vec<Lwe> = fixture
        .right
        .iter()
        .zip(PAYLOAD_DELTAS)
        .map(|(&v, d)| encrypt(v.wrapping_mul(d)))
        .collect();
    let stages = comparator::evaluate(&left, &right, &server);
    let control = &stages[3].output;
    // Exactly the same ciphertext and original payload objects enter all arms.
    let (direct_outputs, direct_control, direct_metrics, direct_trace) = direct_window_d2_select(
        &left,
        &right,
        control,
        &window_key,
        &server.key_switching_key,
        bsk,
    );
    let (left_mask, right_mask) = a30_scalar_selector_masks(PolynomialSize(2048));
    let fft = Fft::new(PolynomialSize(2048));
    let fft_view = fft.as_view();
    let requirement = fft_view
        .forward_scratch()
        .expect("FFT scratch")
        .and(fft_view.backward_scratch().expect("FFT scratch"));
    let mut memory = GlobalPodBuffer::new(requirement);
    let stack = PodStack::new(&mut memory);
    let (scalar_outputs, scalar_controls, scalar_metrics) = scalar_d2_select_tuple(
        &left,
        &right,
        control,
        &constant_key,
        &server.key_switching_key,
        bsk,
        &left_mask,
        &right_mask,
        fft_view,
        &mut *stack,
    );
    let (d1_outputs, d1_control, d1_metrics, d1_trace) = d1::select(
        &left,
        &right,
        control,
        &window_key,
        &server.key_switching_key,
        bsk,
    );
    // No client observations/decryption until all ten KS/BR calls have finished.
    emit(
        json!({"record":"meta","schema":"a191.comparator_pfks.v1","keyset":0,"process_id":std::process::id(),
        "source_id":SOURCE_ID.trim(),"binary_sha256":binary_hash,"params_fingerprint":PARAMS_FINGERPRINT,
        "tfhe":"0.11.3","big_dimension":2048,"small_dimension":859,"glwe_size":2,"polynomial_size":2048,
        "pfks_base_log":24,"pfks_levels":1,"ks_base_log":3,"ks_levels":5,
        "key_family_ids":{"constant":observer::hash_words(constant_key.as_ref()),"window":observer::hash_words(window_key.as_ref()),
            "big":observer::hash_words(big.as_ref()),"small":observer::hash_words(small.as_ref()),"ordinary_ksk":observer::hash_words(server.key_switching_key.as_ref())},
        "main_sha256":observer::hash_bytes(include_bytes!("main.rs")),"comparator_sha256":observer::hash_bytes(include_bytes!("comparator.rs")),
        "driver_sha256":observer::hash_bytes(include_bytes!("a191.rs")),"d1_sha256":observer::hash_bytes(include_bytes!("d1.rs")),
        "observer_sha256":observer::hash_bytes(include_bytes!("observer.rs")),"lock_sha256":observer::hash_bytes(include_bytes!("../Cargo.lock")),
        "all_server_arms_complete_before_observations":true,"raw_secret_bits_serialized":false,"timing_allowed":false}),
    );
    let mut ingress = true;
    for (side, payloads, values) in [
        ("left", &left, fixture.left),
        ("right", &right, fixture.right),
    ] {
        for j in 0..4 {
            let audit = phase_audit(&big, &payloads[j], values[j], PAYLOAD_DELTAS[j]);
            let pass = audit.decode_pass && audit.half_slot_pass && nontrivial(&payloads[j]);
            ingress &= pass;
            emit(
                json!({"record":"payload","schema":"a191.comparator_pfks.v1","keyset":0,"side":side,"lane":j,
                "value":values[j],"delta_log":if j==3 {56} else {59},"lwe":comparator::lwe(&payloads[j],&big),
                "audit":audit_json(audit,&payloads[j],PAYLOAD_DELTAS[j]),"native_pass":pass}),
            );
        }
    }
    let mut comparator_pass = true;
    for (stage, raw_expected) in stages.iter().zip([0i64, 1, -1, 4]) {
        let expected = if stage.final_control {
            12 * SCORE_DELTA
        } else {
            (raw_expected as u64).wrapping_mul(SCORE_DELTA)
        };
        let (record, pass) = comparator::observe(
            stage,
            raw_expected,
            expected,
            &big,
            &small,
            &server.key_switching_key,
        );
        emit(record);
        comparator_pass &= pass;
    }
    let controls: Vec<(&str, &Lwe)> = std::iter::once(("direct_window", &direct_control))
        .chain(
            scalar_controls
                .iter()
                .enumerate()
                .map(|(i, c)| (["scalar/0", "scalar/1", "scalar/2", "scalar/3"][i], c)),
        )
        .chain(std::iter::once(("direct_d1", &d1_control)))
        .collect();
    let controls_equal = controls
        .iter()
        .all(|(_, c)| lwe_bitwise_equal(c, &direct_control));
    let mut support = true;
    let mut controls_native = true;
    let mut control_observers = true;
    for (arm, ct) in controls {
        let obs = comparator::switched(control, ct, &big, &small, &server.key_switching_key);
        let degree = obs["actual_address"].as_u64().unwrap() as usize;
        let error = centered_degree_error(degree, 1536);
        let within = error.abs() <= STRICT_RADIUS;
        let audit = phase_audit(&small, ct, 12, SCORE_DELTA);
        let native = audit.decode_pass && audit.half_slot_pass;
        let closure = obs["coefficient_identity_pass"] == true
            && obs["input"]["direct_phase_matches"] == true
            && obs["small"]["direct_phase_matches"] == true;
        support &= within;
        controls_native &= native;
        control_observers &= closure;
        emit(
            json!({"record":"selector_control","schema":"a191.comparator_pfks.v1","keyset":0,"arm":arm,
            "ks_observation":obs,"expected_control":12,"expected_center":1536,"support_radius":63,
            "effective_error":error,"support_pass":within,"native_pass":native,"observer_pass":closure,
            "same_actual_comparator":true,"control_sha256":hash_lwe(control),"ordinary_ks_calls":1}),
        );
    }
    let expected = fixture.expected();
    let mut direct_ok = true;
    let mut scalar_ok = true;
    let mut d1_ok = true;
    for j in 0..4 {
        let delta = PAYLOAD_DELTAS[j];
        let da = phase_audit(&big, &direct_outputs[j], expected[j], delta);
        let sa = phase_audit(&big, &scalar_outputs[j], expected[j], delta);
        let oa = phase_audit(&big, &d1_outputs[j], expected[j], delta);
        direct_ok &= lane_pass(da, &direct_outputs[j]) && da.decoded == sa.decoded;
        scalar_ok &= lane_pass(sa, &scalar_outputs[j]);
        d1_ok &= lane_pass(oa, &d1_outputs[j]) && oa.decoded == sa.decoded;
        emit(
            json!({"record":"selector_lane","schema":"a191.comparator_pfks.v1","keyset":0,"lane":j,"expected":expected[j],
            "delta_log":if j==3 {56} else {59},"direct":audit_json(da,&direct_outputs[j],delta),"scalar":audit_json(sa,&scalar_outputs[j],delta),
            "direct_d1":audit_json(oa,&d1_outputs[j],delta),"direct_lwe":comparator::lwe(&direct_outputs[j],&big),
            "scalar_lwe":comparator::lwe(&scalar_outputs[j],&big),"d1_lwe":comparator::lwe(&d1_outputs[j],&big)}),
        );
    }
    let direct_observer = observer::observe_arm(
        "direct_window",
        true,
        fixture,
        &left,
        &right,
        control,
        &direct_control,
        &direct_outputs,
        &direct_trace,
        &glwe_secret,
        &small,
        parameters,
    );
    let d1_observer = d1::observe(
        fixture,
        &left,
        &right,
        control,
        &d1_control,
        &d1_outputs,
        &d1_trace,
        &glwe_secret,
        &small,
        parameters,
    );
    let control_ok = controls_equal && controls_native && control_observers;
    let prerequisites =
        ingress && comparator_pass && control_ok && scalar_ok && scalar_metrics.counters_pass();
    let direct_class = classify_case(
        support,
        prerequisites && direct_metrics.counters_pass() && direct_observer,
        direct_ok,
    );
    let d1_class = classify_case(
        support,
        prerequisites && direct_class == "pass" && d1_metrics.pass() && d1_observer,
        d1_ok,
    );
    let complete = direct_class == "pass" && d1_class == "pass";
    emit(
        json!({"record":"case","schema":"a191.comparator_pfks.v1","keyset":0,"fixture_index":7,
        "ingress_pass":ingress,"comparator_pass":comparator_pass,"all_six_control_bytes_equal":controls_equal,
        "controls_native_pass":controls_native,"control_observers_pass":control_observers,"actual_support_pass":support,
        "scalar_pass":scalar_ok,"direct_pass":direct_ok,"d1_pass":d1_ok,"prerequisites_pass":prerequisites,
        "direct_observer_pass":direct_observer,"d1_observer_pass":d1_observer,"direct_class":direct_class,"d1_class":d1_class,
        "direct_counters_pass":direct_metrics.counters_pass(),"scalar_counters_pass":scalar_metrics.counters_pass(),"d1_counters":d1_metrics.json(),
        "actual_counts":{"comparator_ks":stages.iter().map(|s|s.ks).sum::<usize>(),"comparator_br":stages.iter().map(|s|s.br).sum::<usize>(),"comparator_samples":stages.iter().map(|s|s.samples).sum::<usize>(),
            "direct_pfks":direct_metrics.pfks_calls,"direct_ks":direct_metrics.control_ks_calls,"direct_br":direct_metrics.blind_rotations,"direct_samples":direct_metrics.sample_extractions,
            "scalar_pfks":scalar_metrics.pfks_calls,"scalar_ks":scalar_metrics.control_ks_calls,"scalar_br":scalar_metrics.blind_rotations,"scalar_samples":scalar_metrics.sample_extractions},
        "pass":complete}),
    );
    emit(
        json!({"record":"summary","schema":"a191.comparator_pfks.v1","process_id":std::process::id(),"keysets":1,"cases":1,"records":48,
        "gate_pass":complete,"status":if complete {"A191_FIRST_COMPOSITION_PASS"} else {"A191_COMPLETE_NEGATIVE"},
        "pfks":20,"ks":10,"br":10,"samples":16,"actual_comparator":true,"supplied_selector":false,
        "full_id":false,"score_bridge":false,"tie_threshold_exercised":false,"actual_p_fail":null,"timing_allowed":false,"automatic_expansion":false}),
    );
    Ok(complete)
}

pub(super) fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        emit(plan(false));
        return;
    }
    if args.len() != 2 || args[0] != "--run" || !args[1].starts_with("--expected-binary-sha256=") {
        eprintln!("A191_INVALID: expected no arguments or --run --expected-binary-sha256=SHA256");
        std::process::exit(2);
    }
    let hash = args[1].strip_prefix("--expected-binary-sha256=").unwrap();
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        eprintln!("A191_INVALID: canonical binary SHA256 required");
        std::process::exit(2);
    }
    match run(hash) {
        Ok(true) => (),
        Ok(false) => {
            eprintln!(
                "A191_COMPLETE_NEGATIVE: preserve first comparator/selector outcomes without retry"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("A191_INVALID: {error}");
            std::process::exit(2);
        }
    }
}
