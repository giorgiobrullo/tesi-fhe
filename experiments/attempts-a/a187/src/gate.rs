fn main() {
    if let Err(error) = run187() {
        eprintln!("A187_ERROR: {error}");
        std::process::exit(1);
    }
}

fn hash_words(words: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn run187() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let execute = args.iter().any(|x| x == "--run");
    let expected_binary = args
        .iter()
        .find_map(|x| x.strip_prefix("--expected-binary-sha256="));
    if args.len() != if execute { 2 } else { 0 }
        || args
            .iter()
            .any(|x| x != "--run" && !x.starts_with("--expected-binary-sha256="))
    {
        return Err("only noargs PLAN or --run plus one binary hash is permitted".into());
    }
    let arms = [
        "old_padding_separate",
        "direct54_sidecar51",
        "negative_consumer_x2",
    ];
    let counts = [63usize, 71, 71];
    let scores = &[255u64, 256, 254, 4095];
    println!(
        "{}",
        json!({"record":"plan","schema":"a187.precision_n4.v1","execution_requested":execute,
        "fixture_index":2,"scores":scores,"keysets":1,"arms":arms,"pbs_ks_per_arm":counts,
        "pbs":205,"ks":205,"input_glwe_encryptions":1,"public_glwe_products":4,
        "input_sample_extractions":8,"pbs_output_sample_extractions":205,"total_sample_extractions":213,
        "raw_records":211,"timing_allowed":false,"automatic_expansion":false,
        "survivor_flags_only":true,"coefficient_degree_replay_is_extra_crypto_ms":false})
    );
    if !execute {
        return Ok(());
    }
    let source_id = include_str!("../SOURCE_DIGEST.txt").trim();
    if std::env::var("A187_RUN_ACK").as_deref() != Ok("A187_FIRST_N4_AUTHORIZED")
        || std::env::var("A187_SOURCE_SHA256").as_deref() != Ok(source_id)
        || std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("1")
    {
        return Err("requires actual A187 source/authorization/thread environment".into());
    }
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    if !binary
        .components()
        .any(|x| x.as_os_str() == "target-a187-only")
    {
        return Err("requires isolated target-a187-only".into());
    }
    let binary_hash = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&binary).map_err(|e| e.to_string())?)
    );
    if expected_binary != Some(binary_hash.as_str()) {
        return Err("actual binary hash mismatch".into());
    }
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("../REFERENCE.json")).map_err(|e| e.to_string())?;
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let server = ServerKey::new(&client);
    let (glwe_secret, small_secret, parameters) = client.into_raw_parts();
    let big_secret = glwe_secret.as_lwe_secret_key();
    assert_eq!(big_secret.lwe_dimension().0, 2048);
    assert_eq!(small_secret.lwe_dimension().0, 859);
    let modulus = CiphertextModulus::new_native();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let (full, low) = include!("input_construction.rs");
    println!(
        "{}",
        json!({"record":"provenance","schema":"a187.precision_n4.v1","source_id":source_id,
        "binary_sha256":binary_hash,"child_pid":std::process::id(),"reference_sha256":format!("{:x}",Sha256::digest(include_bytes!("../REFERENCE.json"))),
        "params":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "parameter_fingerprint":"b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1",
        "big_key_sha256":hash_words(big_secret.as_ref()),"small_key_sha256":hash_words(small_secret.as_ref()),
        "raw_secret_bits_serialized":false,"key_sensitive_client_local_only":true})
    );
    let old = evaluate(&full, &low, &server, ARMS[3]);
    let old = precision::Output {
        correction_low: old.low.clone(),
        correction_middle: old.middle.clone(),
        evaluation: old,
        refreshes: 0,
    };
    let new = precision::evaluate(&full, &low, &server, false);
    let negative = precision::evaluate(&full, &low, &server, true);
    let evaluations = [old, new, negative];
    // All 205 server KS/PBS calls complete before any client output diagnostics.
    let expected = [0u64, 0, 1, 0];
    let phase = |ct: &Lwe| decrypt_lwe_ciphertext(&big_secret, ct).0;
    let decoded = |ct: &Lwe, log: u32| phase(ct).wrapping_add(1 << (log - 1)) >> log;
    let words = |cts: &[Lwe]| cts.iter().map(|x| phase(x).to_string()).collect::<Vec<_>>();
    let errors = |cts: &[Lwe], log: u32, shift: u32, mask: u64| {
        cts.iter()
            .zip(scores)
            .map(|(ct, x)| {
                (phase(ct).wrapping_sub(((x >> shift) & mask).wrapping_shl(log)) as i64).to_string()
            })
            .collect::<Vec<_>>()
    };
    let strict = |cts: &[Lwe], log: u32, shift: u32, mask: u64| {
        cts.iter().zip(scores).all(|(ct, x)| {
            let want = (x >> shift) & mask;
            decoded(ct, log) == want
                && (phase(ct).wrapping_sub(want << log) as i64 as i128).abs() < (1i128 << (log - 1))
        })
    };
    let mut cases = Vec::new();
    let mut event_count = 0;
    for (arm, output) in evaluations.iter().enumerate() {
        let ev = &output.evaluation;
        let mut preimages = true;
        let mut closure = true;
        let mut stock_degrees = true;
        assert_eq!(ev.events.len(), counts[arm]);
        let refs = reference["arms"][arm]["events"].as_array().unwrap();
        assert_eq!(refs.len(), ev.events.len());
        for (event, nominal) in ev.events.iter().zip(refs) {
            let input_phase = phase(&event.input);
            let small_phase = decrypt_lwe_ciphertext(&small_secret, &event.switched).0;
            let output_phase = phase(&event.output);
            let mut address = switch_word(*event.switched.get_body().data) as i64;
            for (a, s) in event
                .switched
                .get_mask()
                .as_ref()
                .iter()
                .zip(small_secret.as_ref())
            {
                address -= switch_word(*a) as i64 * *s as i64;
            }
            let address = address.rem_euclid(4096) as usize;
            let coefficient = coefficient_observer::observe(
                event.switched.as_ref(),
                small_secret.as_ref(),
                small_phase,
                address,
                0,
            );
            let degrees_match_stock = event.switched.as_ref().iter().all(|x| {
                switch_word(*x) as usize
                    == tfhe::core_crypto::fft_impl::common::pbs_modulus_switch(
                        *x,
                        PolynomialSize(2048),
                    )
            });
            let body_hash = hash_words(&event.body);
            assert_eq!(nominal["stage"].as_str(), Some(event.name.as_str()));
            assert_eq!(nominal["body_sha256"].as_str(), Some(body_hash.as_str()));
            let expected_word: u64 = nominal["expected_lut_word"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let raw = event.body[address % 2048];
            let raw = if address >= 2048 {
                raw.wrapping_neg()
            } else {
                raw
            };
            let preimage = raw == expected_word;
            preimages &= preimage;
            closure &= coefficient["closure_pass"].as_bool() == Some(true);
            stock_degrees &= degrees_match_stock;
            println!(
                "{}",
                json!({"record":"event","keyset":0,"case":2,"arm":arm,"stage":event.name,
                "input_sha256":digest(&event.input),"small_sha256":digest(&event.switched),"output_sha256":digest(&event.output),
                "body_sha256":body_hash,"big_phase_word":input_phase.to_string(),"small_phase_word":small_phase.to_string(),
                "output_phase_word":output_phase.to_string(),"ks_phase_increment":(small_phase.wrapping_sub(input_phase) as i64).to_string(),
                "rounded_big_phase_address":switch_word(input_phase),"rounded_small_phase_address":switch_word(small_phase),
                "actual_ms_address":address,"lut_word_at_actual_address":raw.to_string(),"expected_lut_word":expected_word.to_string(),
                "exact_preimage_pass":preimage,"output_error_at_actual_address":(output_phase.wrapping_sub(raw) as i64).to_string(),
                "stock_degree_formula_match":degrees_match_stock,"coefficient_observer":coefficient,"client_only":true})
            );
            event_count += 1;
        }
        let digit_log = if arm == 0 { 51 } else { 54 };
        let flags: Vec<_> = ev.flags.iter().map(|x| decoded(x, 59)).collect();
        let low_native = strict(&ev.low, digit_log, 0, 15);
        let middle_native = strict(&ev.middle, digit_log, 4, 15);
        let top_native = strict(&ev.top, 60, 8, 15);
        let sidecar_native = strict(&output.correction_low, 51, 0, 15)
            && strict(&output.correction_middle, 51, 4, 15);
        let final_exact = flags == expected;
        let final_native = ev.flags.iter().zip(expected).all(|(ct, want)| {
            decoded(ct, 59) == want
                && (phase(ct).wrapping_sub(want << 59) as i64 as i128).abs() < (1i128 << 58)
        });
        // Historical A149 acceptance used these exact decodes, without the new preimage gate.
        let old_decode = ev
            .low
            .iter()
            .zip(scores)
            .all(|(ct, x)| decoded(ct, 51) == (x & 15))
            && ev
                .middle
                .iter()
                .zip(scores)
                .all(|(ct, x)| decoded(ct, 51) == ((x >> 4) & 15))
            && ev
                .top
                .iter()
                .zip(scores)
                .all(|(ct, x)| decoded(ct, 60) == (x >> 8));
        let joint = low_native
            && middle_native
            && top_native
            && final_native
            && preimages
            && closure
            && stock_degrees;
        let case = json!({"record":"case","arm":arm,"arm_name":arms[arm],"keyset":0,"case":2,"scores":scores,
            "full_sha256":full.iter().map(digest).collect::<Vec<_>>(),"packed_low_sha256":low.iter().map(digest).collect::<Vec<_>>(),
            "input_full_errors":errors(&full,52,0,4095),"input_packed_low_errors":errors(&low,60,0,15),
            "digit_log":digit_log,"low_words":words(&ev.low),"middle_words":words(&ev.middle),"top_words":words(&ev.top),"flag_words":words(&ev.flags),
            "correction_low_words":words(&output.correction_low),"correction_middle_words":words(&output.correction_middle),
            "low_native_pass":low_native,"middle_native_pass":middle_native,"top_native_pass":top_native,
            "old_sidecar_native_diagnostic":sidecar_native,"final_native_pass":final_native,"final_flags_pass":final_exact,
            "flags":flags,"expected_flags":expected,"all_preimages_pass":preimages,"coefficient_closure_pass":closure,
            "stock_degree_formula_pass":stock_degrees,"joint_gate_pass":joint,
            "old_a149_functional_pass":if arm==0 {Some(old_decode&&final_exact)} else {None},
            "wrong_scale_detected":if arm==2 {Some(!final_exact)} else {None},
            "br":ev.events.len(),"ks":ev.events.len(),"refreshes":output.refreshes});
        println!("{case}");
        cases.push(case);
    }
    let gate = cases[1]["joint_gate_pass"] == true
        && cases[2]["wrong_scale_detected"] == true
        && cases.iter().all(|c| {
            c["coefficient_closure_pass"] == true && c["stock_degree_formula_pass"] == true
        })
        && event_count == 205;
    println!(
        "{}",
        json!({"record":"summary","status":if gate {"A187_FIRST_N4_GATE_PASS"} else {"A187_COMPLETE_NEGATIVE"},
        "gate_pass":gate,"old_a149_functional_pass":cases[0]["old_a149_functional_pass"],"new_joint_gate_pass":cases[1]["joint_gate_pass"],
        "wrong_scale_detected":cases[2]["wrong_scale_detected"],"coefficient_events":event_count,"pbs":205,"ks":205,
        "input_glwe_encryptions":1,"public_glwe_products":4,"input_sample_extractions":8,"pbs_output_sample_extractions":205,
        "actual_coefficient_degree_replays":205,"extra_crypto_ms_calls":0,"refresh_calls":0,
        "formal_tail":false,"latency_claim":false,"a53_or_service":false,"keysets":1,"cases":1})
    );
    if !gate {
        return Err(
            "complete changed-precision gate failed; preserve old and new outcomes without retry"
                .into(),
        );
    }
    Ok(())
}
