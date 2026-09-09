#![recursion_limit = "256"]
use integrate_frontier_nibble_id::nibble::{self, Glwe, Lwe};
use integrate_frontier_nibble_id::{
    a126_aligned_operation_counts, clear_private_argmin, integration_scan_flags,
    plan_private_argmin_execution, private_argmin_a126, TemplateView, A44_PARAMETER_BINDING,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::{ClientKey, ServerKey};
mod coefficient_observer;
fn hash_words(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for x in words {
        h.update(x.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
fn digest(ct: &Lwe) -> String {
    hash_words(ct.as_ref())
}
fn degree(x: u64) -> u64 {
    x.wrapping_add(1 << 51) >> 52
}
fn ints(v: &Value) -> Vec<i64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_i64().unwrap())
        .collect()
}
fn scene(f: &Value) -> (Vec<i64>, Vec<Vec<i64>>) {
    (
        ints(&f["probe"]),
        f["gallery"].as_array().unwrap().iter().map(ints).collect(),
    )
}
fn templates<'a>(g: &'a [Vec<i64>], threshold: i64) -> Vec<TemplateView<'a>> {
    g.iter()
        .map(|t| TemplateView {
            template: t,
            norm2: t.iter().map(|x| x * x).sum(),
            threshold,
        })
        .collect()
}
fn public_contract(
    f: &Value,
    q: &[i64],
    t: &[TemplateView<'_>],
) -> integrate_frontier_nibble_id::ScoreDomain {
    let p = plan_private_argmin_execution(t).unwrap();
    assert!(p.aligned_fast_path);
    let scores: Vec<_> = t
        .iter()
        .map(|t| t.norm2 - 2 * q.iter().zip(t.template).map(|(x, y)| x * y).sum::<i64>())
        .collect();
    assert_eq!(scores, ints(&f["raw_scores"]));
    assert_eq!(p.execution_domain.lower, f["lower"].as_i64().unwrap());
    assert_eq!(p.execution_domain.upper, f["upper"].as_i64().unwrap());
    assert_eq!(
        clear_private_argmin(&scores, t).unwrap().code,
        f["expected_code"].as_u64().unwrap()
    );
    p.execution_domain
}
fn words(cts: &[Lwe], phase: impl Fn(&Lwe) -> u64) -> Vec<String> {
    cts.iter().map(|x| phase(x).to_string()).collect()
}
fn native(cts: &[Lwe], wanted: &[u64], log: u32, phase: impl Fn(&Lwe) -> u64) -> bool {
    cts.len() == wanted.len()
        && cts.iter().zip(wanted).all(|(c, w)| {
            let p = phase(c);
            p.wrapping_add(1 << (log - 1)) >> log == *w
                && (p.wrapping_sub(w << log) as i64 as i128).abs() < (1i128 << (log - 1))
        })
}
fn output_data(
    out: &nibble::IntegratedOutput,
    expected: u64,
    phase: impl Fn(&Lwe) -> u64,
) -> Value {
    let phases = [phase(&out.low_digit), phase(&out.high_digit)];
    let digits = phases.map(|p| p.wrapping_add(1 << 58) >> 59);
    let code = digits[0] + 15 * digits[1];
    json!({"code":code,"digits":digits,"words":phases.map(|x|x.to_string()),"hashes":[digest(&out.low_digit),digest(&out.high_digit)],"br":out.br,"ks":out.ks,"pbs_samples":out.pbs_samples,"pass":code==expected&&digits[0]<15&&digits[1]<16&&phases.iter().zip([expected%15,expected/15]).all(|(p,w)|(p.wrapping_sub(w<<59)as i64 as i128).abs()<(1i128<<58))})
}
fn state_hashes(state: &nibble::precision::Output, roots: [&Lwe; 2]) -> Value {
    json!({"low":state.evaluation.low.iter().map(digest).collect::<Vec<_>>(),
 "middle":state.evaluation.middle.iter().map(digest).collect::<Vec<_>>(),
 "top":state.evaluation.top.iter().map(digest).collect::<Vec<_>>(),
 "flags":state.evaluation.flags.iter().map(digest).collect::<Vec<_>>(),
 "correction_low":state.correction_low.iter().map(digest).collect::<Vec<_>>(),
 "correction_middle":state.correction_middle.iter().map(digest).collect::<Vec<_>>(),
 "roots":roots.map(digest)})
}
fn run() -> Result<(), String> {
    let plans: Value = serde_json::from_str(include_str!("../../R3_CONTROL_STAGES.json")).unwrap();
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!(
            "{}",
            json!({"record":"plan","schema":"nibble_parallel_r3.v1","execution_requested":false,"stages":plans,"automatic_expansion":false})
        );
        return Ok(());
    }
    if args.len() != 3
        || args[0] != "--run"
        || !args[1].starts_with("--stage=")
        || !args[2].starts_with("--expected-binary-sha256=")
    {
        return Err("exact fixed stage and binary SHA required".into());
    }
    let stage = args[1].strip_prefix("--stage=").unwrap();
    let plan = plans.get(stage).ok_or("unknown stage")?;
    let source = include_str!("../SOURCE_DIGEST.txt").trim();
    if std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("8")
        || std::env::var("INTEGRATE_FRONTIER_R3_ACK").as_deref() != Ok("FIXED_PARALLEL_ENDPOINT")
        || std::env::var("INTEGRATE_FRONTIER_R3_SOURCE").as_deref() != Ok(source)
    {
        return Err("exact eight-thread/source/ACK environment required".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        != Some("target-integrate-frontier-r3-only")
    {
        return Err("isolated target required".into());
    }
    let binary = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&exe).map_err(|e| e.to_string())?)
    );
    if args[2].strip_prefix("--expected-binary-sha256=") != Some(binary.as_str()) {
        return Err("actual binary hash mismatch".into());
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .map_err(|e| e.to_string())?;
    assert_eq!(pool.current_num_threads(), 8);
    let all: Value = serde_json::from_str(include_str!("../../R3_CONTROL_FIXTURES.json")).unwrap();
    let references: Value =
        serde_json::from_str(include_str!("../../R3_CONTROL_TARGET_REFERENCE.json")).unwrap();
    let n = plan["n"].as_u64().unwrap() as usize;
    let fixtures = &all[n.to_string()];
    let reference = &references[n.to_string()];
    let keys = plan["keysets"].as_u64().unwrap() as usize;
    let timing = plan["kind"] == "timing";
    println!(
        "{}",
        json!({"record":"start","schema":"nibble_parallel_r3.v1","stage":stage,"plan":plan,"source_id":source,"binary_sha256":binary,"pid":std::process::id(),"tfhe":"1.7.0","parameter_fingerprint":"ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61","rayon_pool_threads":8,"timed":timing,"automatic_expansion":false})
    );
    let mut all_pass = true;
    let mut completed = 0usize;
    let mut generated = 0usize;
    let mut identities = std::collections::HashSet::new();
    'keys: for keyset in 0..keys {
        let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let server = ServerKey::new(&client);
        let (glwe_secret, small_secret, parameters, _) = match client.atomic_pattern {
            AtomicPatternClientKey::Standard(k) => k.into_raw_parts(),
            _ => return Err("Standard client required".into()),
        };
        let big = glwe_secret.as_lwe_secret_key();
        let big_hash = hash_words(big.as_ref());
        let small_hash = hash_words(small_secret.as_ref());
        if !identities.insert(big_hash.clone()) || !identities.insert(small_hash.clone()) {
            return Err("duplicate key identity; no resampling".into());
        }
        generated += 1;
        println!(
            "{}",
            json!({"record":"key","keyset":keyset,"big_key_sha256":big_hash,"small_key_sha256":small_hash})
        );
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let indices: Vec<usize> = plan["fixture_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        // All public setup and GLWE encryption is outside every timing interval.
        let mut packed_queries = Vec::new();
        for index in &indices {
            let (q, g) = scene(&fixtures[*index]);
            let ts = templates(&g, fixtures[*index]["threshold"].as_i64().unwrap());
            public_contract(&fixtures[*index], &q, &ts);
            let mut plaintext = vec![0u64; 2048];
            for i in 0..512 {
                plaintext[i] = (q[i] as u64).wrapping_mul(1 << 52);
                plaintext[1024 + i] = (q[i] as u64).wrapping_mul(1 << 60);
            }
            let mut packed = Glwe::new(
                0,
                GlweSize(2),
                PolynomialSize(2048),
                CiphertextModulus::new_native(),
            );
            encrypt_glwe_ciphertext(
                &glwe_secret,
                &mut packed,
                &PlaintextList::from_container(plaintext),
                parameters.glwe_noise_distribution(),
                &mut generator,
            );
            assert!(packed.get_mask().as_ref().iter().any(|x| *x != 0));
            packed_queries.push(packed);
        }
        for (position, index) in indices.iter().copied().enumerate() {
            let f = &fixtures[index];
            let (q, g) = scene(f);
            let ts = templates(&g, f["threshold"].as_i64().unwrap());
            let domain = public_contract(f, &q, &ts);
            let packed = &packed_queries[position];
            let expected = f["expected_code"].as_u64().unwrap();
            let phase = |ct: &Lwe| decrypt_lwe_ciphertext(&big, ct).0;
            if timing {
                let order = plan["orders"][position].as_str().unwrap();
                let mut baseline = None;
                let mut parallel = None;
                let mut base_ns = 0u64;
                let mut parallel_ns = 0u64;
                for arm in if order == "baseline_parallel" {
                    [0, 1]
                } else {
                    [1, 0]
                } {
                    // Timer includes pool entry, the complete score->ID endpoint and its temporary drops.
                    // Oracle/decryption/hash/JSON and key/input preparation are outside both intervals.
                    let start = Instant::now();
                    if arm == 0 {
                        let out = pool
                            .install(|| {
                                private_argmin_a126(
                                    A44_PARAMETER_BINDING,
                                    &server,
                                    packed,
                                    &ts,
                                    domain,
                                )
                            })
                            .map_err(|e| format!("{e:?}"))?;
                        base_ns = start.elapsed().as_nanos().try_into().unwrap();
                        baseline = Some(out);
                    } else {
                        let out =
                            pool.install(|| nibble::parallel_nibble_id(&server, packed, &ts))?;
                        parallel_ns = start.elapsed().as_nanos().try_into().unwrap();
                        parallel = Some(out);
                    }
                }
                let b = baseline.unwrap();
                let count = a126_aligned_operation_counts(n).unwrap();
                let b_out = nibble::IntegratedOutput {
                    low_digit: b.low_digit,
                    high_digit: b.high_digit,
                    br: b.metrics.total_pbs_count as usize,
                    ks: count.key_switches as usize,
                    pbs_samples: count.output_marginals as usize,
                };
                let p = parallel.unwrap();
                let bj = output_data(&b_out, expected, phase);
                let pj = output_data(&p, expected, phase);
                let counts = bj["br"] == plan["ledger"]["baseline_br"]
                    && pj["br"] == plan["ledger"]["candidate_br"]
                    && pj["ks"] == plan["ledger"]["candidate_ks"]
                    && pj["pbs_samples"] == plan["ledger"]["candidate_pbs_samples"];
                let pass = bj["pass"] == true
                    && pj["pass"] == true
                    && counts
                    && base_ns > 0
                    && parallel_ns > 0;
                println!(
                    "{}",
                    json!({"record":"pair","position":position,"case":index,"keyset":keyset,"fixture_name":f["name"],"packed_sha256":hash_words(packed.as_ref()),"order":order,"warmup":position<2,"baseline_ns":base_ns,"parallel_ns":parallel_ns,"baseline":bj,"parallel":pj,"counts_pass":counts,"gate_pass":pass})
                );
                completed += 1;
                if !pass {
                    all_pass = false;
                    break 'keys;
                }
                continue;
            }
            let result = pool.install(|| nibble::parallel_diagnostic(&server, packed, &ts))?;
            let target = index == 0;
            let mut target_json = Value::Null;
            if target {
                let serial = pool.install(|| {
                    nibble::serial_reference(&result.full, &result.packed_low, &server, false, true)
                });
                let serial_scan = pool
                    .install(|| integration_scan_flags(&server, &serial.evaluation.flags))
                    .map_err(|e| format!("{e:?}"))?;
                let negative = pool.install(|| {
                    nibble::serial_reference(&result.full, &result.packed_low, &server, true, false)
                });
                let baseline = pool
                    .install(|| {
                        private_argmin_a126(A44_PARAMETER_BINDING, &server, packed, &ts, domain)
                    })
                    .map_err(|e| format!("{e:?}"))?;
                // Client diagnostics begin after every target server call.
                let equality = serial.evaluation.low == result.state.evaluation.low
                    && serial.evaluation.middle == result.state.evaluation.middle
                    && serial.evaluation.top == result.state.evaluation.top
                    && serial.evaluation.flags == result.state.evaluation.flags
                    && serial.correction_low == result.state.correction_low
                    && serial.correction_middle == result.state.correction_middle
                    && serial_scan.0 == result.endpoint.low_digit
                    && serial_scan.1 == result.endpoint.high_digit;
                let refs = reference["events"].as_array().unwrap();
                assert_eq!(serial.evaluation.events.len(), refs.len());
                let mut preimages = true;
                let mut closures = true;
                let mut stock = true;
                for (event, nominal) in serial.evaluation.events.iter().zip(refs) {
                    let small_phase = decrypt_lwe_ciphertext(&small_secret, &event.switched).0;
                    let mut address = degree(*event.switched.get_body().data) as i64;
                    for (a, s) in event
                        .switched
                        .get_mask()
                        .as_ref()
                        .iter()
                        .zip(small_secret.as_ref())
                    {
                        address -= degree(*a) as i64 * *s as i64;
                    }
                    let address = address.rem_euclid(4096) as usize;
                    let coefficient = coefficient_observer::observe(
                        event.switched.as_ref(),
                        small_secret.as_ref(),
                        small_phase,
                        address,
                        keyset,
                    );
                    let match_stock = event.switched.as_ref().iter().all(|x| {
                        degree(*x)
                            == tfhe::core_crypto::fft_impl::common::modulus_switch(
                                *x,
                                CiphertextModulusLog(12),
                            )
                    });
                    let body_hash = hash_words(&event.body);
                    assert_eq!(nominal["stage"].as_str(), Some(event.name.as_str()));
                    assert_eq!(nominal["body_sha256"].as_str(), Some(body_hash.as_str()));
                    let wanted: u64 = nominal["expected_lut_word"]
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
                    let preimage = raw == wanted;
                    preimages &= preimage;
                    closures &= coefficient["closure_pass"] == true;
                    stock &= match_stock;
                    let input_phase = phase(&event.input);
                    let output_phase = phase(&event.output);
                    println!(
                        "{}",
                        json!({"record":"event","keyset":keyset,"case":index,"stage":event.name,"input_sha256":digest(&event.input),"small_sha256":digest(&event.switched),"output_sha256":digest(&event.output),"body_sha256":body_hash,"big_phase_word":input_phase.to_string(),"small_phase_word":small_phase.to_string(),"output_phase_word":output_phase.to_string(),"ks_phase_increment":(small_phase.wrapping_sub(input_phase)as i64).to_string(),"rounded_big_phase_address":degree(input_phase),"rounded_small_phase_address":degree(small_phase),"actual_ms_address":address,"lut_word_at_actual_address":raw.to_string(),"expected_lut_word":wanted.to_string(),"exact_preimage_pass":preimage,"output_error_at_actual_address":(output_phase.wrapping_sub(raw)as i64).to_string(),"stock_degree_formula_match":match_stock,"coefficient_observer":coefficient})
                    );
                }
                let neg_flags: Vec<_> = negative
                    .evaluation
                    .flags
                    .iter()
                    .map(|ct| phase(ct).wrapping_add(1 << 58) >> 59)
                    .collect();
                let wanted: Vec<_> = f["expected_flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap())
                    .collect();
                let neg_detected = neg_flags != wanted;
                let baseline_digits = [
                    phase(&baseline.low_digit).wrapping_add(1 << 58) >> 59,
                    phase(&baseline.high_digit).wrapping_add(1 << 58) >> 59,
                ];
                let base_code = baseline_digits[0] + 15 * baseline_digits[1];
                let counts = serial.evaluation.calls
                    == plan["ledger"]["arms"][1].as_u64().unwrap() as usize
                    && negative.evaluation.calls == serial.evaluation.calls
                    && baseline.metrics.total_pbs_count
                        == plan["ledger"]["baseline_br"].as_u64().unwrap()
                    && serial_scan.2 == serial_scan.3;
                let pass = equality
                    && preimages
                    && closures
                    && stock
                    && neg_detected
                    && base_code == expected
                    && baseline_digits[0] < 15
                    && baseline_digits[1] < 16
                    && counts;
                target_json = json!({"record":"target","keyset":keyset,"case":index,"serial_parallel_bytes_equal":equality,"serial_hashes":state_hashes(&serial,[&serial_scan.0,&serial_scan.1]),"parallel_hashes":state_hashes(&result.state,[&result.endpoint.low_digit,&result.endpoint.high_digit]),"all_preimages_pass":preimages,"coefficient_closure_pass":closures,"stock_formula_pass":stock,"events":refs.len(),"refreshes":serial.refreshes,"negative_flags":neg_flags,"wrong_scale_detected":neg_detected,"baseline_code":base_code,"baseline_digits":baseline_digits,"baseline_br":baseline.metrics.total_pbs_count,"counts_pass":counts,"gate_pass":pass});
                println!("{target_json}");
            }
            let state = &result.state;
            let ev = &state.evaluation;
            let scores: Vec<u64> = f["scores"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect();
            let low: Vec<_> = scores.iter().map(|x| x & 15).collect();
            let mid: Vec<_> = scores.iter().map(|x| (x >> 4) & 15).collect();
            let top: Vec<_> = scores.iter().map(|x| x >> 8).collect();
            let expected_flags: Vec<_> = f["expected_flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .collect();
            let low_ok = native(&ev.low, &low, 54, phase);
            let mid_ok = native(&ev.middle, &mid, 54, phase);
            let top_ok = native(&ev.top, &top, 60, phase);
            let flags_ok = native(&ev.flags, &expected_flags, 59, phase);
            let sidecar = native(&state.correction_low, &low, 51, phase)
                && native(&state.correction_middle, &mid, 51, phase);
            let endpoint = output_data(&result.endpoint, expected, phase);
            let counts = result.endpoint.br
                == plan["ledger"]["candidate_br"].as_u64().unwrap() as usize
                && result.endpoint.ks == plan["ledger"]["candidate_ks"].as_u64().unwrap() as usize
                && result.endpoint.pbs_samples
                    == plan["ledger"]["candidate_pbs_samples"].as_u64().unwrap() as usize
                && state.refreshes == plan["ledger"]["refreshes"].as_u64().unwrap() as usize;
            let pass = low_ok
                && mid_ok
                && top_ok
                && flags_ok
                && counts
                && endpoint["pass"] == true
                && (!target || target_json["gate_pass"] == true);
            println!(
                "{}",
                json!({"record":"case","keyset":keyset,"case":index,"position":position,"fixture_name":f["name"],"n":n,"packed_sha256":hash_words(packed.as_ref()),"full_sha256":result.full.iter().map(digest).collect::<Vec<_>>(),"packed_low_sha256":result.packed_low.iter().map(digest).collect::<Vec<_>>(),"full_words":words(&result.full,phase),"packed_low_words":words(&result.packed_low,phase),"low_words":words(&ev.low,phase),"middle_words":words(&ev.middle,phase),"top_words":words(&ev.top,phase),"flag_words":words(&ev.flags,phase),"correction_low_words":words(&state.correction_low,phase),"correction_middle_words":words(&state.correction_middle,phase),"low_native_pass":low_ok,"middle_native_pass":mid_ok,"top_native_pass":top_ok,"final_native_pass":flags_ok,"old_sidecar_native_diagnostic":sidecar,"endpoint":endpoint,"refreshes":state.refreshes,"target_checked":target,"counts_pass":counts,"gate_pass":pass})
            );
            completed += 1;
            if !pass {
                all_pass = false;
                break 'keys;
            }
        }
    }
    println!(
        "{}",
        json!({"record":"summary","schema":"nibble_parallel_r3.v1","stage":stage,"gate_pass":all_pass,"completed":completed,"generated_keysets":generated,"planned":keys*plan["fixture_indices"].as_array().unwrap().len(),"timed":timing,"no_resampling":true})
    );
    if all_pass {
        Ok(())
    } else {
        Err("first complete negative preserved; no retry".into())
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("R3_ERROR: {e}");
        std::process::exit(1);
    }
}
