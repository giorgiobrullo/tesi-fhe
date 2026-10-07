//! Isolated A138: packed score -> two nibble adapters -> actual A34 -> A135 masks.
//! No secret key or plaintext score enters the server evaluator. Outputs/traces are local
//! diagnostics, not a service response. This file has not been typechecked or run as FHE.
use serde_json::json;
use sha2::{Digest, Sha256};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
include!("a34_tables.rs");

fn scale(input: &Lwe, factor: u64) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut out, Cleartext(factor));
    out
}
fn add(input: &Lwe, other: &Lwe) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_add_assign(&mut out, other);
    out
}
fn sub(input: &Lwe, other: &Lwe) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_sub_assign(&mut out, other);
    out
}
fn offset(input: &Lwe, value: u64) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(value));
    out
}
fn digest(input: &Lwe) -> String {
    let mut hash = Sha256::new();
    for x in input.as_ref() {
        hash.update(x.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}
fn switch_word(x: u64) -> u64 {
    x.wrapping_add(1 << 51) >> 52
}

struct Event {
    name: String,
    input: Lwe,
    switched: Lwe,
    output: Lwe,
    body: Vec<u64>,
}
struct Backend<'a> {
    server: &'a ServerKey,
    events: Vec<Event>,
}
impl<'a> Backend<'a> {
    fn bsk(&self) -> &FourierLweBootstrapKeyOwned {
        match &self.server.bootstrapping_key {
            ShortintBootstrappingKey::Classic(bsk) => bsk,
            _ => panic!("A138 requires the classic A44 key"),
        }
    }
    fn body_pbs(&mut self, input: &Lwe, body: Vec<u64>, name: String) -> Lwe {
        let bsk = self.bsk();
        let modulus = CiphertextModulus::new_native();
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            bsk.glwe_size(),
            &PlaintextList::from_container(body.clone()),
            modulus,
        );
        let mut switched =
            LweCiphertext::new(0, self.server.key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(&self.server.key_switching_key, input, &mut switched);
        let mut out = LweCiphertext::new(0, input.lwe_size(), modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut out, &accumulator, bsk);
        self.events.push(Event {
            name,
            input: input.clone(),
            switched,
            output: out.clone(),
            body,
        });
        out
    }
    fn table(&mut self, input: &Lwe, values: Vec<u64>, name: String) -> Lwe {
        let n = self.bsk().polynomial_size().0;
        assert!(values.len().is_power_of_two() && n % values.len() == 0);
        let box_size = n / values.len();
        // Literal public stock helper, allowing already-scaled wrapping words.
        let mut body: Vec<u64> = values.iter().flat_map(|x| vec![*x; box_size]).collect();
        for x in &mut body[..box_size / 2] {
            *x = x.wrapping_neg();
        }
        body.rotate_left(box_size / 2);
        self.body_pbs(input, body, name)
    }
    fn msb(&mut self, centered: &Lwe, output_log: u32, name: String) -> Lwe {
        let alpha = 1u64 << (output_log - 1);
        let raw = self.body_pbs(centered, vec![alpha.wrapping_neg(); 2048], name);
        offset(&raw, alpha)
    }
    fn nibble(&mut self, input: &Lwe, independent: bool, prefix: &str) -> Lwe {
        // Input d*Delta60 on full torus. Half-digit center avoids the sign edge.
        let centered = offset(input, 1 << 59);
        let msb_small = self.msb(&centered, 54, format!("{prefix}.msb54"));
        let fold = if independent {
            self.msb(&centered, 63, format!("{prefix}.msb63_independent_scale"))
        } else {
            scale(&msb_small, 512)
        };
        let remainder = sub(input, &fold);
        let low = self.table(
            &remainder,
            (0..8).map(|r| r << 51).collect(),
            format!("{prefix}.low3"),
        );
        add(&low, &msb_small)
    }
    fn initial(&mut self, tops: &[Lwe]) -> Vec<Lwe> {
        let codes: Vec<_> = tops
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    x,
                    (0..16)
                        .map(|v| a34_top_classifier_slot_lut(v) << 59)
                        .collect(),
                    format!("a34.classify/{i}"),
                )
            })
            .collect();
        let mut layer: Vec<_> = codes
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(x, 4 << 59),
                    (0..16)
                        .map(|v| a34_canonical_category_lut(v) << 59)
                        .collect(),
                    format!("a34.canonical/{i}"),
                )
            })
            .collect();
        let mut depth = 0;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    if pair.len() == 1 {
                        pair[0].clone()
                    } else {
                        self.table(
                            &add(&pair[0], &pair[1]),
                            (0..16).map(|v| a34_pair_category_lut(v) << 59).collect(),
                            format!("a34.reduce/{depth}/{i}"),
                        )
                    }
                })
                .collect();
            depth += 1;
        }
        codes
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(&add(x, &layer[0]), 4 << 59),
                    (0..16).map(|v| a34_top_candidate_lut(v) << 59).collect(),
                    format!("a34.candidate/{i}"),
                )
            })
            .collect()
    }
    fn round(&mut self, active: &[Lwe], digits: &[Lwe], name: &str) -> Vec<Lwe> {
        assert_eq!(active.len(), digits.len());
        assert!((1..=128).contains(&active.len()));
        let before = self.events.len();
        let masked: Vec<_> = active
            .iter()
            .zip(digits)
            .enumerate()
            .map(|(i, (a, d))| {
                let input = add(&scale(d, 256), &scale(a, 16));
                let signed = self.table(
                    &input,
                    (0..16).map(|v| (16 - v) << 51).collect(),
                    format!("{name}.mask/{i}"),
                );
                offset(&add(&signed, d), 16 << 51)
            })
            .collect();
        let mut layer = masked.clone();
        let mut log = 52u32;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    if pair.len() == 1 {
                        scale(&pair[0], 2)
                    } else {
                        let input = scale(&sub(&pair[0], &pair[1]), 1 << (59 - log));
                        let abs = self.table(
                            &input,
                            (0u64..16)
                                .map(|v| v.wrapping_sub(8).wrapping_shl(log))
                                .collect(),
                            format!("{name}.minimum/{log}/{i}"),
                        );
                        offset(
                            &sub(&add(&pair[0], &pair[1]), &abs),
                            (8u64 << log).wrapping_neg(),
                        )
                    }
                })
                .collect();
            log += 1;
        }
        let minimum = scale(&layer[0], 1 << (59 - log));
        let signed_valid = self.table(&minimum, vec![1 << 58; 16], format!("{name}.valid"));
        let valid = offset(&signed_valid, 1 << 58);
        let outputs = masked
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let input = add(&sub(&scale(q, 128), &minimum), &scale(&valid, 16));
                let values = (0..16)
                    .map(|v| {
                        if v == 0 {
                            (1u64 << 58).wrapping_neg()
                        } else {
                            1 << 58
                        }
                    })
                    .collect();
                let signed = self.table(&input, values, format!("{name}.update/{i}"));
                offset(&signed, 1 << 58)
            })
            .collect();
        assert_eq!(self.events.len() - before, 3 * active.len());
        outputs
    }
}

struct Evaluation {
    low: Vec<Lwe>,
    middle: Vec<Lwe>,
    top: Vec<Lwe>,
    flags: Vec<Lwe>,
    events: Vec<Event>,
}
fn evaluate(
    full: &[Lwe],
    packed_low: &[Lwe],
    server: &ServerKey,
    independent: bool,
    wrong_scale: bool,
) -> Evaluation {
    let mut backend = Backend {
        server,
        events: Vec::new(),
    };
    let mut low = Vec::new();
    let mut middle = Vec::new();
    let mut top = Vec::new();
    for (i, (f, l)) in full.iter().zip(packed_low).enumerate() {
        let d0 = backend.nibble(l, independent, &format!("ingress/{i}/low"));
        let residual = sub(f, &scale(&d0, 2));
        let d1 = backend.nibble(
            &scale(&residual, 16),
            independent,
            &format!("ingress/{i}/middle"),
        );
        top.push(sub(&residual, &scale(&d1, 32)));
        low.push(d0);
        middle.push(d1);
    }
    let active = backend.initial(&top);
    let middle_for_consumer: Vec<_> = middle
        .iter()
        .map(|x| scale(x, if wrong_scale { 2 } else { 1 }))
        .collect();
    let low_for_consumer: Vec<_> = low
        .iter()
        .map(|x| scale(x, if wrong_scale { 2 } else { 1 }))
        .collect();
    let active = backend.round(&active, &middle_for_consumer, "middle_round");
    let flags = backend.round(&active, &low_for_consumer, "low_round");
    assert_eq!(
        backend.events.len(),
        (if independent { 16 } else { 14 }) * full.len() - 1
    );
    Evaluation {
        low,
        middle,
        top,
        flags,
        events: backend.events,
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("A138_ERROR: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let execute = args.iter().any(|x| x == "--run");
    let expected_hash = args
        .iter()
        .find_map(|x| x.strip_prefix("--expected-binary-sha256="));
    let keysets: usize = args
        .iter()
        .find_map(|x| x.strip_prefix("--keysets="))
        .unwrap_or("1")
        .parse()
        .map_err(|_| "invalid keysets")?;
    for a in &args {
        if a != "--run"
            && !a.starts_with("--expected-binary-sha256=")
            && !a.starts_with("--keysets=")
        {
            return Err(format!("unknown argument {a}"));
        }
    }
    if !(1..=3).contains(&keysets) {
        return Err("keysets must be1..3".into());
    }
    let fixtures: Vec<[u64; 4]> = vec![
        [15, 0, 255, 1024],
        [7, 8, 15, 1024],
        [255, 256, 254, 4095],
        [1023, 1023, 1024, 4095],
        [1024, 4095, 2048, 4094],
        [4095, 511, 512, 510],
        [128, 127, 127, 129],
        [16, 16, 15, 15],
    ];
    println!(
        "{}",
        json!({"record":"plan","stage":"first_composed_n4","fixtures":fixtures,"keysets":keysets,"arms":["shared512","independent_scale","negative_wrong_consumer_scale"],"br_ks_per_fixture":[55,63,55],"output":"canonical survivor flags; A53/service not invoked","runtime_executed":false,"formal_bound":false})
    );
    if !execute {
        return Ok(());
    }
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    if !binary
        .components()
        .any(|x| x.as_os_str() == "target-a138-only")
    {
        return Err("requires isolated target-a138-only".into());
    }
    let hash = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&binary).map_err(|e| e.to_string())?)
    );
    if expected_hash != Some(hash.as_str()) {
        return Err("requires independently supplied matching binary hash".into());
    }
    println!(
        "{}",
        json!({"record":"provenance","binary_sha256":hash,"source_sha256":format!("{:x}",Sha256::digest(include_bytes!("main.rs"))),"tables_sha256":format!("{:x}",Sha256::digest(include_bytes!("a34_tables.rs"))),"lock_sha256":format!("{:x}",Sha256::digest(include_bytes!("../Cargo.lock"))),"params":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64","parameter_fingerprint":"b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1","secret_keys_saved":false})
    );
    let mut failures = [0usize; 2];
    let mut negatives_by_key = vec![0usize; keysets];
    let mut cases = 0usize;
    for keyset in 0..keysets {
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
        for (case, scores) in fixtures.iter().enumerate() {
            // One real, nontrivial encrypted packed probe shared by all four public products.
            // Public offsets target diagnostic score centers; this is not an enrollment scene.
            let probe: Vec<i64> = (0..512).map(|i| if i % 2 == 0 { 1 } else { -1 }).collect();
            let mut plaintext = vec![0u64; 2048];
            for i in 0..512 {
                plaintext[i] = (probe[i] as u64).wrapping_shl(52);
                plaintext[1024 + i] = (probe[i] as u64).wrapping_shl(60);
            }
            let mut packed = GlweCiphertext::new(
                0,
                glwe_secret.glwe_dimension().to_glwe_size(),
                glwe_secret.polynomial_size(),
                modulus,
            );
            encrypt_glwe_ciphertext(
                &glwe_secret,
                &mut packed,
                &PlaintextList::from_container(plaintext),
                parameters.glwe_noise_distribution(),
                &mut generator,
            );
            let mut full = Vec::new();
            let mut low = Vec::new();
            for (i, x) in scores.iter().enumerate() {
                let mut template = vec![0i64; 512];
                template[..113 + i].fill(if i % 2 == 0 { 3 } else { -3 });
                let dot: i64 = probe.iter().zip(&template).map(|(a, b)| a * b).sum();
                let mut poly = vec![0u64; 2048];
                for j in 0..512 {
                    poly[511 - j] = (-2 * template[j]) as u64;
                }
                let poly = Polynomial::from_container(poly);
                let mut product =
                    GlweCiphertext::new(0, packed.glwe_size(), packed.polynomial_size(), modulus);
                for (mut out, input) in product
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(packed.as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_mul_assign(&mut out, &input, &poly);
                }
                for (degree, log, outputs) in [(511, 52, &mut full), (1535, 60, &mut low)] {
                    let mut ct =
                        LweCiphertext::new(0, big_secret.lwe_dimension().to_lwe_size(), modulus);
                    extract_lwe_sample_from_glwe_ciphertext(
                        &product,
                        &mut ct,
                        MonomialDegree(degree),
                    );
                    lwe_ciphertext_plaintext_add_assign(
                        &mut ct,
                        Plaintext(((*x as i64 + 2 * dot) as u64).wrapping_shl(log)),
                    );
                    assert!(ct.get_mask().as_ref().iter().any(|v| *v != 0));
                    outputs.push(ct);
                }
            }
            let evaluations = [
                evaluate(&full, &low, &server, false, false),
                evaluate(&full, &low, &server, true, false),
                evaluate(&full, &low, &server, false, true),
            ];
            // Only the client section below sees secret keys or fixture labels.
            let minimum = *scores.iter().min().unwrap();
            let expected: Vec<u64> = scores
                .iter()
                .map(|s| u64::from(minimum <= 1023 && *s == minimum))
                .collect();
            for (arm, evaluation) in evaluations.iter().enumerate() {
                let decode = |ct: &Lwe, log: u32| {
                    decrypt_lwe_ciphertext(&big_secret, ct)
                        .0
                        .wrapping_add(1u64 << (log - 1))
                        >> log
                };
                let flags: Vec<_> = evaluation.flags.iter().map(|x| decode(x, 59)).collect();
                let low_decoded: Vec<_> = evaluation.low.iter().map(|x| decode(x, 51)).collect();
                let middle_decoded: Vec<_> =
                    evaluation.middle.iter().map(|x| decode(x, 51)).collect();
                let top_decoded: Vec<_> = evaluation.top.iter().map(|x| decode(x, 60)).collect();
                let native = low_decoded.iter().zip(scores).all(|(d, s)| *d == (*s & 15))
                    && middle_decoded
                        .iter()
                        .zip(scores)
                        .all(|(d, s)| *d == ((*s >> 4) & 15))
                    && top_decoded.iter().zip(scores).all(|(d, s)| *d == (*s >> 8));
                let phase_errors = |ciphertexts: &[Lwe], log: u32, shift: u32, mask: u64| {
                    ciphertexts
                        .iter()
                        .zip(scores)
                        .map(|(ct, score)| {
                            let expected_word = ((score >> shift) & mask).wrapping_shl(log);
                            let error = decrypt_lwe_ciphertext(&big_secret, ct)
                                .0
                                .wrapping_sub(expected_word);
                            (error as i64).to_string()
                        })
                        .collect::<Vec<_>>()
                };
                let consumer = flags == expected;
                if arm < 2 {
                    failures[arm] += usize::from(!native || !consumer);
                } else {
                    negatives_by_key[keyset] += usize::from(!consumer);
                }
                for event in &evaluation.events {
                    let input_phase = decrypt_lwe_ciphertext(&big_secret, &event.input).0;
                    let small_phase = decrypt_lwe_ciphertext(&small_secret, &event.switched).0;
                    let output_phase = decrypt_lwe_ciphertext(&big_secret, &event.output).0;
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
                    let raw = event.body[address % 2048];
                    let raw = if address >= 2048 {
                        raw.wrapping_neg()
                    } else {
                        raw
                    };
                    let mut body_hash = Sha256::new();
                    for w in &event.body {
                        body_hash.update(w.to_le_bytes());
                    }
                    println!(
                        "{}",
                        json!({"record":"event","keyset":keyset,"case":case,"arm":arm,"stage":event.name,"input_sha256":digest(&event.input),"small_sha256":digest(&event.switched),"output_sha256":digest(&event.output),"body_sha256":format!("{:x}",body_hash.finalize()),"big_phase_word":input_phase.to_string(),"small_phase_word":small_phase.to_string(),"ks_phase_increment":(small_phase.wrapping_sub(input_phase) as i64).to_string(),"actual_ms_address":address,"rounded_big_phase_address":switch_word(input_phase),"rounded_small_phase_address":switch_word(small_phase),"output_phase_word":output_phase.to_string(),"lut_word_at_actual_address":raw.to_string(),"output_error_at_actual_address":(output_phase.wrapping_sub(raw) as i64).to_string(),"client_only":true})
                    );
                }
                println!(
                    "{}",
                    json!({"record":"case","keyset":keyset,"case":case,"arm":arm,"scores":scores,"full_sha256":full.iter().map(digest).collect::<Vec<_>>(),"packed_low_sha256":low.iter().map(digest).collect::<Vec<_>>(),"input_full_errors":phase_errors(&full,52,0,4095),"input_packed_low_errors":phase_errors(&low,60,0,15),"low51":low_decoded,"middle51":middle_decoded,"top60":top_decoded,"low51_errors":phase_errors(&evaluation.low,51,0,15),"middle51_errors":phase_errors(&evaluation.middle,51,4,15),"top60_errors":phase_errors(&evaluation.top,60,8,15),"native_decode_pass":native,"composed_a34_a135_pass":consumer,"flags":flags,"expected_flags":expected,"pass":native&&consumer,"br":evaluation.events.len(),"ks":evaluation.events.len(),"not_a53_or_service":true})
                );
            }
            cases += 1;
        }
    }
    let pass = failures == [0, 0]
        && negatives_by_key.iter().all(|count| *count > 0)
        && cases == 8 * keysets;
    println!(
        "{}",
        json!({"record":"summary","status":if pass {"BOUNDED_COMPOSED_GATE_PASS"} else {"GATE_FAIL"},"positive_arm_failures":failures,"wrong_scale_negatives_detected_by_key":negatives_by_key,"case_count":cases,"p_fail_certified":false,"a53_service_validated":false,"latency_claim_allowed":false})
    );
    if !pass {
        return Err("composed gate or negative control failed; retain all output".into());
    }
    Ok(())
}
