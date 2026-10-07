// Included in diagnostic.rs so original extraction functions remain byte-identical.
include!("retained_br.rs");

const A175_SCHEMA: &str = "a175.actual_extraction_consumer.v1";
const A175_U: u64 = 1u64 << 52;
const A175_Q: i128 = 1i128 << 64;

fn a175_emit(mut row: Value) {
    row.as_object_mut()
        .unwrap()
        .insert("schema".into(), json!(A175_SCHEMA));
    println!("{row}");
}

fn a175_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for word in words {
        h.update(word.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}

fn a175_hex(words: &[u64]) -> String {
    words
        .iter()
        .map(|w| format!("{:016x}", w.swap_bytes()))
        .collect()
}

fn a175_center(value: i128) -> i128 {
    (value + A175_Q / 2).rem_euclid(A175_Q) - A175_Q / 2
}

fn a175_dot(words: &[u64], secret: &[u64]) -> u64 {
    assert_eq!(words.len(), secret.len() + 1);
    assert!(secret.iter().all(|s| *s <= 1));
    words
        .iter()
        .zip(secret)
        .fold(0u64, |sum, (w, s)| sum.wrapping_add(w.wrapping_mul(*s)))
}

fn a175_lwe_observation(ct: &Lwe, secret: &[u64], tfhe_phase: u64) -> Value {
    let words = ct.as_ref();
    let dot = a175_dot(words, secret);
    json!({"words_le_hex":a175_hex(words),"sha256":a175_hash(words),
        "word_count":words.len(),"phase":tfhe_phase.to_string(),
        "client_mask_dot":dot.to_string(),
        "direct_phase_matches_tfhe":words.last().unwrap().wrapping_sub(dot)==tfhe_phase})
}

fn a175_target(degree: usize) -> i64 {
    let value = i64::from((64..192).contains(&(degree % 2048)));
    if degree % 4096 >= 2048 {
        -value
    } else {
        value
    }
}

fn a175_target_accumulator(sk: &ServerKey) -> Glwe {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A175 requires classic BSK"),
    };
    assert_eq!(bsk.polynomial_size().0, 2048);
    let mut body = vec![0u64; 2048];
    body[64..192].fill(1u64 << 59);
    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        bsk.glwe_size(),
        &PlaintextList::from_container(body),
        CiphertextModulus::new_native(),
    )
}

struct A175Consumer {
    arm_index: usize,
    bit: usize,
    candidate_state: i64,
    candidate: Lwe,
    input: Lwe,
    switched: Lwe,
    output: Lwe,
    receipt: A175Receipt,
    stock_glwe_identical: bool,
    stock_output_identical: bool,
    traced_glwe_sha256: String,
    stock_glwe_sha256: String,
    stock_output_sha256: String,
}

// Server-only evaluation: no secret or clear candidate/score argument.
fn a175_consume(
    candidate: &Lwe,
    weighted: &Lwe,
    multiplier: i64,
    sk: &ServerKey,
) -> (
    Lwe,
    Lwe,
    Lwe,
    A175Receipt,
    bool,
    bool,
    String,
    String,
    String,
) {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A175 requires classic BSK"),
    };
    let mut input = candidate.clone();
    if multiplier == 1 {
        lwe_ciphertext_add_assign(&mut input, weighted);
    } else {
        assert_eq!(multiplier, -1);
        lwe_ciphertext_sub_assign(&mut input, weighted);
    }
    let mut switched = LweCiphertext::new(
        0u64,
        sk.key_switching_key.output_lwe_size(),
        input.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext(&sk.key_switching_key, &input, &mut switched);
    let accumulator = a175_target_accumulator(sk);
    let mut traced = accumulator.clone();
    let receipt = a175_retained_blind_rotate(&switched, &mut traced, bsk);
    let mut output = LweCiphertext::new(0u64, input.lwe_size(), input.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(&traced, &mut output, MonomialDegree(0));
    let mut stock = accumulator;
    blind_rotate_assign(&switched, &mut stock, bsk);
    let mut stock_output = LweCiphertext::new(0u64, input.lwe_size(), input.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(&stock, &mut stock_output, MonomialDegree(0));
    let same_glwe = traced.as_ref() == stock.as_ref();
    let same_output = output.as_ref() == stock_output.as_ref();
    (
        input,
        switched,
        output,
        receipt,
        same_glwe,
        same_output,
        a175_hash(traced.as_ref()),
        a175_hash(stock.as_ref()),
        digest(&stock_output),
    )
}

fn a175_key_record(sk: &ServerKey, keyset: usize) {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => bsk,
        _ => panic!("A175 classic BSK"),
    };
    let mut hash = Sha256::new();
    for z in bsk.as_view().data() {
        hash.update(z.re.to_le_bytes());
        hash.update(z.im.to_le_bytes());
    }
    a175_emit(
        json!({"record":"consumer_keyset","keyset":keyset,"process_id":std::process::id(),
        "ksk_sha256":a175_hash(sk.key_switching_key.as_ref()),"fourier_bsk_sha256":format!("{:x}",hash.finalize()),
        "big_dimension":sk.key_switching_key.input_key_lwe_dimension().0,
        "small_dimension":sk.key_switching_key.output_key_lwe_dimension().0,
        "ks_base_log":sk.key_switching_key.decomposition_base_log().0,
        "ks_level_count":sk.key_switching_key.decomposition_level_count().0,
        "consumer_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("actual_consumer.rs"))),
        "retained_br_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("retained_br.rs"))),
        "candidate_encryption_noise":"A44 glwe_noise_distribution under flattened GLWE binary key",
        "candidate_provenance":"fresh_client_lwe_not_prior_selector_round",
        "key_membership_attested":false,"key_sensitive_client_local_only":true}),
    );
}

fn a175_observe(
    row: &A175Consumer,
    weighted: &Lwe,
    big: &LweSecretKeyView<'_, u64>,
    small: &LweSecretKeyOwned<u64>,
    sk: &ServerKey,
    keyset: usize,
    scene: &str,
    x: u64,
) -> [bool; 6] {
    let cp = decrypt_lwe_ciphertext(big, &row.candidate).0;
    let wp = decrypt_lwe_ciphertext(big, weighted).0;
    let ip = decrypt_lwe_ciphertext(big, &row.input).0;
    let kp = decrypt_lwe_ciphertext(small, &row.switched).0;
    let op = decrypt_lwe_ciphertext(big, &row.output).0;
    let c = row.candidate_state;
    let bit = row.bit;
    let m = if bit == 2 { 1i64 } else { -1i64 };
    let expected_bit = (x >> bit) & 1;
    let weight = if bit < 3 { 1u64 << (bit + 1) } else { 1 };
    let wanted = i64::from(c == 1 && expected_bit == 0);
    let cp_ideal = (c as u64).wrapping_shl(59);
    let wp_ideal = (expected_bit * weight).wrapping_shl(59);
    let ip_ideal = cp_ideal.wrapping_add(wp_ideal.wrapping_mul(m as u64));
    let decomp = SignedDecomposer::<u64>::new(
        sk.key_switching_key.decomposition_base_log(),
        sk.key_switching_key.decomposition_level_count(),
    );
    let remainders: Vec<i64> = row
        .input
        .get_mask()
        .as_ref()
        .iter()
        .map(|w| w.wrapping_sub(decomp.closest_representable(*w)) as i64)
        .collect();
    let r = remainders
        .iter()
        .zip(big.as_ref())
        .map(|(v, s)| *v as i128 * *s as i128)
        .sum::<i128>();
    let ks_increment = kp.wrapping_sub(ip) as i64;
    let inferred_row_term = a175_center(ks_increment as i128 - r);
    let words = row.switched.as_ref();
    let body_residue = words
        .last()
        .unwrap()
        .wrapping_sub((row.receipt.body as u64).wrapping_mul(A175_U)) as i64;
    let weighted_degrees: i128 = row
        .receipt
        .masks
        .iter()
        .zip(small.as_ref())
        .map(|(d, s)| *d as i128 * *s as i128)
        .sum();
    let weighted_residues: i128 = words
        .iter()
        .zip(&row.receipt.masks)
        .zip(small.as_ref())
        .map(|((w, d), s)| {
            w.wrapping_sub((*d as u64).wrapping_mul(A175_U)) as i64 as i128 * *s as i128
        })
        .sum();
    let address = (row.receipt.body as i128 - weighted_degrees).rem_euclid(4096) as usize;
    let phase_only_address = pbs_modulus_switch(kp, PolynomialSize(2048));
    let lut_value = a175_target(address);
    let output_actual = decode(op, 59) as i64;
    let output_actual = if output_actual >= 16 {
        output_actual - 32
    } else {
        output_actual
    };
    let observations = [
        a175_lwe_observation(&row.candidate, big.as_ref(), cp),
        a175_lwe_observation(weighted, big.as_ref(), wp),
        a175_lwe_observation(&row.input, big.as_ref(), ip),
        a175_lwe_observation(&row.switched, small.as_ref(), kp),
        a175_lwe_observation(&row.output, big.as_ref(), op),
    ];
    let phase_closure = observations
        .iter()
        .all(|v| v["direct_phase_matches_tfhe"] == true);
    let linear_closure = ip == cp.wrapping_add(wp.wrapping_mul(m as u64));
    let ms_closure = (address as u64)
        .wrapping_mul(A175_U)
        .wrapping_add(body_residue as u64)
        .wrapping_sub(weighted_residues as u64)
        == kp;
    let receipt_matches_words = row.receipt.body
        == pbs_modulus_switch(*words.last().unwrap(), PolynomialSize(2048))
        && words[..words.len() - 1]
            .iter()
            .zip(&row.receipt.masks)
            .zip(&row.receipt.raw_mask_nonzero)
            .all(|((w, d), nz)| {
                *d == pbs_modulus_switch(*w, PolynomialSize(2048)) && *nz == (*w != 0)
            });
    let candidate_native_pass = decode(cp, 59) == (c as u64 & 31);
    let address_pass = lut_value == wanted;
    let raw_output_pass = output_actual == lut_value;
    let semantic_output_pass = output_actual == wanted;
    let stock_pass = row.stock_glwe_identical && row.stock_output_identical;
    let observer_pass = phase_closure && linear_closure && ms_closure && receipt_matches_words;
    let gates = [
        candidate_native_pass,
        address_pass,
        raw_output_pass,
        semantic_output_pass,
        stock_pass,
        observer_pass,
    ];
    a175_emit(
        json!({"record":"actual_consumer","keyset":keyset,"scene":scene,"x":x,
        "arm":if row.arm_index==0 {"baseline_dual"} else {"single_full_direct_b0_b1"},
        "bit":bit,"level":7-bit,"candidate":c,"source_multiplier":m,
        "expected_bit":expected_bit,"weight_delta59":weight,"expected_output":wanted,
        "candidate_lwe":observations[0],"weighted_lwe":observations[1],"encoded_lwe":observations[2],
        "post_ks_lwe":observations[3],"output_lwe":observations[4],
        "candidate_error":(cp.wrapping_sub(cp_ideal) as i64).to_string(),
        "producer_error":(wp.wrapping_sub(wp_ideal) as i64).to_string(),
        "encoded_error":(ip.wrapping_sub(ip_ideal) as i64).to_string(),
        "ks_increment":ks_increment.to_string(),"ks_remainder_sum":r.to_string(),
        "inferred_signed_ks_row_term":inferred_row_term.to_string(),
        "ks_row_term_independently_measured":false,
        "ks_base_log":sk.key_switching_key.decomposition_base_log().0,
        "ks_level_count":sk.key_switching_key.decomposition_level_count().0,
        "receipt_body":row.receipt.body,"receipt_masks":row.receipt.masks,
        "receipt_raw_mask_nonzero":row.receipt.raw_mask_nonzero,
        "client_weighted_degrees":weighted_degrees.to_string(),
        "client_weighted_residues":weighted_residues.to_string(),
        "body_residue":body_residue.to_string(),"actual_address":address,
        "phase_only_address":phase_only_address,"actual_lut_value":lut_value,"output_actual":output_actual,
        "output_error_at_actual_address":(op.wrapping_sub((lut_value as u64).wrapping_shl(59)) as i64).to_string(),
        "traced_glwe_sha256":row.traced_glwe_sha256,"stock_glwe_sha256":row.stock_glwe_sha256,
        "stock_output_sha256":row.stock_output_sha256,
        "stock_glwe_byte_identical":row.stock_glwe_identical,"stock_output_byte_identical":row.stock_output_identical,
        "ks_calls":1,"traced_br_calls":1,"stock_br_calls":1,"sample_calls":2,
        "traced_ms_body_calls":1,"traced_ms_mask_calls":row.receipt.raw_mask_nonzero.iter().filter(|v|**v).count(),
        "candidate_native_pass":gates[0],"actual_address_pass":gates[1],
        "output_at_actual_address_pass":gates[2],"semantic_output_pass":gates[3],
        "stock_equivalence_pass":gates[4],"observer_closure_pass":gates[5],"pass":gates.iter().all(|v|*v),
        "candidate_is_previous_selector_output":false,"client_aggregates_independently_attested":false,
        "secret_key_bits_serialized":false,"p_fail_certified":false,"latency_claim_allowed":false}),
    );
    gates
}
