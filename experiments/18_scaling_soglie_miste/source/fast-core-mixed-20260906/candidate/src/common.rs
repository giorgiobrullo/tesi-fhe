// Client-only helpers copied from the passed size smoke harness.
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn words_hash(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for word in words {
        h.update(word.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
fn emit(file: &mut fs::File, mut value: Value) {
    value["observed_unix_ns"] = json!(unix_ns());
    serde_json::to_writer(&mut *file, &value).unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();
}

fn encrypt(query: &[i64], log: u32, secret: &GlweSecretKeyOwned<u64>) -> Glwe {
    let mut plain = vec![0u64; 2048];
    for (i, x) in query.iter().enumerate() {
        plain[i] = (*x as u64).wrapping_mul(1u64 << log);
        plain[1024 + i] = (x.rem_euclid(16) as u64) << 60;
    }
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut ct = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(2048),
        CiphertextModulus::new_native(),
    );
    encrypt_glwe_ciphertext(
        secret,
        &mut ct,
        &PlaintextList::from_container(plain),
        PARAMS.glwe_noise_distribution,
        &mut generator,
    );
    assert!(ct.get_mask().as_ref().iter().any(|x| *x != 0));
    ct
}

fn input_observation(
    ct: &Glwe,
    query: &[i64],
    log: u32,
    secret: &GlweSecretKeyOwned<u64>,
) -> Value {
    let mut plain = PlaintextList::new(0u64, PlaintextCount(2048));
    decrypt_glwe_ciphertext(secret, ct, &mut plain);
    let mut expected = vec![0u64; 2048];
    for (i, x) in query.iter().enumerate() {
        expected[i] = (*x as u64).wrapping_mul(1u64 << log);
        expected[1024 + i] = (x.rem_euclid(16) as u64) << 60;
    }
    let max_error = plain
        .as_ref()
        .iter()
        .zip(expected)
        .map(|(p, e)| (p.wrapping_sub(e) as i64 as i128).abs())
        .max()
        .unwrap();
    json!({"coefficient_checks":2048,"max_abs_error_torus":max_error as u64,"pass":max_error < (1i128<<(log-1))})
}

struct Output {
    digits: [Lwe; 3],
    counts: Value,
}
fn observe(output: &Output, expected: usize, secret: &GlweSecretKeyOwned<u64>) -> Value {
    let big = secret.as_lwe_secret_key();
    let phases: Vec<u64> = output
        .digits
        .iter()
        .map(|ct| decrypt_lwe_ciphertext(&big, ct).0)
        .collect();
    let digits: Vec<u64> = phases
        .iter()
        .map(|v| v.wrapping_add(1 << 58) >> 59)
        .collect();
    let id = digits[0] + 15 * digits[1] + 225 * digits[2];
    let errors: Vec<i64> = phases
        .iter()
        .zip([expected % 15, (expected / 15) % 15, expected / 225])
        .map(|(phase, d)| phase.wrapping_sub((d as u64) << 59) as i64)
        .collect();
    let pass = digits.iter().all(|v| *v < 15) && id == expected as u64;
    json!({"digits":digits,"id":id,"phases":phases,"errors_torus":errors,"counts":output.counts,
        "ciphertext_words":output.digits.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
        "ciphertext_sha256":output.digits.iter().map(|ct|words_hash(ct.as_ref())).collect::<Vec<_>>(),"pass":pass})
}
