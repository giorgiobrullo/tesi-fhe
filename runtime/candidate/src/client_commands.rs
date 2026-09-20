//! Trusted-client encryption and response decoding.
use crate::keys::{client_key_compatibile_con_params, decode_bound_key};
use crate::profile::QueryProfile;
use crate::protocol::*;
use crate::wire::{
    bytes_to_u64, decode_output_header, decode_plain_digit, encode_probe_coefficients, json_quote,
    output_digit_words, probe_header, reconstruct_code, scrivi_u64,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::ClientKey;

pub(crate) fn encrypt(dir: &str, probe_path: &str, out: &str, profile: QueryProfile) {
    let modulus = CiphertextModulus::<u64>::new_native();
    let key_bytes = std::fs::read(format!("{dir}/client.key")).unwrap();
    let key_payload = decode_bound_key(&key_bytes, CLIENT_KEY_MAGIC)
        .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
    let ck: ClientKey = bincode::deserialize(key_payload)
        .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
    assert!(
        client_key_compatibile_con_params(&ck),
        "chiave client incompatibile con il profilo A44 fast mixed"
    );
    let (glwe_sk, _, params, _) = match ck.atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => panic!("richiesta client key Standard TFHE 1.7"),
    };
    let poly = glwe_sk.polynomial_size();
    let probe: Vec<i64> = std::fs::read_to_string(probe_path)
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let t0 = Instant::now();
    let coeff = encode_probe_coefficients(&probe, poly.0, profile)
        .unwrap_or_else(|e| panic!("probe non valido: {e}"));
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut glwe =
        GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
    encrypt_glwe_ciphertext(
        &glwe_sk,
        &mut glwe,
        &PlaintextList::from_container(coeff),
        params.glwe_noise_distribution(),
        &mut gen,
    );
    let header = probe_header(poly.0, glwe_sk.glwe_dimension().0, profile);
    scrivi_u64(out, &header, &[glwe.as_ref()]);
    println!(
        "{{\"query_profile\":{},\"query_profile_id\":{},\"score_delta_log\":{},\"encrypt_ms\":{:.2},\"probe_ct_b\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
        json_quote(profile.name()), profile.wire(), profile.score_delta_log(),
        t0.elapsed().as_secs_f64() * 1000.0,
        std::fs::metadata(out).unwrap().len(),
        json_quote(A44_PARAMS_ID),
        json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
        json_quote(VARIANT_ID),
        json_quote(CIRCUIT_SHA256),
    );
}

pub(crate) fn decrypt(dir: &str, ct_path: &str) {
    let modulus = CiphertextModulus::<u64>::new_native();
    let key_bytes = std::fs::read(format!("{dir}/client.key")).unwrap();
    let key_payload = decode_bound_key(&key_bytes, CLIENT_KEY_MAGIC)
        .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
    let ck: ClientKey = bincode::deserialize(key_payload)
        .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
    assert!(
        client_key_compatibile_con_params(&ck),
        "chiave client incompatibile con il profilo A44 fast mixed"
    );
    let (enc_key, _) = ck.encryption_key_and_noise();
    let (hdr, dati) = bytes_to_u64(&std::fs::read(ct_path).unwrap())
        .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
    let header =
        decode_output_header(&hdr).unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
    let [low_words, middle_words, high_words] = output_digit_words(&header, &dati)
        .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
    let expected_lwe_size = enc_key.lwe_dimension().to_lwe_size().0;
    assert_eq!(
        header.lwe_size, expected_lwe_size,
        "esito cifrato non valido: lwe_size incompatibile con la chiave client"
    );
    let low_ct = LweCiphertext::from_container(low_words, modulus);
    let middle_ct = LweCiphertext::from_container(middle_words, modulus);
    let high_ct = LweCiphertext::from_container(high_words, modulus);
    let low = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &low_ct).0)
        .unwrap_or_else(|e| panic!("esito cifrato non valido: low: {e}"));
    let middle = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &middle_ct).0)
        .unwrap_or_else(|e| panic!("esito cifrato non valido: middle: {e}"));
    let high = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &high_ct).0)
        .unwrap_or_else(|e| panic!("esito cifrato non valido: high: {e}"));
    let code = reconstruct_code(low, middle, high, header.gallery_size)
        .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
    println!(
        "{}",
        serde_json::json!({
            "query_profile": header.profile.name(),
            "query_profile_id": header.profile.wire(),
            "autorizzato": code != 0,
            "indice": code.checked_sub(1),
            "codice": code,
            "low": low,
            "middle": middle,
            "high": high,
            "iscritti": header.gallery_size,
            "galleria_epoch": header.epoch,
            "galleria_revision": header.revision,
            "params_id": A44_PARAMS_ID,
            "params_fingerprint_sha256": A44_PARAMETER_FINGERPRINT_SHA256,
            "variant_id": VARIANT_ID,
            "circuit_sha256": CIRCUIT_SHA256,
        })
    );
}
