//! Explicit local diagnostic commands, separate from normal service requests.
use crate::keys::{
    atomic_write, client_key_compatibile_con_params, decode_bound_key, encode_bound_key,
};
use crate::protocol::*;
use crate::wire::{json_quote, sha256_hex};
use bincode::Options;
use pfks_core::service::ServerBundle;
use std::path::Path;
use tfhe::shortint::ClientKey;

pub(crate) fn export_phase_key(directory: &Path, destination: &Path) {
    assert!(
        !destination.exists(),
        "phase key export never overwrites an existing artifact"
    );
    let bound = std::fs::read(directory.join("client.key")).expect("local fresh client key");
    assert!(bound.len() <= 1024 * 1024, "bounded client key");
    let payload = decode_bound_key(&bound, CLIENT_KEY_MAGIC).expect("current client binding");
    let client: ClientKey = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(payload)
        .expect("exact client key");
    assert!(client_key_compatibile_con_params(&client));
    let (secret, _) = client.encryption_key_and_noise();
    assert_eq!(secret.lwe_dimension().0, 2048);
    assert!(secret.as_ref().iter().all(|word| *word <= 1));
    let bytes: Vec<u8> = secret
        .as_ref()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    atomic_write(destination, &bytes, 0o600).expect("private diagnostic key output");
    println!(
        "{}",
        serde_json::json!({"schema":"local-phase-key-export.v1","words":2048,
        "sha256":sha256_hex(&bytes),"scope":"fresh experiment only; never upload this private file"})
    );
}

pub(crate) fn mutate_bundle(source: &str, destination: &Path, mutation: &str) {
    let bound = std::fs::read(source).expect("public evaluation bundle");
    let payload = decode_bound_key(&bound, SERVER_KEY_MAGIC).expect("current bundle envelope");
    let bundle: ServerBundle =
        bincode::deserialize(payload).expect("valid diagnostic source bundle");
    drop(bound);
    let changed = bundle
        .diagnostic_payload(mutation)
        .expect("fixed public bundle diagnostic");
    let envelope = encode_bound_key(SERVER_KEY_MAGIC, &changed);
    assert!(envelope.len() <= MAX_SERVER_KEY_BODY_BYTES);
    atomic_write(destination, &envelope, 0o600).expect("private diagnostic destination");
    println!(
        "{{\"mutation\":{},\"bytes\":{},\"sha256\":{}}}",
        json_quote(mutation),
        envelope.len(),
        json_quote(&sha256_hex(&envelope))
    );
}
