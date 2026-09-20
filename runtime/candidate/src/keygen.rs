//! Generate and validate a new, bound key family before writing it.
use crate::keys::{atomic_write, encode_bound_key, ensure_private_directory, PARAMS};
use crate::protocol::*;
use crate::supplement;
use crate::wire::{json_quote, sha256_hex};
use pfks_core::service::{EvaluationKeys, ServerBundle};
use std::path::Path;
use std::time::Instant;
use tfhe::shortint::{ClientKey, ServerKey};

pub(crate) fn generate(dir: &Path) {
    for name in ["client.key", "server.key", "g4.key"] {
        assert!(
            !dir.join(name).exists(),
            "keygen never overwrites an existing key artifact"
        );
    }
    ensure_private_directory(dir).unwrap();
    let t0 = Instant::now();
    let ck = ClientKey::new(PARAMS);
    let sk = ServerKey::new(&ck);
    let client_path = dir.join("client.key");
    let server_path = dir.join("server.key");
    let client_payload = bincode::serialize(&ck).unwrap();
    let bundle = pfks_core::service::generate_bundle(&ck, sk).unwrap();
    let server_payload = bincode::serialize(&bundle).unwrap();
    drop(bundle);
    let roundtrip: ServerBundle =
        bincode::deserialize(&server_payload).expect("actual bundle roundtrip decode");
    let roundtrip_bytes = bincode::serialize(&roundtrip).expect("actual bundle roundtrip encode");
    assert_eq!(
        server_payload, roundtrip_bytes,
        "actual serialized bundle roundtrip changed bytes"
    );
    drop(roundtrip_bytes);
    let checked = EvaluationKeys::from_bundle(roundtrip)
        .expect("actual selected bundle validation before writing");
    drop(checked);
    let server_envelope = encode_bound_key(SERVER_KEY_MAGIC, &server_payload);
    assert!(
        server_envelope.len() <= MAX_SERVER_KEY_BODY_BYTES,
        "serialized server bundle exceeds the fixed HTTP upload limit"
    );
    atomic_write(
        &client_path,
        &encode_bound_key(CLIENT_KEY_MAGIC, &client_payload),
        0o600,
    )
    .unwrap();
    atomic_write(&server_path, &server_envelope, 0o600).unwrap();
    let supplemental = supplement::generate(&ck, &server_envelope, &dir.join("g4.key"))
        .expect("optional G4 sidecar generation");
    atomic_write(
        &dir.join("supplement-setup.json"),
        supplemental.to_string().as_bytes(),
        0o600,
    )
    .unwrap();
    println!(
        "{{\"bundle_roundtrip_equal\":true,\"bundle_validation_pass\":true,\"server_payload_b\":{},\"server_envelope_sha256\":{},\"keygen_s\":{:.2},\"client_key_b\":{},\"server_key_b\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
        server_payload.len(), json_quote(&sha256_hex(&server_envelope)),
        t0.elapsed().as_secs_f64(),
        std::fs::metadata(client_path).unwrap().len(),
        std::fs::metadata(server_path).unwrap().len(),
        json_quote(A44_PARAMS_ID),
        json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
        json_quote(VARIANT_ID),
        json_quote(CIRCUIT_SHA256),
    );
}
