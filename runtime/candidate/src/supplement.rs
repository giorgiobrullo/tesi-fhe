//! Explicit bounded G4 evaluation-key sidecar. It never contains a client secret.
use crate::gallery::Galleria;
use crate::keys::{atomic_write, decode_bound_key, encode_bound_key};
use crate::protocol::*;
use crate::runtime;
use crate::wire::sha256_hex;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::ClientKey;

#[derive(Serialize, Deserialize)]
struct Payload {
    schema: String,
    base_server_envelope_sha256: String,
    bridge_sha256: String,
    bridge: Vec<u8>,
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn generate(
    client: &ClientKey,
    base_envelope: &[u8],
    destination: &Path,
) -> Result<serde_json::Value, String> {
    if !runtime::mode().uses_g4() {
        return Ok(serde_json::json!({"required":false}));
    }
    if destination.exists() {
        return Err("supplement destination already exists".into());
    }
    let (glwe, _, _, _) = match client.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return Err("supplement requires a Standard client key".into()),
    };
    let started = Instant::now();
    let (bridge, diagnostic_small_secret, setup) = pfks_core::multibit::BridgeKeys::generate(&glwe);
    drop(diagnostic_small_secret);
    bridge.validate()?;
    let bridge_bytes = bincode::serialize(&bridge).map_err(|error| error.to_string())?;
    drop(bridge);
    let payload = Payload {
        schema: "a44-shared-glwe-g4-evaluation.v1".into(),
        base_server_envelope_sha256: sha256_hex(base_envelope),
        bridge_sha256: sha256_hex(&bridge_bytes),
        bridge: bridge_bytes,
    };
    let serialized = bincode::serialize(&payload).map_err(|error| error.to_string())?;
    let envelope = encode_bound_key(G4_KEY_MAGIC, &serialized);
    if envelope.len() > MAX_G4_KEY_BODY_BYTES {
        return Err("G4 envelope exceeds its fixed limit".into());
    }
    // Validate without installing: keygen is a different process from the server.
    let checked = decode(&envelope, &sha256_hex(base_envelope))?;
    drop(checked);
    atomic_write(destination, &envelope, 0o600).map_err(|error| error.to_string())?;
    Ok(
        serde_json::json!({"required":true,"envelope_bytes":envelope.len(),
        "envelope_sha256":sha256_hex(&envelope),"setup":setup,
        "total_setup_seconds":started.elapsed().as_secs_f64(),
        "supplement_container_bytes":296_288_256u64,"client_secret_uploaded":false}),
    )
}

pub fn decode(bytes: &[u8], base_sha256: &str) -> Result<pfks_core::multibit::BridgeKeys, String> {
    if bytes.is_empty() || bytes.len() > MAX_G4_KEY_BODY_BYTES {
        return Err("G4 envelope size is invalid".into());
    }
    if !digest_valid(base_sha256) {
        return Err("base-key fingerprint is invalid".into());
    }
    let raw = decode_bound_key(bytes, G4_KEY_MAGIC)?;
    let payload: Payload = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_G4_KEY_BODY_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(raw)
        .map_err(|error| format!("G4 payload: {error}"))?;
    if payload.schema != "a44-shared-glwe-g4-evaluation.v1"
        || payload.base_server_envelope_sha256 != base_sha256
        || !digest_valid(&payload.bridge_sha256)
        || sha256_hex(&payload.bridge) != payload.bridge_sha256
    {
        return Err("G4 schema, base family or bridge fingerprint mismatch".into());
    }
    let bridge: pfks_core::multibit::BridgeKeys = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_G4_KEY_BODY_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&payload.bridge)
        .map_err(|error| format!("G4 bridge: {error}"))?;
    bridge.validate()?;
    Ok(bridge)
}

pub fn upload(gallery: &mut Galleria, bytes: &[u8]) -> Result<serde_json::Value, String> {
    if !runtime::mode().uses_g4() {
        return Err("this compiled service does not use G4 keys".into());
    }
    let base = gallery
        .chiave_sha256
        .as_deref()
        .ok_or("upload the bound base key first")?;
    let fingerprint = sha256_hex(bytes);
    if let Some(existing) = &gallery.g4_sha256 {
        if *existing != fingerprint {
            return Err("a different G4 family is already installed; use a new process".into());
        }
        return Ok(
            serde_json::json!({"ok":true,"idempotente":true,"g4_sha256":existing,"base_sha256":base}),
        );
    }
    let bridge = decode(bytes, base)?;
    bridge.install();
    gallery.g4_sha256 = Some(fingerprint.clone());
    Ok(
        serde_json::json!({"ok":true,"idempotente":false,"g4_sha256":fingerprint,"base_sha256":base}),
    )
}
