//! Explicit, bounded local conversions from the one preserved v8 protocol.
use super::*;

const OLD_VARIANT: &str = "head-mixed-b22-tfhe17-base15-three-p16-v1";
const OLD_CIRCUIT: &str = "44235731e8b242ca97ad24483d74b837cc79ca52197cfb839d44580d45bdee04";

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("conversion source must be a bounded regular file".into());
    }
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    (&mut file).take(maximum as u64 + 1).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err("conversion source changed size or exceeded its bound".into());
    }
    Ok(bytes)
}

fn legacy_key(bytes: &[u8], magic: u64) -> Result<&[u8], String> {
    if bytes.len() < KEY_ENVELOPE_FIXED_BYTES { return Err("truncated v8 key".into()); }
    let words: Vec<u64> = bytes[..KEY_ENVELOPE_FIXED_BYTES].chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap())).collect();
    let bindings = [A44_PARAMS_ID, A44_PARAMETER_FINGERPRINT_SHA256, OLD_VARIANT, OLD_CIRCUIT];
    let mut offset = KEY_ENVELOPE_FIXED_BYTES;
    if words[0] != magic || words[1] != 8 { return Err("expected exact v8 key magic/version".into()); }
    for (index, binding) in bindings.iter().enumerate() {
        if words[2 + index] != binding.len() as u64 { return Err("v8 binding length mismatch".into()); }
        let end = offset + binding.len();
        if bytes.get(offset..end) != Some(binding.as_bytes()) { return Err("v8 key binding mismatch".into()); }
        offset = end;
    }
    let length = usize::try_from(words[6]).map_err(|_| "v8 payload length overflow")?;
    if offset.checked_add(length) != Some(bytes.len()) { return Err("v8 key trailing/truncated payload".into()); }
    Ok(&bytes[offset..])
}

pub fn keys(source: &Path, destination: &Path) -> Result<serde_json::Value, String> {
    if destination.exists() { return Err("key conversion requires a new directory".into()); }
    let old_client = read(&source.join("client.key"), 1024 * 1024)?;
    let old_server = read(&source.join("server.key"), MAX_SERVER_KEY_BODY_BYTES)?;
    let client_payload = legacy_key(&old_client, CLIENT_KEY_MAGIC)?;
    let server_payload = legacy_key(&old_server, SERVER_KEY_MAGIC)?;
    let client: ClientKey = bincode::DefaultOptions::new().with_fixint_encoding().with_limit(1024 * 1024)
        .reject_trailing_bytes().deserialize(client_payload).map_err(|error| error.to_string())?;
    if !client_key_compatibile_con_params(&client) { return Err("v8 client parameter mismatch".into()); }
    let new_server = encode_bound_key(SERVER_KEY_MAGIC, server_payload);
    let checked = deserialize_bound_server_key(&new_server)?;
    drop(checked);
    let new_client = encode_bound_key(CLIENT_KEY_MAGIC, client_payload);
    if decode_bound_key(&new_server, SERVER_KEY_MAGIC)? != server_payload
        || decode_bound_key(&new_client, CLIENT_KEY_MAGIC)? != client_payload {
        return Err("conversion changed a common cryptographic payload".into());
    }
    ensure_private_directory(destination).map_err(|error| error.to_string())?;
    atomic_write(&destination.join("client.key"), &new_client, 0o600).map_err(|error| error.to_string())?;
    atomic_write(&destination.join("server.key"), &new_server, 0o600).map_err(|error| error.to_string())?;
    let supplemental = supplement::generate(&client, &new_server, &destination.join("g4.key"))?;
    let receipt = serde_json::json!({"schema":"exact-v8-to-v9-key-rebind.v1","source_changed":false,
        "common_payloads_equal":true,"server_payload_sha256":sha256_hex(server_payload),
        "old_server_envelope_sha256":sha256_hex(&old_server),"new_server_envelope_sha256":sha256_hex(&new_server),
        "old_client_envelope_sha256":sha256_hex(&old_client),"new_client_envelope_sha256":sha256_hex(&new_client),
        "client_payload_sha256":sha256_hex(client_payload),"supplemental":supplemental,
        "new_circuit_sha256":CIRCUIT_SHA256,"new_variant":VARIANT_ID});
    atomic_write(&destination.join("REBIND.json"), receipt.to_string().as_bytes(), 0o600).map_err(|error| error.to_string())?;
    Ok(receipt)
}

pub fn probe(source: &Path, destination: &Path) -> Result<serde_json::Value, String> {
    if destination.exists() { return Err("probe conversion never overwrites a destination".into()); }
    let bytes = read(source, MAX_PROBE_BODY_BYTES)?;
    let (header, words) = bytes_to_u64(&bytes)?;
    let mut wanted = vec![PROBE_MAGIC, 8, PROBE_LAYOUT_DUAL_SAME_GLWE, POLYNOMIAL_SIZE as u64,
        GLWE_DIMENSION as u64, PROBE_DIM as u64, LOG_SCORE_DELTA as u64, LOG_LOW_MOD16_DELTA as u64,
        QueryProfile::Head51.wire()];
    for text in [A44_PARAMS_ID,A44_PARAMETER_FINGERPRINT_SHA256,OLD_VARIANT,OLD_CIRCUIT] { wanted.push(text.len() as u64); }
    for text in [A44_PARAMS_ID,A44_PARAMETER_FINGERPRINT_SHA256,OLD_VARIANT,OLD_CIRCUIT] { wanted.extend(text_words(text)); }
    if header != wanted || words.len() != (GLWE_DIMENSION + 1) * POLYNOMIAL_SIZE {
        return Err("v8 probe profile, geometry or full binding mismatch".into());
    }
    let new_header = probe_header(POLYNOMIAL_SIZE, GLWE_DIMENSION, QueryProfile::Head51);
    decode_probe_header(&new_header)?;
    let output = u64_to_bytes(&new_header, &[&words]);
    if bytes_to_u64(&output)?.1 != words { return Err("probe rebind changed GLWE words".into()); }
    atomic_write(destination, &output, 0o600).map_err(|error| error.to_string())?;
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    Ok(serde_json::json!({"schema":"exact-v8-to-v9-probe-rebind.v1","common_glwe_words_equal":true,
        "glwe_words":words.len(),"glwe_payload_sha256":sha256_hex(&payload),
        "old_wire_sha256":sha256_hex(&bytes),"new_wire_sha256":sha256_hex(&output)}))
}

pub fn plan(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = read(path, 32 * 1024 * 1024)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let rows = value.as_array().ok_or("plan fixture must be an array")?;
    if rows.is_empty() || rows.len() > MAX_GALLERY { return Err("plan fixture size is invalid".into()); }
    let mut gallery = Galleria { dim: PROBE_DIM, t_default: 4, iscritti: Vec::new(),
        chiave: None, chiave_sha256: None, g4_sha256: None, epoch: 1, revision: 0 };
    for (index, row) in rows.iter().enumerate() {
        let object = row.as_object().ok_or("plan row must be an object")?;
        if object.len() != 2 || !object.contains_key("template") || !object.contains_key("threshold") {
            return Err("plan rows require exactly template and threshold".into());
        }
        let template = object["template"].as_array().ok_or("plan template must be an array")?
            .iter().map(|word| word.as_i64().ok_or("plan coordinates must be i64 integers"))
            .collect::<Result<Vec<_>, _>>()?;
        let threshold = object["threshold"].as_i64().ok_or("plan threshold must be i64")?;
        upsert_entry(&mut gallery, format!("synthetic_plan_{index}"), template, threshold)?;
    }
    metadata::status_json(&gallery)
}
