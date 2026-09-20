//! Bound key envelopes and private, atomic artifact writes.
use crate::protocol::*;
use bincode::Options;
use pfks_core::service::{EvaluationKeys, ServerBundle};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
pub(crate) use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::ClientKey;

pub(crate) fn encode_bound_key(magic: u64, payload: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(
        KEY_ENVELOPE_FIXED_BYTES
            + A44_PARAMS_ID.len()
            + A44_PARAMETER_FINGERPRINT_SHA256.len()
            + VARIANT_ID.len()
            + CIRCUIT_SHA256.len()
            + payload.len(),
    );
    for word in [
        magic,
        WIRE_VERSION,
        A44_PARAMS_ID.len() as u64,
        A44_PARAMETER_FINGERPRINT_SHA256.len() as u64,
        VARIANT_ID.len() as u64,
        CIRCUIT_SHA256.len() as u64,
        payload.len() as u64,
    ] {
        envelope.extend_from_slice(&word.to_le_bytes());
    }
    envelope.extend_from_slice(A44_PARAMS_ID.as_bytes());
    envelope.extend_from_slice(A44_PARAMETER_FINGERPRINT_SHA256.as_bytes());
    envelope.extend_from_slice(VARIANT_ID.as_bytes());
    envelope.extend_from_slice(CIRCUIT_SHA256.as_bytes());
    envelope.extend_from_slice(payload);
    envelope
}

pub(crate) fn decode_bound_key<'a>(
    data: &'a [u8],
    expected_magic: u64,
) -> Result<&'a [u8], String> {
    if data.len() < KEY_ENVELOPE_FIXED_BYTES {
        return Err(
            "chiave senza envelope fast mixed v8; formati precedenti non supportati".to_string(),
        );
    }
    let words: Vec<u64> = data[..KEY_ENVELOPE_FIXED_BYTES]
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("chunk da 8 byte")))
        .collect();
    if words[0] != expected_magic {
        return Err("magic della chiave fast mixed non valido".to_string());
    }
    if words[1] != WIRE_VERSION {
        return Err(format!(
            "versione dell'envelope chiave non supportata: {}",
            words[1]
        ));
    }
    let params_len = usize::try_from(words[2])
        .map_err(|_| "lunghezza params_id non rappresentabile".to_string())?;
    let fingerprint_len = usize::try_from(words[3])
        .map_err(|_| "lunghezza fingerprint non rappresentabile".to_string())?;
    let variant_len = usize::try_from(words[4])
        .map_err(|_| "lunghezza variant_id non rappresentabile".to_string())?;
    let circuit_len = usize::try_from(words[5])
        .map_err(|_| "lunghezza circuit hash non rappresentabile".to_string())?;
    let payload_len = usize::try_from(words[6])
        .map_err(|_| "lunghezza chiave non rappresentabile".to_string())?;
    let params_end = KEY_ENVELOPE_FIXED_BYTES
        .checked_add(params_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let fingerprint_end = params_end
        .checked_add(fingerprint_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let variant_end = fingerprint_end
        .checked_add(variant_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let circuit_end = variant_end
        .checked_add(circuit_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let payload_end = circuit_end
        .checked_add(payload_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    if payload_end != data.len() {
        return Err("lunghezza dell'envelope chiave incoerente".to_string());
    }
    if &data[KEY_ENVELOPE_FIXED_BYTES..params_end] != A44_PARAMS_ID.as_bytes()
        || &data[params_end..fingerprint_end] != A44_PARAMETER_FINGERPRINT_SHA256.as_bytes()
        || &data[fingerprint_end..variant_end] != VARIANT_ID.as_bytes()
        || &data[variant_end..circuit_end] != CIRCUIT_SHA256.as_bytes()
    {
        return Err("binding parametri/variante/circuito della chiave errato".to_string());
    }
    Ok(&data[circuit_end..payload_end])
}

pub(crate) fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        // Anche una directory preesistente viene riportata al permesso richiesto.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub(crate) fn atomic_write(path: &Path, data: &[u8], unix_mode: u32) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "il file chiave deve avere una directory padre",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "nome del file chiave non valido",
            )
        })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    #[cfg(not(unix))]
    let _ = unix_mode;

    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
pub(crate) fn client_key_compatibile_con_params(chiave: &ClientKey) -> bool {
    let (glwe_secret_key, small_secret_key, params, wopbs) = match chiave.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return false,
    };
    let expected: tfhe::shortint::PBSParameters = PARAMS.into();
    params == expected
        && wopbs.is_none()
        && glwe_secret_key.glwe_dimension() == PARAMS.glwe_dimension
        && glwe_secret_key.polynomial_size() == PARAMS.polynomial_size
        && small_secret_key.lwe_dimension() == PARAMS.lwe_dimension
}

pub(crate) fn deserialize_bound_server_key(data: &[u8]) -> Result<EvaluationKeys, String> {
    pfks_core::service::validate_serialized_bundle_size(data.len())?;
    let payload = decode_bound_key(data, SERVER_KEY_MAGIC)?;
    // Native serde containers can panic on malformed geometry. Reject at upload boundary.
    std::panic::catch_unwind(|| {
        let bundle: ServerBundle = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_SERVER_KEY_BODY_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|error| format!("payload bincode del bundle non valido: {error}"))?;
        EvaluationKeys::from_bundle(bundle)
    })
    .map_err(|_| "geometria interna del bundle non valida".to_string())?
}
