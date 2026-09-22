use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

pub const CORE_SHA256: &str = "7ad812724bf43742d9d03ec9db204e93d6a2c0db3e6ea9dbc650054633fa3596";
const CONTRACT: &str = "a28-tfhe0.11.3-m2c2-tuniform-full52-low60-offset1024-code56.v1";
const MAX_CLIENT_BYTES: u64 = 1024 * 1024;
const MAX_SERVER_BYTES: u64 = 160 * 1024 * 1024;

pub struct Keys {
    pub secret: GlweSecretKeyOwned<u64>,
    pub server: ServerKey,
    pub noise: DynamicDistribution<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    core_sha256: String,
    contract: String,
    parameters_sha256: String,
    client_sha256: String,
    server_sha256: String,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parameters_sha256() -> Result<String, String> {
    bincode::serialize(&PARAMS).map(|bytes| sha(&bytes)).map_err(|_| "cannot encode native parameters".into())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(path).map_err(|_| "cannot create a new private key file".to_string())?;
    file.write_all(bytes).and_then(|_| file.sync_all())
        .map_err(|_| "cannot finish writing a private key file".into())
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "incomplete A28 key directory".to_string())?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0 || metadata.len() > limit {
        return Err("A28 key files must be bounded regular files with permission 0600".into());
    }
    fs::read(path).map_err(|_| "cannot read a private key file".into())
}

fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T, String> {
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(limit)
        .reject_trailing_bytes().deserialize(bytes)
        .map_err(|_| "invalid native A28 key serialization".into())
}

fn assemble(client: ClientKey, server: ServerKey) -> Result<Keys, String> {
    if client.parameters != PARAMS.into() {
        return Err("client key parameters do not match A28".into());
    }
    let (secret, small_secret, parameters) = client.into_raw_parts();
    if secret.glwe_dimension() != PARAMS.glwe_dimension
        || secret.polynomial_size() != PARAMS.polynomial_size
        || small_secret.lwe_dimension() != PARAMS.lwe_dimension
        || secret.as_ref().iter().chain(small_secret.as_ref()).any(|&bit| bit > 1) {
        return Err("invalid A28 client key geometry".into());
    }
    let bootstrap = match &server.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err("A28 requires a classic bootstrap key".into()),
    };
    let switch = &server.key_switching_key;
    if server.message_modulus != PARAMS.message_modulus
        || server.carry_modulus != PARAMS.carry_modulus
        || server.ciphertext_modulus != PARAMS.ciphertext_modulus
        || bootstrap.input_lwe_dimension() != PARAMS.lwe_dimension
        || bootstrap.glwe_size() != PARAMS.glwe_dimension.to_glwe_size()
        || bootstrap.polynomial_size() != PARAMS.polynomial_size
        || bootstrap.decomposition_base_log() != PARAMS.pbs_base_log
        || bootstrap.decomposition_level_count() != PARAMS.pbs_level
        || switch.input_key_lwe_dimension() != secret.as_lwe_secret_key().lwe_dimension()
        || switch.output_key_lwe_dimension() != PARAMS.lwe_dimension
        || switch.decomposition_base_log() != PARAMS.ks_base_log
        || switch.decomposition_level_count() != PARAMS.ks_level
        || switch.ciphertext_modulus() != PARAMS.ciphertext_modulus {
        return Err("server key parameters do not match A28".into());
    }
    Ok(Keys { secret, server, noise: parameters.glwe_noise_distribution() })
}

pub fn load_or_generate(directory: &Path) -> Result<Keys, String> {
    if !directory.is_absolute() {
        return Err("--keys must be an absolute private directory".into());
    }
    if sha(include_bytes!("../vendor/private_argmin.rs")) != CORE_SHA256 {
        return Err("vendored A28 source differs from its frozen digest".into());
    }
    if !directory.exists() {
        DirBuilder::new().recursive(true).mode(0o700).create(directory)
            .map_err(|_| "cannot create the private A28 key directory".to_string())?;
    }
    let metadata = fs::symlink_metadata(directory).map_err(|_| "cannot inspect the key directory".to_string())?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("A28 key directory must be a real directory with permission 0700".into());
    }
    let empty = fs::read_dir(directory).map_err(|_| "cannot inspect the key directory".to_string())?
        .next().is_none();
    if empty {
        eprintln!("A28: generating dedicated keys; no query timer has started");
        let client = ClientKey::new(PARAMS);
        let server = ServerKey::new(&client);
        let client_bytes = bincode::serialize(&client).map_err(|_| "cannot serialize client key".to_string())?;
        let server_bytes = bincode::serialize(&server).map_err(|_| "cannot serialize server key".to_string())?;
        let manifest = Manifest {
            schema: "a28-web-keys.v1".into(), core_sha256: CORE_SHA256.into(),
            contract: CONTRACT.into(), parameters_sha256: parameters_sha256()?,
            client_sha256: sha(&client_bytes), server_sha256: sha(&server_bytes),
        };
        if client_bytes.len() as u64 > MAX_CLIENT_BYTES || server_bytes.len() as u64 > MAX_SERVER_BYTES {
            return Err("generated key exceeds the A28 capsule limit".into());
        }
        write_new(&directory.join("client.key"), &client_bytes)?;
        write_new(&directory.join("server.key"), &server_bytes)?;
        // Written last: a partial directory is never silently regenerated or reused.
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| "cannot serialize key manifest".to_string())?;
        write_new(&directory.join("manifest.json"), &manifest_bytes)?;
        return assemble(client, server);
    }

    let manifest_bytes = read_private(&directory.join("manifest.json"), 16 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|_| "invalid A28 key manifest".to_string())?;
    if manifest.schema != "a28-web-keys.v1" || manifest.core_sha256 != CORE_SHA256
        || manifest.contract != CONTRACT || manifest.parameters_sha256 != parameters_sha256()? {
        return Err("key directory belongs to a different source or cryptographic contract".into());
    }
    let client_bytes = read_private(&directory.join("client.key"), MAX_CLIENT_BYTES)?;
    let server_bytes = read_private(&directory.join("server.key"), MAX_SERVER_BYTES)?;
    if sha(&client_bytes) != manifest.client_sha256 || sha(&server_bytes) != manifest.server_sha256 {
        return Err("A28 key capsule hashes do not match; existing files were not changed".into());
    }
    assemble(deserialize(&client_bytes, MAX_CLIENT_BYTES)?, deserialize(&server_bytes, MAX_SERVER_BYTES)?)
}
