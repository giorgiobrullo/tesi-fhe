//! Exact A44 parameter binding and observable key geometry checks.
use super::contracts::*;
use crate::compat::{ServerKey, ShortintBootstrappingKey};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::PBSOrder;

pub fn a44_parameter_fingerprint_sha256() -> String {
    format!("{:x}", Sha256::digest(A44_PARAMETER_CANONICAL.as_bytes()))
}

/// Verifica la parte serializzabile del binding. Il controllo e' intenzionalmente esatto e
/// distingue maiuscole/minuscole: un endpoint non puo' negoziare o degradare silenziosamente a un
/// preset con lo stesso plaintext modulus.
pub fn validate_a44_parameter_binding_text(
    binding: A44ParameterBinding<'_>,
) -> Result<(), PrivateArgminError> {
    if binding.params_id != A44_PARAMS_ID {
        return Err(PrivateArgminError::A44ParameterIdMismatch);
    }
    if binding.fingerprint_sha256 != A44_PARAMETER_FINGERPRINT_SHA256 {
        return Err(PrivateArgminError::A44ParameterFingerprintMismatch);
    }
    if a44_parameter_fingerprint_sha256() != A44_PARAMETER_FINGERPRINT_SHA256 {
        return Err(PrivateArgminError::A44ParameterFingerprintDefinitionMismatch);
    }
    Ok(())
}

fn require_a44_parameter_field(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), PrivateArgminError> {
    if actual != expected {
        return Err(PrivateArgminError::A44ParameterGeometryMismatch {
            field,
            expected: expected as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

/// Verifica i campi del preset che restano osservabili in una [`ServerKey`]. Distribuzioni del
/// rumore e `log2_p_fail` non sono presenti nella chiave generata: sono legati dal fingerprint e,
/// quando esistera' una serializzazione, dovranno essere autenticati dal protocollo esterno.
pub fn validate_a44_parameter_binding(
    binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
) -> Result<(), PrivateArgminError> {
    validate_a44_parameter_binding_text(binding)?;
    require_a44_parameter_field("message_modulus", server_key.message_modulus.0 as usize, 2)?;
    require_a44_parameter_field("carry_modulus", server_key.carry_modulus.0 as usize, 8)?;
    require_a44_parameter_field(
        "max_noise_level",
        server_key.max_noise_level.get() as usize,
        15,
    )?;
    require_a44_parameter_field("max_degree", server_key.max_degree.get() as usize, 15)?;
    require_a44_parameter_field(
        "pbs_order_keyswitch_bootstrap",
        usize::from(server_key.pbs_order == PBSOrder::KeyswitchBootstrap),
        1,
    )?;
    require_a44_parameter_field(
        "ciphertext_modulus_native",
        usize::from(server_key.ciphertext_modulus.is_native_modulus()),
        1,
    )?;

    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    require_a44_parameter_field(
        "bsk_input_lwe_dimension",
        bootstrap_key.input_lwe_dimension().0,
        859,
    )?;
    require_a44_parameter_field(
        "bsk_output_lwe_dimension",
        bootstrap_key.output_lwe_dimension().0,
        2048,
    )?;
    require_a44_parameter_field("bsk_glwe_size", bootstrap_key.glwe_size().0, 2)?;
    require_a44_parameter_field(
        "bsk_polynomial_size",
        bootstrap_key.polynomial_size().0,
        2048,
    )?;
    require_a44_parameter_field("pbs_base_log", bootstrap_key.decomposition_base_log().0, 23)?;
    require_a44_parameter_field("pbs_level", bootstrap_key.decomposition_level_count().0, 1)?;

    let key_switching_key = &server_key.key_switching_key;
    require_a44_parameter_field(
        "ksk_input_lwe_dimension",
        key_switching_key.input_key_lwe_dimension().0,
        2048,
    )?;
    require_a44_parameter_field(
        "ksk_output_lwe_dimension",
        key_switching_key.output_key_lwe_dimension().0,
        859,
    )?;
    require_a44_parameter_field(
        "ks_base_log",
        key_switching_key.decomposition_base_log().0,
        3,
    )?;
    require_a44_parameter_field(
        "ks_level",
        key_switching_key.decomposition_level_count().0,
        5,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/parameters.rs"]
mod tests;
