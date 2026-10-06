//! Fixed protocol values bound to the circuit contract.
//!
//! The frozen core keeps its older arithmetic module private. These wire constants
//! describe the selected native input and output, not its retained legacy scale.

pub const PROBE_DIM: usize = 512;
pub const PROBE_NORM2_MAX: i64 = 1024;
pub const SCORE_DOMAIN_MAX_WIDTH: i64 = 4096;
pub const Q_MAX: i64 = 3;
pub const LOG_SCORE_DELTA: u32 = 51;
pub const LOG_LOW_MOD16_DELTA: u32 = 60;
pub const LOG_DIGIT_DELTA: u32 = 59;
pub const LOW_MOD16_OFFSET: usize = 1024;
pub const POLYNOMIAL_SIZE: usize = 2048;
pub const GLWE_DIMENSION: usize = 1;
pub const OUTPUT_LWE_WORDS: usize = 2049;
pub const MAX_GALLERY: usize = pfks_core::service::MAX_GALLERY_SIZE;

pub const A44_PARAMS_ID: &str = "tfhe-rs-1.7.0-v0_11-m1c3-classic-ks-pbs-gaussian-2m64";
pub const A44_PARAMETER_FINGERPRINT_SHA256: &str =
    "ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61";
pub const HTTP_CONTRACT: &str = "exact-open-set-id-v9-composite-tfhe17-base15-three-lwe";
pub const VARIANT_ID: &str = include_str!("../../variant-id.txt");
pub const CIRCUIT_SHA256: &str = include_str!("../../circuit.sha256");

pub const WIRE_VERSION: u64 = 9;
pub const PROBE_MAGIC: u64 = u64::from_le_bytes(*b"VRCOPR17");
pub const OUTPUT_MAGIC: u64 = u64::from_le_bytes(*b"VRCOUT17");
pub const CLIENT_KEY_MAGIC: u64 = u64::from_le_bytes(*b"VRCCK17!");
pub const SERVER_KEY_MAGIC: u64 = u64::from_le_bytes(*b"VRCHD17!");
pub const PROBE_LAYOUT_DUAL_SAME_GLWE: u64 = 1;
pub const OUTPUT_MODE_EXACT_ID_THREE_LWE: u64 = 5;
pub const OUTPUT_LWES: usize = pfks_core::service::ID_DIGITS;
pub const OUTPUT_DIGIT_BASE: usize = pfks_core::service::ID_BASE as usize;
pub const PROBE_FIXED_HEADER_WORDS: usize = 9;
pub const OUTPUT_FIXED_HEADER_WORDS: usize = 11;
pub const BINDING_LENGTH_WORDS: usize = 4;
pub const KEY_ENVELOPE_FIXED_BYTES: usize = 7 * 8;
pub const MAX_SERVER_KEY_BODY_BYTES: usize = 320 * 1024 * 1024;
pub const G4_KEY_MAGIC: u64 = u64::from_le_bytes(*b"VRCG4V9!");
pub const MAX_G4_KEY_BODY_BYTES: usize = 288 * 1024 * 1024;
pub const MAX_PROBE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_ENROLLMENT_BODY_BYTES: usize = 8 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compiled_protocol_matches_the_canonical_circuit_contract() {
        let bytes = include_bytes!("../../CIRCUIT_CONTRACT.json");
        let contract: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(CIRCUIT_SHA256.len(), 64);
        assert_eq!(crate::wire::sha256_hex(bytes), CIRCUIT_SHA256);
        assert_eq!(contract["http_contract"], HTTP_CONTRACT);
        assert_eq!(contract["variant_id"], VARIANT_ID);
        assert_eq!(contract["wire_version"], WIRE_VERSION);
        assert_eq!(contract["core_package"], pfks_core::service::CORE_PACKAGE_NAME);
        assert_eq!(
            contract["core_id_contract"],
            pfks_core::service::ID_CONTRACT
        );
        assert_eq!(
            contract["core_source_sha256"],
            crate::runtime::CORE_SOURCE_SHA256
        );
        assert_eq!(contract["gallery"]["minimum_size"], 1);
        assert_eq!(contract["gallery"]["maximum_size"], MAX_GALLERY);
        assert_eq!(
            contract["gallery"]["maximum_domain_width"],
            SCORE_DOMAIN_MAX_WIDTH
        );
        assert_eq!(contract["parameters"]["id"], A44_PARAMS_ID);
        assert_eq!(
            contract["parameters"]["fingerprint_sha256"],
            A44_PARAMETER_FINGERPRINT_SHA256
        );
        assert_eq!(
            contract["query"],
            json!({
                "coordinates": [-Q_MAX, Q_MAX],
                "dimension": PROBE_DIM,
                "fixed_header_words": PROBE_FIXED_HEADER_WORDS,
                "full_delta_log": LOG_SCORE_DELTA,
                "glwe_size": GLWE_DIMENSION + 1,
                "low_delta_log": LOG_LOW_MOD16_DELTA,
                "low_offset": LOW_MOD16_OFFSET,
                "maximum_norm2": PROBE_NORM2_MAX,
                "polynomial_size": POLYNOMIAL_SIZE,
                "profile": "head51",
                "profile_id": 2,
            })
        );
        assert_eq!(
            contract["output"],
            json!({
                "base": OUTPUT_DIGIT_BASE,
                "decode": "low + 15*middle + 225*high",
                "delta_log": LOG_DIGIT_DELTA,
                "digits": OUTPUT_LWES,
                "fixed_header_words": OUTPUT_FIXED_HEADER_WORDS,
                "lwe_words": OUTPUT_LWE_WORDS,
                "mode": OUTPUT_MODE_EXACT_ID_THREE_LWE,
            })
        );
        assert_eq!(
            contract["http_limits_bytes"],
            json!({
                "g4_key": MAX_G4_KEY_BODY_BYTES,
                "enrollment": MAX_ENROLLMENT_BODY_BYTES,
                "key": MAX_SERVER_KEY_BODY_BYTES,
                "probe": MAX_PROBE_BODY_BYTES,
            })
        );
        for (name, magic) in [
            ("client_key", CLIENT_KEY_MAGIC),
            ("server_key", SERVER_KEY_MAGIC),
            ("probe", PROBE_MAGIC),
            ("output", OUTPUT_MAGIC),
        ] {
            assert_eq!(
                contract["magics"][name],
                String::from_utf8(magic.to_le_bytes().to_vec()).unwrap()
            );
        }
        assert_eq!(OUTPUT_LWES, 3);
        assert_eq!(OUTPUT_DIGIT_BASE.pow(3) - 1, MAX_GALLERY);
        assert_eq!(
            MAX_SERVER_KEY_BODY_BYTES,
            pfks_core::service::MAX_HEAD_BUNDLE_BYTES
        );
    }
}
