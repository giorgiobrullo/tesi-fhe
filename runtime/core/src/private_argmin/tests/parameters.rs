use super::*;

#[test]
fn a44_parameter_binding_text_is_exact_and_fail_closed() {
    assert_eq!(
        a44_parameter_fingerprint_sha256(),
        A44_PARAMETER_FINGERPRINT_SHA256
    );
    assert_eq!(
        validate_a44_parameter_binding_text(A44_PARAMETER_BINDING),
        Ok(())
    );
    assert_eq!(
        validate_a44_parameter_binding_text(A44ParameterBinding {
            params_id: "tfhe-rs-1.7.0-wrong",
            fingerprint_sha256: A44_PARAMETER_FINGERPRINT_SHA256,
        }),
        Err(PrivateArgminError::A44ParameterIdMismatch)
    );
    assert_eq!(
        validate_a44_parameter_binding_text(A44ParameterBinding {
            params_id: A44_PARAMS_ID,
            fingerprint_sha256: "00",
        }),
        Err(PrivateArgminError::A44ParameterFingerprintMismatch)
    );
}
