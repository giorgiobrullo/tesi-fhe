//! Common Head key geometry shared by both already-passing finalists.
use tfhe::core_crypto::prelude::*;

pub const HEAD_FOURIER_PAYLOAD_BYTES:usize=112_590_848;
pub const HEAD_FOURIER_COMPLEX_WORDS:usize=7_036_928;
pub const MAX_HEAD_BUNDLE_BYTES:usize=320*1024*1024;

pub fn validate_head(key:&FourierLweBootstrapKeyOwned) -> Result<(),String> {
    if key.input_lwe_dimension().0!=859 || key.glwe_size().0!=2 || key.polynomial_size().0!=2048
        || key.decomposition_base_log().0!=15 || key.decomposition_level_count().0!=2
        || key.as_view().data().len()!=HEAD_FOURIER_COMPLEX_WORDS
        || std::mem::size_of_val(key.as_view().data())!=HEAD_FOURIER_PAYLOAD_BYTES {
        return Err("Head key geometry or container length differs from15x2 profile".into());
    }
    if key.as_view().data().iter().any(|value|!value.re.is_finite() || !value.im.is_finite()) {
        return Err("Head Fourier key contains a non-finite value".into());
    }
    Ok(())
}
