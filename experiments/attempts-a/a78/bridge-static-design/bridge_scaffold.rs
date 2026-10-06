//! A78/U2 source-only bridge scaffold.
//!
//! Status: `UNCOMPILED_STATIC_DRAFT`.  This file is intentionally not attached to a Cargo target.
//! It records the narrow same-version tfhe-rs 1.7 API path discovered by the static audit:
//!
//! A44-big p16 -> pair/add + x4 -> CM packing -> A78 OR4 -> lane0 -> A44-small KSK
//! -> A44 PBS p2-input/p16-output -> A44-big p16.
//!
//! The last ordinary PBS preserves the stock CM output spacing (2^61) until the CM circuit has
//! finished, and emits the A53 Boolean spacing (2^59).  No p-fail claim follows from this source.

#![allow(dead_code)]

use std::mem::size_of_val;

use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    allocate_and_generate_new_cm_lwe_packing_key, pack_lwe_ciphertexts_into_cm,
    CM_PARAM_2_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::{
    CmLweCiphertext, CmLweCiphertextOwned, CmLwePackingKeyOwned,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::
    V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::ClientKey;

pub const A53_BOOLEAN_DELTA_LOG: u32 = 59;
pub const CM_P2_DELTA_LOG: u32 = 61;
pub const INGRESS_RESCALE: u64 = 1u64 << (CM_P2_DELTA_LOG - A53_BOOLEAN_DELTA_LOG);

pub const A44_BIG_DIMENSION: usize = 2_048;
pub const A44_SMALL_DIMENSION: usize = 859;
pub const CM_SMALL_DIMENSION: usize = 762;
pub const CM_BIG_DIMENSION: usize = 3 * 512;
pub const CM_WIDTH: usize = 2;

// CmLwePackingKey layout: w * n_in * L * (n_out + w) u64.
pub const INGRESS_PACKING_KEY_U64S: usize =
    CM_WIDTH * A44_BIG_DIMENSION * 4 * (CM_SMALL_DIMENSION + CM_WIDTH);
pub const INGRESS_PACKING_KEY_BYTES: usize = INGRESS_PACKING_KEY_U64S * 8;

// Ordinary LweKeyswitchKey layout: n_in * L * (n_out + 1) u64.
// The conservative egress targets A44-small and reuses A44's 3x5 decomposition.
pub const EGRESS_TO_A44_SMALL_KEY_U64S: usize =
    CM_BIG_DIMENSION * 5 * (A44_SMALL_DIMENSION + 1);
pub const EGRESS_TO_A44_SMALL_KEY_BYTES: usize = EGRESS_TO_A44_SMALL_KEY_U64S * 8;

pub const BRIDGE_EVALUATION_KEY_BYTES: usize =
    INGRESS_PACKING_KEY_BYTES + EGRESS_TO_A44_SMALL_KEY_BYTES;

pub struct BridgeEvaluationKeys {
    pub ingress_a44_big_to_cm_small: CmLwePackingKeyOwned<u64>,
    pub egress_cm_big_lane0_to_a44_small: LweKeyswitchKeyOwned<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeKeyError {
    A44ClientKeyIsNotStandard,
}

/// Client/dealer-only access to the two A44 secret-key views.
///
/// U2 pins `EncryptionKeyChoice::Big`; the public encryption key is therefore the 2048-dimensional
/// view, while the Standard atomic-pattern key also owns the 859-dimensional PBS input key.
pub fn a44_secret_views(
    client_key: &ClientKey,
) -> Result<
    (
        LweSecretKeyView<'_, u64>,
        LweSecretKeyView<'_, u64>,
    ),
    BridgeKeyError,
> {
    let AtomicPatternClientKey::Standard(standard) = &client_key.atomic_pattern else {
        return Err(BridgeKeyError::A44ClientKeyIsNotStandard);
    };
    let big = standard.large_lwe_secret_key();
    let small = standard.small_lwe_secret_key();
    assert_eq!(big.lwe_dimension(), LweDimension(A44_BIG_DIMENSION));
    assert_eq!(small.lwe_dimension(), LweDimension(A44_SMALL_DIMENSION));
    Ok((big, small))
}

/// Generate only the two additional bridge evaluation keys.
///
/// The authorized client/dealer must already own the U2/A44 keys and the independent A78 lane
/// keys.  The online server receives only the returned evaluation keys.
pub fn generate_bridge_evaluation_keys<Gen: ByteRandomGenerator>(
    a44_big_sk: LweSecretKeyView<'_, u64>,
    a44_small_sk: LweSecretKeyView<'_, u64>,
    cm_small_sks: &[LweSecretKeyOwned<u64>],
    cm_big_sks: &[LweSecretKeyOwned<u64>],
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> BridgeEvaluationKeys {
    let cm = CM_PARAM_2_2_MINUS_64;
    let a44 = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
    assert_eq!(cm.cm_dimension.0, CM_WIDTH);
    assert_eq!(cm.lwe_dimension.0, CM_SMALL_DIMENSION);
    assert_eq!(cm.glwe_dimension.0 * cm.polynomial_size.0, CM_BIG_DIMENSION);
    assert_eq!(a44_big_sk.lwe_dimension(), LweDimension(A44_BIG_DIMENSION));
    assert_eq!(a44_small_sk.lwe_dimension(), LweDimension(A44_SMALL_DIMENSION));
    assert_eq!(cm_small_sks.len(), CM_WIDTH);
    assert_eq!(cm_big_sks.len(), CM_WIDTH);
    assert!(cm_small_sks
        .iter()
        .all(|key| key.lwe_dimension() == LweDimension(CM_SMALL_DIMENSION)));
    assert!(cm_big_sks
        .iter()
        .all(|key| key.lwe_dimension() == LweDimension(CM_BIG_DIMENSION)));

    // Exact API direction: encrypt the A44-big key coefficients under the two independent
    // CM-small lane keys, placing one input ciphertext in each CM body.
    let ingress_a44_big_to_cm_small = allocate_and_generate_new_cm_lwe_packing_key(
        &a44_big_sk,
        cm_small_sks,
        cm.base_log_ks,
        cm.level_ks,
        cm.lwe_noise_distribution,
        cm.ciphertext_modulus,
        generator,
    );

    // Conservative scale-restoring egress: lane 0 only, CM-big -> A44-small.  The following
    // ordinary A44 PBS (server function below) performs the 2^61 -> 2^59 LUT conversion and
    // returns an A44-big ciphertext.  Target-key noise and decomposition are the A44 values.
    let egress_cm_big_lane0_to_a44_small = allocate_and_generate_new_lwe_keyswitch_key(
        &cm_big_sks[0],
        &a44_small_sk,
        a44.ks_base_log,
        a44.ks_level,
        a44.lwe_noise_distribution,
        a44.ciphertext_modulus,
        generator,
    );

    assert_eq!(
        size_of_val(ingress_a44_big_to_cm_small.as_ref()),
        INGRESS_PACKING_KEY_BYTES
    );
    assert_eq!(
        size_of_val(egress_cm_big_lane0_to_a44_small.as_ref()),
        EGRESS_TO_A44_SMALL_KEY_BYTES
    );

    BridgeEvaluationKeys {
        ingress_a44_big_to_cm_small,
        egress_cm_big_lane0_to_a44_small,
    }
}

/// Server-only ingress for OR groups of length two through four.
///
/// Pair sums are formed while all inputs still share the A44-big key.  Scaling after each sum
/// maps `pair * 2^59` exactly to `pair * 2^61`; packing then changes only the secret-key domain.
pub fn ingress_group2_to4_to_cm_small(
    candidates: &[LweCiphertextOwned<u64>],
    packing_key: &CmLwePackingKeyOwned<u64>,
) -> CmLweCiphertextOwned<u64> {
    assert!((2..=4).contains(&candidates.len()));
    assert!(candidates.iter().all(|candidate| {
        candidate.lwe_size().to_lwe_dimension() == LweDimension(A44_BIG_DIMENSION)
            && candidate.ciphertext_modulus() == packing_key.ciphertext_modulus()
    }));

    let mut pair01 = candidates[0].clone();
    lwe_ciphertext_add_assign(&mut pair01, &candidates[1]);
    lwe_ciphertext_cleartext_mul_assign(&mut pair01, Cleartext(INGRESS_RESCALE));
    let pair23 = if candidates.len() >= 3 {
        let mut pair = candidates[2].clone();
        if candidates.len() == 4 {
            lwe_ciphertext_add_assign(&mut pair, &candidates[3]);
        }
        lwe_ciphertext_cleartext_mul_assign(&mut pair, Cleartext(INGRESS_RESCALE));
        pair
    } else {
        // A public all-zero LWE is a valid trivial encryption under the same key shape.
        LweCiphertext::new(
            0u64,
            candidates[0].lwe_size(),
            candidates[0].ciphertext_modulus(),
        )
    };

    let pair_sums = [pair01, pair23];
    let mut packed = CmLweCiphertext::new(
        0u64,
        packing_key.output_lwe_dimension(),
        packing_key.output_cm_dimension(),
        packing_key.ciphertext_modulus(),
    );
    pack_lwe_ciphertexts_into_cm(packing_key, &pair_sums, &mut packed);
    packed
}

/// Public accumulator for the conservative egress PBS.
///
/// The input CM flag keeps the stock p2 spacing `2^61`.  An ordinary A44 blind rotation uses a
/// four-slot input LUT and writes Boolean 0/1 at A53's output spacing `2^59`.
pub fn a44_scale_restore_accumulator() -> GlweCiphertextOwned<u64> {
    let a44 = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
    generate_programmable_bootstrap_glwe_lut(
        a44.polynomial_size,
        a44.glwe_dimension.to_glwe_size(),
        4,
        a44.ciphertext_modulus,
        1u64 << A53_BOOLEAN_DELTA_LOG,
        |slot| u64::from(slot != 0),
    )
}

/// Server-only stock-spacing egress.
///
/// `cm_output` is the output of A78 PBS2 at p2 spacing.  Extracting lane 0 only copies the shared
/// mask plus body 0 and adds no cryptographic noise.  The ad-hoc KSK targets A44-small; the
/// existing U2 A44 bootstrap key then refreshes, rescales, and returns A44-big at `2^59`.
pub fn egress_lane0_via_a44_pbs(
    cm_output: &CmLweCiphertextOwned<u64>,
    egress_key: &LweKeyswitchKeyOwned<u64>,
    a44_scale_restore: &GlweCiphertextOwned<u64>,
    a44_bootstrap_key: &FourierLweBootstrapKeyOwned,
) -> LweCiphertextOwned<u64> {
    assert_eq!(cm_output.cm_dimension().0, CM_WIDTH);
    assert_eq!(cm_output.lwe_dimension().0, CM_BIG_DIMENSION);
    assert_eq!(
        egress_key.input_key_lwe_dimension(),
        LweDimension(CM_BIG_DIMENSION)
    );
    assert_eq!(
        egress_key.output_key_lwe_dimension(),
        LweDimension(A44_SMALL_DIMENSION)
    );
    assert_eq!(
        a44_bootstrap_key.input_lwe_dimension(),
        LweDimension(A44_SMALL_DIMENSION)
    );
    assert_eq!(
        a44_bootstrap_key.output_lwe_dimension(),
        LweDimension(A44_BIG_DIMENSION)
    );
    assert_eq!(
        a44_scale_restore.polynomial_size(),
        a44_bootstrap_key.polynomial_size()
    );

    let lane0_cm_big = cm_output.extract_lwe_ciphertext(0);
    let mut a44_small = LweCiphertext::new(
        0u64,
        egress_key.output_key_lwe_dimension().to_lwe_size(),
        egress_key.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext(egress_key, &lane0_cm_big, &mut a44_small);

    let mut a44_big = LweCiphertext::new(
        0u64,
        a44_bootstrap_key.output_lwe_dimension().to_lwe_size(),
        egress_key.ciphertext_modulus(),
    );
    programmable_bootstrap_lwe_ciphertext(
        &a44_small,
        &mut a44_big,
        a44_scale_restore,
        a44_bootstrap_key,
    );
    a44_big
}
