//! Isolated A52 component for the canonical high-score lane.
//!
//! This crate is intentionally not integrated with the exact-ID core.  It materializes only the
//! A49 proposal: sample a bounded 12-bit score encoded at `Delta=2^51`, apply the audited public
//! offset, and refresh `floor(x/256)` as one standard-p16 LWE at `Delta=2^59`.

use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::ServerKey;

pub const PROBE_DIM: usize = 512;
pub const POLYNOMIAL_SIZE: usize = 2_048;
pub const FULL_LANE_OFFSET: usize = 0;
pub const LOW_LANE_OFFSET: usize = PROBE_DIM;
pub const MID_LANE_OFFSET: usize = 2 * PROBE_DIM;
pub const CANONICAL_HIGH_LANE_OFFSET: usize = 1_536;
pub const LANE_OFFSETS: [usize; 4] = [
    FULL_LANE_OFFSET,
    LOW_LANE_OFFSET,
    MID_LANE_OFFSET,
    CANONICAL_HIGH_LANE_OFFSET,
];
pub const CANONICAL_HIGH_LANE_END: usize = CANONICAL_HIGH_LANE_OFFSET + PROBE_DIM;
pub const CANONICAL_HIGH_SAMPLE_DEGREE: usize = CANONICAL_HIGH_LANE_END - 1;
pub const TEMPLATE_SUPPORT_END: usize = PROBE_DIM - 1;
pub const PRECEDING_LANE_PRODUCT_MAX_RAW_DEGREE: usize =
    MID_LANE_OFFSET + (PROBE_DIM - 1) + TEMPLATE_SUPPORT_END;
pub const CANONICAL_HIGH_PRODUCT_MIN_RAW_DEGREE: usize = CANONICAL_HIGH_LANE_OFFSET;
pub const CANONICAL_HIGH_PRODUCT_MAX_RAW_DEGREE: usize =
    CANONICAL_HIGH_SAMPLE_DEGREE + TEMPLATE_SUPPORT_END;
pub const SCORE_DOMAIN_SIZE: u64 = 4_096;
pub const FULL_DELTA_LOG: u32 = 52;
pub const LOW_DELTA_LOG: u32 = 60;
pub const MID_DELTA_LOG: u32 = 56;
pub const CANONICAL_SCORE_DELTA_LOG: u32 = 51;
pub const P16_DELTA_LOG: u32 = 59;
pub const P16_MODULUS: usize = 16;
pub const BLIND_ROTATION_MODULUS: usize = 2 * POLYNOMIAL_SIZE;
pub const BLIND_ROTATION_LOG: u32 = 12;
pub const HIGH_PRE_PBS_OFFSET_TORUS: u64 = 0xfbfc_0000_0000_0000;
pub const HIGH_OPEN_MARGIN_TORUS: u64 = 1u64 << 50;

pub const A52_PARAMS_ID: &str = "tfhe0113-m2c2-tuniform-a52-canonical-high-v1";
pub const A52_PARAMETER_AND_LAYOUT_CANONICAL: &str = "tfhe-rs=0.11.3;symbol=V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;bootstrap=classic_ks_pbs;lwe_dimension=879;glwe_dimension=1;polynomial_size=2048;lwe_noise=tuniform_bound_log2=46;glwe_noise=tuniform_bound_log2=17;pbs_base_log=23;pbs_level=1;ks_base_log=3;ks_level=5;message_modulus=4;carry_modulus=4;max_noise_level=5;log2_p_fail=-71.625;ciphertext_modulus=native;encryption_key_choice=Big;layout_score_domain=0..4095;lane_offset=1536;lane_length=512;sample_degree=2047;input_delta_log=51;pre_pbs_offset=-257*2^50;output_modulus=16;output_delta_log=59;operation_order=KS_PBS";
pub const A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256: &str =
    "2cf9b69545e4063f96ab773acbfbd89396472a7a0ed643f63d1c258a75694e99";

pub type Lwe = LweCiphertextOwned<u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A52Binding<'a> {
    pub params_id: &'a str,
    pub fingerprint_sha256: &'a str,
}

pub const A52_BINDING: A52Binding<'static> = A52Binding {
    params_id: A52_PARAMS_ID,
    fingerprint_sha256: A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A52OperationCounts {
    pub blind_rotations: u64,
    pub classical_key_switches: u64,
    pub output_marginals: u64,
    pub sample_extractions: u64,
    pub public_plaintext_additions: u64,
}

pub const A52_PER_TEMPLATE_COUNTS: A52OperationCounts = A52OperationCounts {
    blind_rotations: 1,
    classical_key_switches: 1,
    output_marginals: 1,
    sample_extractions: 1,
    public_plaintext_additions: 2,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum A52Error {
    ParameterIdMismatch,
    FingerprintMismatch,
    FingerprintDefinitionMismatch,
    StaticLayoutMismatch(&'static str),
    ParameterGeometryMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    UnsupportedBootstrappingKey,
    InvalidScoreLweShape,
    InvalidScoreLweModulus,
    ScoreOutsideBoundedDomain(u64),
}

impl Display for A52Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParameterIdMismatch => write!(formatter, "A52 params_id mismatch"),
            Self::FingerprintMismatch => write!(formatter, "A52 fingerprint mismatch"),
            Self::FingerprintDefinitionMismatch => {
                write!(formatter, "A52 compiled fingerprint definition mismatch")
            }
            Self::StaticLayoutMismatch(field) => {
                write!(formatter, "A52 static layout mismatch for {field}")
            }
            Self::ParameterGeometryMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "A52 parameter geometry mismatch for {field}: expected {expected}, got {actual}"
            ),
            Self::UnsupportedBootstrappingKey => {
                write!(formatter, "A52 requires a classic bootstrapping key")
            }
            Self::InvalidScoreLweShape => write!(formatter, "A52 score LWE has the wrong shape"),
            Self::InvalidScoreLweModulus => {
                write!(
                    formatter,
                    "A52 score LWE does not use the bound native modulus"
                )
            }
            Self::ScoreOutsideBoundedDomain(score) => {
                write!(formatter, "A52 clear score {score} is outside 0..4095")
            }
        }
    }
}

impl std::error::Error for A52Error {}

pub fn a52_parameter_and_layout_fingerprint_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(A52_PARAMETER_AND_LAYOUT_CANONICAL.as_bytes())
    )
}

pub fn validate_a52_binding_text(binding: A52Binding<'_>) -> Result<(), A52Error> {
    if binding.params_id != A52_PARAMS_ID {
        return Err(A52Error::ParameterIdMismatch);
    }
    if binding.fingerprint_sha256 != A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256 {
        return Err(A52Error::FingerprintMismatch);
    }
    if a52_parameter_and_layout_fingerprint_sha256() != A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256
    {
        return Err(A52Error::FingerprintDefinitionMismatch);
    }
    Ok(())
}

pub fn validate_a52_static_layout() -> Result<(), A52Error> {
    let checks = [
        (PROBE_DIM == 512, "probe_dim"),
        (POLYNOMIAL_SIZE == 2_048, "polynomial_size"),
        (
            CANONICAL_HIGH_LANE_OFFSET == 3 * PROBE_DIM,
            "canonical_lane_offset",
        ),
        (LANE_OFFSETS == [0, 512, 1_024, 1_536], "four_lane_offsets"),
        (
            CANONICAL_HIGH_LANE_END == POLYNOMIAL_SIZE,
            "canonical_lane_end",
        ),
        (
            CANONICAL_HIGH_SAMPLE_DEGREE == POLYNOMIAL_SIZE - 1,
            "sample_degree",
        ),
        (
            PRECEDING_LANE_PRODUCT_MAX_RAW_DEGREE + 1 == CANONICAL_HIGH_SAMPLE_DEGREE,
            "preceding_lane_cannot_reach_sample",
        ),
        (
            CANONICAL_HIGH_SAMPLE_DEGREE == CANONICAL_HIGH_LANE_OFFSET + TEMPLATE_SUPPORT_END,
            "canonical_lane_diagonal",
        ),
        (
            CANONICAL_HIGH_PRODUCT_MIN_RAW_DEGREE <= CANONICAL_HIGH_SAMPLE_DEGREE,
            "canonical_product_contains_sample",
        ),
        (
            CANONICAL_HIGH_PRODUCT_MAX_RAW_DEGREE < CANONICAL_HIGH_SAMPLE_DEGREE + POLYNOMIAL_SIZE,
            "wrapped_canonical_product_cannot_rehit_sample",
        ),
        (
            BLIND_ROTATION_MODULUS == 2 * POLYNOMIAL_SIZE,
            "blind_rotation_modulus",
        ),
        (
            BLIND_ROTATION_LOG == BLIND_ROTATION_MODULUS.ilog2(),
            "blind_rotation_log",
        ),
        (SCORE_DOMAIN_SIZE == 1 << 12, "score_domain"),
        (P16_MODULUS == 16, "p16_modulus"),
        (P16_DELTA_LOG == 59, "p16_delta"),
        (CANONICAL_SCORE_DELTA_LOG == 51, "canonical_score_delta"),
        (FULL_DELTA_LOG == 52, "full_delta"),
        (LOW_DELTA_LOG == 60, "low_delta"),
        (MID_DELTA_LOG == 56, "mid_delta"),
        (
            HIGH_PRE_PBS_OFFSET_TORUS == 0u64.wrapping_sub(257u64 << 50),
            "high_pre_pbs_offset",
        ),
    ];
    for (valid, field) in checks {
        if !valid {
            return Err(A52Error::StaticLayoutMismatch(field));
        }
    }
    Ok(())
}

fn require_parameter_field(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), A52Error> {
    if actual != expected {
        return Err(A52Error::ParameterGeometryMismatch {
            field,
            expected: expected as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

pub fn validate_a52_server_key(
    binding: A52Binding<'_>,
    server_key: &ServerKey,
) -> Result<(), A52Error> {
    validate_a52_binding_text(binding)?;
    validate_a52_static_layout()?;
    require_parameter_field("message_modulus", server_key.message_modulus.0 as usize, 4)?;
    require_parameter_field("carry_modulus", server_key.carry_modulus.0 as usize, 4)?;
    require_parameter_field(
        "max_noise_level",
        server_key.max_noise_level.get() as usize,
        5,
    )?;
    require_parameter_field("max_degree", server_key.max_degree.get() as usize, 15)?;
    require_parameter_field(
        "pbs_order_keyswitch_bootstrap",
        usize::from(server_key.pbs_order == PBSOrder::KeyswitchBootstrap),
        1,
    )?;
    require_parameter_field(
        "ciphertext_modulus_native",
        usize::from(server_key.ciphertext_modulus.is_native_modulus()),
        1,
    )?;

    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(A52Error::UnsupportedBootstrappingKey),
    };
    require_parameter_field(
        "bsk_input_lwe_dimension",
        bootstrap_key.input_lwe_dimension().0,
        879,
    )?;
    require_parameter_field(
        "bsk_output_lwe_dimension",
        bootstrap_key.output_lwe_dimension().0,
        POLYNOMIAL_SIZE,
    )?;
    require_parameter_field("bsk_glwe_size", bootstrap_key.glwe_size().0, 2)?;
    require_parameter_field(
        "bsk_polynomial_size",
        bootstrap_key.polynomial_size().0,
        POLYNOMIAL_SIZE,
    )?;
    require_parameter_field("pbs_base_log", bootstrap_key.decomposition_base_log().0, 23)?;
    require_parameter_field("pbs_level", bootstrap_key.decomposition_level_count().0, 1)?;

    let key_switching_key = &server_key.key_switching_key;
    require_parameter_field(
        "ksk_input_lwe_dimension",
        key_switching_key.input_key_lwe_dimension().0,
        POLYNOMIAL_SIZE,
    )?;
    require_parameter_field(
        "ksk_output_lwe_dimension",
        key_switching_key.output_key_lwe_dimension().0,
        879,
    )?;
    require_parameter_field(
        "ks_base_log",
        key_switching_key.decomposition_base_log().0,
        3,
    )?;
    require_parameter_field(
        "ks_level",
        key_switching_key.decomposition_level_count().0,
        5,
    )?;
    Ok(())
}

/// Materialize the A49 high digit with exactly one classical KS and one blind rotation.
pub fn canonical_high_digit(
    binding: A52Binding<'_>,
    server_key: &ServerKey,
    canonical_score: &Lwe,
) -> Result<Lwe, A52Error> {
    canonical_high_digit_with_trace(binding, server_key, canonical_score)
        .map(|(output, _trace)| output)
}

/// Retains the actual ordinary-KS output consumed by the unchanged stock PBS.
/// Degrees are replayed with the same cached public function used inside that PBS;
/// they are not a second MS/PBS invocation or a phase-only approximation.
pub struct A52HighTrace {
    pub shifted: Lwe,
    pub switched: Lwe,
    pub accumulator_body: Vec<u64>,
    pub mask_degrees: Vec<usize>,
    pub body_degree: usize,
}

pub fn canonical_high_digit_with_trace(
    binding: A52Binding<'_>,
    server_key: &ServerKey,
    canonical_score: &Lwe,
) -> Result<(Lwe, A52HighTrace), A52Error> {
    validate_a52_server_key(binding, server_key)?;
    if !canonical_score.ciphertext_modulus().is_native_modulus()
        || canonical_score.ciphertext_modulus() != server_key.ciphertext_modulus
    {
        return Err(A52Error::InvalidScoreLweModulus);
    }

    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(A52Error::UnsupportedBootstrappingKey),
    };
    if canonical_score.lwe_size() != bootstrap_key.output_lwe_dimension().to_lwe_size() {
        return Err(A52Error::InvalidScoreLweShape);
    }

    let key_switching_key = &server_key.key_switching_key;
    let modulus = canonical_score.ciphertext_modulus();
    let mut shifted = canonical_score.clone();
    lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(HIGH_PRE_PBS_OFFSET_TORUS));
    let mut switched = LweCiphertext::new(
        0u64,
        key_switching_key.output_key_lwe_dimension().to_lwe_size(),
        modulus,
    );
    keyswitch_lwe_ciphertext(key_switching_key, &shifted, &mut switched);

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        PolynomialSize(POLYNOMIAL_SIZE),
        bootstrap_key.glwe_size(),
        P16_MODULUS,
        modulus,
        1u64 << P16_DELTA_LOG,
        |digit| digit,
    );
    let mut output = LweCiphertext::new(
        0u64,
        bootstrap_key.output_lwe_dimension().to_lwe_size(),
        modulus,
    );
    programmable_bootstrap_lwe_ciphertext(&switched, &mut output, &accumulator, bootstrap_key);
    let mask_degrees = switched
        .get_mask()
        .as_ref()
        .iter()
        .map(|&word| pbs_modulus_switch(word, PolynomialSize(POLYNOMIAL_SIZE)))
        .collect();
    let body_degree =
        pbs_modulus_switch(*switched.get_body().data, PolynomialSize(POLYNOMIAL_SIZE));
    let trace = A52HighTrace {
        shifted,
        switched,
        accumulator_body: accumulator.get_body().as_ref().to_vec(),
        mask_degrees,
        body_degree,
    };
    Ok((output, trace))
}

pub fn native_pbs_modulus_switch_clear(phase: u64) -> usize {
    (phase.wrapping_add(1u64 << 51) >> 52) as usize
}

pub fn standard_p16_identity_accumulator_codes() -> Vec<i64> {
    let box_size = POLYNOMIAL_SIZE / P16_MODULUS;
    let mut body = (0..P16_MODULUS)
        .flat_map(|digit| std::iter::repeat(digit as i64).take(box_size))
        .collect::<Vec<_>>();
    let half_box = box_size / 2;
    for value in &mut body[..half_box] {
        *value = -*value;
    }
    body.rotate_left(half_box);
    body
}

pub fn negacyclic_accumulator_code(rotation: usize) -> i64 {
    let body = standard_p16_identity_accumulator_codes();
    let rotation = rotation % BLIND_ROTATION_MODULUS;
    if rotation < POLYNOMIAL_SIZE {
        body[rotation]
    } else {
        -body[rotation - POLYNOMIAL_SIZE]
    }
}

pub fn clear_canonical_high_digit(score: u64, torus_error: i64) -> Result<u64, A52Error> {
    if score >= SCORE_DOMAIN_SIZE {
        return Err(A52Error::ScoreOutsideBoundedDomain(score));
    }
    validate_a52_static_layout()?;
    let phase = (score << CANONICAL_SCORE_DELTA_LOG)
        .wrapping_add(HIGH_PRE_PBS_OFFSET_TORUS)
        .wrapping_add(torus_error as u64);
    let rotation = native_pbs_modulus_switch_clear(phase);
    Ok(negacyclic_accumulator_code(rotation).rem_euclid(32) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_and_static_layout_are_exact() {
        assert_eq!(
            a52_parameter_and_layout_fingerprint_sha256(),
            A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256
        );
        assert_eq!(validate_a52_binding_text(A52_BINDING), Ok(()));
        assert_eq!(validate_a52_static_layout(), Ok(()));
        assert!(matches!(
            validate_a52_binding_text(A52Binding {
                params_id: "wrong",
                fingerprint_sha256: A52_PARAMETER_AND_LAYOUT_FINGERPRINT_SHA256,
            }),
            Err(A52Error::ParameterIdMismatch)
        ));
    }

    #[test]
    fn every_clear_center_and_open_margin_are_exact() {
        for error in [
            0,
            HIGH_OPEN_MARGIN_TORUS as i64 - 1,
            -(HIGH_OPEN_MARGIN_TORUS as i64 - 1),
        ] {
            for score in 0..SCORE_DOMAIN_SIZE {
                assert_eq!(clear_canonical_high_digit(score, error), Ok(score >> 8));
            }
        }
        assert!((0..SCORE_DOMAIN_SIZE).any(|score| {
            clear_canonical_high_digit(score, HIGH_OPEN_MARGIN_TORUS as i64) != Ok(score >> 8)
        }));
    }

    #[test]
    fn each_high_digit_occupies_one_complete_accumulator_box() {
        for high in 0..16u64 {
            let rotations = (0..256u64)
                .map(|residue| {
                    let score = 256 * high + residue;
                    let phase = (score << CANONICAL_SCORE_DELTA_LOG)
                        .wrapping_add(HIGH_PRE_PBS_OFFSET_TORUS);
                    let rotation = native_pbs_modulus_switch_clear(phase) as i64;
                    if rotation >= POLYNOMIAL_SIZE as i64 {
                        rotation - BLIND_ROTATION_MODULUS as i64
                    } else {
                        rotation
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(rotations.iter().min(), Some(&(128 * high as i64 - 64)));
            assert_eq!(rotations.iter().max(), Some(&(128 * high as i64 + 63)));
        }
    }

    #[test]
    fn structural_count_is_one_ks_one_br_one_fresh_output() {
        assert_eq!(
            A52_PER_TEMPLATE_COUNTS,
            A52OperationCounts {
                blind_rotations: 1,
                classical_key_switches: 1,
                output_marginals: 1,
                sample_extractions: 1,
                public_plaintext_additions: 2,
            }
        );
    }

    #[test]
    fn exact_phase_does_not_imply_exact_coefficientwise_rotation() {
        // A legal 879-mask binary-secret example with only the first two bits set.
        // It is not asserted to be the old run's KSK output or a typical sample.
        let mask_word = 1u64 << 51;
        let body = HIGH_PRE_PBS_OFFSET_TORUS.wrapping_add(2 * mask_word);
        let round = |word| pbs_modulus_switch(word, PolynomialSize(POLYNOMIAL_SIZE));
        let phase = body.wrapping_sub(2 * mask_word);
        let actual_degree =
            (round(body) + BLIND_ROTATION_MODULUS - 2 * round(mask_word)) % BLIND_ROTATION_MODULUS;
        assert_eq!(phase, HIGH_PRE_PBS_OFFSET_TORUS);
        assert_eq!(round(phase), 4_032);
        assert_eq!(actual_degree, 4_031);
        assert_eq!(clear_canonical_high_digit(0, 0), Ok(0));
        assert_eq!(
            negacyclic_accumulator_code(actual_degree).rem_euclid(32),
            17
        );
    }

    #[test]
    fn public_shift_cannot_enlarge_both_adjacent_boundary_margins() {
        assert_eq!(clear_canonical_high_digit(255, 0), Ok(0));
        assert_eq!(clear_canonical_high_digit(256, 0), Ok(1));
        assert_ne!(
            clear_canonical_high_digit(255, HIGH_OPEN_MARGIN_TORUS as i64),
            Ok(0),
        );
        assert_ne!(
            clear_canonical_high_digit(256, -(HIGH_OPEN_MARGIN_TORUS as i64) - 1),
            Ok(1),
        );
    }

    #[test]
    fn independent_accumulator_codes_equal_the_actual_stock_lut() {
        let actual = generate_programmable_bootstrap_glwe_lut(
            PolynomialSize(POLYNOMIAL_SIZE),
            GlweSize(2),
            P16_MODULUS,
            CiphertextModulus::new_native(),
            1u64 << P16_DELTA_LOG,
            |digit| digit,
        );
        for degree in 0..BLIND_ROTATION_MODULUS {
            let word = actual.get_body().as_ref()[degree % POLYNOMIAL_SIZE];
            let expected = if degree < POLYNOMIAL_SIZE {
                word
            } else {
                word.wrapping_neg()
            };
            assert_eq!(
                (negacyclic_accumulator_code(degree) as u64).wrapping_mul(1u64 << 59),
                expected,
            );
        }
    }
}
