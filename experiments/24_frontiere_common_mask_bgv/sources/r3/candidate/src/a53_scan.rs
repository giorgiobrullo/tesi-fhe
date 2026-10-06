//! A62: A53 base-15 group-of-four scan integrated with the isolated A44 core.
//!
//! The clear/raw geometry remains byte-derived from the frozen A58 materialization.  Unlike A58,
//! this module is part of an actual Cargo crate and [`fhe`] is wired to the A44 core through the
//! concrete backend in `private_argmin.rs`.  No build or FHE execution claim follows from that
//! source integration alone.

use std::collections::BTreeMap;

pub mod fhe;

pub const MAX_GALLERY_SIZE: usize = 128;
pub const GROUP_SIZE: usize = 4;
pub const REDUCTION_RADIX: usize = 15;
pub const OUTPUT_BASE: u16 = 15;
pub const P16: usize = 16;
pub const SIGNED_INPUT_PERIOD: i32 = 32;
pub const POLYNOMIAL_SIZE: usize = 2_048;
pub const BOX_SIZE: usize = POLYNOMIAL_SIZE / P16;
pub const STRICT_MARGIN_RADIUS: i32 = (BOX_SIZE / 2 - 1) as i32;
pub const BOOL_OUTPUT_PERIOD: u16 = 32;
pub const CODE_OUTPUT_PERIOD: u16 = 256;
pub const BOOL_DELTA_LOG: u32 = 59;
pub const CODE_DELTA_LOG: u32 = 56;
pub const A62_WIRE_OUTPUT_LWES: usize = 2;
pub const A62_ROOT_DELTA_LOG: u32 = BOOL_DELTA_LOG;
pub const CURRENT_TUNIFORM_MAX_NOISE_LEVEL: usize = 5;
pub const A44_MAX_NOISE_LEVEL: usize = 15;
pub const SELECTOR_SECOND_SAMPLE_DEGREE: usize = POLYNOMIAL_SIZE / 2;

pub const A53_CONTRACT_ID: &str = "a62-exact-open-set-id-base15-two-p16-roots-v1";
pub const A53_CONTRACT_DESCRIPTION: &str =
    "two p16 roots reconstruct 0=reject or i+1 for the first admitted exact global minimum";

pub const A44_PARAMS_ID: &str = "tfhe-rs-1.7.0-v0_11-m1c3-classic-ks-pbs-gaussian-2m64";
pub const A44_PARAMETER_FINGERPRINT_SHA256: &str =
    "ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61";
pub const A44_PARAMETER_CANONICAL: &str = "tfhe-rs=1.7.0;symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;bootstrap=classic_ks_pbs;modulus_switch=standard;lwe_dimension=859;glwe_dimension=1;polynomial_size=2048;lwe_noise=gaussian_stddev_2.3088161607134664e-6;glwe_noise=gaussian_stddev_2.845267479601915e-15;pbs_base_log=23;pbs_level=1;ks_base_log=3;ks_level=5;message_modulus=2;carry_modulus=8;max_noise_level=15;log2_p_fail=-64.088;ciphertext_modulus=native;encryption_key_choice=Big";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceGuard {
    pub repository_path: &'static str,
    pub sha256: &'static str,
}

/// Inputs read while deriving A58.  The Python static gate hashes every path before reporting GO.
pub const SOURCE_GUARDS: &[SourceGuard] = &[
    SourceGuard {
        repository_path: "tmp/a38-combined-prototype/src/private_argmin.rs",
        sha256: "9fc9013f1b322ad89d4a3902de3d945abf5aec9f335f1fb4088d73b44c151e79",
    },
    SourceGuard {
        repository_path: "tmp/a38-combined-prototype/src/lib.rs",
        sha256: "855288001429bf9148412d984b26acc4df9179b0bfc79f91469a1eb274807532",
    },
    SourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/src/private_argmin.rs",
        sha256: "d6793b2a5040d39060b561552d976d4718f299d35a051a3304eaa3219bab912c",
    },
    SourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/src/lib.rs",
        sha256: "c31619b88e87ac73e3174281b1453433f08f8ab0cd6d7e50a79ca16539ddf434",
    },
    SourceGuard {
        repository_path: "tmp/a44-p16-retune-prototype/Cargo.lock",
        sha256: "f0072f805e3559203affcd73dc94ca30610552a63b3cfb1da8d4e6d78aa435dd",
    },
    SourceGuard {
        repository_path: "tmp/a50-canonical-radix15-model/a50_canonical_radix15_model.py",
        sha256: "19196d9e17a30e5197601dacf42b9416239608a99489b4a1a284f488e102c4cb",
    },
    SourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/a53_radix15_group4_scan_model.py",
        sha256: "a03c8753298e0959133b0c915b911172795bafba353d86b75c7cdfb38d31eb9f",
    },
    SourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/test_a53_static.py",
        sha256: "c64026b21134d6df1b0e2d2dfdf4358137a98dc6b832f5cfde2e43b50d9166ae",
    },
    SourceGuard {
        repository_path: "tmp/a53-radix15-group4-scan-model/README.md",
        sha256: "12c95ef11b91e1922312336ad7380b4b98ef616ddf6f9046aa05ae060053d179",
    },
];

/// Canonical p16 slots.  Only the reachable local phases 0..=8 carry a payload.
pub const GROUP_OR_SLOT_LUT: [u16; P16] = [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
pub const LOCAL_FIRST_SLOT_LUT: [u16; P16] = [0, 4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
pub const DIGIT_IDENTITY_SLOT_LUT: [u16; P16] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const LOW_CODE_SLOT_LUT: [u16; P16] = DIGIT_IDENTITY_SLOT_LUT;
pub const HIGH_CODE_SLOT_LUT: [u16; P16] = [
    0, 15, 30, 45, 60, 75, 90, 105, 120, 135, 150, 165, 180, 195, 210, 225,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectorOffsets {
    pub low: u16,
    pub high: u16,
}

impl SelectorOffsets {
    pub const fn new(low: u16, high: u16) -> Self {
        Self { low, high }
    }
}

/// Public post-extraction offsets for every full group, at the Boolean output period 32.
/// Lengths one through three use `(0,0)` and are handled by [`selector_offsets`].
pub const FULL_GROUP_SELECTOR_OFFSETS: [SelectorOffsets; 32] = [
    SelectorOffsets::new(2, 30),
    SelectorOffsets::new(4, 28),
    SelectorOffsets::new(6, 26),
    SelectorOffsets::new(1, 0),
    SelectorOffsets::new(3, 30),
    SelectorOffsets::new(5, 28),
    SelectorOffsets::new(7, 26),
    SelectorOffsets::new(2, 0),
    SelectorOffsets::new(4, 30),
    SelectorOffsets::new(6, 28),
    SelectorOffsets::new(8, 26),
    SelectorOffsets::new(3, 0),
    SelectorOffsets::new(5, 30),
    SelectorOffsets::new(7, 28),
    SelectorOffsets::new(2, 2),
    SelectorOffsets::new(4, 0),
    SelectorOffsets::new(6, 30),
    SelectorOffsets::new(8, 28),
    SelectorOffsets::new(3, 2),
    SelectorOffsets::new(5, 0),
    SelectorOffsets::new(7, 30),
    SelectorOffsets::new(9, 28),
    SelectorOffsets::new(4, 2),
    SelectorOffsets::new(6, 0),
    SelectorOffsets::new(8, 30),
    SelectorOffsets::new(10, 28),
    SelectorOffsets::new(5, 2),
    SelectorOffsets::new(7, 0),
    SelectorOffsets::new(9, 30),
    SelectorOffsets::new(4, 4),
    SelectorOffsets::new(6, 2),
    SelectorOffsets::new(8, 0),
];

/// Direct-code layouts for the sole group, at output period 256 and `Delta_code`.
pub const DIRECT_SELECTOR_OFFSETS_BY_LENGTH: [SelectorOffsets; GROUP_SIZE] = [
    SelectorOffsets::new(0, 0),
    SelectorOffsets::new(0, 0),
    SelectorOffsets::new(0, 0),
    SelectorOffsets::new(2, 254),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputScale {
    BooleanDigit,
    ExactCode,
}

impl OutputScale {
    pub const fn period(self) -> u16 {
        match self {
            Self::BooleanDigit => BOOL_OUTPUT_PERIOD,
            Self::ExactCode => CODE_OUTPUT_PERIOD,
        }
    }

    pub const fn delta_log(self) -> u32 {
        match self {
            Self::BooleanDigit => BOOL_DELTA_LOG,
            Self::ExactCode => CODE_DELTA_LOG,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum A53StaticError {
    GallerySize,
    GroupIndex,
    GroupLength,
    DirectLayoutRequiresFirstGroup,
    ConflictingRequirement,
    InvalidBody,
    ContractViolation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorLayout {
    pub group_index: usize,
    pub group_length: usize,
    pub direct_code_scale: bool,
    pub scale: OutputScale,
    pub offsets: SelectorOffsets,
    pub assigned_independent_slots: usize,
    pub residue_body: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrimitiveCounts {
    pub blind_rotations: u64,
    pub key_switches: u64,
    pub output_marginals: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanCounts {
    pub gallery_size: usize,
    pub groups: usize,
    pub group_flag_nodes: u64,
    pub local_first_nodes: u64,
    pub prefix_nodes: u64,
    pub selector_blind_rotations: u64,
    pub selector_key_switches: u64,
    pub selector_marginals: u64,
    pub digit_reduction_nodes: u64,
    pub total: PrimitiveCounts,
}

pub const A53_N127_SCAN_COUNTS: PrimitiveCounts = PrimitiveCounts {
    blind_rotations: 136,
    key_switches: 136,
    output_marginals: 168,
};
pub const A53_N127_FULL_COUNTS: PrimitiveCounts = PrimitiveCounts {
    blind_rotations: 3_390,
    key_switches: 3_009,
    output_marginals: 3_930,
};

fn residue_neg(value: u16, period: u16) -> u16 {
    (period - value % period) % period
}

fn assign_slot(
    assignments: &mut [Option<u16>; P16],
    slot: usize,
    value: u16,
    period: u16,
) -> Result<(), A53StaticError> {
    let value = value % period;
    match assignments[slot] {
        Some(existing) if existing != value => Err(A53StaticError::ConflictingRequirement),
        _ => {
            assignments[slot] = Some(value);
            Ok(())
        }
    }
}

fn virtual_requirement(phase: i32, raw_output: u16, period: u16) -> (usize, u16) {
    let virtual_phase = phase.rem_euclid(SIGNED_INPUT_PERIOD);
    let slot = virtual_phase.rem_euclid(P16 as i32) as usize;
    let required = if virtual_phase < P16 as i32 {
        raw_output % period
    } else {
        residue_neg(raw_output, period)
    };
    (slot, required)
}

pub fn slot_lut_residue_body(slots: &[u16; P16], period: u16) -> Result<Vec<u16>, A53StaticError> {
    let assignments = std::array::from_fn(|slot| Some(slots[slot] % period));
    robust_residue_body(&assignments, period)
}

fn robust_residue_body(
    assignments: &[Option<u16>; P16],
    period: u16,
) -> Result<Vec<u16>, A53StaticError> {
    let mut coefficients = vec![None; POLYNOMIAL_SIZE];
    for (slot, desired) in assignments.iter().copied().enumerate() {
        let Some(desired) = desired else {
            continue;
        };
        for error in -STRICT_MARGIN_RADIUS..=STRICT_MARGIN_RADIUS {
            let degree = slot as i32 * BOX_SIZE as i32 + error;
            let cycles = degree.div_euclid(POLYNOMIAL_SIZE as i32);
            let index = degree.rem_euclid(POLYNOMIAL_SIZE as i32) as usize;
            let body_value = if cycles.rem_euclid(2) == 0 {
                desired % period
            } else {
                residue_neg(desired, period)
            };
            match coefficients[index] {
                Some(existing) if existing != body_value => {
                    return Err(A53StaticError::ConflictingRequirement);
                }
                _ => coefficients[index] = Some(body_value),
            }
        }
    }
    Ok(coefficients
        .into_iter()
        .map(|value| value.unwrap_or(0))
        .collect())
}

pub fn sample_residue(
    body: &[u16],
    phase: i32,
    error: i32,
    sample_degree: usize,
    period: u16,
) -> Result<u16, A53StaticError> {
    if body.len() != POLYNOMIAL_SIZE {
        return Err(A53StaticError::InvalidBody);
    }
    let degree = phase as i64 * BOX_SIZE as i64 + error as i64 + sample_degree as i64;
    let cycles = degree.div_euclid(POLYNOMIAL_SIZE as i64);
    let index = degree.rem_euclid(POLYNOMIAL_SIZE as i64) as usize;
    let value = body[index] % period;
    Ok(if cycles.rem_euclid(2) == 0 {
        value
    } else {
        residue_neg(value, period)
    })
}

pub fn group_local_phase(group: &[bool]) -> Result<u16, A53StaticError> {
    if group.is_empty() || group.len() > GROUP_SIZE {
        return Err(A53StaticError::GroupLength);
    }
    let flag = u16::from(group.iter().any(|candidate| *candidate));
    Ok(flag
        + 4 * u16::from(group.first().copied().unwrap_or(false))
        + 2 * u16::from(group.get(1).copied().unwrap_or(false))
        + u16::from(group.get(2).copied().unwrap_or(false)))
}

pub fn local_first(group: &[bool]) -> Result<u16, A53StaticError> {
    if group.is_empty() || group.len() > GROUP_SIZE {
        return Err(A53StaticError::GroupLength);
    }
    Ok(group
        .iter()
        .position(|candidate| *candidate)
        .map_or(0, |index| index as u16 + 1))
}

pub fn selector_offsets(
    group_index: usize,
    group_length: usize,
    direct_code_scale: bool,
) -> Result<SelectorOffsets, A53StaticError> {
    if group_index >= MAX_GALLERY_SIZE.div_ceil(GROUP_SIZE) {
        return Err(A53StaticError::GroupIndex);
    }
    if !(1..=GROUP_SIZE).contains(&group_length) {
        return Err(A53StaticError::GroupLength);
    }
    if direct_code_scale {
        if group_index != 0 {
            return Err(A53StaticError::DirectLayoutRequiresFirstGroup);
        }
        return Ok(DIRECT_SELECTOR_OFFSETS_BY_LENGTH[group_length - 1]);
    }
    Ok(if group_length == GROUP_SIZE {
        FULL_GROUP_SELECTOR_OFFSETS[group_index]
    } else {
        SelectorOffsets::default()
    })
}

pub fn selector_requirements(
    group_index: usize,
    group_length: usize,
    direct_code_scale: bool,
) -> Result<BTreeMap<i32, (u16, u16)>, A53StaticError> {
    selector_offsets(group_index, group_length, direct_code_scale)?;
    let mut outputs = BTreeMap::new();
    for prefix in 0..=1i32 {
        for local in 0..=group_length as i32 {
            let phase = local - GROUP_SIZE as i32 * prefix;
            let code = if local > 0 && prefix == 0 {
                GROUP_SIZE as u16 * group_index as u16 + local as u16
            } else {
                0
            };
            let low = code % OUTPUT_BASE;
            let high = code / OUTPUT_BASE;
            let desired = if direct_code_scale {
                (low, OUTPUT_BASE * high)
            } else {
                (low, high)
            };
            match outputs.insert(phase, desired) {
                Some(existing) if existing != desired => {
                    return Err(A53StaticError::ConflictingRequirement);
                }
                _ => {}
            }
        }
    }
    Ok(outputs)
}

pub fn selector_layout(
    group_index: usize,
    group_length: usize,
    direct_code_scale: bool,
) -> Result<SelectorLayout, A53StaticError> {
    let scale = if direct_code_scale {
        OutputScale::ExactCode
    } else {
        OutputScale::BooleanDigit
    };
    let period = scale.period();
    let offsets = selector_offsets(group_index, group_length, direct_code_scale)?;
    let outputs = selector_requirements(group_index, group_length, direct_code_scale)?;
    let mut assignments = [None; P16];
    for (phase, (desired_low, desired_high)) in outputs {
        for (virtual_phase, desired, public_offset) in [
            (phase, desired_low, offsets.low),
            (
                phase + (SELECTOR_SECOND_SAMPLE_DEGREE / BOX_SIZE) as i32,
                desired_high,
                offsets.high,
            ),
        ] {
            let raw = (desired + period - public_offset % period) % period;
            let (slot, required) = virtual_requirement(virtual_phase, raw, period);
            assign_slot(&mut assignments, slot, required, period)?;
        }
    }
    let assigned_independent_slots = assignments.iter().filter(|value| value.is_some()).count();
    let residue_body = robust_residue_body(&assignments, period)?;
    Ok(SelectorLayout {
        group_index,
        group_length,
        direct_code_scale,
        scale,
        offsets,
        assigned_independent_slots,
        residue_body,
    })
}

pub fn validate_selector_layout(layout: &SelectorLayout) -> Result<(), A53StaticError> {
    let expected = selector_requirements(
        layout.group_index,
        layout.group_length,
        layout.direct_code_scale,
    )?;
    let canonical_offsets = selector_offsets(
        layout.group_index,
        layout.group_length,
        layout.direct_code_scale,
    )?;
    if layout.offsets != canonical_offsets || layout.residue_body.len() != POLYNOMIAL_SIZE {
        return Err(A53StaticError::InvalidBody);
    }
    let period = layout.scale.period();
    for (phase, desired) in expected {
        for error in -STRICT_MARGIN_RADIUS..=STRICT_MARGIN_RADIUS {
            let low = (sample_residue(&layout.residue_body, phase, error, 0, period)?
                + layout.offsets.low)
                % period;
            let high = (sample_residue(
                &layout.residue_body,
                phase,
                error,
                SELECTOR_SECOND_SAMPLE_DEGREE,
                period,
            )? + layout.offsets.high)
                % period;
            if (low, high) != desired {
                return Err(A53StaticError::ContractViolation);
            }
        }
    }
    Ok(())
}

pub fn clear_exclusive_prefix(flags: &[bool]) -> Result<Vec<bool>, A53StaticError> {
    if flags.is_empty() {
        return Err(A53StaticError::GroupLength);
    }
    let mut seen = false;
    Ok(flags
        .iter()
        .map(|flag| {
            let prefix = seen;
            seen |= *flag;
            prefix
        })
        .collect())
}

pub fn clear_scan(candidates: &[bool]) -> Result<u16, A53StaticError> {
    if candidates.is_empty() || candidates.len() > MAX_GALLERY_SIZE {
        return Err(A53StaticError::GallerySize);
    }
    let groups: Vec<&[bool]> = candidates.chunks(GROUP_SIZE).collect();
    let flags: Vec<bool> = groups
        .iter()
        .map(|group| group.iter().any(|candidate| *candidate))
        .collect();
    let prefixes = clear_exclusive_prefix(&flags)?;
    let direct = groups.len() == 1;
    let mut low_digits = Vec::with_capacity(groups.len());
    let mut high_digits = Vec::with_capacity(groups.len());
    for (group_index, (group, prefix)) in groups.iter().zip(prefixes).enumerate() {
        let phase = local_first(group)? as i32 - GROUP_SIZE as i32 * i32::from(prefix);
        let (low, high) = selector_requirements(group_index, group.len(), direct)?
            .get(&phase)
            .copied()
            .ok_or(A53StaticError::ContractViolation)?;
        low_digits.push(low);
        high_digits.push(high);
    }
    let code = if direct {
        low_digits[0] + high_digits[0]
    } else {
        low_digits.iter().sum::<u16>() + OUTPUT_BASE * high_digits.iter().sum::<u16>()
    };
    let reference = candidates
        .iter()
        .position(|candidate| *candidate)
        .map_or(0, |index| index as u16 + 1);
    if code != reference {
        return Err(A53StaticError::ContractViolation);
    }
    Ok(code)
}

pub fn reduction_nodes(mut items: usize, radix: usize) -> Result<u64, A53StaticError> {
    if items == 0 || radix < 2 {
        return Err(A53StaticError::GroupLength);
    }
    let mut nodes = 0u64;
    while items > 1 {
        let full = items / radix;
        let tail = items % radix;
        nodes += full as u64 + u64::from(tail >= 2);
        items = full + usize::from(tail > 0);
    }
    Ok(nodes)
}

pub fn exclusive_prefix_nodes(items: usize, radix: usize) -> Result<u64, A53StaticError> {
    if items == 0 || radix < 2 {
        return Err(A53StaticError::GroupLength);
    }
    if items <= 2 {
        return Ok(0);
    }
    if items <= radix {
        return Ok((items - 2) as u64);
    }
    let lengths: Vec<usize> = (0..items)
        .step_by(radix)
        .map(|start| radix.min(items - start))
        .collect();
    let block_totals = lengths.iter().filter(|length| **length >= 2).count() as u64;
    let expansion = lengths[0].saturating_sub(2) as u64
        + lengths[1..]
            .iter()
            .map(|length| (length - 1) as u64)
            .sum::<u64>();
    Ok(block_totals + expansion + exclusive_prefix_nodes(lengths.len(), radix)?)
}

pub fn scan_counts(gallery_size: usize) -> Result<ScanCounts, A53StaticError> {
    if gallery_size == 0 || gallery_size > MAX_GALLERY_SIZE {
        return Err(A53StaticError::GallerySize);
    }
    let lengths: Vec<usize> = (0..gallery_size)
        .step_by(GROUP_SIZE)
        .map(|start| GROUP_SIZE.min(gallery_size - start))
        .collect();
    let groups = lengths.len();
    let non_singletons = lengths.iter().filter(|length| **length >= 2).count() as u64;
    let prefix_nodes = exclusive_prefix_nodes(groups, REDUCTION_RADIX)?;
    let selector_blind_rotations = groups as u64;
    let digit_reduction_nodes = 2 * reduction_nodes(groups, REDUCTION_RADIX)?;
    let blind_rotations =
        2 * non_singletons + prefix_nodes + selector_blind_rotations + digit_reduction_nodes;
    let output_marginals = blind_rotations + selector_blind_rotations;
    Ok(ScanCounts {
        gallery_size,
        groups,
        group_flag_nodes: non_singletons,
        local_first_nodes: non_singletons,
        prefix_nodes,
        selector_blind_rotations,
        selector_key_switches: selector_blind_rotations,
        selector_marginals: 2 * selector_blind_rotations,
        digit_reduction_nodes,
        total: PrimitiveCounts {
            blind_rotations,
            key_switches: blind_rotations,
            output_marginals,
        },
    })
}

pub const fn raw_l1_ledger() -> [(&'static str, usize); 7] {
    [
        ("group-4 OR", 4),
        ("local-first length 1 forwarding", 1),
        ("local-first length 2", 7),
        ("local-first length 3/4", 8),
        ("radix-15 prefix OR", 15),
        ("signed selector local-4*prefix", 5),
        ("radix-15 digit reduction", 15),
    ]
}

pub fn maximum_raw_l1() -> usize {
    raw_l1_ledger()
        .iter()
        .map(|(_, value)| *value)
        .max()
        .unwrap_or(0)
}

pub fn residue_body_to_torus(body: &[u16], scale: OutputScale) -> Vec<u64> {
    let delta = 1u64 << scale.delta_log();
    body.iter()
        .map(|residue| (*residue as u64).wrapping_mul(delta))
        .collect()
}

#[cfg(test)]
mod source_only_tests {
    use super::*;

    #[test]
    fn every_local_pattern_and_strict_margin_is_exact() {
        let body = slot_lut_residue_body(&LOCAL_FIRST_SLOT_LUT, BOOL_OUTPUT_PERIOD).unwrap();
        for length in 1..=GROUP_SIZE {
            for mask in 0..1usize << length {
                let group: Vec<bool> = (0..length).map(|bit| mask & (1 << bit) != 0).collect();
                let phase = group_local_phase(&group).unwrap() as i32;
                let expected = local_first(&group).unwrap();
                for error in -STRICT_MARGIN_RADIUS..=STRICT_MARGIN_RADIUS {
                    assert_eq!(
                        sample_residue(&body, phase, error, 0, BOOL_OUTPUT_PERIOD).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn all_selector_layouts_include_negative_states_and_strict_margins() {
        for group in 0..MAX_GALLERY_SIZE.div_ceil(GROUP_SIZE) {
            for length in 1..=GROUP_SIZE {
                validate_selector_layout(&selector_layout(group, length, false).unwrap()).unwrap();
            }
        }
        for length in 1..=GROUP_SIZE {
            validate_selector_layout(&selector_layout(0, length, true).unwrap()).unwrap();
        }
        assert_eq!(
            selector_offsets(14, 4, false).unwrap(),
            SelectorOffsets::new(2, 2)
        );
    }

    #[test]
    fn exact_first_tie_contract_is_exhaustive_through_twelve() {
        for size in 1..=12 {
            for mask in 0..1usize << size {
                let candidates: Vec<bool> = (0..size).map(|bit| mask & (1 << bit) != 0).collect();
                let expected = candidates
                    .iter()
                    .position(|candidate| *candidate)
                    .map_or(0, |index| index as u16 + 1);
                assert_eq!(clear_scan(&candidates).unwrap(), expected);
            }
        }
    }

    #[test]
    fn all_gallery_boundaries_and_counts_are_exact() {
        for size in 1..=MAX_GALLERY_SIZE {
            assert_eq!(clear_scan(&vec![false; size]).unwrap(), 0);
            assert_eq!(clear_scan(&vec![true; size]).unwrap(), 1);
            for winner in 0..size {
                let mut candidates = vec![false; size];
                candidates[winner] = true;
                assert_eq!(clear_scan(&candidates).unwrap(), winner as u16 + 1);
            }
            let counts = scan_counts(size).unwrap();
            assert_eq!(counts.total.blind_rotations, counts.total.key_switches);
            assert_eq!(
                counts.total.output_marginals,
                counts.total.blind_rotations + counts.groups as u64
            );
        }
        assert_eq!(scan_counts(127).unwrap().total, A53_N127_SCAN_COUNTS);
        assert_eq!(maximum_raw_l1(), A44_MAX_NOISE_LEVEL);
        assert!(maximum_raw_l1() > CURRENT_TUNIFORM_MAX_NOISE_LEVEL);
    }
}
