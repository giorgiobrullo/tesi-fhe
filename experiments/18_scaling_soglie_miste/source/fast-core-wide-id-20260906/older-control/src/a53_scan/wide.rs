//! Constructive three-digit sibling of the frozen group4/base15 A53 lookup.
use super::*;

pub const MAX_GALLERY_SIZE: usize = 15 * 15 * 15 - 1;
pub const ID_DIGITS: usize = 3;
pub const CONTRACT: &str = "a126-adapted-a53-three-p16-roots-dual-plus-single-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorLayout {
    pub group_index: usize,
    pub group_length: usize,
    pub dual_lanes: [usize; 2],
    pub single_lane: usize,
    pub offsets: SelectorOffsets,
    pub dual_residue_body: Vec<u16>,
    pub single_residue_body: Vec<u16>,
}

pub fn identity_digits(identity: usize) -> Result<[u16; ID_DIGITS], A53StaticError> {
    if identity > MAX_GALLERY_SIZE {
        return Err(A53StaticError::GallerySize);
    }
    Ok([(identity % 15) as u16, ((identity / 15) % 15) as u16, (identity / 225) as u16])
}

fn validate_group(group_index: usize, group_length: usize) -> Result<(), A53StaticError> {
    if !(1..=GROUP_SIZE).contains(&group_length) {
        return Err(A53StaticError::GroupLength);
    }
    let last = group_index.checked_mul(GROUP_SIZE)
        .and_then(|start| start.checked_add(group_length))
        .ok_or(A53StaticError::GroupIndex)?;
    if last > MAX_GALLERY_SIZE {
        return Err(A53StaticError::GroupIndex);
    }
    Ok(())
}

/// Two independent-slot overlaps impose o0-o1=a and o0+o1=b modulo32.
fn full_group_offsets(a: u16, b: u16) -> Option<SelectorOffsets> {
    if (a + b) % 2 != 0 {
        return None;
    }
    let low = ((a + b) % BOOL_OUTPUT_PERIOD) / 2;
    let high = (b + BOOL_OUTPUT_PERIOD - low) % BOOL_OUTPUT_PERIOD;
    Some(SelectorOffsets::new(low, high))
}

fn lane_plan(group_index: usize, group_length: usize) -> Result<([usize; 2], usize, SelectorOffsets), A53StaticError> {
    validate_group(group_index, group_length)?;
    if group_length < GROUP_SIZE {
        return Ok(([0, 1], 2, SelectorOffsets::default()));
    }
    let digits = identity_digits(GROUP_SIZE * (group_index + 1))?;
    for pair in [[0, 1], [0, 2], [1, 2]] {
        if let Some(offsets) = full_group_offsets(digits[pair[0]], digits[pair[1]]) {
            let remaining = (0..ID_DIGITS).find(|lane| !pair.contains(lane)).unwrap();
            return Ok((pair, remaining, offsets));
        }
    }
    // Among three integer parities, at least two agree.
    Err(A53StaticError::ConflictingRequirement)
}

pub fn selector_requirements(group_index: usize, group_length: usize) -> Result<BTreeMap<i32, [u16; ID_DIGITS]>, A53StaticError> {
    validate_group(group_index, group_length)?;
    let mut outputs = BTreeMap::new();
    for prefix in 0..=1i32 {
        for local in 0..=group_length as i32 {
            let phase = local - GROUP_SIZE as i32 * prefix;
            let identity = if local > 0 && prefix == 0 {
                GROUP_SIZE * group_index + local as usize
            } else {
                0
            };
            let desired = identity_digits(identity)?;
            if outputs.insert(phase, desired).is_some_and(|existing| existing != desired) {
                return Err(A53StaticError::ConflictingRequirement);
            }
        }
    }
    Ok(outputs)
}

pub fn selector_layout(group_index: usize, group_length: usize) -> Result<SelectorLayout, A53StaticError> {
    let (dual_lanes, single_lane, offsets) = lane_plan(group_index, group_length)?;
    let outputs = selector_requirements(group_index, group_length)?;
    let period = BOOL_OUTPUT_PERIOD;
    let mut dual_assignments = [None; P16];
    let mut single_assignments = [None; P16];
    for (phase, desired) in outputs {
        for (lane, shift, offset) in [(dual_lanes[0], 0, offsets.low),
            (dual_lanes[1], (SELECTOR_SECOND_SAMPLE_DEGREE / BOX_SIZE) as i32, offsets.high)] {
            let raw = (desired[lane] + period - offset) % period;
            let (slot, required) = virtual_requirement(phase + shift, raw, period);
            assign_slot(&mut dual_assignments, slot, required, period)?;
        }
        let (slot, required) = virtual_requirement(phase, desired[single_lane], period);
        assign_slot(&mut single_assignments, slot, required, period)?;
    }
    Ok(SelectorLayout {
        group_index, group_length, dual_lanes, single_lane, offsets,
        dual_residue_body: robust_residue_body(&dual_assignments, period)?,
        single_residue_body: robust_residue_body(&single_assignments, period)?,
    })
}

pub fn validate_selector_layout(layout: &SelectorLayout) -> Result<(), A53StaticError> {
    let (dual_lanes, single_lane, offsets) = lane_plan(layout.group_index, layout.group_length)?;
    if layout.dual_lanes != dual_lanes || layout.single_lane != single_lane || layout.offsets != offsets
        || layout.dual_residue_body.len() != POLYNOMIAL_SIZE
        || layout.single_residue_body.len() != POLYNOMIAL_SIZE {
        return Err(A53StaticError::InvalidBody);
    }
    for (phase, expected) in selector_requirements(layout.group_index, layout.group_length)? {
        for error in -STRICT_MARGIN_RADIUS..=STRICT_MARGIN_RADIUS {
            let mut actual = [0u16; ID_DIGITS];
            actual[dual_lanes[0]] = (sample_residue(&layout.dual_residue_body, phase, error, 0,
                BOOL_OUTPUT_PERIOD)? + offsets.low) % BOOL_OUTPUT_PERIOD;
            actual[dual_lanes[1]] = (sample_residue(&layout.dual_residue_body, phase, error,
                SELECTOR_SECOND_SAMPLE_DEGREE, BOOL_OUTPUT_PERIOD)? + offsets.high) % BOOL_OUTPUT_PERIOD;
            actual[single_lane] = sample_residue(&layout.single_residue_body, phase, error, 0,
                BOOL_OUTPUT_PERIOD)?;
            if actual != expected {
                return Err(A53StaticError::ContractViolation);
            }
        }
    }
    Ok(())
}

pub fn scan_counts(gallery_size: usize) -> Result<ScanCounts, A53StaticError> {
    if gallery_size == 0 || gallery_size > MAX_GALLERY_SIZE {
        return Err(A53StaticError::GallerySize);
    }
    let lengths: Vec<_> = (0..gallery_size).step_by(GROUP_SIZE)
        .map(|start| GROUP_SIZE.min(gallery_size - start)).collect();
    let groups = lengths.len();
    let non_singletons = lengths.iter().filter(|length| **length >= 2).count() as u64;
    let prefix_nodes = exclusive_prefix_nodes(groups, REDUCTION_RADIX)?;
    let selector_blind_rotations = 2 * groups as u64;
    let selector_marginals = 3 * groups as u64;
    let digit_reduction_nodes = 3 * reduction_nodes(groups, REDUCTION_RADIX)?;
    let blind_rotations = 2 * non_singletons + prefix_nodes + selector_blind_rotations + digit_reduction_nodes;
    Ok(ScanCounts {
        gallery_size, groups, group_flag_nodes: non_singletons, local_first_nodes: non_singletons,
        prefix_nodes, selector_blind_rotations, selector_key_switches: selector_blind_rotations,
        selector_marginals, digit_reduction_nodes,
        total: PrimitiveCounts { blind_rotations, key_switches: blind_rotations,
            output_marginals: blind_rotations + groups as u64 },
    })
}
