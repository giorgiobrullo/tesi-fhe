//! Structural operation counts for the historical circuits.
use super::*;

pub(super) fn or_reduction_pbs(mut items: usize) -> u64 {
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(OR_BLOCK);
        count += items as u64;
    }
    count
}

pub(super) fn radix4_exclusive_prefix_pbs(items: usize) -> u64 {
    if items <= 2 {
        return 0;
    }
    if items <= OR_BLOCK {
        return (items - 2) as u64;
    }
    let mut totals = 0u64;
    let mut expansion = 0u64;
    let mut groups = 0usize;
    for start in (0..items).step_by(OR_BLOCK) {
        let len = (items - start).min(OR_BLOCK);
        groups += 1;
        totals += u64::from(len > 1);
        expansion += if start == 0 {
            len.saturating_sub(2) as u64
        } else {
            (len - 1) as u64
        };
    }
    totals + expansion + radix4_exclusive_prefix_pbs(groups)
}

pub(super) fn first_one_scan_pbs(items: usize) -> u64 {
    let groups = items.div_ceil(FIRST_ONE_GROUP);
    let group_totals = (0..items)
        .step_by(FIRST_ONE_GROUP)
        .filter(|&start| (items - start).min(FIRST_ONE_GROUP) > 1)
        .count() as u64;
    group_totals + radix4_exclusive_prefix_pbs(groups) + items as u64
}

pub(super) fn output_bit_positions(gallery_size: usize) -> Vec<u32> {
    (0..usize::BITS)
        .filter(|&bit_position| {
            (0..gallery_size).any(|index| output_code_has_bit(index, bit_position))
        })
        .collect()
}

pub(super) fn output_code_has_bit(index: usize, bit_position: u32) -> bool {
    (((index + 1) >> bit_position) & 1) == 1
}

pub(super) fn output_code_pbs(gallery_size: usize) -> u64 {
    let positions = output_bit_positions(gallery_size);
    let bit_pbs: u64 = positions
        .iter()
        .copied()
        .map(|bit_position| {
            (0..gallery_size)
                .filter(|&index| output_code_has_bit(index, bit_position))
                .count()
        })
        .map(|items| or_reduction_pbs(items).max(1))
        .sum();
    // Tre digit freschi 1/2/4 e il tag di accettazione 8 entrano in una sola LUT di gruppo.
    bit_pbs + positions.len().div_ceil(3) as u64
}

pub(super) fn aligned_a34_top_pbs_count(gallery_size: usize) -> Option<u64> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    Some(
        27 * n
            + 8 * or_reduction_pbs(gallery_size)
            + first_one_scan_pbs(gallery_size)
            + output_code_pbs(gallery_size)
            - 1,
    )
}

pub fn a34_aligned_operation_counts(gallery_size: usize) -> Option<A34OperationCounts> {
    let blind_rotations = aligned_a34_top_pbs_count(gallery_size)?;
    let n = gallery_size as u64;
    Some(A34OperationCounts {
        blind_rotations,
        key_switches: blind_rotations - 3 * n,
        output_marginals: blind_rotations + 4 * n,
    })
}

pub(super) fn reduction_pbs_with_radix(mut items: usize, radix: usize) -> u64 {
    debug_assert!(radix >= 2);
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(radix);
        count += items as u64;
    }
    count
}

pub(super) fn reduction_pbs_forwarding_singletons(mut items: usize, radix: usize) -> u64 {
    debug_assert!(radix >= 2);
    let mut count = 0u64;
    while items > 1 {
        let full = items / radix;
        let tail = items % radix;
        count += full as u64 + u64::from(tail >= 2);
        items = full + usize::from(tail > 0);
    }
    count
}

pub(super) fn exclusive_prefix_pbs_with_radix(items: usize, radix: usize) -> u64 {
    debug_assert!(items > 0);
    debug_assert!(radix >= 2);
    if items <= 2 {
        return 0;
    }
    if items <= radix {
        return (items - 2) as u64;
    }
    let mut totals = 0u64;
    let mut expansion = 0u64;
    let mut groups = 0usize;
    for start in (0..items).step_by(radix) {
        let len = (items - start).min(radix);
        groups += 1;
        totals += u64::from(len > 1);
        expansion += if start == 0 {
            len.saturating_sub(2) as u64
        } else {
            (len - 1) as u64
        };
    }
    totals + expansion + exclusive_prefix_pbs_with_radix(groups, radix)
}

pub(super) fn a38_low_selection_pbs(gallery_size: usize) -> u64 {
    10 * gallery_size as u64 + 8 * reduction_pbs_with_radix(gallery_size, A38_REDUCTION_RADIX)
}

pub(super) fn a38_scan_output_counts(gallery_size: usize) -> A38OperationCounts {
    let groups = gallery_size.div_ceil(A38_SCAN_GROUP_SIZE);
    let group_nodes = (0..gallery_size)
        .step_by(A38_SCAN_GROUP_SIZE)
        .filter(|&start| (gallery_size - start).min(A38_SCAN_GROUP_SIZE) > 1)
        .count() as u64;
    let prefix_nodes = exclusive_prefix_pbs_with_radix(groups, A38_REDUCTION_RADIX);
    let digit_nodes = 2 * reduction_pbs_with_radix(groups, A38_REDUCTION_RADIX);
    let blind_rotations = 2 * group_nodes + prefix_nodes + groups as u64 + digit_nodes;
    A38OperationCounts {
        blind_rotations,
        key_switches: blind_rotations,
        output_marginals: blind_rotations + groups as u64,
    }
}

pub(super) fn aligned_a38_pbs_count(gallery_size: usize) -> Option<u64> {
    let old_total = aligned_a34_top_pbs_count(gallery_size)?;
    let old_low = 12 * gallery_size as u64 + 8 * or_reduction_pbs(gallery_size);
    let old_scan_output = first_one_scan_pbs(gallery_size) + output_code_pbs(gallery_size);
    let new_scan_output = a38_scan_output_counts(gallery_size).blind_rotations;
    Some(
        old_total - old_low - old_scan_output
            + a38_low_selection_pbs(gallery_size)
            + new_scan_output,
    )
}

pub fn a38_aligned_operation_counts(gallery_size: usize) -> Option<A38OperationCounts> {
    let blind_rotations = aligned_a38_pbs_count(gallery_size)?;
    let n = gallery_size as u64;
    let scan = a38_scan_output_counts(gallery_size);
    Some(A38OperationCounts {
        blind_rotations,
        key_switches: blind_rotations - 3 * n,
        // A34-top conserva quattro estrazioni fuse extra per template; il selettore A34 espone
        // inoltre due marginali per rotazione, quindi una marginale extra per gruppo.
        output_marginals: blind_rotations + 4 * n + (scan.output_marginals - scan.blind_rotations),
    })
}

pub fn a41_aligned_operation_counts(gallery_size: usize) -> Option<A41OperationCounts> {
    a38_aligned_operation_counts(gallery_size)
}

pub fn a44_aligned_operation_counts(gallery_size: usize) -> Option<A44OperationCounts> {
    a41_aligned_operation_counts(gallery_size)
}

pub(super) fn a50_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let baseline = a44_aligned_operation_counts(gallery_size)?;
    let old_nodes = reduction_pbs_with_radix(gallery_size, A38_REDUCTION_RADIX);
    let new_nodes = reduction_pbs_forwarding_singletons(gallery_size, A50_REDUCTION_RADIX);
    let saving = 8 * old_nodes.checked_sub(new_nodes)?;
    Some(A62OperationCounts {
        blind_rotations: baseline.blind_rotations.checked_sub(saving)?,
        key_switches: baseline.key_switches.checked_sub(saving)?,
        output_marginals: baseline.output_marginals.checked_sub(saving)?,
    })
}

/// Conteggio strutturale A62: A44 con selezione A50 e scan/output A53.
pub fn a62_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let a50 = a50_aligned_operation_counts(gallery_size)?;
    let removed = a38_scan_output_counts(gallery_size);
    let inserted = a53_scan_counts(gallery_size).ok()?.total;
    Some(A62OperationCounts {
        blind_rotations: a50
            .blind_rotations
            .checked_sub(removed.blind_rotations)?
            .checked_add(inserted.blind_rotations)?,
        key_switches: a50
            .key_switches
            .checked_sub(removed.key_switches)?
            .checked_add(inserted.key_switches)?,
        output_marginals: a50
            .output_marginals
            .checked_sub(removed.output_marginals)?
            .checked_add(inserted.output_marginals)?,
    })
}

/// Structural A126 counts: N fewer BR/KS; the same two output marginals replace two PBS.
pub fn a126_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let mut counts = a62_aligned_operation_counts(gallery_size)?;
    counts.blind_rotations = counts.blind_rotations.checked_sub(gallery_size as u64)?;
    counts.key_switches = counts.key_switches.checked_sub(gallery_size as u64)?;
    Some(counts)
}

pub fn expected_pbs_count(gallery_size: usize) -> Option<u64> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    Some(
        32 * n
            + 25 * or_reduction_pbs(gallery_size)
            + first_one_scan_pbs(gallery_size)
            + output_code_pbs(gallery_size)
            + 13,
    )
}

pub(super) fn winner_mask_pbs(mask: &[bool]) -> u64 {
    let enabled = mask.iter().filter(|&&value| value).count();
    if enabled == 0 || enabled == mask.len() {
        0
    } else {
        or_reduction_pbs(enabled)
    }
}

/// Conteggio esatto quando le soglie pubbliche consentono di evitare gli slot disabilitati.
///
/// [`expected_pbs_count`] resta il limite indipendente dai valori. La combinazione uniforme
/// allineata restituisce il conteggio del percorso A38 combinato; ogni altro caso sottrae le
/// tredici riduzioni dense A29 e aggiunge soltanto quelle richieste dai bit realmente non costanti
/// delle soglie.
pub fn expected_pbs_count_for_thresholds(
    gallery_size: usize,
    thresholds: &[i64],
    domain: ScoreDomain,
) -> Option<u64> {
    if thresholds.len() != gallery_size || validate_domain(domain).is_err() {
        return None;
    }
    if aligned_uniform_fast_path_for_thresholds(thresholds, domain) {
        return aligned_a38_pbs_count(gallery_size);
    }
    let maximum = expected_pbs_count(gallery_size)?;
    let metadata: Vec<(u64, bool)> = thresholds
        .iter()
        .map(|&threshold| {
            let below = threshold < domain.lower;
            let clamped = threshold.clamp(domain.lower, domain.upper);
            ((clamped - domain.lower) as u64, below)
        })
        .collect();
    let mut masks: Vec<Vec<bool>> = (0..SCORE_BITS)
        .rev()
        .map(|bit_position| {
            metadata
                .iter()
                .map(|(threshold, _)| ((threshold >> bit_position) & 1) == 1)
                .collect()
        })
        .collect();
    masks.push(metadata.iter().map(|(_, below)| *below).collect());
    let dense = 13 * or_reduction_pbs(gallery_size);
    let sparse: u64 = masks.iter().map(|mask| winner_mask_pbs(mask)).sum();
    Some(maximum - dense + sparse)
}
