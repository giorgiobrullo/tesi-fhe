// Exact A66 functions; see SOURCE_PINS.json. Constants also copied from that source.
const A34_TOP_CLASSIFIER_MODULUS: usize = 16;
const A34_TOP_CLASSIFIER_CODES: [u64; 16] = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0];
fn a34_top_classifier_slot_lut(slot: u64) -> u64 {
    debug_assert!(slot < A34_TOP_CLASSIFIER_MODULUS as u64);
    if slot.is_multiple_of(2) {
        A34_TOP_CLASSIFIER_CODES[(slot / 2) as usize]
    } else {
        0
    }
}

fn a34_canonical_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        0 => 3,
        2 => 1,
        7 => 7,
        _ => 0,
    }
}

fn a34_pair_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        1 | 2 | 4 | 8 => 1,
        3 | 6 | 10 => 3,
        7 | 14 => 7,
        0 => 0,
        _ => 0,
    }
}

fn a34_top_candidate_lut(input_phase: u64) -> u64 {
    u64::from(matches!(input_phase, 3 | 14))
}

