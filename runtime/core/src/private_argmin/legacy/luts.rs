//! Lookup tables and bit encodings for the historical argmin circuits.
use super::*;

pub(super) fn zero_candidate_lut(code: u64, candidate_weight: u64, bit_weight: u64) -> u64 {
    let mut output = None;
    for candidate in [false, true] {
        for bit in [false, true] {
            if u64::from(candidate) * candidate_weight + u64::from(bit) * bit_weight == code {
                let value = u64::from(candidate && !bit);
                assert!(output.is_none() || output == Some(value), "layout ambiguo");
                output = Some(value);
            }
        }
    }
    output.unwrap_or(0)
}

pub(super) fn update_candidate_from_zero_lut(code: u64) -> u64 {
    // L'ingresso e' `candidate + zero_candidate - any_zero` modulo 16. Sui soli stati
    // raggiungibili vale uno esattamente quando il candidato sopravvive al livello corrente.
    u64::from(code == 1)
}

pub(super) fn encoded_zero_candidate_lut(code: u64) -> u64 {
    // Nei livelli dispari il candidato attivo e' 15, gli inattivi sono 0/1. Sommando il bit
    // pesato 1/2/4/8, il codice 15 resta raggiungibile soltanto per (attivo, bit=0). L'attivo e'
    // pero' il valore torus *negativo* -1, non il messaggio positivo 15: la rotazione
    // negaciclica nega la casella 15. La LUT base deve quindi contenere -1 per ottenere +1.
    if code == 15 {
        u64::MAX
    } else {
        0
    }
}

pub(super) fn weighted_or_lut(code: u64, weight: u64) -> u64 {
    if (1..=OR_BLOCK as u64).contains(&code) {
        weight
    } else {
        0
    }
}

pub(super) fn output_group_lut(code: u64, bit_offset: u32, group_len: usize) -> u64 {
    assert!((1..=3).contains(&group_len));
    if code >= 8 {
        let payload_mask = (1u64 << group_len) - 1;
        ((code - 8) & payload_mask) << bit_offset
    } else {
        0
    }
}

#[cfg(test)]
pub(super) fn aligned_output_group_lut(code: u64, bit_offset: u32, group_len: usize) -> u64 {
    assert!((1..=3).contains(&group_len));
    let payload_modulus = 1u64 << group_len;
    if code < payload_modulus {
        code << bit_offset
    } else {
        0
    }
}

#[cfg(test)]
pub(super) fn aligned_classifier_slot_lut(slot: u64, weight: u64) -> u64 {
    debug_assert!(matches!(weight, 1 | 3));
    match slot {
        // Il grado zero osserva gli slot pari per h'=0..3.
        0 => 2,
        2 => 3,
        4 | 6 => 4,
        // Il grado N/8 osserva gli slot dispari. Sul semigiro alto la negaciclicita'
        // produce automaticamente -weight per h'=4 e zero per h'=5..7.
        1 => weight,
        3 | 5 | 7 => 0,
        _ => unreachable!("la LUT A33 valuta soltanto gli slot 0..7"),
    }
}

#[cfg(test)]
pub(super) fn aligned_pair_flag_lut(code: u64) -> u64 {
    // Gli input includono l'offset pubblico +4. I codici con almeno un indicatore positivo sono
    // {2,5,6,7,8}; quelli senza positivi sono {0,1,3,4}.
    u64::from(matches!(code, 2 | 5 | 6 | 7 | 8))
}

#[cfg(test)]
pub(super) fn aligned_candidate_lut(code: u64) -> u64 {
    u64::from(code == 3)
}

pub(super) fn a34_top_classifier_slot_lut(slot: u64) -> u64 {
    debug_assert!(slot < A34_TOP_CLASSIFIER_MODULUS as u64);
    if slot.is_multiple_of(2) {
        A34_TOP_CLASSIFIER_CODES[(slot / 2) as usize]
    } else {
        0
    }
}

pub(super) fn a34_canonical_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        0 => 3,
        2 => 1,
        7 => 7,
        _ => 0,
    }
}

pub(super) fn a34_pair_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        1 | 2 | 4 | 8 => 1,
        3 | 6 | 10 => 3,
        7 | 14 => 7,
        0 => 0,
        _ => 0,
    }
}

pub(super) fn a34_top_candidate_lut(input_phase: u64) -> u64 {
    u64::from(matches!(input_phase, 3 | 14))
}

pub(super) fn boolean_and_lut(code: u64) -> u64 {
    u64::from(code == 2)
}

pub(super) const COMPARISON_LESS: u64 = 0;
pub(super) const COMPARISON_EQUAL: u64 = 2;
pub(super) const COMPARISON_GREATER: u64 = 4;

pub(super) fn comparison_state_lut(code: u64) -> u64 {
    let mut output = None;
    for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
        for any_zero in [false, true] {
            for threshold_bit in [false, true] {
                let input = state
                    .wrapping_sub(u64::from(any_zero))
                    .wrapping_sub(u64::from(threshold_bit))
                    & (PBS_MESSAGE_MODULUS as u64 - 1);
                if input == code {
                    let minimum_bit = !any_zero;
                    let next = if state != COMPARISON_EQUAL {
                        state
                    } else {
                        match (minimum_bit, threshold_bit) {
                            (false, true) => COMPARISON_LESS,
                            (true, false) => COMPARISON_GREATER,
                            _ => COMPARISON_EQUAL,
                        }
                    };
                    assert!(output.is_none() || output == Some(next), "layout ambiguo");
                    output = Some(next);
                }
            }
        }
    }
    output.unwrap_or(COMPARISON_GREATER)
}

pub(super) fn comparison_accept_tag_lut(code: u64) -> u64 {
    let mut output = None;
    for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
        for below in [false, true] {
            if state + u64::from(below) == code {
                let value = 8 * u64::from(state != COMPARISON_GREATER && !below);
                assert!(output.is_none() || output == Some(value), "layout ambiguo");
                output = Some(value);
            }
        }
    }
    output.unwrap_or(0)
}

pub(super) fn bit_source_delta(bit_index: u32) -> u32 {
    if bit_index < SPLIT_LOW_BITS {
        LOW_MOD16_DELTA_LOG
    } else {
        FULL_DELTA_LOG
    }
}

pub(super) fn is_canonical_boolean_bit(bit_index: u32) -> bool {
    (3..=7).contains(&bit_index)
}

pub(super) fn recodes_bit(bit_index: u32) -> bool {
    // Il bit alto non possiede una correction ciphertext. I bit 3..=6 ricevono invece una uscita
    // Booleana dalla stessa blind rotation della correzione; il bit 7 riusa direttamente la sua
    // correzione, che nasce gia' a Delta_bool.
    bit_index == HIGH_SCORE_BIT
}

pub(super) fn extracted_bit_weight(bit_index: u32) -> u64 {
    if is_canonical_boolean_bit(bit_index) || recodes_bit(bit_index) {
        return 1;
    }
    let correction_log = bit_source_delta(bit_index) + bit_index;
    if correction_log <= BOOL_DELTA_LOG + 1 {
        2
    } else {
        1u64 << (correction_log - BOOL_DELTA_LOG)
    }
}

pub(super) fn zero_layout(bit_weight: u64) -> (u64, u64) {
    match bit_weight {
        1 => (1, 2),
        _ => (1, bit_weight),
    }
}
