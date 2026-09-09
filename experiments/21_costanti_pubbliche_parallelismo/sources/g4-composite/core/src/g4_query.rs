//! Separate one-query-at-a-time experimental dynamic selector. No secret is used
//! during evaluation. Client phase observations happen only after it returns.
use super::*;
use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Mutex};
use tfhe::core_crypto::algorithms::lwe_multi_bit_programmable_bootstrapping::
    modulus_switch_multi_bit_blind_rotate_assign;

const MAX_READY: usize = 4;
static ENABLED: AtomicBool = AtomicBool::new(false);
static VERIFY: AtomicBool = AtomicBool::new(false);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static READY: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static ROTATIONS: AtomicUsize = AtomicUsize::new(0);
static CHECKED_GLWES: AtomicUsize = AtomicUsize::new(0);
static BAD_EQUALITY: AtomicBool = AtomicBool::new(false);
static TRACES: Mutex<Vec<Trace>> = Mutex::new(Vec::new());

struct Trace {
    node: (usize, usize, bool),
    ready: usize,
    left: Vec<Lwe>,
    right: Vec<Lwe>,
    combined: Lwe,
    original904: Lwe,
    centered: g4_dynamic::Centered,
    groups: Vec<Vec<usize>>,
    output: Vec<Lwe>,
    stock_hashes: Vec<String>,
    batch_hashes: Vec<String>,
    stock_equal: bool,
}

pub fn begin_query(enabled: bool, verify: bool, trace: bool) {
    assert!(!verify || (enabled && trace), "diagnostic equality requires saved traces");
    assert!(!trace || verify, "this diagnostic traces only with stock equality enabled");
    if enabled { let _ = multibit::installed_primitive_keys(); }
    ENABLED.store(enabled, Ordering::Relaxed);
    VERIFY.store(verify, Ordering::Relaxed);
    TRACE_ENABLED.store(trace, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    ROTATIONS.store(0, Ordering::Relaxed);
    CHECKED_GLWES.store(0, Ordering::Relaxed);
    BAD_EQUALITY.store(false, Ordering::Relaxed);
    TRACES.lock().unwrap().clear();
}

pub(super) fn configure_level(ready: usize) { READY.store(ready, Ordering::Relaxed); }

fn active() -> bool {
    let ready = READY.load(Ordering::Relaxed);
    ENABLED.load(Ordering::Relaxed) && (1..=MAX_READY).contains(&ready)
}

/// The ordinary count type records mask coefficients, not subset roundings.
/// Only selected controls replace859 coefficients by904; separate stats report
/// all3616 public subset roundings per selected control.
pub(super) fn adjust_expected_counts(mut counts: h_untraced::Counts) -> h_untraced::Counts {
    counts.centering_mask_terms += 45 * CALLS.load(Ordering::Relaxed) as u64;
    counts
}

pub fn query_stats() -> Value {
    let calls = CALLS.load(Ordering::Relaxed);
    let rotations = ROTATIONS.load(Ordering::Relaxed);
    let checked = CHECKED_GLWES.load(Ordering::Relaxed);
    json!({"enabled":ENABLED.load(Ordering::Relaxed),"max_ready":MAX_READY,
        "verify":VERIFY.load(Ordering::Relaxed),"trace":TRACE_ENABLED.load(Ordering::Relaxed),
        "selected_controls":calls,"g4_glwe_rotations":rotations,"grouped_mask_coefficients":904*calls,
        "public_subset_roundings":3616*calls,"shared_synthesized_groups":226*calls,
        "separate_stock_synthesized_groups_equivalent":226*rotations,
        "external_products":226*rotations,"checked_stock_glwes":checked,"checked_stock_words":4096*checked,
        "stock_batch_equality_pass":!BAD_EQUALITY.load(Ordering::Relaxed),
        "ks_saved":0,"br_saved":0,"pfks_saved":0,
        "candidate_producers":0,"diagnostic_stock_producers":1,
        "scope":"serial shared synthesis on original outer merge scheduling; diagnostic duplicate stock work excluded from operation counts"})
}

pub(super) fn maybe_select<const N: usize>(
    left: &[Lwe], right: &[Lwe], combined: &Lwe, groups: &[&[usize]],
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
) -> Option<([Lwe; N], wide_id::Metrics)> {
    if !active() { return None; }
    assert_eq!((left.len(), right.len()), (N, N));
    assert!((1..=3).contains(&groups.len()));
    let (ksk, bsk) = multibit::installed_primitive_keys().primitive_keys();
    let modulus = combined.ciphertext_modulus();
    assert!(modulus.is_native_modulus());
    let mut metrics = wide_id::Metrics::default();
    let mut original904 = Lwe::new(0, LweSize(905), modulus);
    keyswitch_lwe_ciphertext(ksk, combined, &mut original904);
    metrics.ks = 1;
    let centered = g4_dynamic::grouped_mean(&original904);
    metrics.grouped_centering = true;
    metrics.public_centering_calls = 1;
    metrics.public_centering_mask_terms = 904;
    metrics.public_centering_body_additions = 1;
    let mut pfks: [Option<Glwe>; N] = std::array::from_fn(|_| None);
    for &lane in groups.iter().flat_map(|group| group.iter()) {
        assert!(lane < N && pfks[lane].is_none());
        let mut difference = right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
        metrics.lwe_subtractions += 1;
        let mut term = Glwe::new(0, window.output_glwe_size(), window.output_polynomial_size(), modulus);
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(window, &mut term, &difference);
        metrics.pfks += 1;
        pfks[lane] = Some(term);
    }
    let mut accumulators = Vec::with_capacity(groups.len());
    for group in groups {
        assert!(!group.is_empty() && group.len() <= 3);
        let mut accumulator: Option<Glwe> = None;
        for (position, &lane) in group.iter().enumerate() {
            let offset = 41 * position;
            let mut term = pfks[lane].as_ref().unwrap().clone();
            for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial, MonomialDegree(offset));
                metrics.polynomial_permutation_calls += 1;
            }
            metrics.monomial_calls += 1;
            metrics.nonidentity_monomial_calls += usize::from(offset != 0);
            if let Some(acc) = accumulator.as_mut() {
                for (word, value) in acc.as_mut().iter_mut().zip(term.as_ref()) { *word = word.wrapping_add(*value); }
                metrics.glwe_additions += 1;
            } else { accumulator = Some(term); }
        }
        accumulators.push(accumulator.unwrap());
    }
    let stock = VERIFY.load(Ordering::Relaxed).then(|| {
        let mut stock = accumulators.clone();
        for accumulator in &mut stock {
            modulus_switch_multi_bit_blind_rotate_assign(&centered.corrected, accumulator, bsk, ThreadCount(1), true);
        }
        stock
    });
    assert_eq!(g4_dynamic::batch_same_control(&centered.corrected, &mut accumulators, bsk), 226);
    metrics.br = accumulators.len();
    let equal = stock.as_ref().is_none_or(|reference| reference == &accumulators);
    if !equal { BAD_EQUALITY.store(true, Ordering::Relaxed); }
    if stock.is_some() { CHECKED_GLWES.fetch_add(accumulators.len(), Ordering::Relaxed); }
    CALLS.fetch_add(1, Ordering::Relaxed);
    ROTATIONS.fetch_add(accumulators.len(), Ordering::Relaxed);
    let mut output: [Lwe; N] = std::array::from_fn(|_| allocate_and_trivially_encrypt_new_lwe_ciphertext(
        LweSize(2049), Plaintext(0), modulus));
    for (accumulator, group) in accumulators.iter().zip(groups) {
        for (position, &lane) in group.iter().enumerate() {
            extract_lwe_sample_from_glwe_ciphertext(accumulator, &mut output[lane], MonomialDegree(41 * position));
            lwe_ciphertext_add_assign(&mut output[lane], &left[lane]);
            metrics.samples += 1;
            metrics.lwe_addbacks += 1;
        }
    }
    if TRACE_ENABLED.load(Ordering::Relaxed) {
        TRACES.lock().unwrap().push(Trace { node: NODE.with(|node| node.get().expect("selected trace needs tree position")), ready: READY.load(Ordering::Relaxed),
            left:left.to_vec(),right:right.to_vec(),combined:combined.clone(),original904,centered,
            groups:groups.iter().map(|group|group.to_vec()).collect(),output:output.to_vec(),
            stock_hashes:stock.as_ref().map_or_else(Vec::new,|items|items.iter().map(|ct|observer::hash_words(ct.as_ref())).collect()),
            batch_hashes:accumulators.iter().map(|ct|observer::hash_words(ct.as_ref())).collect(),stock_equal:equal });
    }
    Some((output, metrics))
}

fn observed_combined_digit(phase: u64) -> i64 {
    let shifted = phase.wrapping_add(SCORE_DELTA / 2) as i64 as i128;
    let rounded = (shifted.abs() + SCORE_DELTA as i128 / 2) / SCORE_DELTA as i128;
    (if shifted < 0 { -rounded } else { rounded }) as i64
}

fn window_at(degree: isize) -> u64 {
    let coefficient = degree.rem_euclid(2048);
    let value = u64::from((1..=7).any(|c| (coefficient - (128*c-64)).abs() <= 20));
    if degree.div_euclid(2048).rem_euclid(2) == 0 { value } else { value.wrapping_neg() }
}

pub fn observe_completed(secret: &GlweSecretKeyOwned<u64>, small904: &LweSecretKeyOwned<u64>) -> Vec<Value> {
    let traces = std::mem::take(&mut *TRACES.lock().unwrap());
    let big = secret.as_lwe_secret_key();
    traces.into_iter().map(|trace| {
        let combined_phase = decrypt_lwe_ciphertext(&big, &trace.combined).0;
        let observed_digit = observed_combined_digit(combined_phase);
        let center = 128 * observed_digit - 64;
        let (grouped, address) = g4_dynamic::grouped_observation(&trace.original904, &trace.centered, small904);
        let displacement = (address as i64 - center + 2048).rem_euclid(4096) - 2048;
        let choose_right = observed_digit > 0;
        let matrix: Vec<Vec<Vec<u64>>> = trace.groups.iter().map(|group| (0..group.len()).map(|i| (0..group.len())
            .map(|j|window_at(address as isize + 41*(i as isize-j as isize))).collect()).collect()).collect();
        let matrix_pass = matrix.iter().all(|group|group.iter().enumerate().all(|(i,row)|row.iter().enumerate()
            .all(|(j,&value)|value==u64::from(choose_right && i==j))));
        let active: Vec<_> = trace.groups.iter().flat_map(|group|group.iter().copied()).collect();
        let selected = if choose_right { &trace.right } else { &trace.left };
        let errors: Vec<i64> = trace.output.iter().enumerate().map(|(lane, ct)| {
            let expected_phase = if active.contains(&lane) { decrypt_lwe_ciphertext(&big,&selected[lane]).0 } else { 0 };
            decrypt_lwe_ciphertext(&big,ct).0.wrapping_sub(expected_phase) as i64
        }).collect();
        let omitted_zero = trace.output.iter().enumerate().all(|(lane,ct)|active.contains(&lane)||ct.as_ref().iter().all(|&word|word==0));
        let pass = (-7..=7).contains(&observed_digit) && displacement.abs() <= 20 && matrix_pass && omitted_zero
            && trace.stock_equal && trace.stock_hashes == trace.batch_hashes
            && errors.iter().all(|error|error.unsigned_abs()<SCORE_DELTA/2);
        json!({"record":"g4_dynamic_query_consumer","ready_merges":trace.ready,"groups":trace.groups,
            "tree_node":{"level":trace.node.0,"pair":trace.node.1,"final":trace.node.2},
            "left":trace.left.iter().map(|ct|g4_dynamic::lwe_observation(ct,&big)).collect::<Vec<_>>(),
            "right":trace.right.iter().map(|ct|g4_dynamic::lwe_observation(ct,&big)).collect::<Vec<_>>(),
            "combined":g4_dynamic::lwe_observation(&trace.combined,&big),"grouped_control":grouped,
            "output":trace.output.iter().map(|ct|g4_dynamic::lwe_observation(ct,&big)).collect::<Vec<_>>(),
            "observed_combined_digit":observed_digit,"observed_center":center,"actual_address_displacement":displacement,
            "window_matrix":matrix,"window_matrix_pass":matrix_pass,"omitted_lanes_exact_zero":omitted_zero,
            "output_errors_relative_to_selected_input_phase":errors,
            "stock_glwe_hashes":trace.stock_hashes,"batch_glwe_hashes":trace.batch_hashes,
            "native_stock_batch_full_words_equal":trace.stock_equal,"checked_glwes":trace.groups.len(),
            "internal_semantics_scope":"Observed combined and payload phases only; no independent intended-node genealogy. Whole-query fixture ID oracle is separate.",
            "pass":pass})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_control_decoder_and_window_include_both_sides_of_each_center() {
        for digit in -7i64..=7 {
            let phase = ((2*digit-1) as u64).wrapping_mul(SCORE_DELTA/2);
            for offset in [-(SCORE_DELTA as i64/2)+1,0,SCORE_DELTA as i64/2-1] {
                assert_eq!(observed_combined_digit(phase.wrapping_add(offset as u64)),digit);
            }
            for radius in -20isize..=20 {
                for width in 1..=3 { for i in 0..width { for j in 0..width {
                    assert_eq!(window_at(128*digit as isize-64+radius+41*(i-j)),u64::from(digit>0&&i==j));
                }}}
            }
        }
    }
}

thread_local! { static NODE: std::cell::Cell<Option<(usize, usize, bool)>> = const { std::cell::Cell::new(None) }; }

// A nested Rayon task may run on the waiting caller's thread. Restore its enclosing
// context on return, rather than leaving another merge's position in thread-local state.
pub(super) struct NodeScope(Option<Option<(usize, usize, bool)>>);
impl Drop for NodeScope {
    fn drop(&mut self) {
        if let Some(previous) = self.0 { NODE.with(|node| node.set(previous)); }
    }
}
pub(super) fn node_scope(level: usize, pair: usize, final_predicate: bool) -> NodeScope {
    if !TRACE_ENABLED.load(Ordering::Relaxed) { return NodeScope(None); }
    NodeScope(Some(NODE.with(|node| node.replace(Some((level, pair, final_predicate))))))
}
