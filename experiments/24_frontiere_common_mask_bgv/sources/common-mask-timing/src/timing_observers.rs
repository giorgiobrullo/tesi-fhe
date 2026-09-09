//! Client-only observations, called after every preclock operation or all three block clocks.
use crate::{
    crypto::{ClientKeys, Lwe},
    endpoint::Output,
    gate_observer,
    model::{A44_DELTA, LAYOUTS},
    observe, records,
};
use serde_json::{json, Value};
use tfhe::core_crypto::prelude::*;

pub fn vector_equal(a: &[Lwe], b: &[Lwe]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.as_ref() == y.as_ref())
}
pub fn prefix_equal(ai: &[Lwe], ab: &[Vec<Lwe>], bi: &[Lwe], bb: &[Vec<Lwe>]) -> bool {
    vector_equal(ai, bi)
        && ab.len() == bb.len()
        && ab.iter().zip(bb).all(|(x, y)| vector_equal(x, y))
}
pub fn prefix_words(initial: &[Lwe], bits: &[Vec<Lwe>]) -> Value {
    json!({"initial":initial.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>(),
        "bits":bits.iter().map(|row|row.iter().map(|ct|ct.as_ref()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "initial_sha256":records::hashes(initial),"bits_sha256":bits.iter().map(|row|records::hashes(row)).collect::<Vec<_>>()})
}
pub fn prefix_record(
    client: &ClientKeys,
    initial: &[Lwe],
    bits: &[Vec<Lwe>],
    active: &[u64],
    values: &[u64],
    counts: (u64, u64, u64),
) -> Value {
    let initial = records::ordinary_vector(client, initial, active, A44_DELTA);
    let bits: Vec<_> = bits
        .iter()
        .enumerate()
        .map(|(level, row)| {
            let messages: Vec<_> = values
                .iter()
                .map(|v| ((v >> LAYOUTS[level].bit) & 1) * LAYOUTS[level].weight)
                .collect();
            // All weighted outputs use the strict consumer Delta59 half-unit contract.
            records::ordinary_vector(client, row, &messages, A44_DELTA)
        })
        .collect();
    let pass = records::canonical(&initial) && bits.iter().all(|row| records::canonical(row));
    json!({"initial_candidates":initial,"bits":bits,"ordinary_br":counts.0,"ordinary_ks":counts.1,
        "ordinary_marginals":counts.2,"consumer_unit":A44_DELTA,"pass":pass})
}
pub fn input_record(
    glwe: &GlweSecretKeyOwned<u64>,
    packed: &GlweCiphertextOwned<u64>,
    plain: &[u64],
    index: usize,
) -> Value {
    let mut phase = PlaintextList::new(0, PlaintextCount(2048));
    decrypt_glwe_ciphertext(glwe, packed, &mut phase);
    let errors: Vec<_> = phase
        .as_ref()
        .iter()
        .zip(plain)
        .map(|(actual, target)| actual.wrapping_sub(*target) as i64)
        .collect();
    let pass = errors.iter().all(|e| e.unsigned_abs() < (1 << 51));
    json!({"type":"input_observation","index":index,"packed_sha256":observe::words_hash(packed.as_ref()),
        "phase_words":phase.as_ref(),"expected_words":plain,"errors":errors,
        "client_mask_dot_words":packed.get_body().as_ref().iter().zip(phase.as_ref()).map(|(b,p)|b.wrapping_sub(*p)).collect::<Vec<_>>(),
        "pass":pass})
}
pub fn score_record(client: &ClientKeys, full: &[Lwe], low: &[Lwe], normalized: &[u64]) -> Value {
    let full: Vec<_> = full
        .iter()
        .map(|ct| gate_observer::node(client, ct))
        .collect();
    let low: Vec<_> = low
        .iter()
        .map(|ct| gate_observer::node(client, ct))
        .collect();
    let pass = full.iter().zip(normalized).all(|(row, s)| {
        row["nontrivial_mask"] == true
            && (row["phase"]
                .as_u64()
                .unwrap()
                .wrapping_sub(s.wrapping_shl(52)) as i64)
                .unsigned_abs()
                < (1 << 51)
    }) && low.iter().zip(normalized).all(|(row, s)| {
        row["nontrivial_mask"] == true
            && (row["phase"]
                .as_u64()
                .unwrap()
                .wrapping_sub(s.wrapping_shl(60)) as i64)
                .unsigned_abs()
                < (1 << 59)
    });
    json!({"full":full,"low":low,"normalized_scores":normalized,"initial_score_samples":32,"pass":pass})
}
pub fn ledger(out: &Output) -> Value {
    json!({"ordinary_br":out.ordinary_br,"ordinary_ks":out.ordinary_ks,"ordinary_marginals":out.ordinary_marginals,
        "selector":observe::counts(out.cm)})
}
pub fn physical(blocks: usize) -> Value {
    json!({"ordinary_br":1003+749*blocks,"ordinary_ks":1003+749*blocks,"ordinary_marginals":1463+953*blocks,
        "cm_br":152+152*blocks,"cm_ks":144+144*blocks,"packing":88+88*blocks,"extraction":96+96*blocks,
        "initial_score_samples":96+96*blocks,"packed_encryptions":6,"complete_endpoints":3+3*blocks,"extra_joint4_prefixes":2})
}
