//! Client-only observations. Called after all four server arms and every CM consumer return.
use crate::{crypto::{ClientKeys, Domain, Lwe}, ingress, observe};
use serde_json::{json, Value};
use std::collections::HashMap;
use tfhe::core_crypto::prelude::*;

const N: usize = 2048;
pub fn node(client: &ClientKeys, ct: &Lwe) -> Value {
    let domain = match ct.lwe_size().0 { 2049 => Domain::A44Big, 860 => Domain::A44Small,
        _ => panic!("unexpected ordinary ciphertext dimension") };
    let mut row = observe::lwe(client, ct, domain, 0);
    row["words"] = json!(ct.as_ref());
    row["nontrivial_mask"] = json!(ct.get_mask().as_ref().iter().any(|x| *x != 0));
    row
}
fn phase(row: &Value) -> u64 { row["phase"].as_u64().unwrap() }
fn at(body: &[u64], degree: usize) -> u64 {
    let degree = degree % (2*body.len());
    if degree < body.len() { body[degree] } else { body[degree-body.len()].wrapping_neg() }
}
fn round(word: u64, log: u32) -> usize { (word.wrapping_add(1 << (63-log)) >> (64-log)) as usize }
fn unit(body: &[u64], lane: usize, stride: usize, offset: u64) -> u64 {
    if offset != 0 { return offset*2; }
    let log = body.iter().skip(lane).step_by(stride).filter(|x| **x != 0)
        .map(|x| x.trailing_zeros()).min().expect("nonzero observed raw lane");
    1u64 << log
}
pub fn vector(client: &ClientKeys, values: &[Lwe], targets: &[u64], units: &[u64]) -> (Vec<Value>, bool) {
    assert_eq!((values.len(), targets.len()), (units.len(), units.len()));
    let rows: Vec<_> = values.iter().zip(targets).zip(units).map(|((ct, target), unit)| {
        let mut row = node(client, ct);
        let error = phase(&row).wrapping_sub(*target) as i64;
        row["target"] = json!(target); row["unit"] = json!(unit); row["error"] = json!(error);
        row["within_half_unit"] = json!(error.unsigned_abs() < unit/2); row
    }).collect();
    let pass = rows.iter().all(|row| row["within_half_unit"] == true && row["nontrivial_mask"] == true);
    (rows, pass)
}

pub fn ordinary_events(
    client: &ClientKeys, events: &[ingress::Event], full: &[Lwe], low: &[Lwe], scores: &[u64],
) -> (Vec<Value>, bool) {
    let mut semantic = HashMap::new();
    for ((f, l), score) in full.iter().zip(low).zip(scores) {
        semantic.insert(observe::words_hash(f.as_ref()), score.wrapping_shl(52));
        semantic.insert(observe::words_hash(l.as_ref()), score.wrapping_shl(60));
    }
    let mut all_pass = true;
    let rows = events.iter().enumerate().map(|(index, event)| {
        let inputs: Vec<_> = event.inputs.iter().map(|ct| node(client, ct)).collect();
        let outputs: Vec<_> = event.outputs.iter().map(|ct| node(client, ct)).collect();
        let targets: Vec<u64> = event.inputs.iter().map(|ct| semantic[&observe::words_hash(ct.as_ref())]).collect();
        let mut output_targets = Vec::new();
        let mut detail = Value::Null;
        let mut pass = true;
        match event.kind {
            "scale" | "add" | "sub" | "offset" => {
                let expected: Vec<_> = (0..event.outputs[0].as_ref().len()).map(|i| {
                    let a = event.inputs[0].as_ref()[i];
                    match event.kind {
                        "scale" => a.wrapping_mul(event.factor),
                        "add" => a.wrapping_add(event.inputs[1].as_ref()[i]),
                        "sub" => a.wrapping_sub(event.inputs[1].as_ref()[i]),
                        _ => if i+1 == event.inputs[0].as_ref().len() { a.wrapping_add(event.factor) } else { a },
                    }
                }).collect();
                pass = expected == event.outputs[0].as_ref();
                output_targets.push(match event.kind {
                    "scale" => targets[0].wrapping_mul(event.factor),
                    "add" => targets[0].wrapping_add(targets[1]),
                    "sub" => targets[0].wrapping_sub(targets[1]),
                    _ => targets[0].wrapping_add(event.factor),
                });
                detail = json!({"affine_words_equal":pass});
            }
            "ks" => {
                output_targets.push(targets[0]);
                let grid_dot = event.inputs[0].get_mask().as_ref().iter().zip(client.ordinary_big.as_ref())
                    .fold(0u64, |sum, (a, s)| sum.wrapping_add((a.wrapping_add(1 << 48) & (u64::MAX << 49)).wrapping_mul(*s)));
                detail = json!({"phase_increment":phase(&outputs[0]).wrapping_sub(phase(&inputs[0])) as i64,
                    "input_grid15_mask_dot":grid_dot});
            }
            "br" => {
                let log = 12-event.stride.ilog2();
                let mask: Vec<_> = event.inputs[0].get_mask().as_ref().iter().map(|x| round(*x,log)*event.stride).collect();
                let body = round(*event.inputs[0].get_body().data,log)*event.stride;
                let dot = mask.iter().zip(client.ordinary_small.as_ref()).fold(0usize, |s, (a,b)| (s+a*(*b as usize))%(2*N));
                let degree = (body+2*N-dot)%(2*N);
                let semantic_degree = (round(targets[0],log)*event.stride)%(2*N);
                let actual_raw: Vec<_> = (0..event.raw.len()).map(|lane| at(&event.lut,degree+lane)).collect();
                let semantic_raw: Vec<_> = (0..event.raw.len()).map(|lane| at(&event.lut,semantic_degree+lane)).collect();
                let raw: Vec<_> = event.raw.iter().map(|ct| node(client,ct)).collect();
                let units: Vec<_> = event.offsets.iter().enumerate().map(|(lane,offset)| unit(&event.lut,lane,event.stride,*offset)).collect();
                let errors: Vec<_> = raw.iter().zip(&actual_raw).map(|(r,target)| phase(r).wrapping_sub(*target) as i64).collect();
                let half_diagnostics: Vec<_> = errors.iter().zip(&units).map(|(error,unit)| error.unsigned_abs()<unit/2).collect();
                let offset_equal = event.raw.iter().zip(&event.outputs).zip(&event.offsets).all(|((a,b),offset)| {
                    a.get_mask().as_ref()==b.get_mask().as_ref() && a.get_body().data.wrapping_add(*offset)==*b.get_body().data
                });
                pass = mask==event.mask && body==event.body && offset_equal && actual_raw==semantic_raw;
                output_targets = semantic_raw.iter().zip(&event.offsets).map(|(word,offset)| word.wrapping_add(*offset)).collect();
                detail = json!({"raw":raw,"lut_words":event.lut,"lut_sha256":observe::words_hash(&event.lut),
                    "ms_log":log,"stride":event.stride,"offsets":event.offsets,"switched_mask":event.mask,
                    "switched_body":event.body,"rounded_mask_dot":dot,"degree":degree,"semantic_degree":semantic_degree,
                    "actual_raw_words":actual_raw,"semantic_raw_words":semantic_raw,"output_units":units,
                    "pbs_errors":errors,"half_unit_diagnostics":half_diagnostics,"half_unit_diagnostics_gate":false,
                    "offset_words_equal":offset_equal,"switch_words_equal":mask==event.mask && body==event.body,
                    "raw_support_pass":actual_raw==semantic_raw});
            }
            _ => panic!("unknown event"),
        }
        for (ct, target) in event.outputs.iter().zip(&output_targets) {
            let old = semantic.insert(observe::words_hash(ct.as_ref()), *target);
            if let Some(old) = old { assert_eq!(old,*target,"same ciphertext has inconsistent clear ancestry"); }
        }
        all_pass &= pass;
        json!({"index":index,"kind":event.kind,"factor":event.factor,"inputs":inputs,"outputs":outputs,
            "input_targets":targets,"output_targets":output_targets,"detail":detail,"pass":pass})
    }).collect();
    (rows,all_pass)
}
