//! Passed client-only probe helpers, extracted without semantic changes.
use crate::crypto::centered::{self, CmProbe, OrdinaryProbe};
use crate::crypto::{ClientKeys, Cm, Domain, Lwe};
use crate::model::{A44_DELTA, CM_DELTA};
use crate::observe;
use serde_json::{json, Value};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;

pub fn ct_record(
    client: &ClientKeys,
    ct: &Lwe,
    domain: Domain,
    lane: usize,
    target: u64,
    unit: u64,
) -> Value {
    let mut row = observe::lwe(client, ct, domain, lane);
    let phase = row["phase"].as_u64().unwrap();
    let error = phase.wrapping_sub(target) as i64;
    row["words"] = json!(ct.as_ref());
    row["expected_word"] = json!(target);
    row["unit"] = json!(unit);
    row["signed_phase_error"] = json!(error);
    row["phase_within_half_unit"] = json!(error.unsigned_abs() < unit / 2);
    row
}

pub fn cm_record(client: &ClientKeys, ct: &Cm, big: bool, targets: &[u64], unit: u64) -> Value {
    assert_eq!(targets.len(), 4);
    let domain = if big { Domain::CmBig } else { Domain::CmSmall };
    json!({"words":ct.as_ref(),"sha256":observe::words_hash(ct.as_ref()),
        "dimension":ct.lwe_dimension().0,"lane_count":4,
        "lanes":(0..4).map(|j| ct_record(client,&ct.extract_lwe_ciphertext(j),domain,j,targets[j],unit)).collect::<Vec<_>>()})
}

pub fn raw_word(body: &[u64], degree: usize) -> u64 {
    assert!(degree < 2 * body.len());
    let word = body[degree % body.len()];
    if degree >= body.len() {
        word.wrapping_neg()
    } else {
        word
    }
}

pub fn ordinary_record(
    client: &ClientKeys,
    p: &OrdinaryProbe,
    kind: &str,
    modulus: usize,
    input: u64,
    input_unit: u64,
    output: u64,
) -> Value {
    let target = output * A44_DELTA;
    let raw_target = target.wrapping_sub(p.offset);
    let input_row = ct_record(
        client,
        &p.input,
        Domain::A44Small,
        0,
        input * input_unit,
        input_unit,
    );
    let raw = ct_record(client, &p.raw, Domain::A44Big, 0, raw_target, A44_DELTA);
    let out = ct_record(client, &p.output, Domain::A44Big, 0, target, A44_DELTA);
    let degree = input_row["coefficientwise"]["address"].as_u64().unwrap() as usize;
    let body = p.lut.get_body();
    let actual = raw_word(body.as_ref(), degree);
    let offset_exact = p.raw.get_mask().as_ref() == p.output.get_mask().as_ref()
        && (*p.raw.get_body().data).wrapping_add(p.offset) == *p.output.get_body().data;
    let pass = actual == raw_target
        && offset_exact
        && raw["phase_within_half_unit"] == true
        && out["phase_within_half_unit"] == true;
    json!({"kind":kind,"input_modulus":modulus,"input_message":input,"output_message":output,
        "lut_body_sha256":observe::words_hash(body.as_ref()),"input":input_row,"raw":raw,"output":out,
        "degree":degree,"actual_lut_word":actual,"semantic_raw_word":raw_target,"address_ok":actual==raw_target,
        "offset":p.offset,"offset_exact":offset_exact,"pass":pass})
}

pub fn cm_bodies(lut: &CmGlweCiphertextOwned<u64>) -> Vec<Vec<u64>> {
    lut.get_bodies()
        .iter()
        .map(|p| p.as_ref().to_vec())
        .collect()
}

pub fn cm_probe_record(
    client: &ClientKeys,
    p: &CmProbe,
    kind: &str,
    inputs: &[u64],
    outputs: &[u64],
) -> Value {
    let input_targets: Vec<_> = inputs.iter().map(|x| x * CM_DELTA).collect();
    let output_targets: Vec<_> = outputs.iter().map(|x| x * CM_DELTA).collect();
    let raw_targets: Vec<_> = output_targets
        .iter()
        .map(|x| x.wrapping_sub(p.offset))
        .collect();
    let input_row = cm_record(client, &p.input, false, &input_targets, CM_DELTA);
    let raw = cm_record(client, &p.raw, true, &raw_targets, CM_DELTA);
    let out = cm_record(client, &p.output, true, &output_targets, CM_DELTA);
    let bodies = cm_bodies(&p.lut);
    let addresses: Vec<_> = (0..4).map(|j| {
        let degree = input_row["lanes"][j]["coefficientwise"]["address"].as_u64().unwrap() as usize;
        let actual = raw_word(&bodies[j],degree);
        json!({"degree":degree,"actual_lut_word":actual,"semantic_raw_word":raw_targets[j],"address_ok":actual==raw_targets[j]})
    }).collect();
    let dim = p.raw.lwe_dimension().0;
    let offset_exact = p.raw.as_ref()[..dim] == p.output.as_ref()[..dim]
        && (0..4)
            .all(|j| p.raw.as_ref()[dim + j].wrapping_add(p.offset) == p.output.as_ref()[dim + j]);
    let pass = offset_exact
        && (0..4).all(|j| {
            addresses[j]["address_ok"] == true
                && raw["lanes"][j]["phase_within_half_unit"] == true
                && out["lanes"][j]["phase_within_half_unit"] == true
        });
    json!({"kind":kind,"input_messages":inputs,"output_messages":outputs,
        "lut_body_sha256":bodies.iter().map(|b|observe::words_hash(b)).collect::<Vec<_>>(),
        "input":input_row,"raw":raw,"output":out,"addresses":addresses,
        "offset":p.offset,"offset_exact":offset_exact,"pass":pass})
}

pub fn bridge_inputs_record(client: &ClientKeys, b: &centered::BridgeInputs, values: &[u64]) -> Value {
    json!({"extracted":b.extracted.iter().enumerate().map(|(j,x)|ct_record(client,x,Domain::CmBig,j,values[j]*CM_DELTA,CM_DELTA)).collect::<Vec<_>>(),
        "small":b.small.iter().enumerate().map(|(j,x)|ct_record(client,x,Domain::A44Small,0,values[j]*CM_DELTA,CM_DELTA)).collect::<Vec<_>>()})
}

