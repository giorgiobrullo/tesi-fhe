use crate::{a98, wide};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;
use wide::Lwe;
const N: usize = 2048;

fn wh(words: &[u64]) -> String {
    let mut h = Sha256::new();
    for x in words {
        h.update(x.to_le_bytes());
    }
    format!("{:x}", h.finalize())
}
fn phase(ct: &Lwe, secret: &[u64]) -> u64 {
    ct.get_mask()
        .as_ref()
        .iter()
        .zip(secret)
        .fold(*ct.get_body().data, |s, (a, b)| {
            s.wrapping_sub(a.wrapping_mul(*b))
        })
}
fn decode(value: u64, log: u32) -> u64 {
    value.wrapping_add(1u64 << (log - 1)) >> log
}
fn close(value: u64, target: u64, log: u32) -> bool {
    (value.wrapping_sub(target) as i64 as i128).abs() < 1i128 << (log - 1)
}
fn at(body: &[u64], degree: usize) -> u64 {
    let degree = degree % 4096;
    if degree < N {
        body[degree]
    } else {
        body[degree - N].wrapping_neg()
    }
}
fn node(ct: &Lwe, secret: &[u64]) -> Value {
    let p = phase(ct, secret);
    let dot = ct
        .get_mask()
        .as_ref()
        .iter()
        .zip(secret)
        .fold(0u64, |sum, (a, s)| sum.wrapping_add(a.wrapping_mul(*s)));
    json!({"words":ct.as_ref(),"sha256":wh(ct.as_ref()),"phase":p,
        "client_mask_dot":dot,"direct_phase_matches":ct.get_body().data.wrapping_sub(dot)==p})
}

fn witness(step: &wide::Step, logs: &[u32], big: &[u64], small: &[u64]) -> Value {
    // Observer-only aggregate for separating input rounding and weighted KSK error.
    // No secret or evaluation-key row is serialized, and no FHE is performed here.
    let grid15_mask_dot =
        step.input
            .get_mask()
            .as_ref()
            .iter()
            .zip(big)
            .fold(0u64, |sum, (a, secret)| {
                let rounded = a.wrapping_add(1 << 48) & (u64::MAX << 49);
                sum.wrapping_add(rounded.wrapping_mul(*secret))
            });
    let log = CiphertextModulusLog(step.log);
    let centered =
        lwe_ciphertext_centered_binary_modulus_switch::<u64, usize, _>(step.small.clone(), log);
    let (_, centered_correction, _) = centered.into_raw_parts();
    let exact = a98::exact_head_start_modulus_switch(step.small.clone(), log).unwrap();
    let switch_replay_equal = exact.body() * step.stride == step.body
        && exact
            .mask()
            .map(|x| x * step.stride)
            .eq(step.mask.iter().copied());
    let (_, exact_correction, _) = exact.into_raw_parts();
    let tie = a98::head_start_tie_bit(step.small.get_mask().as_ref(), log).unwrap();
    let dot = step
        .mask
        .iter()
        .zip(small)
        .fold(0usize, |s, (a, b)| (s + a * *b as usize) % 4096);
    let degree = (step.body + 4096 - dot) % 4096;
    let ideal: Vec<_> = (0..step.outputs.len())
        .map(|lane| at(&step.lut, degree + lane))
        .collect();
    let raw: Vec<_> = step.raw.iter().map(|ct| phase(ct, big)).collect();
    let output: Vec<_> = step.outputs.iter().map(|ct| phase(ct, big)).collect();
    let actual_lut_output = (0..raw.len()).all(|i| close(raw[i], ideal[i], logs[i]));
    let offset_phase_equal =
        (0..raw.len()).all(|i| raw[i].wrapping_add(step.offsets[i]) == output[i]);
    json!({"name":step.name,"client_grid15_mask_dot":grid15_mask_dot,"input_node":node(&step.input,big),"small_node":node(&step.small,small),
        "raw_nodes":step.raw.iter().map(|ct|node(ct,big)).collect::<Vec<_>>(),
        "output_nodes":step.outputs.iter().map(|ct|node(ct,big)).collect::<Vec<_>>(),"input_sha256":wh(step.input.as_ref()),"input_phase":phase(&step.input,big),
        "small_words":step.small.as_ref(),"small_phase":phase(&step.small,small),
        "log":step.log,"stride":step.stride,"centered_correction":centered_correction,
        "half_case":1u64<<(63-step.log),"tie":tie,"exact_correction":exact_correction,
        "switch_replay_equal":switch_replay_equal,"switched_mask":step.mask,"switched_body":step.body,
        "switched_mask_dot":dot,"degree":degree,"lut_sha256":wh(&step.lut),"ideal_raw":ideal,
        "raw_phases":raw,"offsets":step.offsets,"output_phases":output,
        "output_sha256":step.outputs.iter().map(|ct|wh(ct.as_ref())).collect::<Vec<_>>(),
        "logs":logs,"actual_lut_output":actual_lut_output,"offset_phase_equal":offset_phase_equal,
        "pass":switch_replay_equal && actual_lut_output && offset_phase_equal})
}

pub fn observe(
    result: &wide::Result,
    score: u64,
    input: &Lwe,
    big: &[u64],
    small: &[u64],
) -> Value {
    let stages: Vec<_> = result
        .steps
        .iter()
        .zip([vec![58], vec![58], vec![59], vec![58], vec![59], vec![59]])
        .map(|(step, logs)| witness(step, &logs, big, small))
        .collect();
    let head_phases = [
        phase(&result.steps[0].outputs[0], big),
        phase(&result.steps[1].outputs[0], big),
    ];
    let digits = head_phases.map(|p| decode(p, 58));
    let d0 = digits[0] as i128;
    let d1 = digits[1] as i128;
    let q0 = score as i128 / 256;
    let y = score as i128 - 256 * d0;
    let q1 = y / 16;
    let r = y - 16 * d1;
    let v1 = d1 + r / 16;
    let invariant = (d0 == q0 || d0 == (q0 - 1).max(0))
        && y >= 0
        && (d1 == q1 || d1 == (q1 - 1).max(0))
        && (0..16).contains(&d0)
        && (0..32).contains(&d1)
        && (0..32).contains(&r)
        && (0..32).contains(&v1);
    let want_residual = if (0..32).contains(&r) {
        Some(vec![((r % 16) as u64) << 59, ((r / 16) as u64) << 58])
    } else {
        None
    };
    let want_carry = if (0..32).contains(&v1) {
        Some(vec![((v1 % 16) as u64) << 59, ((v1 / 16) as u64) << 59])
    } else {
        None
    };
    let ideal_residual: Vec<_> = (0..2)
        .map(|i| stages[2 + i]["ideal_raw"][0].as_u64().unwrap())
        .collect();
    let ideal_carry: Vec<_> = (0..2)
        .map(|i| stages[4 + i]["ideal_raw"][0].as_u64().unwrap())
        .collect();
    let normalizer_targets = want_residual.as_ref() == Some(&ideal_residual)
        && want_carry.as_ref() == Some(&ideal_carry);
    let phases = result.outputs.each_ref().map(|ct| phase(ct, big));
    let logs = [59, 59, 59];
    let output_digits = std::array::from_fn::<_, 3, _>(|i| decode(phases[i], logs[i]));
    let want = [score % 16, score / 16 % 16, score / 256];
    let canonical =
        output_digits == want && (0..3).all(|i| close(phases[i], want[i] << logs[i], logs[i]));
    let shared_normalizer_inputs = [(2, 3), (4, 5)].into_iter().all(|(a, b)| {
        let left = &result.steps[a];
        let right = &result.steps[b];
        left.input == right.input
            && left.small == right.small
            && left.mask == right.mask
            && left.body == right.body
    });
    let input_phase = phase(input, big);
    let pass = decode(input_phase, 51) == score
        && invariant
        && shared_normalizer_inputs
        && normalizer_targets
        && canonical
        && result.residual_affine_bytes_equal
        && stages.iter().all(|row| row["pass"] == true)
        && (
            result.counts.br,
            result.counts.ks,
            result.counts.samples,
            result.counts.gadget_levels,
        ) == (6, 4, 6, 8);
    json!({"record":"head_ingress","input_node":node(input,big),
        "canonical_nodes":result.outputs.iter().map(|ct|node(ct,big)).collect::<Vec<_>>(),"score":score,"input_phase":input_phase,"input_sha256":wh(input.as_ref()),
        "head_phases":head_phases,"head_digits":digits,"target_residual":r,"target_v1":v1,
        "shared_normalizer_inputs":shared_normalizer_inputs,"redundant_invariant":invariant,"residual_affine_bytes_equal":result.residual_affine_bytes_equal,
        "want_residual":want_residual,"want_carry":want_carry,"normalizer_targets":normalizer_targets,
        "stages":stages,"canonical_phases":phases,"canonical_digits":output_digits,
        "canonical_sha256":result.outputs.each_ref().map(|ct|wh(ct.as_ref())),"canonical_pass":canonical,
        "counts":{"br":result.counts.br,"ks":result.counts.ks,"samples":result.counts.samples,"gadget_levels":result.counts.gadget_levels},
        "pass":pass})
}
