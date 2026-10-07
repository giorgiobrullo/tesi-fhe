//! Fixed finite client-local egress diagnostic. No feedback chooses offsets or inputs.
use crate::crypto::{self, ClientKeys, Domain, EvaluationKeys, RoundResult, Trace};
use crate::model::{A44_DELTA, CM_DELTA};
use crate::{decode, emit};
use serde_json::json;

pub const OFFSETS: [i64; 2] = [-(1i64 << 59), 1i64 << 59];

/// Public identity accumulator lookup at the actual coefficientwise address.
fn identity_value(degree: usize) -> u64 {
    let cell = ((degree + 256) / 512) % 8;
    if cell < 4 {
        cell as u64
    } else {
        0u64.wrapping_sub((cell - 4) as u64) % 32
    }
}

fn retained(round: &RoundResult, index: usize) -> &Trace {
    let tag = format!("egress_small/{index}");
    let items: Vec<_> = round.traces.iter().filter(|x| x.tag == tag).collect();
    assert_eq!(
        items.len(),
        1,
        "one original retained egress input required"
    );
    assert_eq!(items[0].lane, 0);
    items[0]
}

/// Complete all16 server probes before observing a client secret. Original rounds stay immutable.
pub fn run(
    client: &ClientKeys,
    key: &EvaluationKeys,
    baseline: &RoundResult,
    wrong: &RoundResult,
) -> bool {
    assert!(baseline.completed && wrong.completed);
    assert_eq!(baseline.outputs.len(), 4);
    assert_eq!(wrong.outputs.len(), 4);
    let mut probes = Vec::new();
    for (arm, round) in [("baseline", baseline), ("wrong_lane", wrong)] {
        for offset in OFFSETS {
            for index in 0..4 {
                let original = retained(round, index);
                let probe = crypto::egress_margin_probe(key, &original.ct, offset);
                probes.push((arm, offset, index, original, probe));
            }
        }
    }
    let mut baseline_outputs_pass = true;
    let mut baseline_support_pass = true;
    let mut binding_pass = true;
    let mut all_outputs_match_lut = true;
    let mut wrong_mismatches = [0usize; 2];
    let mut wrong_discriminators = [0usize; 2];
    let mut body_additions = 0;
    let mut ordinary_pbs = 0;
    let mut ordinary_ks = 0;
    for (arm, offset, index, original, probe) in probes {
        let expected = u64::from(index == 0);
        let shifted = Trace {
            tag: "margin_input".into(),
            domain: Domain::A44Small,
            lane: 0,
            ct: probe.shifted_input,
        };
        let output = Trace {
            tag: "margin_output".into(),
            domain: Domain::A44Big,
            lane: 0,
            ct: probe.output,
        };
        let original_phase = crypto::decrypt_trace(client, original);
        let shifted_phase = crypto::decrypt_trace(client, &shifted);
        let output_phase = crypto::decrypt_trace(client, &output);
        let original_degree = crypto::coefficientwise_degree(client, original, 2048);
        let shifted_degree = crypto::coefficientwise_degree(client, &shifted, 2048);
        let degree_offset = if offset < 0 { -128i64 } else { 128i64 };
        let address_closure =
            shifted_degree == (original_degree as i64 + degree_offset).rem_euclid(4096) as usize;
        let masks_equal = original.ct.get_mask().as_ref() == shifted.ct.get_mask().as_ref();
        let phase_closure = shifted_phase == original_phase.wrapping_add(offset as u64);
        let input_lut_value = identity_value(shifted_degree);
        let output_value = decode(output_phase, A44_DELTA);
        let output_error = output_phase.wrapping_sub(expected * A44_DELTA) as i64;
        let output_matches =
            output_value == expected && (output_error as i128).abs() < (A44_DELTA / 2) as i128;
        let lut_error = output_phase.wrapping_sub(input_lut_value.wrapping_mul(A44_DELTA)) as i64;
        let output_matches_lut =
            output_value == input_lut_value && (lut_error as i128).abs() < (A44_DELTA / 2) as i128;
        let input_expected_cell = input_lut_value == expected;
        binding_pass &= masks_equal && phase_closure && address_closure;
        all_outputs_match_lut &= output_matches_lut;
        if arm == "baseline" {
            baseline_outputs_pass &= output_matches;
            baseline_support_pass &= input_expected_cell;
        } else {
            wrong_mismatches[usize::from(offset > 0)] += usize::from(!output_matches);
            wrong_discriminators[usize::from(offset > 0)] +=
                usize::from(!input_expected_cell && !output_matches && output_matches_lut);
        }
        body_additions += probe.body_additions;
        ordinary_pbs += probe.ordinary_pbs;
        ordinary_ks += probe.ordinary_ks;
        emit(
            json!({"type":"egress_margin_probe","arm":arm,"offset_i64":offset.to_string(),
            "index":index,"source_case":if arm=="baseline"{"n4_plain"}else{"n4_negative_WrongLaneKsk"},
            "source_stage":original.tag,"expected":expected,"input_delta_u64":CM_DELTA.to_string(),
            "output_delta_u64":A44_DELTA.to_string(),"original_phase_u64":original_phase.to_string(),
            "shifted_phase_u64":shifted_phase.to_string(),"output_phase_u64":output_phase.to_string(),
            "output_signed_error_i64":output_error.to_string(),"output_decoded":output_value,
            "original_coefficientwise_degree":original_degree,"shifted_coefficientwise_degree":shifted_degree,
            "degree_offset":degree_offset,"address_closure":address_closure,"phase_closure":phase_closure,
            "mask_unchanged":masks_equal,"input_lut_value":input_lut_value,"input_expected_cell":input_expected_cell,
            "output_matches_expected":output_matches,"output_matches_lut":output_matches_lut,
            "counts":{"body_additions":probe.body_additions,
            "ordinary_pbs":probe.ordinary_pbs,"ordinary_ks":probe.ordinary_ks},
            "client_local_key_sensitive":true,"clear_address_prediction_is_fhe_result":false}),
        );
    }
    let count_pass = body_additions == 16 && ordinary_pbs == 16 && ordinary_ks == 0;
    // At least one observed wrong output among the fixed eight probes, with all matched controls valid.
    let finite_coverage = wrong_discriminators.iter().sum::<usize>() > 0;
    let passed = baseline_outputs_pass
        && baseline_support_pass
        && binding_pass
        && count_pass
        && all_outputs_match_lut
        && finite_coverage;
    emit(
        json!({"type":"egress_margin_summary","probe_count":16,"baseline_probe_count":8,
        "wrong_lane_probe_count":8,"offsets_i64":OFFSETS.map(|x| x.to_string()),
        "baseline_outputs_pass":baseline_outputs_pass,"baseline_support_pass":baseline_support_pass,
        "binding_pass":binding_pass,"counts":{"body_additions":body_additions,"ordinary_pbs":ordinary_pbs,"ordinary_ks":ordinary_ks},
        "count_pass":count_pass,"wrong_output_mismatches_by_offset":wrong_mismatches,
        "wrong_discriminators_by_offset":wrong_discriminators,"all_outputs_match_lut":all_outputs_match_lut,
        "finite_wrong_output_coverage":finite_coverage,"coverage_rule":"at least one of eight fixed wrong-lane probes crosses an exact LUT value and decrypts that value; all baseline probes pass and all16 outputs match their consumed LUT values",
        "passed":passed,"original_a150_control_reinterpreted":false,"no_retry_until_pass":true,
        "scope":"one deterministic N4 bit7 witness, one fresh key; no universal detection or probability claim"}),
    );
    passed
}
