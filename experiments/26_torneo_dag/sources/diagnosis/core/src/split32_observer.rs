fn full_input_json(ct: &Lwe,message: u64,input: &InputObservation,big: &LweSecretKeyView<'_,u64>) -> serde_json::Value {
    let mut row=input_json(ct,message,input);
    let node=comparator::lwe(ct,big);
    for key in ["client_mask_dot","direct_phase_matches"] {row[key]=node[key].clone();}
    let decoded=input.phase.wrapping_add(SCORE_DELTA/2)>>59;
    row["decoded"]=json!(decoded);
    row["strict_half_slot_pass"]=json!((input.error as i64).unsigned_abs()<SCORE_DELTA/2);
    row["nontrivial"]=json!(nontrivial(ct));row
}

fn glwe_json(ct: &Glwe,phase: &[u64]) -> serde_json::Value {
    let dots:Vec<_>=ct.get_body().as_ref().iter().zip(phase).map(|(b,p)|b.wrapping_sub(*p)).collect();
    json!({"words":ct.as_ref(),"sha256":observer::hash_words(ct.as_ref()),
        "phase_words":phase,"phase_sha256":observer::hash_words(phase),"client_mask_dot_words":dots,
        "client_mask_dot_reconstructed_from_body_and_decryption":true})
}

pub(super) struct Observation {
    pub pass: bool,
    pub input_pass: bool,
    pub control_pass: bool,
    pub assembly_pass: bool,
    pub output_pass: bool,
    pub decoded: Vec<u64>,
    pub output_errors: Vec<i64>,
    pub centering_body_changed: bool,
    pub centering_address_changed: bool,
}

pub(super) fn observe(
    fixture: &Fixture,left: &[Lwe],right: &[Lwe],stages: &[comparator::Stage],combined: &Lwe,
    selected: &Selection,window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,glwe: &GlweSecretKeyOwned<u64>,small: &LweSecretKeyView<'_,u64>,ksk: &LweKeyswitchKeyOwned<u64>,
) -> Observation {
    let big=glwe.as_lwe_secret_key();let trace=&selected.trace;
    let parameters=PfksParameters {base_log:window_key.decomposition_base_log().0,
        level_count:window_key.decomposition_level_count().0};
    let lm:Vec<_>=fixture.left.iter().map(|m|m*SCORE_DELTA).collect();
    let rm:Vec<_>=fixture.right.iter().map(|m|m*SCORE_DELTA).collect();
    let messages:Vec<_>=rm.iter().zip(&lm).map(|(r,l)|r.wrapping_sub(*l)).collect();
    let lo:Vec<_>=(0..5).map(|i|input_observation(&left[i],&big,lm[i],parameters)).collect();
    let ro:Vec<_>=(0..5).map(|i|input_observation(&right[i],&big,rm[i],parameters)).collect();
    let differences:Vec<_>=(0..5).map(|i|input_observation(&trace.differences[i],&big,messages[i],parameters)).collect();
    let pfks_phases:Vec<_>=trace.pfks.iter().map(|ct|glwe_phase(glwe,ct)).collect();
    let function=window();
    let key_errors:Vec<Vec<u64>>=differences.iter().zip(&pfks_phases).map(|(input,phase)| {
        phase.iter().zip(function.as_ref()).map(|(p,w)|p.wrapping_sub(input.rounded_phase.wrapping_mul(*w))).collect()
    }).collect();
    let pre_phases:Vec<_>=trace.pre_br.iter().map(|ct|glwe_phase(glwe,ct)).collect();
    let post_phases:Vec<_>=trace.post_br.iter().map(|ct|glwe_phase(glwe,ct)).collect();

    let switched=comparator::switched(combined,&trace.uncorrected_control,&big,small,ksk);
    let (centered,centering_pass)=mean_center::observe(&trace.uncorrected_control,&selected.control,
        trace.stock_correction,trace.mean_correction,&switched,small);
    let effective=centered["actual_address"].as_u64().unwrap() as usize;
    let centering_body_changed=centered["body_word_changed"].as_bool().unwrap();
    let centering_address_changed=centered["body_address_changed"].as_bool().unwrap();
    let displacement=centered_degree_error(effective,fixture.center_degree);
    let support=displacement.abs()<=20;
    let mut expected_combined=stages[0].output.clone();
    for (i,word) in expected_combined.as_mut().iter_mut().enumerate() {
        *word=stages[0].output.as_ref()[i].wrapping_mul(4)
            .wrapping_add(stages[1].output.as_ref()[i].wrapping_mul(2)).wrapping_add(stages[2].output.as_ref()[i]);
    }
    *expected_combined.get_mut_body().data=expected_combined.get_body().data.wrapping_sub(SCORE_DELTA/2);
    let combined_words_pass=expected_combined.as_ref()==combined.as_ref();
    let source_phases:Vec<_>=stages.iter().map(|s|decrypt_lwe_ciphertext(&big,&s.output).0).collect();
    let expected_phase=source_phases[0].wrapping_mul(4).wrapping_add(source_phases[1].wrapping_mul(2))
        .wrapping_add(source_phases[2]).wrapping_sub(SCORE_DELTA/2);
    let combined_phase=switched["input"]["phase"].as_u64().unwrap();
    let combined_phase_pass=combined_phase==expected_phase;
    let shared_control:Vec<_>=trace.controls_before.iter().zip(&trace.controls_after).map(|(before,after)|
        before.as_ref()==selected.control.as_ref() && after.as_ref()==selected.control.as_ref()).collect();
    let weights:Vec<Vec<Vec<i64>>>=OFFSETS.iter().map(|offsets|offsets.iter().map(|o|offsets.iter()
        .map(|t|at(function.as_ref(),effective as isize+*o as isize-*t as isize) as i64).collect()).collect()).collect();
    let weights_pass=weights.iter().all(|group|group.iter().enumerate().all(|(i,row)|row.iter().enumerate()
        .all(|(j,w)|*w==i64::from(fixture.choose_right && i==j))));
    let control_pass=centering_pass && combined_words_pass && combined_phase_pass && shared_control.iter().all(|p|*p)
        && switched["coefficient_identity_pass"]==true && switched["input"]["direct_phase_matches"]==true
        && switched["small"]["direct_phase_matches"]==true && support && weights_pass;
    emit(json!({"record":"split32_control","fixture":fixture.name,"index":fixture.index,
        "source_ternary_output_sha256":stages.iter().map(|s|hash_lwe(&s.output)).collect::<Vec<_>>(),
        "source_ternary_output_phases":source_phases,"combined_message_phase":fixture.combined_message_phase,
        "combined_phase_error":combined_phase.wrapping_sub(fixture.combined_message_phase) as i64,
        "combined_all_words_pass":combined_words_pass,"combined_phase_assembly_pass":combined_phase_pass,
        "ks_observation":switched,"mean_center_observation":centered,"center_degree":fixture.center_degree,"actual_degree":effective,"displacement":displacement,
        "support_pass":support,"weights":weights,"weights_pass":weights_pass,
        "control_before_sha256":trace.controls_before.iter().map(hash_lwe).collect::<Vec<_>>(),
        "control_after_sha256":trace.controls_after.iter().map(hash_lwe).collect::<Vec<_>>(),
        "same_control_all_words":shared_control,"shared_ordinary_ks_calls":selected.metrics.ks,
        "dynamic_blind_rotations":selected.metrics.br,"pass":control_pass}));

    let mut input_pass=true;let mut decomposition_pass=true;
    for lane in 0..5 {
        let l=full_input_json(&left[lane],lm[lane],&lo[lane],&big);
        let r=full_input_json(&right[lane],rm[lane],&ro[lane],&big);
        let d=full_input_json(&trace.differences[lane],messages[lane],&differences[lane],&big);
        let word_pass=trace.differences[lane].as_ref().iter().zip(right[lane].as_ref()).zip(left[lane].as_ref())
            .all(|((d,r),l)|*d==r.wrapping_sub(*l));
        let phase_pass=differences[lane].phase==ro[lane].phase.wrapping_sub(lo[lane].phase);
        let error_pass=differences[lane].error==ro[lane].error.wrapping_sub(lo[lane].error);
        let actual_input_pass=[(&l,fixture.left[lane],fixture.left_nontrivial[lane]),
            (&r,fixture.right[lane],fixture.right_nontrivial[lane])].iter().all(|(row,message,expected_nontrivial)|
            row["direct_phase_matches"]==true && row["strict_half_slot_pass"]==true && row["decoded"]==*message
            && row["nontrivial"]==*expected_nontrivial
            && (*expected_nontrivial || row["phase"]==message*SCORE_DELTA));
        input_pass &= actual_input_pass;
        let relation=pfks_phases[lane].iter().zip(function.as_ref()).zip(&key_errors[lane]).all(|((p,w),e)|
            *p==differences[lane].rounded_phase.wrapping_mul(*w).wrapping_add(*e));
        let pass=word_pass && phase_pass && error_pass && relation && d["direct_phase_matches"]==true;
        decomposition_pass &= pass;
        emit(json!({"record":"split32_difference_pfks","fixture":fixture.name,"index":fixture.index,"lane":lane,
            "left":l,"right":r,"difference":d,"left_expected_nontrivial":fixture.left_nontrivial[lane],
            "right_expected_nontrivial":fixture.right_nontrivial[lane],"difference_all_words_pass":word_pass,
            "difference_phase_pass":phase_pass,"difference_error_pass":error_pass,"input_pass":actual_input_pass,
            "function_sha256":observer::hash_words(function.as_ref()),"pfks":glwe_json(&trace.pfks[lane],&pfks_phases[lane]),
            "aggregate_key_error_words":key_errors[lane],"aggregate_key_error_sha256":observer::hash_words(&key_errors[lane]),
            "decomposition_identity_pass":relation,"difference_decode_is_gating":false,
            "primitive_row_errors_independently_measured":false,"independent_noise_assumed":false,"pass":pass}));
    }

    let mut assembly_pass=true;
    for group_index in 0..2 {
        let group=GROUPS[group_index];let offsets=OFFSETS[group_index];
        let words_pass=(0..GLWE_SIZE).all(|component|(0..POLYNOMIAL_SIZE).all(|k| {
            let expected=group.iter().zip(offsets).fold(0u64,|sum,(&lane,&offset)|sum.wrapping_add(at(
                &trace.pfks[lane].as_ref()[component*POLYNOMIAL_SIZE..(component+1)*POLYNOMIAL_SIZE],k as isize-offset as isize)));
            trace.pre_br[group_index].as_ref()[component*POLYNOMIAL_SIZE+k]==expected
        }));
        let phase_pass=(0..POLYNOMIAL_SIZE).all(|k| {
            let expected=group.iter().zip(offsets).fold(0u64,|sum,(&lane,&offset)|
                sum.wrapping_add(at(&pfks_phases[lane],k as isize-offset as isize)));
            pre_phases[group_index][k]==expected
        });
        let pass=words_pass && phase_pass;assembly_pass &= pass;
        emit(json!({"record":"split32_accumulator","fixture":fixture.name,"index":fixture.index,"group":group_index,
            "lanes":group,"offsets":offsets,"function_sha256":observer::hash_words(function.as_ref()),
            "source_pfks_sha256":group.iter().map(|i|observer::hash_words(trace.pfks[*i].as_ref())).collect::<Vec<_>>(),
            "pre_br":glwe_json(&trace.pre_br[group_index],&pre_phases[group_index]),
            "post_br":glwe_json(&trace.post_br[group_index],&post_phases[group_index]),
            "control_sha256":hash_lwe(&selected.control),"control_before_sha256":hash_lwe(&trace.controls_before[group_index]),
            "control_after_sha256":hash_lwe(&trace.controls_after[group_index]),"actual_degree":effective,
            "all_words_assembly_pass":words_pass,"all_phase_assembly_pass":phase_pass,"pass":pass}));
    }

    let mut output_pass=true;let mut noise_closure_pass=true;let mut decoded=Vec::new();let mut output_errors=Vec::new();
    for lane in 0..5 {
        let group_index=usize::from(lane>=3);let local=if lane<3 {lane} else {lane-3};
        let group=GROUPS[group_index];let offsets=OFFSETS[group_index];let degree=effective as isize+offsets[local] as isize;
        let mut ideal=0u64;let mut error=0u64;let mut rho=0u64;let mut key_error=0u64;let mut exact_pre=0u64;let mut contributions=Vec::new();
        for (&term,&offset) in group.iter().zip(offsets) {
            let at_degree=degree-offset as isize;let weight=at(function.as_ref(),at_degree);
            let eta=at(&key_errors[term],at_degree);let phase=at(&pfks_phases[term],at_degree);
            ideal=ideal.wrapping_add(messages[term].wrapping_mul(weight));
            error=error.wrapping_add(differences[term].error.wrapping_mul(weight));
            rho=rho.wrapping_add((differences[term].rho as u64).wrapping_mul(weight));
            key_error=key_error.wrapping_add(eta);exact_pre=exact_pre.wrapping_add(phase);
            contributions.push(json!({"term":term,"virtual_degree":at_degree,"message_weight":weight as i64,
                "aggregate_key_error":eta as i64,"exact_pfks_phase":phase}));
        }
        let actual_pre=at(&pre_phases[group_index],degree);
        let correction=comparator::lwe(&trace.corrections[lane],&big);
        let output=comparator::lwe(&selected.output[lane],&big);
        let correction_phase=correction["phase"].as_u64().unwrap();let output_phase=output["phase"].as_u64().unwrap();
        let wanted=fixture.expected[lane]*SCORE_DELTA;let ideal_final=lm[lane].wrapping_add(ideal);
        let support_error=ideal_final.wrapping_sub(wanted);let assembly=actual_pre.wrapping_sub(exact_pre);
        let br=correction_phase.wrapping_sub(actual_pre);let addback=output_phase.wrapping_sub(correction_phase).wrapping_sub(lo[lane].phase);
        let terms=[support_error,error,rho,key_error,assembly,br,lo[lane].error,addback];
        let semantic=output_phase.wrapping_sub(wanted);let offset=offsets[local];
        let post_words=trace.post_br[group_index].as_ref();
        let sample_words_pass=(0..POLYNOMIAL_SIZE).all(|j| {
            let expected=if j<=offset {post_words[offset-j]} else {post_words[POLYNOMIAL_SIZE+offset-j].wrapping_neg()};
            trace.corrections[lane].as_ref()[j]==expected
        }) && *trace.corrections[lane].get_body().data==post_words[POLYNOMIAL_SIZE+offset];
        let sample_phase_pass=correction_phase==post_phases[group_index][offset];
        let addback_words_pass=selected.output[lane].as_ref().iter().zip(trace.corrections[lane].as_ref()).zip(left[lane].as_ref())
            .all(|((o,c),l)|*o==c.wrapping_add(*l));
        let closure=terms.iter().fold(0u64,|s,t|s.wrapping_add(*t))==semantic
            && ideal.wrapping_add(error).wrapping_add(rho).wrapping_add(key_error)==exact_pre
            && assembly==0 && addback==0 && sample_words_pass && sample_phase_pass && addback_words_pass
            && correction["direct_phase_matches"]==true && output["direct_phase_matches"]==true;
        noise_closure_pass &= closure;
        let digit=output_phase.wrapping_add(SCORE_DELTA/2)>>59;
        let strict=(semantic as i64).unsigned_abs()<SCORE_DELTA/2;
        let nontrivial_output=nontrivial(&selected.output[lane]);
        let pass=closure && strict && digit==fixture.expected[lane] && nontrivial_output;
        output_pass &= pass;decoded.push(digit);output_errors.push(semantic as i64);
        emit(json!({"record":"split32_noise_lane","fixture":fixture.name,"index":fixture.index,"lane":lane,"group":group_index,
            "offset":offset,"virtual_degree":degree,"term_contributions":contributions,"delta":SCORE_DELTA,"expected_phase":wanted,
            "ideal_correction":ideal,"ideal_final":ideal_final,"exact_pre_br_phase_reconstructed":exact_pre,"actual_pre_br_phase":actual_pre,
            "correction":correction,"output":output,"left_phase":lo[lane].phase,
            "support_message_residual":support_error as i64,"transmitted_difference_error":error as i64,
            "transmitted_difference_rho":rho as i64,"aggregate_pfks_key_error":key_error as i64,
            "exact_assembly_residual":assembly as i64,"br_and_numeric_residual":br as i64,
            "left_addback_input_error":lo[lane].error as i64,"addback_arithmetic_residual":addback as i64,
            "semantic_error":semantic as i64,"centered_terms_unwrapped_sum_decimal":terms.iter().map(|t|*t as i64 as i128).sum::<i128>().to_string(),
            "sample_extraction_all_words_pass":sample_words_pass,"sample_phase_pass":sample_phase_pass,
            "addback_all_words_pass":addback_words_pass,"closure_pass":closure,"decoded":digit,"strict_half_slot_pass":strict,
            "nontrivial_output":nontrivial_output,"pass":pass,"same_key_control_and_sibling_errors_independent":false,
            "rowwise_key_error_measured":false,"formal_failure_bound":null}));
    }
    Observation {pass:input_pass && control_pass && decomposition_pass && assembly_pass && noise_closure_pass && output_pass,
        input_pass,control_pass,assembly_pass,output_pass,decoded,output_errors,centering_body_changed,centering_address_changed}
}
