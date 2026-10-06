//! A171 local client observer; native ring identities, no tail or key-membership proof.
use super::*;

/// Extend coefficients to signed virtual degrees in Z_q[X]/(X^N+1).
fn at(poly: &[u64], degree: isize) -> u64 {
    let n = poly.len() as isize;
    let word = poly[degree.rem_euclid(n) as usize];
    if degree.div_euclid(n).rem_euclid(2) == 0 {
        word
    } else {
        word.wrapping_neg()
    }
}

fn glwe_phase(secret: &GlweSecretKeyOwned<u64>, ct: &Glwe) -> Vec<u64> {
    let mut phase = PlaintextList::new(0u64, PlaintextCount(POLYNOMIAL_SIZE));
    decrypt_glwe_ciphertext(secret, ct, &mut phase);
    phase.as_ref().to_vec()
}

struct InputObservation {
    phase: u64,
    error: u64,
    rho: i128,
    rounded_phase: u64,
    digits: Vec<i64>,
    levels: Vec<usize>,
    body_digits: Vec<i64>,
}

fn input_observation(
    input: &Lwe,
    secret: &LweSecretKeyView<'_, u64>,
    message: u64,
    parameters: PfksParameters,
) -> InputObservation {
    assert_eq!(input.as_ref().len(), secret.as_ref().len() + 1);
    let decomposer = SignedDecomposer::<u64>::new(
        DecompositionBaseLog(parameters.base_log),
        DecompositionLevelCount(parameters.level_count),
    );
    let phase = decrypt_lwe_ciphertext(secret, input).0;
    let mut rho = 0i128;
    let mut digits = Vec::new();
    let mut levels = Vec::new();
    let mut body_digits = Vec::new();
    for (row, &word) in input.as_ref().iter().enumerate() {
        let rounded = decomposer.closest_representable(word);
        let remainder = rounded.wrapping_sub(word) as i64 as i128;
        if row == secret.as_ref().len() {
            rho += remainder;
        } else {
            let secret_word = secret.as_ref()[row];
            assert!(secret_word <= 1, "binary input-key assumption");
            rho -= secret_word as i128 * remainder;
        }
        let terms: Vec<_> = decomposer.decompose(rounded).collect();
        let reconstructed = terms.iter().fold(0u64, |sum, term| {
            sum.wrapping_add(
                term.value()
                    .wrapping_mul(1u64 << (64 - parameters.base_log * term.level().0)),
            )
        });
        assert_eq!(
            reconstructed, rounded,
            "actual TFHE decomposition including body row"
        );
        if row == 0 {
            levels = terms.iter().map(|term| term.level().0).collect();
        }
        for term in terms {
            digits.push(term.value() as i64);
            if row == secret.as_ref().len() {
                body_digits.push(term.value() as i64);
            }
        }
    }
    InputObservation {
        phase,
        error: phase.wrapping_sub(message),
        rho,
        rounded_phase: phase.wrapping_add(rho as u64),
        digits,
        levels,
        body_digits,
    }
}

// Appended after exact A137 at/glwe_phase/input_observation helpers.
#[derive(Default)]
pub(super) struct Metrics {
    pub pfks: usize,
    pub rotations: usize,
    pub polynomial_permutations: usize,
    pub glwe_additions: usize,
    pub ks: usize,
    pub br: usize,
    pub samples: usize,
    pub lwe_subtractions: usize,
    pub lwe_addbacks: usize,
}

impl Metrics {
    pub fn pass(&self) -> bool {
        self.pfks == 4
            && self.rotations == 4
            && self.polynomial_permutations == 8
            && self.glwe_additions == 3
            && self.ks == 1
            && self.br == 1
            && self.samples == 4
            && self.lwe_subtractions == 4
            && self.lwe_addbacks == 4
    }
    pub fn json(&self) -> serde_json::Value {
        json!({"pfks":self.pfks,"rotations":self.rotations,
            "polynomial_permutations":self.polynomial_permutations,
            "glwe_additions":self.glwe_additions,"ks":self.ks,"br":self.br,
            "samples":self.samples,"lwe_subtractions":self.lwe_subtractions,
            "lwe_addbacks":self.lwe_addbacks,"pass":self.pass()})
    }
}

pub(super) struct Trace {
    differences: Vec<Lwe>,
    pfks: Vec<Glwe>,
    pre_br: Glwe,
    corrections: [Lwe; OUTPUTS],
}

pub(super) fn select(
    left: &[Lwe],
    right: &[Lwe],
    encrypted_control: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe; OUTPUTS], Lwe, Metrics, Trace) {
    assert_eq!(left.len(), OUTPUTS);
    assert_eq!(right.len(), OUTPUTS);
    let modulus = encrypted_control.ciphertext_modulus();
    let mut metrics = Metrics::default();
    let mut differences = Vec::with_capacity(OUTPUTS);
    let mut pfks = Vec::with_capacity(OUTPUTS);
    let mut accumulator: Option<Glwe> = None;
    for lane in 0..OUTPUTS {
        let mut difference = right[lane].clone();
        assert_eq!(difference.as_ref().len(), left[lane].as_ref().len());
        for (word, &l) in difference.as_mut().iter_mut().zip(left[lane].as_ref()) {
            *word = word.wrapping_sub(l);
        }
        metrics.lwe_subtractions += 1;
        let mut term = GlweCiphertext::new(
            0u64,
            window_key.output_glwe_size(),
            window_key.output_polynomial_size(),
            modulus,
        );
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            window_key,
            &mut term,
            &difference,
        );
        metrics.pfks += 1;
        differences.push(difference);
        pfks.push(term.clone());
        for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
            polynomial_wrapping_monic_monomial_mul_assign(
                &mut polynomial,
                MonomialDegree((RIGHT_CONTROL as usize + lane) * BOX_SIZE),
            );
            metrics.polynomial_permutations += 1;
        }
        metrics.rotations += 1;
        if let Some(acc) = accumulator.as_mut() {
            for (word, &value) in acc.as_mut().iter_mut().zip(term.as_ref()) {
                *word = word.wrapping_add(value);
            }
            metrics.glwe_additions += 1;
        } else {
            accumulator = Some(term);
        }
    }
    let mut accumulator = accumulator.expect("four difference payloads");
    let pre_br = accumulator.clone();
    let mut control =
        LweCiphertext::new(0u64, ksk.output_key_lwe_dimension().to_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, encrypted_control, &mut control);
    metrics.ks += 1;
    blind_rotate_assign(&control, &mut accumulator, bsk);
    metrics.br += 1;
    let corrections: [Lwe; OUTPUTS] = std::array::from_fn(|lane| {
        let mut output =
            LweCiphertext::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut output,
            MonomialDegree(lane * BOX_SIZE),
        );
        metrics.samples += 1;
        output
    });
    let outputs = std::array::from_fn(|lane| {
        let mut output = corrections[lane].clone();
        assert_eq!(output.as_ref().len(), left[lane].as_ref().len());
        for (word, &l) in output.as_mut().iter_mut().zip(left[lane].as_ref()) {
            *word = word.wrapping_add(l);
        }
        metrics.lwe_addbacks += 1;
        output
    });
    (
        outputs,
        control,
        metrics,
        Trace {
            differences,
            pfks,
            pre_br,
            corrections,
        },
    )
}

pub(super) fn arm_order(fixture: usize, offset: usize) -> [usize; 4] {
    const ORDERS: [[usize; 4]; 24] = [
        [0, 1, 2, 3],
        [0, 1, 3, 2],
        [0, 2, 1, 3],
        [0, 2, 3, 1],
        [0, 3, 1, 2],
        [0, 3, 2, 1],
        [1, 0, 2, 3],
        [1, 0, 3, 2],
        [1, 2, 0, 3],
        [1, 2, 3, 0],
        [1, 3, 0, 2],
        [1, 3, 2, 0],
        [2, 0, 1, 3],
        [2, 0, 3, 1],
        [2, 1, 0, 3],
        [2, 1, 3, 0],
        [2, 3, 0, 1],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [3, 0, 2, 1],
        [3, 1, 0, 2],
        [3, 1, 2, 0],
        [3, 2, 0, 1],
        [3, 2, 1, 0],
    ];
    assert!(fixture < 8 && offset < 3);
    ORDERS[fixture + 8 * offset]
}

fn shifted(poly: &[u64], degree: isize, term: usize) -> u64 {
    at(
        poly,
        degree - ((RIGHT_CONTROL as usize + term) * BOX_SIZE) as isize,
    )
}

fn input_json(ct: &Lwe, message: u64, input: &InputObservation) -> serde_json::Value {
    json!({"words":ct.as_ref(),"sha256":hash_lwe(ct),"message_phase":message,
        "phase":input.phase,"error":input.error as i64,
        "rho_decimal":input.rho.to_string(),"rounded_phase":input.rounded_phase,
        "digits":input.digits,"levels":input.levels,"body_digits":input.body_digits})
}

pub(super) fn observe(
    fixture: Fixture,
    left: &[Lwe],
    right: &[Lwe],
    input_control: &Lwe,
    control: &Lwe,
    outputs: &[Lwe; OUTPUTS],
    trace: &Trace,
    glwe_secret: &GlweSecretKeyOwned<u64>,
    small_secret: &LweSecretKeyView<'_, u64>,
    parameters: PfksParameters,
) -> bool {
    let big = glwe_secret.as_lwe_secret_key();
    let left_messages: Vec<_> = (0..OUTPUTS)
        .map(|j| fixture.left[j].wrapping_mul(PAYLOAD_DELTAS[j]))
        .collect();
    let right_messages: Vec<_> = (0..OUTPUTS)
        .map(|j| fixture.right[j].wrapping_mul(PAYLOAD_DELTAS[j]))
        .collect();
    let messages: Vec<_> = (0..OUTPUTS)
        .map(|j| right_messages[j].wrapping_sub(left_messages[j]))
        .collect();
    let lobs: Vec<_> = (0..OUTPUTS)
        .map(|j| input_observation(&left[j], &big, left_messages[j], parameters))
        .collect();
    let robs: Vec<_> = (0..OUTPUTS)
        .map(|j| input_observation(&right[j], &big, right_messages[j], parameters))
        .collect();
    let obs: Vec<_> = (0..OUTPUTS)
        .map(|j| input_observation(&trace.differences[j], &big, messages[j], parameters))
        .collect();
    let phases: Vec<_> = trace
        .pfks
        .iter()
        .map(|ct| glwe_phase(glwe_secret, ct))
        .collect();
    let function = signed_cell_mask(PolynomialSize(POLYNOMIAL_SIZE), 0);
    let errors: Vec<Vec<u64>> = (0..OUTPUTS)
        .map(|j| {
            phases[j]
                .iter()
                .zip(function.as_ref())
                .map(|(&phase, &f)| phase.wrapping_sub(obs[j].rounded_phase.wrapping_mul(f)))
                .collect()
        })
        .collect();
    let pre_br_phase = glwe_phase(glwe_secret, &trace.pre_br);
    let mut pass = true;
    for j in 0..OUTPUTS {
        let words_ok = trace.differences[j]
            .as_ref()
            .iter()
            .zip(right[j].as_ref())
            .zip(left[j].as_ref())
            .all(|((&d, &r), &l)| d == r.wrapping_sub(l));
        let phase_ok = obs[j].phase == robs[j].phase.wrapping_sub(lobs[j].phase);
        let error_ok = obs[j].error == robs[j].error.wrapping_sub(lobs[j].error);
        pass &= words_ok && phase_ok && error_ok;
        let digit_changes = obs[j]
            .digits
            .iter()
            .zip(&robs[j].digits)
            .zip(&lobs[j].digits)
            .filter(|((d, r), l)| **d != **r - **l)
            .count();
        let native_error = obs[j].error as i64;
        emit(
            json!({"record":"d1_difference_pfks", "fixture":fixture.name,"term":j,
            "key_family":"window","function_sha256":observer::hash_words(function.as_ref()),
            "left":input_json(&left[j],left_messages[j],&lobs[j]),
            "right":input_json(&right[j],right_messages[j],&robs[j]),
            "difference":input_json(&trace.differences[j],messages[j],&obs[j]),
            "difference_words_pass":words_ok,"difference_phase_pass":phase_ok,
            "difference_error_pass":error_ok,"nonlinear_digit_count":digit_changes,
            "rho_difference_discrepancy_decimal":(obs[j].rho-robs[j].rho+lobs[j].rho).to_string(),
            "difference_native_half_slot_diagnostic":native_error.unsigned_abs()<PAYLOAD_DELTAS[j]/2,
            "difference_native_decode_diagnostic":obs[j].phase.wrapping_add(PAYLOAD_DELTAS[j]/2)/PAYLOAD_DELTAS[j]
                == messages[j]/PAYLOAD_DELTAS[j],
            "difference_native_pass_is_prerequisite":false,
            "pfks_output_sha256":observer::hash_words(trace.pfks[j].as_ref()),
            "phase_polynomial_sha256":observer::hash_words(&phases[j]),
            "aggregate_key_error_polynomial_sha256":observer::hash_words(&errors[j]),
            "aggregate_key_error_max_abs_centered":errors[j].iter().map(|&x|(x as i64).unsigned_abs()).max(),
            "key_error_definition":"phase(PFKS(delta))-(phase(delta)+rho_delta)*W0=-sum(d_delta*eta_window)",
            "primitive_row_errors_independently_measured":false,"independent_noise_assumed":false}),
        );
    }
    let words_ok = (0..GLWE_SIZE).all(|component| {
        (0..POLYNOMIAL_SIZE).all(|coeff| {
            let sum = (0..OUTPUTS).fold(0u64, |sum, t| {
                sum.wrapping_add(shifted(
                    &trace.pfks[t].as_ref()
                        [component * POLYNOMIAL_SIZE..(component + 1) * POLYNOMIAL_SIZE],
                    coeff as isize,
                    t,
                ))
            });
            sum == trace.pre_br.as_ref()[component * POLYNOMIAL_SIZE + coeff]
        })
    });
    pass &= words_ok;
    let effective = effective_rotation_degree(control, small_secret);
    let degree_error = centered_degree_error(effective, fixture.control as usize * BOX_SIZE);
    let body_ms = pbs_modulus_switch(*control.get_body().data, PolynomialSize(POLYNOMIAL_SIZE))
        % (2 * POLYNOMIAL_SIZE);
    let mask_ms: Vec<_> = control
        .get_mask()
        .as_ref()
        .iter()
        .map(|&a| pbs_modulus_switch(a, PolynomialSize(POLYNOMIAL_SIZE)) % (2 * POLYNOMIAL_SIZE))
        .collect();
    let mask_ms_sum = mask_ms
        .iter()
        .zip(small_secret.as_ref())
        .fold(0usize, |sum, (&a, &s)| {
            (sum + a * s as usize) % (2 * POLYNOMIAL_SIZE)
        });
    let control_phase = decrypt_lwe_ciphertext(small_secret, control).0;
    let input_control_phase = decrypt_lwe_ciphertext(&big, input_control).0;
    emit(json!({"record":"d1_accumulator", "fixture":fixture.name,
        "pre_br_sha256":observer::hash_words(trace.pre_br.as_ref()),
        "pre_br_phase_sha256":observer::hash_words(&pre_br_phase),
        "exact_all_words_assembly_pass":words_ok,"control_words":control.as_ref(),
        "control_sha256":hash_lwe(control),"input_control_sha256":hash_lwe(input_control),
        "input_control_phase":input_control_phase,"post_ks_control_phase":control_phase,
        "actual_ks_aggregate_error":control_phase.wrapping_sub(input_control_phase) as i64,
        "modulus_switched_body":body_ms,"modulus_switched_masks":mask_ms,
        "secret_weighted_modulus_switched_mask_sum":mask_ms_sum,
        "actual_effective_rotation_degree":effective,"actual_effective_rotation_error":degree_error,
        "rounded_phase_degree_diagnostic":modulus_switch_degree(control_phase),
        "support_ok":degree_error.abs()<=STRICT_RADIUS,
        "client_aggregate_key_membership_attested":false,"timing_interpretation_allowed":false}));
    for lane in 0..OUTPUTS {
        let degree = (effective + lane * BOX_SIZE) as isize;
        let mut ideal_correction = 0u64;
        let mut input_error = 0u64;
        let mut rho = 0u64;
        let mut key_error = 0u64;
        let mut exact_pre_br = 0u64;
        let mut contributions = Vec::new();
        for t in 0..OUTPUTS {
            let weight = shifted(function.as_ref(), degree, t);
            ideal_correction = ideal_correction.wrapping_add(messages[t].wrapping_mul(weight));
            input_error = input_error.wrapping_add(obs[t].error.wrapping_mul(weight));
            rho = rho.wrapping_add((obs[t].rho as u64).wrapping_mul(weight));
            let term_key = shifted(&errors[t], degree, t);
            let term_exact = shifted(&phases[t], degree, t);
            key_error = key_error.wrapping_add(term_key);
            exact_pre_br = exact_pre_br.wrapping_add(term_exact);
            contributions.push(json!({"term":t,"message_window_weight":weight as i64,
                "aggregate_key_error_contribution":term_key as i64,
                "exact_pfks_phase_contribution":term_exact}));
        }
        let actual_pre_br = at(&pre_br_phase, degree);
        let raw_phase = decrypt_lwe_ciphertext(&big, &trace.corrections[lane]).0;
        let output_phase = decrypt_lwe_ciphertext(&big, &outputs[lane]).0;
        let expected = fixture.expected()[lane].wrapping_mul(PAYLOAD_DELTAS[lane]);
        let ideal_final = left_messages[lane].wrapping_add(ideal_correction);
        let support_error = ideal_final.wrapping_sub(expected);
        let assembly = actual_pre_br.wrapping_sub(exact_pre_br);
        let br = raw_phase.wrapping_sub(actual_pre_br);
        let addback = output_phase
            .wrapping_sub(raw_phase)
            .wrapping_sub(lobs[lane].phase);
        let error = output_phase.wrapping_sub(expected);
        let terms = [
            support_error,
            input_error,
            rho,
            key_error,
            assembly,
            br,
            lobs[lane].error,
            addback,
        ];
        let addback_words = outputs[lane]
            .as_ref()
            .iter()
            .zip(trace.corrections[lane].as_ref())
            .zip(left[lane].as_ref())
            .all(|((&out, &raw), &l)| out == raw.wrapping_add(l));
        let identity = terms.iter().fold(0u64, |sum, &x| sum.wrapping_add(x)) == error
            && ideal_correction
                .wrapping_add(input_error)
                .wrapping_add(rho)
                .wrapping_add(key_error)
                == exact_pre_br
            && assembly == 0
            && addback == 0
            && addback_words;
        pass &= identity;
        emit(
            json!({"record":"d1_noise_lane","fixture":fixture.name,"lane":lane,
            "delta":PAYLOAD_DELTAS[lane],"expected_phase":expected,"actual_pre_br_virtual_degree":degree,
            "ideal_correction":ideal_correction,"ideal_final":ideal_final,
            "exact_pre_br_phase_reconstructed":exact_pre_br,"actual_pre_br_phase":actual_pre_br,
            "raw_correction_phase":raw_phase,"left_phase":lobs[lane].phase,"output_phase":output_phase,
            "raw_correction_words":trace.corrections[lane].as_ref(),"output_words":outputs[lane].as_ref(),
            "raw_correction_sha256":hash_lwe(&trace.corrections[lane]),"output_sha256":hash_lwe(&outputs[lane]),
            "support_message_residual":support_error as i64,"transmitted_difference_error":input_error as i64,
            "transmitted_difference_rho":rho as i64,"aggregate_pfks_key_error":key_error as i64,
            "exact_assembly_residual":assembly as i64,"br_and_numeric_residual":br as i64,
            "left_addback_input_error":lobs[lane].error as i64,"addback_arithmetic_residual":addback as i64,
            "semantic_error":error as i64,"closure_pass":identity,"addback_all_words_pass":addback_words,
            "centered_terms_unwrapped_sum_decimal":terms.iter().map(|&x|x as i64 as i128).sum::<i128>().to_string(),
            "term_contributions":contributions,"strict_half_slot_pass":(error as i64).unsigned_abs()<PAYLOAD_DELTAS[lane]/2,
            "p_fail_proven":false,"left_and_difference_errors_independent":false,
            "key_error_scope":"same window-key rows, aggregate inferred, not rowwise measured",
            "native_difference_decode_is_not_a_consumer_gate":true}),
        );
    }
    pass
}
