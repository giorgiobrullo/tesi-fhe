//! Client-only decomposition of two existing packed D2 arms. No server crypto calls.
//! All arithmetic identities are modulo 2^64; centered representatives are diagnostics.
use super::*;

pub(super) struct PackedTrace {
    pub pfks_outputs: Vec<Glwe>,
    pub pre_br_accumulator: Glwe,
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn hash_words(words: &[u64]) -> String {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    format!("{:x}", hasher.finalize())
}

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

fn center(term: usize) -> isize {
    let branch = if term < OUTPUTS {
        LEFT_CONTROL
    } else {
        RIGHT_CONTROL
    };
    (branch as usize * BOX_SIZE + term % OUTPUTS * BOX_SIZE) as isize
}

fn spread_at(poly: &[u64], degree: isize, term: usize, direct: bool) -> u64 {
    let shifted = degree - center(term);
    if direct {
        at(poly, shifted)
    } else {
        (-STRICT_RADIUS..=STRICT_RADIUS).fold(0u64, |sum, offset| {
            sum.wrapping_add(at(poly, shifted - offset))
        })
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

fn public_statistics(
    inputs: &[InputObservation],
    direct: bool,
    support_ok: bool,
) -> serde_json::Value {
    let digit_gram: Vec<Vec<i128>> = inputs
        .iter()
        .map(|a| {
            inputs
                .iter()
                .map(|b| {
                    assert_eq!(a.digits.len(), b.digits.len());
                    a.digits
                        .iter()
                        .zip(&b.digits)
                        .map(|(&x, &y)| x as i128 * y as i128)
                        .sum()
                })
                .collect()
        })
        .collect();
    let factor = if direct { 1i128 } else { 127i128 };
    let l1: i128 = inputs
        .iter()
        .flat_map(|a| &a.digits)
        .map(|&d| (d as i128).abs())
        .sum();
    let l2: i128 = (0..PACKED_TERMS).map(|t| digit_gram[t][t]).sum();
    // A134 factorization is only asserted in its supported fixed-control domain.
    let output_gram = if support_ok {
        Some(
            (0..OUTPUTS)
                .map(|a| {
                    (0..OUTPUTS)
                        .map(|b| {
                            let shift = a.abs_diff(b);
                            let mut value = 0i128;
                            for branch in [0, OUTPUTS] {
                                for lane in 0..OUTPUTS - shift {
                                    value += digit_gram[branch + lane][branch + lane + shift];
                                }
                            }
                            (factor * value).to_string()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    json!({
        "row_order": "all mask rows then body; identical across eight ciphertexts",
        "actual_level_order": inputs[0].levels,
        "rows_per_input": inputs[0].digits.len() / inputs[0].levels.len(),
        "body_row_retained": true,
        "digit_gram_decimal": digit_gram.iter().map(|row| row.iter().map(ToString::to_string).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "factorized_supported_domain": support_ok,
        "per_output_key_error_l1_decimal": if support_ok {Some((factor*l1).to_string())} else {None},
        "per_output_key_error_squared_l2_decimal": if support_ok {Some((factor*l2).to_string())} else {None},
        "four_output_key_error_gram_decimal": output_gram,
        "interpretation": "public coefficients of aggregate primitive-key errors; not observed covariance",
        "primitive_row_errors_independently_measured": false,
        "independence_or_tail_certified": false
    })
}

/// Pure ciphertext arithmetic checks that the retained direct accumulator is the
/// exact sum of eight monomial-shifted snapshots, including every mask and body.
fn direct_words_equal(trace: &PackedTrace) -> bool {
    let n = POLYNOMIAL_SIZE;
    (0..GLWE_SIZE).all(|component| {
        (0..n).all(|coefficient| {
            let expected = trace
                .pfks_outputs
                .iter()
                .enumerate()
                .fold(0u64, |sum, (term, ct)| {
                    let poly = &ct.as_ref()[component * n..(component + 1) * n];
                    sum.wrapping_add(at(poly, coefficient as isize - center(term)))
                });
            expected == trace.pre_br_accumulator.as_ref()[component * n + coefficient]
        })
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn observe_arm(
    arm: &str,
    direct: bool,
    fixture: Fixture,
    left: &[Lwe],
    right: &[Lwe],
    input_control: &Lwe,
    switched_control: &Lwe,
    outputs: &[Lwe; OUTPUTS],
    trace: &PackedTrace,
    glwe_secret: &GlweSecretKeyOwned<u64>,
    small_secret: &LweSecretKeyView<'_, u64>,
    parameters: PfksParameters,
) -> bool {
    assert_eq!(trace.pfks_outputs.len(), PACKED_TERMS);
    let big_secret = glwe_secret.as_lwe_secret_key();
    let inputs: Vec<_> = left.iter().chain(right).collect();
    let messages: Vec<_> = fixture
        .left
        .iter()
        .chain(&fixture.right)
        .enumerate()
        .map(|(t, &m)| m.wrapping_mul(PAYLOAD_DELTAS[t % OUTPUTS]))
        .collect();
    let observations: Vec<_> = inputs
        .iter()
        .zip(&messages)
        .map(|(input, &m)| input_observation(input, &big_secret, m, parameters))
        .collect();
    let pfks_phases: Vec<_> = trace
        .pfks_outputs
        .iter()
        .map(|ct| glwe_phase(glwe_secret, ct))
        .collect();
    let mut function = vec![0u64; POLYNOMIAL_SIZE];
    if direct {
        function.copy_from_slice(signed_cell_mask(PolynomialSize(POLYNOMIAL_SIZE), 0).as_ref());
    } else {
        // A127's f=-identity and polynomial=-1 jointly implement F=1.
        function[0] = 1;
    }
    let aggregate_key_errors: Vec<Vec<u64>> = pfks_phases
        .iter()
        .zip(&observations)
        .map(|(phase, input)| {
            phase
                .iter()
                .zip(&function)
                .map(|(&actual, &f)| actual.wrapping_sub(input.rounded_phase.wrapping_mul(f)))
                .collect()
        })
        .collect();
    let pre_br_phase = glwe_phase(glwe_secret, &trace.pre_br_accumulator);
    let effective_degree = effective_rotation_degree(switched_control, small_secret);
    let error = centered_degree_error(effective_degree, fixture.control as usize * BOX_SIZE);
    let support_ok = error.abs() <= STRICT_RADIUS;
    let input_control_phase = decrypt_lwe_ciphertext(&big_secret, input_control).0;
    let switched_phase = decrypt_lwe_ciphertext(small_secret, switched_control).0;
    let body_degree = pbs_modulus_switch(
        *switched_control.get_body().data,
        PolynomialSize(POLYNOMIAL_SIZE),
    ) % (2 * POLYNOMIAL_SIZE);
    let mask_degree = switched_control
        .get_mask()
        .as_ref()
        .iter()
        .zip(small_secret.as_ref())
        .fold(0usize, |sum, (&a, &s)| {
            (sum + pbs_modulus_switch(a, PolynomialSize(POLYNOMIAL_SIZE)) * s as usize)
                % (2 * POLYNOMIAL_SIZE)
        });
    let mut identity_pass = !direct || direct_words_equal(trace);
    let function_hash = hash_words(&function);
    for term in 0..PACKED_TERMS {
        let input = &observations[term];
        let max_error = aggregate_key_errors[term]
            .iter()
            .map(|&x| (x as i64).unsigned_abs())
            .max()
            .unwrap();
        emit(json!({
            "record": "pfks_witness", "fixture": fixture.name, "arm": arm, "term": term,
            "producer": format!("{}/{}/pfks/{}", fixture.name, arm, term),
            "key_family": if direct {"window"} else {"constant"},
            "function_sha256": function_hash, "input_sha256": hash_lwe(inputs[term]),
            "pfks_output_sha256": hash_words(trace.pfks_outputs[term].as_ref()),
            "input_message_phase": messages[term], "input_phase": input.phase,
            "input_error": input.error as i64, "rounding_rho_decimal": input.rho.to_string(),
            "rounded_input_phase": input.rounded_phase,
            "phase_polynomial_sha256": hash_words(&pfks_phases[term]),
            "aggregate_key_error_polynomial_sha256": hash_words(&aggregate_key_errors[term]),
            "aggregate_key_error_max_abs_centered": max_error,
            "actual_body_row_digits": input.body_digits, "actual_level_order": input.levels,
            "public_digit_words_sha256": hash_words(&input.digits.iter().map(|&x| x as u64).collect::<Vec<_>>()),
            "key_error_definition": "phase(PFKS) - (phase(input)+rho)*F = -sum(digit*eta)",
            "primitive_row_errors_independently_measured": false
        }));
    }
    emit(json!({
        "record": "accumulator_witness", "fixture": fixture.name, "arm": arm,
        "pre_br_ciphertext_sha256": hash_words(trace.pre_br_accumulator.as_ref()),
        "pre_br_phase_polynomial_sha256": hash_words(&pre_br_phase),
        "post_ks_control_sha256": hash_lwe(switched_control),
        "input_control_sha256": hash_lwe(input_control),
        "input_control_phase": input_control_phase, "post_ks_control_phase": switched_phase,
        "actual_ks_aggregate_error": switched_phase.wrapping_sub(input_control_phase) as i64,
        "modulus_switched_body": body_degree, "secret_weighted_modulus_switched_mask_sum": mask_degree,
        "actual_effective_rotation_degree": effective_degree, "actual_effective_rotation_error": error,
        "rounded_phase_degree_diagnostic": modulus_switch_degree(switched_phase),
        "support_ok": support_ok, "direct_all_ciphertext_words_equal": if direct {Some(identity_pass)} else {None},
        "public_key_error_statistics": public_statistics(&observations, direct, support_ok),
        "diagnostics_after_all_arm_timers": true, "contains_secret_derived_observations": true,
        "not_independent_execution_attestation": true
    }));
    for lane in 0..OUTPUTS {
        // Stock BR applies X^(-body_ms + sum(mask_ms*s)); extracting degree k
        // reads pre-BR degree effective_degree+k, with negacyclic signs intact.
        let degree = (effective_degree + lane * BOX_SIZE) as isize;
        let mut ideal = 0u64;
        let mut input_error = 0u64;
        let mut rho = 0u64;
        let mut key_error = 0u64;
        let mut exact_pre_br = 0u64;
        let mut per_term = Vec::new();
        for term in 0..PACKED_TERMS {
            let weight = spread_at(&function, degree, term, direct);
            ideal = ideal.wrapping_add(messages[term].wrapping_mul(weight));
            input_error = input_error.wrapping_add(observations[term].error.wrapping_mul(weight));
            rho = rho.wrapping_add((observations[term].rho as u64).wrapping_mul(weight));
            let term_key = spread_at(&aggregate_key_errors[term], degree, term, direct);
            key_error = key_error.wrapping_add(term_key);
            let term_exact = spread_at(&pfks_phases[term], degree, term, direct);
            exact_pre_br = exact_pre_br.wrapping_add(term_exact);
            per_term.push(json!({"term":term, "message_window_weight":weight as i64,
                "aggregate_key_error_contribution":term_key as i64,
                "exact_pfks_phase_contribution":term_exact}));
        }
        let actual_pre_br = at(&pre_br_phase, degree);
        let fft_residual = actual_pre_br.wrapping_sub(exact_pre_br);
        let output_phase = decrypt_lwe_ciphertext(&big_secret, &outputs[lane]).0;
        let br_residual = output_phase.wrapping_sub(actual_pre_br);
        let expected_phase = fixture.expected()[lane].wrapping_mul(PAYLOAD_DELTAS[lane]);
        let support_residual = ideal.wrapping_sub(expected_phase);
        let semantic_error = output_phase.wrapping_sub(expected_phase);
        let terms = [
            support_residual,
            input_error,
            rho,
            key_error,
            fft_residual,
            br_residual,
        ];
        let sum = terms.iter().fold(0u64, |sum, &term| sum.wrapping_add(term));
        let exact_decomposition = ideal
            .wrapping_add(input_error)
            .wrapping_add(rho)
            .wrapping_add(key_error)
            == exact_pre_br;
        let pass = sum == semantic_error && exact_decomposition && (!direct || fft_residual == 0);
        identity_pass &= pass;
        emit(json!({
            "record":"noise_lane", "fixture":fixture.name, "arm":arm, "lane":lane,
            "sample_degree":lane*BOX_SIZE, "actual_pre_br_virtual_degree":degree,
            "output_sha256":hash_lwe(&outputs[lane]), "delta":PAYLOAD_DELTAS[lane],
            "expected_phase":expected_phase, "ideal_body_at_actual_degree":ideal,
            "exact_pre_br_phase_reconstructed":exact_pre_br, "actual_pre_br_phase":actual_pre_br,
            "actual_output_phase":output_phase, "support_ok":support_ok,
            "support_message_residual":support_residual as i64,
            "transmitted_input_error":input_error as i64, "transmitted_rounding_rho":rho as i64,
            "aggregate_pfks_key_error":key_error as i64,
            "aggregate_fft_phase_residual":fft_residual as i64,
            "br_and_numeric_residual":br_residual as i64,
            "semantic_error":semantic_error as i64,
            "centered_terms_unwrapped_sum_decimal":terms.iter().map(|&x| x as i64 as i128).sum::<i128>().to_string(),
            "closure_modulus_bits":64, "closure_pass":pass,
            "strict_half_slot_pass":(semantic_error as i64).unsigned_abs() < PAYLOAD_DELTAS[lane]/2,
            "margin_to_half_slot_decimal":(PAYLOAD_DELTAS[lane] as i128/2 - (semantic_error as i64).unsigned_abs() as i128).to_string(),
            "term_contributions":per_term,
            "error_scale": "signed torus words; divide by this lane's Delta for slots",
            "pfks_error_scope":"measured aggregate, not primitive-key-row tail",
            "fft_error_scope":"phase residual after exact integer reconstruction; constant family only",
            "br_error_scope":"actual output minus ideal rotation of retained noisy accumulator",
            "p_fail_proven":false, "performance_interpretation_allowed":false
        }));
    }
    identity_pass
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_and_second_cycle_coefficients_keep_signs() {
        let p = [2u64, 3, 5, 7];
        assert_eq!(at(&p, -1), 7u64.wrapping_neg());
        assert_eq!(at(&p, 4), 2u64.wrapping_neg());
        assert_eq!(at(&p, 8), 2);
    }
}
