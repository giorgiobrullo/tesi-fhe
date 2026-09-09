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
        self.pfks == 5
            && self.rotations == 5
            && self.polynomial_permutations == 10
            && self.glwe_additions == 4
            && self.ks == 1
            && self.br == 1
            && self.samples == 5
            && self.lwe_subtractions == 5
            && self.lwe_addbacks == 5
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
    let mut accumulator = accumulator.expect("five difference payloads");
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
