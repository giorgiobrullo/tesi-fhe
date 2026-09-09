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

fn input_json(ct: &Lwe, message: u64, input: &InputObservation) -> serde_json::Value {
    json!({"words":ct.as_ref(),"sha256":hash_lwe(ct),"message_phase":message,
        "phase":input.phase,"error":input.error as i64,
        "rho_decimal":input.rho.to_string(),"rounded_phase":input.rounded_phase,
        "digits":input.digits,"levels":input.levels,"body_digits":input.body_digits})
}

#[derive(Default)]
pub(super) struct Metrics {
    pub pfks: usize,
    pub ks: usize,
    pub br: usize,
    pub samples: usize,
    pub monomial_calls: usize,
    pub nonidentity_monomial_calls: usize,
    pub polynomial_permutation_calls: usize,
    pub glwe_additions: usize,
    pub lwe_subtractions: usize,
    pub lwe_addbacks: usize,
    pub public_centering_calls: usize,
    pub public_centering_mask_terms: usize,
    pub public_centering_body_additions: usize,
}

impl Metrics {
    pub fn pass(&self) -> bool {
        (self.pfks,self.ks,self.br,self.samples,self.monomial_calls,self.nonidentity_monomial_calls,
            self.polynomial_permutation_calls,self.glwe_additions,self.lwe_subtractions,self.lwe_addbacks)
            == (5,1,2,5,5,3,10,3,5,5)
            && (self.public_centering_calls,self.public_centering_mask_terms,self.public_centering_body_additions)==(1,859,1)
    }
    pub fn json(&self) -> serde_json::Value {
        json!({"br":3+self.br,"ks":3+self.ks,"pfks":self.pfks,"marginals":3+self.samples,
            "gadget_levels":3+self.br,"input_lwe_encryptions":0,
            "monomial_calls":self.monomial_calls,"nonidentity_monomial_calls":self.nonidentity_monomial_calls,
            "polynomial_permutation_calls":self.polynomial_permutation_calls,"glwe_additions":self.glwe_additions,
            "lwe_subtractions":self.lwe_subtractions,"lwe_addbacks":self.lwe_addbacks,
            "public_centering_calls":self.public_centering_calls,"public_centering_mask_terms":self.public_centering_mask_terms,
            "public_centering_body_additions":self.public_centering_body_additions,"correction_extractions":self.samples})
    }
}

pub(super) struct Trace {
    uncorrected_control: Lwe,
    stock_correction: u64,
    mean_correction: u64,
    differences: Vec<Lwe>,
    pfks: Vec<Glwe>,
    pre_br: Vec<Glwe>,
    post_br: Vec<Glwe>,
    controls_before: Vec<Lwe>,
    controls_after: Vec<Lwe>,
    corrections: [Lwe;OUTPUTS],
}

pub(super) struct Selection {
    pub output: [Lwe;OUTPUTS],
    pub control: Lwe,
    pub metrics: Metrics,
    pub trace: Trace,
}

pub(super) fn window() -> Poly {
    let mut values=vec![0u64;POLYNOMIAL_SIZE];
    for combined in 1..=7 {
        for error in -20isize..=20 {
            values[(128*combined-64+error) as usize]=1;
        }
    }
    Polynomial::from_container(values)
}

pub(super) fn select(
    left: &[Lwe],right: &[Lwe],combined: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,bsk: &FourierLweBootstrapKeyOwned,
) -> Selection {
    assert_eq!(left.len(),OUTPUTS);assert_eq!(right.len(),OUTPUTS);
    let modulus=combined.ciphertext_modulus();
    let mut metrics=Metrics::default();
    // Exactly one ordinary KS. Both dynamic rotations borrow this same retained object.
    let mut control=Lwe::new(0u64,ksk.output_key_lwe_dimension().to_lwe_size(),modulus);
    keyswitch_lwe_ciphertext(ksk,combined,&mut control);metrics.ks+=1;
    let centered=mean_center::apply(control);
    metrics.public_centering_calls+=1;
    metrics.public_centering_mask_terms+=centered.original.get_mask().as_ref().len();
    metrics.public_centering_body_additions+=1;
    let mean_center::Centered {original:uncorrected_control,corrected:control,stock_correction,mean_correction}=centered;
    let mut differences=Vec::with_capacity(OUTPUTS);
    let mut pfks=Vec::with_capacity(OUTPUTS);
    for lane in 0..OUTPUTS {
        let mut difference=right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference,&left[lane]);metrics.lwe_subtractions+=1;
        let mut term=Glwe::new(0u64,window_key.output_glwe_size(),window_key.output_polynomial_size(),modulus);
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(window_key,&mut term,&difference);
        metrics.pfks+=1;differences.push(difference);pfks.push(term);
    }
    let mut pre_br=Vec::with_capacity(2);let mut post_br=Vec::with_capacity(2);
    let mut controls_before=Vec::with_capacity(2);let mut controls_after=Vec::with_capacity(2);
    let mut corrections:Vec<Lwe>=Vec::with_capacity(OUTPUTS);
    for (group,offsets) in GROUPS.into_iter().zip(OFFSETS) {
        let mut accumulator:Option<Glwe>=None;
        for (&lane,&offset) in group.iter().zip(offsets) {
            let mut term=pfks[lane].clone();
            for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(&mut polynomial,MonomialDegree(offset));
                metrics.polynomial_permutation_calls+=1;
            }
            metrics.monomial_calls+=1;
            metrics.nonidentity_monomial_calls+=usize::from(offset!=0);
            if let Some(acc)=accumulator.as_mut() {
                for (word,value) in acc.as_mut().iter_mut().zip(term.as_ref()) {*word=word.wrapping_add(*value);}
                metrics.glwe_additions+=1;
            } else {accumulator=Some(term);}
        }
        let mut accumulator=accumulator.unwrap();pre_br.push(accumulator.clone());
        controls_before.push(control.clone());
        blind_rotate_assign(&control,&mut accumulator,bsk);metrics.br+=1;
        controls_after.push(control.clone());post_br.push(accumulator.clone());
        for &offset in offsets {
            let mut output=Lwe::new(0u64,bsk.output_lwe_dimension().to_lwe_size(),modulus);
            extract_lwe_sample_from_glwe_ciphertext(&accumulator,&mut output,MonomialDegree(offset));
            metrics.samples+=1;corrections.push(output);
        }
    }
    let corrections:[Lwe;OUTPUTS]=corrections.try_into().unwrap();
    let output=std::array::from_fn(|lane| {
        let mut output=corrections[lane].clone();
        lwe_ciphertext_add_assign(&mut output,&left[lane]);metrics.lwe_addbacks+=1;output
    });
    Selection {output,control,metrics,trace:Trace {uncorrected_control,stock_correction,mean_correction,differences,pfks,pre_br,post_br,controls_before,controls_after,corrections}}
}

include!("split32_observer.rs");
