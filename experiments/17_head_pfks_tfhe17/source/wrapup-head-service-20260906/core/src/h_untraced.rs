//! Exact five-payload D1 arithmetic; indexed outer scheduling and a direct selected-digit wire.
use super::*;
use rayon::prelude::*;
fn pbs(input: Lwe, final_control: bool, sk: &ServerKey) -> Lwe {
    let bsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("A191 requires the pinned classic Fourier BSK"),
    };
    let mut small = LweCiphertext::new(
        0u64,
        sk.key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size(),
        input.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext(&sk.key_switching_key, &input, &mut small);
    let body = comparator::body(final_control);
    let mut accumulator = GlweCiphertext::new(
        0u64,
        GlweSize(2),
        PolynomialSize(2048),
        input.ciphertext_modulus(),
    );
    accumulator.get_mut_body().as_mut().copy_from_slice(&body);
    // This exact retained small object is borrowed by stock BR; no phase proxy.
    blind_rotate_assign(&small, &mut accumulator, bsk);
    let mut raw = LweCiphertext::new(
        0u64,
        bsk.output_lwe_dimension().to_lwe_size(),
        input.ciphertext_modulus(),
    );
    extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut raw, MonomialDegree(0));
    let mut output = raw;
    if final_control {
        *output.get_mut_body().data = output.get_body().data.wrapping_add(8 * SCORE_DELTA);
    }
    output
}

fn compare(left: &[Lwe], right: &[Lwe], sk: &ServerKey) -> Lwe {
    assert_eq!(left.len(), 4);
    assert_eq!(right.len(), 4);
    let mut stages = Vec::with_capacity(4);
    for j in 0..3 {
        let mut difference = left[j].clone();
        for (word, r) in difference.as_mut().iter_mut().zip(right[j].as_ref()) {
            *word = word.wrapping_sub(*r);
        }
        stages.push(pbs(difference, false, sk));
    }
    let mut combined = stages[0].clone();
    for (i, word) in combined.as_mut().iter_mut().enumerate() {
        *word = stages[0].as_ref()[i]
            .wrapping_mul(4)
            .wrapping_add(stages[1].as_ref()[i].wrapping_mul(2))
            .wrapping_add(stages[2].as_ref()[i]);
    }
    *combined.get_mut_body().data = combined.get_body().data.wrapping_sub(SCORE_DELTA / 2);
    pbs(combined, true, sk)
}

fn select(
    left: &[Lwe],
    right: &[Lwe],
    encrypted_control: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe; OUTPUTS], hd1::Metrics) {
    assert_eq!(left.len(), OUTPUTS);
    assert_eq!(right.len(), OUTPUTS);
    let modulus = encrypted_control.ciphertext_modulus();
    let mut metrics = hd1::Metrics::default();
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
    (outputs, metrics)
}


#[derive(Default, Clone, Copy)]
pub(super) struct Counts {
    pub br: u64, pub ks: u64, pub pfks: u64, pub samples: u64,
    pub score_samples: u64, pub levels: u64, pub scales: u64,
    pub rotations: u64, pub polynomial_permutations: u64,
    pub glwe_additions: u64, pub lwe_subtractions: u64, pub lwe_addbacks: u64,
    pub centering_calls:u64, pub centering_mask_terms:u64, pub centering_body_additions:u64,
}
impl Counts {
    pub fn json(&self) -> serde_json::Value {
        json!({"br":self.br,"ks":self.ks,"pfks":self.pfks,"marginals":self.samples,
            "gadget_levels":self.levels,"initial_score_samples":self.score_samples,
            "prototype_full51_to_full52_scales":self.scales,
            "pfks_monomial_rotations":self.rotations,"polynomial_permutations":self.polynomial_permutations,
            "glwe_additions":self.glwe_additions,"lwe_subtractions":self.lwe_subtractions,"lwe_addbacks":self.lwe_addbacks,
            "public_centering_calls":self.centering_calls,"public_centering_mask_terms":self.centering_mask_terms,
            "public_centering_body_additions":self.centering_body_additions})
    }
    fn merge(&mut self, m: &hd1::Metrics) {
        assert!(m.pass());
        self.br += 4 + m.br as u64; self.ks += 4 + m.ks as u64;
        self.samples += 4 + m.samples as u64; self.pfks += m.pfks as u64;
        self.levels += 4 + m.br as u64;
        self.rotations += m.rotations as u64; self.polynomial_permutations += m.polynomial_permutations as u64;
        self.glwe_additions += m.glwe_additions as u64;
        self.lwe_subtractions += m.lwe_subtractions as u64; self.lwe_addbacks += m.lwe_addbacks as u64;
    }
    pub fn check(&self) {
        let expected = (1397,1143,635,1905,1651,127,0);
        assert_eq!((self.centering_calls,self.centering_mask_terms,self.centering_body_additions),(0,0,0));
        assert_eq!((self.br,self.ks,self.pfks,self.samples,self.levels,self.score_samples,self.scales),expected);
        assert_eq!((self.rotations,self.polynomial_permutations,self.glwe_additions,self.lwe_subtractions,self.lwe_addbacks),
            (635,1270,508,635,635));
    }
}
pub(super) struct Output { pub digits: [Lwe;2], pub counts: Counts }
pub(super) struct Bridge { pub tuples: Vec<[Lwe;OUTPUTS]>, pub counts: Counts }
pub(super) struct TupleOutput { pub tuple: [Lwe;OUTPUTS], pub counts: Counts }
pub(super) struct Diagnostic { pub leaves: Vec<[Lwe;OUTPUTS]>, pub selected: TupleOutput }

fn checked_domain(templates: &[private_argmin::TemplateView<'_>]) -> private_argmin::ScoreDomain {
    let plan=crate::general::plan(templates).unwrap();
    plan.execution_domain
}

// One unchanged full51-only packed prefix, followed by the untraced direct-Delta59 Head.
pub(super) fn hybrid_bridge(
    server: &ServerKey, packed: &Glwe, templates: &[private_argmin::TemplateView<'_>],
    head: &wide::Keys<'_>, normalizer: &wide::Keys<'_>, parallel: bool,
) -> Bridge {
    let domain=checked_domain(templates);
    let scores=private_argmin::head_pfks_score_prefix(server,packed,templates,domain).unwrap();
    let produce=|(index,score): (usize,Lwe)| {
        let [low,middle,top]=split::ingress(&score,head,normalizer);
        let identity=(index+1) as u64;
        let digit=|value| allocate_and_trivially_encrypt_new_lwe_ciphertext(
            LweSize(2049),Plaintext(value*SCORE_DELTA),packed.ciphertext_modulus());
        [top,middle,low,digit(identity%15),digit(identity/15)]
    };
    let tuples=if parallel { scores.into_par_iter().enumerate().map(produce).collect() }
        else { scores.into_iter().enumerate().map(produce).collect() };
    Bridge {tuples,counts:Counts {br:762,ks:508,samples:762,levels:1016,score_samples:127,..Counts::default()}}
}

// Identical indexed odd-tail tree and sentinel arithmetic for either producer.
fn tree<F>(mut bridge: Bridge, bsk: &FourierLweBootstrapKeyOwned, modulus: CiphertextModulus<u64>, parallel: bool, merge: F) -> TupleOutput
where F: Fn(&[[Lwe;OUTPUTS]]) -> ([Lwe;OUTPUTS],hd1::Metrics) + Sync {
    let mut current=bridge.tuples;
    while current.len()>1 {
        let completed:Vec<_>=if parallel { current.par_chunks_exact(2).map(&merge).collect() }
            else { current.chunks_exact(2).map(&merge).collect() };
        let carried=if current.len()%2==1 {Some(current.last().unwrap().clone())} else {None};
        current=completed.into_iter().map(|(out,m)|{bridge.counts.merge(&m);out}).collect();
        if let Some(tail)=carried {current.push(tail);}
    }
    let sentinel=std::array::from_fn(|j| allocate_and_trivially_encrypt_new_lwe_ciphertext(
        bsk.output_lwe_dimension().to_lwe_size(),Plaintext([4,0,0,0,0][j]*PAYLOAD_DELTAS[j]),modulus));
    let (tuple,m)=merge(&[sentinel,current.pop().unwrap()]);bridge.counts.merge(&m);
    TupleOutput {tuple,counts:bridge.counts}
}

pub(super) fn reduce(
    server: &ServerKey, window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    bridge: Bridge, parallel: bool,
) -> TupleOutput {
    let ShortintBootstrappingKey::Classic(bsk)=&server.bootstrapping_key;
    let modulus=bridge.tuples[0][0].ciphertext_modulus();
    tree(bridge,bsk,modulus,parallel,|pair| {
        let control=compare(&pair[0][..4],&pair[1][..4],server);
        select(&pair[0],&pair[1],&control,window,&server.key_switching_key,bsk)
    })
}

// Correctness-only: the original trace-producing comparator/PFKS primitives.
pub(super) fn reduce_traced(
    server: &ServerKey, window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>, bridge: Bridge,
) -> TupleOutput {
    let ShortintBootstrappingKey::Classic(bsk)=&server.bootstrapping_key;
    let modulus=bridge.tuples[0][0].ciphertext_modulus();
    tree(bridge,bsk,modulus,false,|pair| {
        let stages=comparator::evaluate(&pair[0][..4],&pair[1][..4],server);
        let (out,_,metrics,_)=hd1::select(&pair[0],&pair[1],&stages[3].output,window,&server.key_switching_key,bsk);
        (out,metrics)
    })
}

pub(super) fn wire(selected: TupleOutput) -> Output {
    let [top,middle,bottom,low,high]=selected.tuple;
    // Only intermediates and unused score lanes drop inside the endpoint.
    // Returned digit ciphertexts stay alive for postclock observation.
    drop((top,middle,bottom));
    Output {digits:[low,high],counts:selected.counts}
}

pub(super) fn hybrid_endpoint(
    server: &ServerKey, window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    packed: &Glwe, templates: &[private_argmin::TemplateView<'_>], head: &wide::Keys<'_>, normalizer: &wide::Keys<'_>,
) -> Output {
    let bridge=hybrid_bridge(server,packed,templates,head,normalizer,true);
    let result=reduce(server,window,bridge,true);result.counts.check();wire(result)
}

// The preclock caller retains ingress copies; timed functions never call this wrapper.
pub(super) fn diagnostic(
    server: &ServerKey, window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>, bridge: Bridge, parallel: bool,
) -> Diagnostic {
    let leaves=bridge.tuples.clone();
    Diagnostic {leaves,selected:reduce(server,window,bridge,parallel)}
}
