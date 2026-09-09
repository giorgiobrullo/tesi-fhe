//! Exact accepted mean arithmetic with trace retention removed.
use super::*;
use rayon::prelude::*;
use h_untraced::{Bridge,Counts,TupleOutput,Diagnostic,Output};
use crate::general::ThresholdMode;
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
    let mut stages = Vec::with_capacity(3);
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
    combined
}

pub(super) fn select(
    left: &[Lwe],right: &[Lwe],combined: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe;OUTPUTS],d1::Metrics) {
    assert_eq!(left.len(),OUTPUTS);assert_eq!(right.len(),OUTPUTS);
    let modulus=combined.ciphertext_modulus();
    let mut metrics=d1::Metrics::default();
    // Exactly one ordinary KS. Both dynamic rotations borrow this same retained object.
    let mut control=Lwe::new(0u64,ksk.output_key_lwe_dimension().to_lwe_size(),modulus);
    keyswitch_lwe_ciphertext(ksk,combined,&mut control);metrics.ks+=1;
    let centered=mean_center::apply(control);
    metrics.public_centering_calls+=1;
    metrics.public_centering_mask_terms+=centered.original.get_mask().as_ref().len();
    metrics.public_centering_body_additions+=1;
    let mean_center::Centered {corrected:control,..}=centered;
    let mut pfks=Vec::with_capacity(OUTPUTS);
    for lane in 0..OUTPUTS {
        let mut difference=right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference,&left[lane]);metrics.lwe_subtractions+=1;
        let mut term=Glwe::new(0u64,window_key.output_glwe_size(),window_key.output_polynomial_size(),modulus);
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(window_key,&mut term,&difference);
        metrics.pfks+=1;pfks.push(term);
    }
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
        let mut accumulator=accumulator.unwrap();
        blind_rotate_assign(&control,&mut accumulator,bsk);metrics.br+=1;
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
    (output,metrics)
}

fn add_merge(counts:&mut Counts,metrics:&d1::Metrics) {
    assert!(metrics.pass());
    counts.br+=3+metrics.br as u64;counts.ks+=3+metrics.ks as u64;
    counts.samples+=3+metrics.samples as u64;counts.levels+=3+metrics.br as u64;
    counts.pfks+=metrics.pfks as u64;counts.rotations+=metrics.monomial_calls as u64;
    counts.polynomial_permutations+=metrics.polynomial_permutation_calls as u64;
    counts.glwe_additions+=metrics.glwe_additions as u64;
    counts.lwe_subtractions+=metrics.lwe_subtractions as u64;counts.lwe_addbacks+=metrics.lwe_addbacks as u64;
    counts.centering_calls+=metrics.public_centering_calls as u64;
    counts.centering_mask_terms+=metrics.public_centering_mask_terms as u64;
    counts.centering_body_additions+=metrics.public_centering_body_additions as u64;
}

pub(super) fn check(counts: &Counts, n: usize, mode: ThresholdMode) {
    assert!((1..=crate::general::MAX_GALLERY_SIZE).contains(&n));
    let expected = match mode {
        ThresholdMode::AllReject => Counts::default(),
        ThresholdMode::AllAccept => reached(n, n - 1),
        ThresholdMode::CompareSentinel { .. } => {
            assert!(general::sentinel_payload(mode).is_some());
            reached(n, n)
        }
    };
    assert_eq!(*counts, expected);
}

pub(super) fn reached(n: usize, merges: usize) -> Counts {
    assert!((1..=crate::general::MAX_GALLERY_SIZE).contains(&n));
    assert!(merges <= n);
    let n = n as u64;
    let k = merges as u64;
    Counts {
        br: 6 * n + 5 * k, ks: 4 * n + 4 * k, pfks: 5 * k,
        samples: 6 * n + 8 * k, levels: 8 * n + 5 * k, score_samples: n,
        rotations: 5 * k, polynomial_permutations: 10 * k, glwe_additions: 3 * k,
        lwe_subtractions: 5 * k, lwe_addbacks: 5 * k,
        centering_calls: k, centering_mask_terms: 859 * k, centering_body_additions: k,
        ..Counts::default()
    }
}

fn reduce(server:&ServerKey,window:&LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,mut bridge:Bridge,parallel:bool,mode:ThresholdMode) -> TupleOutput {
    assert_ne!(mode, ThresholdMode::AllReject);
    let ShortintBootstrappingKey::Classic(bsk)=&server.bootstrapping_key;
    let modulus=bridge.tuples[0][0].ciphertext_modulus();
    let merge=|pair:&[[Lwe;OUTPUTS]]| {
        let combined=compare(&pair[0][..4],&pair[1][..4],server);
        select(&pair[0],&pair[1],&combined,window,&server.key_switching_key,bsk)
    };
    let mut current=bridge.tuples;
    while current.len()>1 {
        let completed:Vec<_>=if parallel {current.par_chunks_exact(2).map(&merge).collect()}
            else {current.chunks_exact(2).map(&merge).collect()};
        let carried=if current.len()%2==1 {Some(current.last().unwrap().clone())} else {None};
        current=completed.into_iter().map(|(out,metrics)| {add_merge(&mut bridge.counts,&metrics);out}).collect();
        if let Some(tail)=carried {current.push(tail);}
    }
    let winner = current.pop().unwrap();
    let tuple = if let Some(payload) = general::sentinel_payload(mode) {
        let sentinel=std::array::from_fn(|j|allocate_and_trivially_encrypt_new_lwe_ciphertext(
            bsk.output_lwe_dimension().to_lwe_size(),Plaintext(payload[j]*PAYLOAD_DELTAS[j]),modulus));
        let (tuple,metrics)=merge(&[sentinel,winner]);add_merge(&mut bridge.counts,&metrics);
        tuple
    } else {
        assert_eq!(mode, ThresholdMode::AllAccept);
        winner
    };
    TupleOutput {tuple,counts:bridge.counts}
}

pub(super) fn diagnostic(server:&ServerKey,window:&LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,bridge:Bridge,parallel:bool,mode:ThresholdMode) -> Diagnostic {
    let n = bridge.tuples.len();
    let leaves=bridge.tuples.clone();let selected=reduce(server,window,bridge,parallel,mode);check(&selected.counts, n, mode);
    Diagnostic {leaves,selected}
}

pub(super) fn public_rejection(modulus: CiphertextModulus<u64>) -> Output {
    let digits = std::array::from_fn(|_| allocate_and_trivially_encrypt_new_lwe_ciphertext(
        LweSize(2049), Plaintext(0), modulus));
    Output { digits, counts: Counts::default() }
}

pub(super) fn endpoint(server:&ServerKey,window:&LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,packed:&Glwe,
    templates:&[private_argmin::TemplateView<'_>],head:&wide::Keys<'_>,normalizer:&wide::Keys<'_>, parallel: bool, mode: ThresholdMode) -> Output {
    if mode == ThresholdMode::AllReject {
        let output = public_rejection(packed.ciphertext_modulus());
        check(&output.counts, templates.len(), mode);
        return output;
    }
    let bridge=h_untraced::hybrid_bridge(server,packed,templates,head,normalizer,parallel);
    let selected=reduce(server,window,bridge,parallel,mode);check(&selected.counts, templates.len(), mode);h_untraced::wire(selected)
}
