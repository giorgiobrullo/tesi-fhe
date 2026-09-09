//! Six-payload selected M; three score and three base-15 identity lanes.
use super::*;
use crate::general::ThresholdMode;
use h_untraced::Counts;
use rayon::prelude::*;

pub(super) const OUTPUTS: usize = 6;
const PAYLOAD_DELTAS: [u64; OUTPUTS] = [SCORE_DELTA; OUTPUTS];
pub(super) const GROUPS: [&[usize]; 2] = [&[0, 1, 2], &[3, 4, 5]];
pub(super) const OFFSETS: [&[usize]; 2] = [&[0, 41, 82], &[0, 41, 82]];

pub(super) struct Output {
    pub digits: [Lwe; 3],
    pub counts: Counts,
}
pub(super) struct Bridge {
    pub tuples: Vec<[Lwe; OUTPUTS]>,
    pub counts: Counts,
}
pub(super) struct TupleOutput {
    pub tuple: [Lwe; OUTPUTS],
    pub counts: Counts,
}
pub(super) struct Diagnostic {
    pub leaves: Vec<[Lwe; OUTPUTS]>,
    pub selected: TupleOutput,
}

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
    #[cfg(not(feature = "opt-lut-cache"))]
    let body = comparator::body(final_control);
    #[cfg(feature = "opt-lut-cache")]
    let body = comparator::cached_body(final_control);
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

pub(super) fn compare(left: &[Lwe], right: &[Lwe], sk: &ServerKey) -> Lwe {
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
    left: &[Lwe],
    right: &[Lwe],
    combined: &Lwe,
    window_key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) -> ([Lwe; OUTPUTS], Metrics) {
    assert_eq!(left.len(), OUTPUTS);
    assert_eq!(right.len(), OUTPUTS);
    let modulus = combined.ciphertext_modulus();
    let mut metrics = Metrics::default();
    // Exactly one ordinary KS. Both dynamic rotations borrow this same retained object.
    let mut control = Lwe::new(0u64, ksk.output_key_lwe_dimension().to_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, combined, &mut control);
    metrics.ks += 1;
    let centered = mean_center::apply(control);
    metrics.public_centering_calls += 1;
    metrics.public_centering_mask_terms += centered.original.get_mask().as_ref().len();
    metrics.public_centering_body_additions += 1;
    let mean_center::Centered {
        corrected: control, ..
    } = centered;
    #[cfg(not(feature = "opt-owned-pfks"))]
    let mut pfks = Vec::with_capacity(OUTPUTS);
    #[cfg(feature = "opt-owned-pfks")]
    let mut pfks: [Option<Glwe>; OUTPUTS] = std::array::from_fn(|_| None);
    for lane in 0..OUTPUTS {
        let mut difference = right[lane].clone();
        lwe_ciphertext_sub_assign(&mut difference, &left[lane]);
        metrics.lwe_subtractions += 1;
        let mut term = Glwe::new(
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
        #[cfg(not(feature = "opt-owned-pfks"))]
        pfks.push(term);
        #[cfg(feature = "opt-owned-pfks")]
        {
            pfks[lane] = Some(term);
        }
    }
    let mut corrections: Vec<Lwe> = Vec::with_capacity(OUTPUTS);
    for (group, offsets) in GROUPS.into_iter().zip(OFFSETS) {
        let mut accumulator: Option<Glwe> = None;
        for (&lane, &offset) in group.iter().zip(offsets) {
            #[cfg(not(feature = "opt-owned-pfks"))]
            let mut term = pfks[lane].clone();
            #[cfg(feature = "opt-owned-pfks")]
            let mut term = pfks[lane]
                .take()
                .expect("PFKS groups consume each lane once");
            for mut polynomial in term.as_mut_polynomial_list().iter_mut() {
                polynomial_wrapping_monic_monomial_mul_assign(
                    &mut polynomial,
                    MonomialDegree(offset),
                );
                metrics.polynomial_permutation_calls += 1;
            }
            metrics.monomial_calls += 1;
            metrics.nonidentity_monomial_calls += usize::from(offset != 0);
            if let Some(acc) = accumulator.as_mut() {
                for (word, value) in acc.as_mut().iter_mut().zip(term.as_ref()) {
                    *word = word.wrapping_add(*value);
                }
                metrics.glwe_additions += 1;
            } else {
                accumulator = Some(term);
            }
        }
        let mut accumulator = accumulator.unwrap();
        blind_rotate_assign(&control, &mut accumulator, bsk);
        metrics.br += 1;
        for &offset in offsets {
            let mut output = Lwe::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &accumulator,
                &mut output,
                MonomialDegree(offset),
            );
            metrics.samples += 1;
            corrections.push(output);
        }
    }
    let corrections: [Lwe; OUTPUTS] = corrections.try_into().unwrap();
    #[cfg(feature = "opt-owned-pfks")]
    let mut corrections = corrections.into_iter();
    let output = std::array::from_fn(|lane| {
        #[cfg(not(feature = "opt-owned-pfks"))]
        let mut output = corrections[lane].clone();
        #[cfg(feature = "opt-owned-pfks")]
        let mut output = corrections
            .next()
            .expect("one extracted correction per lane");
        lwe_ciphertext_add_assign(&mut output, &left[lane]);
        metrics.lwe_addbacks += 1;
        output
    });
    (output, metrics)
}

fn add_merge(counts: &mut Counts, metrics: &Metrics) {
    assert!(metrics.pass());
    counts.br += 3 + metrics.br as u64;
    counts.ks += 3 + metrics.ks as u64;
    counts.samples += 3 + metrics.samples as u64;
    counts.levels += 3 + metrics.br as u64;
    counts.pfks += metrics.pfks as u64;
    counts.rotations += metrics.monomial_calls as u64;
    counts.polynomial_permutations += metrics.polynomial_permutation_calls as u64;
    counts.glwe_additions += metrics.glwe_additions as u64;
    counts.lwe_subtractions += metrics.lwe_subtractions as u64;
    counts.lwe_addbacks += metrics.lwe_addbacks as u64;
    counts.centering_calls += metrics.public_centering_calls as u64;
    counts.centering_mask_terms += metrics.public_centering_mask_terms as u64;
    counts.centering_body_additions += metrics.public_centering_body_additions as u64;
}

pub(super) fn check(counts: &Counts, n: usize, mode: ThresholdMode) {
    assert!((1..=crate::general::MAX_GALLERY_SIZE).contains(&n));
    let expected = match mode {
        ThresholdMode::AllReject => Counts::default(),
        ThresholdMode::AllAccept => {
            smallcuts::adjust_counts(reached(n, n - 1), n, n - 1, false, smallcuts::mode())
        }
        ThresholdMode::CompareSentinel { .. } => {
            assert!(sentinel_payload(mode).is_some());
            smallcuts::adjust_counts(reached(n, n), n, n - 1, true, smallcuts::mode())
        }
    };
    assert_eq!(*counts, expected);
}

pub(super) fn reached(n: usize, merges: usize) -> Counts {
    assert!((1..=crate::general::MAX_GALLERY_SIZE).contains(&n));
    assert!(merges <= n);
    let n = n as u64;
    let k = merges as u64;
    let saved = n * shared_normalizers::mode().saved_br_per_score();
    Counts {
        br: 6 * n + 5 * k - saved,
        ks: 4 * n + 4 * k,
        pfks: 6 * k,
        samples: 6 * n + 9 * k,
        levels: 8 * n + 5 * k - saved,
        score_samples: n,
        rotations: 6 * k,
        polynomial_permutations: 12 * k,
        glwe_additions: 4 * k,
        lwe_subtractions: 6 * k,
        lwe_addbacks: 6 * k,
        centering_calls: k,
        centering_mask_terms: 859 * k,
        centering_body_additions: k,
        ..Counts::default()
    }
}

fn reduce(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    mut bridge: Bridge,
    parallel: bool,
    mode: ThresholdMode,
) -> TupleOutput {
    assert_ne!(mode, ThresholdMode::AllReject);
    let n = bridge.tuples.len();
    let cuts = smallcuts::mode();
    let narrow = cuts.narrow_for(n);
    let ShortintBootstrappingKey::Classic(bsk) = &server.bootstrapping_key;
    let modulus = bridge.tuples[0][0].ciphertext_modulus();
    let merge = |pair: &[[Lwe; OUTPUTS]]| {
        let combined = compare(&pair[0][..4], &pair[1][..4], server);
        if narrow {
            smallcuts::select_lanes::<OUTPUTS>(
                &pair[0],
                &pair[1],
                &combined,
                &[smallcuts::SCORE_GROUP, smallcuts::ID_TWO],
                window,
                &server.key_switching_key,
                bsk,
            )
        } else {
            select(
                &pair[0],
                &pair[1],
                &combined,
                window,
                &server.key_switching_key,
                bsk,
            )
        }
    };
    let add_real = |counts: &mut Counts, metrics: &Metrics| {
        if narrow {
            smallcuts::add_selection(counts, metrics, 5, 2);
        } else {
            add_merge(counts, metrics);
        }
    };
    let tournament_started = smallcuts::start_timer();
    let mut current = bridge.tuples;
    while current.len() > 1 {
        let candidates = current.len();
        let level_parallel = smallcuts::parallel_level(parallel, candidates / 2);
        let level_started = smallcuts::start_timer();
        let completed: Vec<_> = if level_parallel {
            current.par_chunks_exact(2).map(&merge).collect()
        } else {
            current.chunks_exact(2).map(&merge).collect()
        };
        let carried = if current.len() % 2 == 1 {
            Some(current.last().unwrap().clone())
        } else {
            None
        };
        current = completed
            .into_iter()
            .map(|(out, metrics)| {
                add_real(&mut bridge.counts, &metrics);
                out
            })
            .collect();
        if let Some(tail) = carried {
            current.push(tail);
        }
        smallcuts::record_level(candidates, level_parallel, level_started);
    }
    let winner = current.pop().unwrap();
    smallcuts::record_stage(smallcuts::Stage::Tournament, tournament_started);
    let tuple = if let Some(payload) = sentinel_payload(mode) {
        let final_started = smallcuts::start_timer();
        let sentinel = std::array::from_fn(|j| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                bsk.output_lwe_dimension().to_lwe_size(),
                Plaintext(payload[j] * PAYLOAD_DELTAS[j]),
                modulus,
            )
        });
        let tuple = if cuts.final_id_only() {
            // Retain the original sentinel-left comparison, including its inclusive threshold.
            let combined = compare(&sentinel[..4], &winner[..4], server);
            let id_group = if narrow {
                smallcuts::ID_TWO
            } else {
                smallcuts::ID_THREE
            };
            let (tuple, metrics) = smallcuts::select_lanes::<OUTPUTS>(
                &sentinel,
                &winner,
                &combined,
                &[id_group],
                window,
                &server.key_switching_key,
                bsk,
            );
            smallcuts::add_selection(&mut bridge.counts, &metrics, id_group.len(), 1);
            tuple
        } else {
            let (tuple, metrics) = merge(&[sentinel, winner]);
            add_real(&mut bridge.counts, &metrics);
            tuple
        };
        smallcuts::record_stage(smallcuts::Stage::Final, final_started);
        tuple
    } else {
        assert_eq!(mode, ThresholdMode::AllAccept);
        winner
    };
    TupleOutput {
        tuple,
        counts: bridge.counts,
    }
}

pub(super) fn diagnostic(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    bridge: Bridge,
    parallel: bool,
    mode: ThresholdMode,
) -> Diagnostic {
    let n = bridge.tuples.len();
    let leaves = bridge.tuples.clone();
    let selected = reduce(server, window, bridge, parallel, mode);
    check(&selected.counts, n, mode);
    Diagnostic { leaves, selected }
}

pub(super) fn public_rejection(modulus: CiphertextModulus<u64>) -> Output {
    let digits = std::array::from_fn(|_| {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(LweSize(2049), Plaintext(0), modulus)
    });
    Output {
        digits,
        counts: Counts::default(),
    }
}

pub(super) fn endpoint(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    packed: &Glwe,
    templates: &[private_argmin::TemplateView<'_>],
    head: &wide::Keys<'_>,
    normalizer: &wide::Keys<'_>,
    parallel: bool,
    mode: ThresholdMode,
) -> Output {
    if mode == ThresholdMode::AllReject {
        let output = public_rejection(packed.ciphertext_modulus());
        check(&output.counts, templates.len(), mode);
        return output;
    }
    let bridge = hybrid_bridge(server, packed, templates, head, normalizer, parallel);
    let selected = reduce(server, window, bridge, parallel, mode);
    check(&selected.counts, templates.len(), mode);
    wire(selected)
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
        (
            self.pfks,
            self.ks,
            self.br,
            self.samples,
            self.monomial_calls,
            self.nonidentity_monomial_calls,
            self.polynomial_permutation_calls,
            self.glwe_additions,
            self.lwe_subtractions,
            self.lwe_addbacks,
        ) == (6, 1, 2, 6, 6, 4, 12, 4, 6, 6)
            && (
                self.public_centering_calls,
                self.public_centering_mask_terms,
                self.public_centering_body_additions,
            ) == (1, 859, 1)
    }

    pub(super) fn pass_for(&self, payloads: usize, groups: usize) -> bool {
        payloads >= groups
            && groups > 0
            && (
                self.pfks,
                self.ks,
                self.br,
                self.samples,
                self.monomial_calls,
                self.nonidentity_monomial_calls,
                self.polynomial_permutation_calls,
                self.glwe_additions,
                self.lwe_subtractions,
                self.lwe_addbacks,
            ) == (
                payloads,
                1,
                groups,
                payloads,
                payloads,
                payloads - groups,
                2 * payloads,
                payloads - groups,
                payloads,
                payloads,
            )
            && (
                self.public_centering_calls,
                self.public_centering_mask_terms,
                self.public_centering_body_additions,
            ) == (1, 859, 1)
    }
}

/// Identity zero is reserved for rejection. Real leaf construction uses index+1.
pub(super) fn identity_digits(identity: usize) -> Option<[u64; 3]> {
    if identity > crate::general::MAX_GALLERY_SIZE {
        return None;
    }
    let identity = identity as u64;
    Some([identity % 15, (identity / 15) % 15, identity / 225])
}

pub(super) fn sentinel_payload(mode: ThresholdMode) -> Option<[u64; OUTPUTS]> {
    general::sentinel_payload(mode).map(|[top, middle, low, _, _]| [top, middle, low, 0, 0, 0])
}

fn wire(selected: TupleOutput) -> Output {
    let [top, middle, bottom, low, middle_id, high] = selected.tuple;
    drop((top, middle, bottom));
    Output {
        digits: [low, middle_id, high],
        counts: selected.counts,
    }
}

fn checked_domain(templates: &[private_argmin::TemplateView<'_>]) -> private_argmin::ScoreDomain {
    let plan = crate::general::plan(templates).unwrap();
    plan.execution_domain
}

// One unchanged full51-only packed prefix, followed by the untraced direct-Delta59 Head.
pub(super) fn hybrid_bridge(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[private_argmin::TemplateView<'_>],
    head: &wide::Keys<'_>,
    normalizer: &wide::Keys<'_>,
    parallel: bool,
) -> Bridge {
    let domain = checked_domain(templates);
    let scoring_started = smallcuts::start_timer();
    let scores = private_argmin::head_pfks_score_prefix_with_parallel(
        server, packed, templates, domain, parallel,
    )
    .unwrap();
    smallcuts::record_stage(smallcuts::Stage::Scoring, scoring_started);
    let extraction_started = smallcuts::start_timer();
    let produce = |(index, score): (usize, Lwe)| {
        let [low, middle, top] = split::ingress(&score, head, normalizer);
        let identity = index + 1;
        let digit = |value| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                LweSize(2049),
                Plaintext(value * SCORE_DELTA),
                packed.ciphertext_modulus(),
            )
        };
        let [id_low, id_middle, id_high] = identity_digits(identity).unwrap();
        [
            top,
            middle,
            low,
            digit(id_low),
            digit(id_middle),
            digit(id_high),
        ]
    };
    let tuples = if parallel {
        scores.into_par_iter().enumerate().map(produce).collect()
    } else {
        scores.into_iter().enumerate().map(produce).collect()
    };
    smallcuts::record_stage(smallcuts::Stage::Extraction, extraction_started);
    Bridge {
        tuples,
        counts: reached(templates.len(), 0),
    }
}
