//! Nine-payload tournament with the winning threshold carried alongside the true score.
use super::*;
use h_untraced::Counts;
use rayon::prelude::*;
use service::{ExecutionMode, ScoreDomain, TemplateView};
use wide_id::Metrics;

pub(super) const OUTPUTS: usize = 9;
const PAYLOAD_DELTAS: [u64; OUTPUTS] = [SCORE_DELTA; OUTPUTS];
pub(super) const GROUPS: [&[usize]; 3] = [&[0, 1, 2], &[3, 4, 5], &[6, 7, 8]];
pub(super) const OFFSETS: [&[usize]; 3] = [&[0, 41, 82], &[0, 41, 82], &[0, 41, 82]];

pub(super) struct Bridge {
    pub tuples: Vec<[Lwe; OUTPUTS]>,
    pub counts: Counts,
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

fn compare_scores(left: &[Lwe], right: &[Lwe], sk: &ServerKey) -> Lwe {
    assert_eq!(left.len(), 3);
    assert_eq!(right.len(), 3);
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
    // Exactly one ordinary KS. All three dynamic rotations borrow this same retained object.
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

pub(super) fn add_selection(counts: &mut Counts, metrics: &Metrics, payloads: usize) {
    let groups = match payloads {
        6 => 2,
        9 => 3,
        _ => panic!("mixed endpoint has only nine-lane tree and six-lane final selections"),
    };
    assert_eq!(
        (
            metrics.pfks,
            metrics.ks,
            metrics.br,
            metrics.samples,
            metrics.monomial_calls,
            metrics.nonidentity_monomial_calls,
            metrics.polynomial_permutation_calls,
            metrics.glwe_additions,
            metrics.lwe_subtractions,
            metrics.lwe_addbacks
        ),
        (
            payloads,
            1,
            groups,
            payloads,
            payloads,
            payloads - groups,
            2 * payloads,
            payloads - groups,
            payloads,
            payloads
        )
    );
    assert_eq!(
        (
            metrics.public_centering_calls,
            metrics.public_centering_mask_terms,
            metrics.public_centering_body_additions
        ),
        (1, 859, 1)
    );
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

pub(super) fn reached(n: usize, real_merges: usize, final_predicate: bool) -> Counts {
    assert!((1..=general::MAX_GALLERY_SIZE).contains(&n));
    assert!(real_merges < n);
    assert!(!final_predicate || real_merges == n - 1);
    let (n, k, f) = (n as u64, real_merges as u64, u64::from(final_predicate));
    let saved = n * shared_normalizers::mode().saved_br_per_score();
    Counts {
        br: 6 * n + 6 * k + 5 * f - saved,
        ks: 4 * n + 4 * k + 4 * f,
        pfks: 9 * k + 6 * f,
        samples: 6 * n + 12 * k + 9 * f,
        levels: 8 * n + 6 * k + 5 * f - saved,
        score_samples: n,
        rotations: 9 * k + 6 * f,
        polynomial_permutations: 18 * k + 12 * f,
        glwe_additions: 6 * k + 4 * f,
        lwe_subtractions: 9 * k + 6 * f,
        lwe_addbacks: 9 * k + 6 * f,
        centering_calls: k + f,
        centering_mask_terms: 859 * (k + f),
        centering_body_additions: k + f,
        ..Counts::default()
    }
}

pub const fn operation_counts(n: usize) -> Option<service::Counts> {
    if n == 0 || n > general::MAX_GALLERY_SIZE {
        return None;
    }
    let n = n as u64;
    Some(service::Counts {
        br: 12 * n - 1,
        ks: 8 * n,
        pfks: 9 * n - 3,
        marginals: 18 * n - 3,
        initial_samples: n,
    })
}

/// Keep predicate operands separate from the six payloads that the predicate selects.
pub(super) fn root_parts(winner: &[Lwe; OUTPUTS]) -> (&[Lwe], &[Lwe], &[Lwe]) {
    (&winner[..3], &winner[6..9], &winner[..6])
}

fn reduce(
    server: &ServerKey,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    mut bridge: Bridge,
    parallel: bool,
) -> wide_id::Output {
    let n = bridge.tuples.len();
    let cuts = smallcuts::mode();
    let narrow = cuts.narrow_for(n);
    let ShortintBootstrappingKey::Classic(bsk) = &server.bootstrapping_key;
    let modulus = bridge.tuples[0][0].ciphertext_modulus();
    let merge = |pair: &[[Lwe; OUTPUTS]]| {
        let combined = compare_scores(&pair[0][..3], &pair[1][..3], server);
        if narrow {
            smallcuts::select_lanes::<OUTPUTS>(
                &pair[0],
                &pair[1],
                &combined,
                &[
                    smallcuts::SCORE_GROUP,
                    smallcuts::ID_TWO,
                    smallcuts::THRESHOLD_GROUP,
                ],
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
                if narrow {
                    smallcuts::add_selection(&mut bridge.counts, &metrics, 8, 3);
                } else {
                    add_selection(&mut bridge.counts, &metrics, OUTPUTS);
                }
                out
            })
            .collect();
        if let Some(tail) = carried {
            current.push(tail);
        }
        smallcuts::record_level(candidates, level_parallel, level_started);
    }
    assert_eq!(
        bridge.counts,
        smallcuts::adjust_counts(reached(n, n - 1, false), n, n - 1, false, cuts)
    );
    let winner = current.pop().unwrap();
    smallcuts::record_stage(smallcuts::Stage::Tournament, tournament_started);
    let final_started = smallcuts::start_timer();
    let (score, threshold, keep) = root_parts(&winner);
    let rejects = compare_scores(score, threshold, server);
    let zero: [Lwe; 6] = std::array::from_fn(|_| {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(
            bsk.output_lwe_dimension().to_lwe_size(),
            Plaintext(0),
            modulus,
        )
    });
    let selected = if cuts.final_id_only() {
        let id_group = if narrow {
            smallcuts::ID_TWO
        } else {
            smallcuts::ID_THREE
        };
        let (selected, metrics) = smallcuts::select_lanes::<6>(
            keep,
            &zero,
            &rejects,
            &[id_group],
            window,
            &server.key_switching_key,
            bsk,
        );
        smallcuts::add_selection(&mut bridge.counts, &metrics, id_group.len(), 1);
        selected
    } else if narrow {
        let (selected, metrics) = smallcuts::select_lanes::<6>(
            keep,
            &zero,
            &rejects,
            &[smallcuts::SCORE_GROUP, smallcuts::ID_TWO],
            window,
            &server.key_switching_key,
            bsk,
        );
        smallcuts::add_selection(&mut bridge.counts, &metrics, 5, 2);
        selected
    } else {
        let (selected, metrics) = wide_id::select(
            keep,
            &zero,
            &rejects,
            window,
            &server.key_switching_key,
            bsk,
        );
        add_selection(&mut bridge.counts, &metrics, 6);
        selected
    };
    assert_eq!(
        bridge.counts,
        smallcuts::adjust_counts(reached(n, n - 1, true), n, n - 1, true, cuts)
    );
    let [top, middle, low_score, low, middle_id, high] = selected;
    drop((top, middle, low_score));
    smallcuts::record_stage(smallcuts::Stage::Final, final_started);
    wide_id::Output {
        digits: [low, middle_id, high],
        counts: bridge.counts,
    }
}

/// Public lanes are [ID low, ID middle, ID high, threshold top, threshold middle, threshold low].
pub(super) fn leaf_public_payloads(
    index: usize,
    threshold: i64,
    domain: ScoreDomain,
) -> Result<[u64; 6], String> {
    let identity = index.checked_add(1).ok_or("mixed leaf index overflow")?;
    let mut digits = wide_id::identity_digits(identity)
        .ok_or("mixed leaf identity exceeds three base15 digits")?;
    let threshold = mixed_plan::threshold_payload(threshold, domain)?;
    if threshold.below_domain {
        digits = [0, 0, 0];
    }
    Ok([
        digits[0],
        digits[1],
        digits[2],
        threshold.digits[0],
        threshold.digits[1],
        threshold.digits[2],
    ])
}

fn hybrid_bridge(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    head: &wide::Keys<'_>,
    normalizer: &wide::Keys<'_>,
    parallel: bool,
) -> Result<Bridge, String> {
    // Complete public payload validation before starting the encrypted prefix.
    let public: Vec<_> = templates
        .iter()
        .enumerate()
        .map(|(i, entry)| leaf_public_payloads(i, entry.threshold, domain))
        .collect::<Result<_, _>>()?;
    let scoring_started = smallcuts::start_timer();
    let scores = private_argmin::head_pfks_score_prefix_with_parallel(
        server, packed, templates, domain, parallel,
    )
    .map_err(|error| format!("mixed Head prefix: {error:?}"))?;
    smallcuts::record_stage(smallcuts::Stage::Scoring, scoring_started);
    let extraction_started = smallcuts::start_timer();
    let produce = |(score, public): (Lwe, [u64; 6])| {
        let [low, middle, top] = split::ingress(&score, head, normalizer);
        let digit = |value| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                LweSize(2049),
                Plaintext(value * SCORE_DELTA),
                packed.ciphertext_modulus(),
            )
        };
        [
            top,
            middle,
            low,
            digit(public[0]),
            digit(public[1]),
            digit(public[2]),
            digit(public[3]),
            digit(public[4]),
            digit(public[5]),
        ]
    };
    let tuples = if parallel {
        scores
            .into_par_iter()
            .zip(public.into_par_iter())
            .map(produce)
            .collect()
    } else {
        scores.into_iter().zip(public).map(produce).collect()
    };
    smallcuts::record_stage(smallcuts::Stage::Extraction, extraction_started);
    Ok(Bridge {
        tuples,
        counts: reached(templates.len(), 0, false),
    })
}

pub fn evaluate(
    server: &ServerKey,
    head: &FourierLweBootstrapKeyOwned,
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    parallel: bool,
) -> Result<(Lwe, Lwe, Lwe, service::Counts), String> {
    service::request::validate(packed, templates, domain)?;
    let plan = service::plan(templates)?;
    if plan.mode != ExecutionMode::MixedWinnerThreshold {
        return Err("mixed endpoint requires differing public thresholds".into());
    }
    let expected = service::operation_counts(templates.len(), ExecutionMode::MixedWinnerThreshold)
        .ok_or("mixed gallery size is invalid")?;
    let ShortintBootstrappingKey::Classic(bsk) = &server.bootstrapping_key;
    let head_keys = wide::Keys {
        ksk: &server.key_switching_key,
        bsk: head,
    };
    let normalizer = wide::Keys {
        ksk: &server.key_switching_key,
        bsk,
    };
    let bridge = hybrid_bridge(
        server,
        packed,
        templates,
        domain,
        &head_keys,
        &normalizer,
        parallel,
    )?;
    let output = reduce(server, window, bridge, parallel);
    let counts = service::Counts {
        br: output.counts.br,
        ks: output.counts.ks,
        pfks: output.counts.pfks,
        marginals: output.counts.samples,
        initial_samples: output.counts.score_samples,
    };
    if counts != expected {
        return Err("mixed endpoint operation ledger differs".into());
    }
    let [low, middle, high] = output.digits;
    Ok((low, middle, high, counts))
}
