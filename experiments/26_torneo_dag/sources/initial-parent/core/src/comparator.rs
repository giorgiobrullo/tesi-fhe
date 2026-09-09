//! Four actual ordinary KS/BR/sample calls. No supplied selector or secret input.
use super::*;

pub(super) struct Stage {
    pub name: &'static str,
    pub input: Lwe,
    pub small: Lwe,
    pub raw: Lwe,
    pub output: Lwe,
    pub body: Vec<u64>,
    pub final_control: bool,
    pub ks: usize,
    pub br: usize,
    pub samples: usize,
}

pub(super) fn body(final_control: bool) -> Vec<u64> {
    (0..2048)
        .map(|i| {
            if final_control {
                4 * SCORE_DELTA
            } else if (64..1984).contains(&i) {
                SCORE_DELTA
            } else {
                0
            }
        })
        .collect()
}

#[cfg(feature = "opt-lut-cache")]
pub(super) fn cached_body(final_control: bool) -> &'static [u64] {
    static TERNARY: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();
    static FINAL: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();
    let cache = if final_control { &FINAL } else { &TERNARY };
    cache.get_or_init(|| body(final_control))
}

#[cfg(all(test, feature = "opt-lut-cache"))]
#[test]
fn cached_comparator_bodies_match_both_negacyclic_lut_contracts() {
    for final_control in [false, true] {
        let cached = cached_body(final_control);
        assert_eq!(cached, body(final_control).as_slice());
        assert_eq!(cached.as_ptr(), cached_body(final_control).as_ptr());
        for degree in 0..4096 {
            let stored = cached[degree % 2048];
            let actual = if degree < 2048 { stored } else { stored.wrapping_neg() };
            let expected = (value(final_control, degree) as u64).wrapping_mul(SCORE_DELTA);
            assert_eq!(actual, expected);
        }
    }
}

pub(super) fn value(final_control: bool, degree: usize) -> i64 {
    let v = if final_control {
        4
    } else {
        i64::from((64..1984).contains(&(degree % 2048)))
    };
    if degree < 2048 {
        v
    } else {
        -v
    }
}

fn pbs(name: &'static str, input: Lwe, final_control: bool, sk: &ServerKey) -> Stage {
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
    let ks = 1;
    let body = body(final_control);
    let mut accumulator = GlweCiphertext::new(
        0u64,
        GlweSize(2),
        PolynomialSize(2048),
        input.ciphertext_modulus(),
    );
    accumulator.get_mut_body().as_mut().copy_from_slice(&body);
    // This exact retained small object is borrowed by stock BR; no phase proxy.
    blind_rotate_assign(&small, &mut accumulator, bsk);
    let br = 1;
    let mut raw = LweCiphertext::new(
        0u64,
        bsk.output_lwe_dimension().to_lwe_size(),
        input.ciphertext_modulus(),
    );
    extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut raw, MonomialDegree(0));
    let samples = 1;
    let mut output = raw.clone();
    if final_control {
        *output.get_mut_body().data = output.get_body().data.wrapping_add(8 * SCORE_DELTA);
    }
    Stage {
        name,
        input,
        small,
        raw,
        output,
        body,
        final_control,
        ks,
        br,
        samples,
    }
}

pub(super) fn evaluate(left: &[Lwe], right: &[Lwe], sk: &ServerKey) -> Vec<Stage> {
    assert_eq!(left.len(), 4);
    assert_eq!(right.len(), 4);
    let mut stages = Vec::with_capacity(4);
    for (j, name) in ["ternary/top", "ternary/middle", "ternary/low"]
        .into_iter()
        .enumerate()
    {
        let mut difference = left[j].clone();
        for (word, r) in difference.as_mut().iter_mut().zip(right[j].as_ref()) {
            *word = word.wrapping_sub(*r);
        }
        stages.push(pbs(name, difference, false, sk));
    }
    let mut combined = stages[0].output.clone();
    for (i, word) in combined.as_mut().iter_mut().enumerate() {
        *word = stages[0].output.as_ref()[i]
            .wrapping_mul(4)
            .wrapping_add(stages[1].output.as_ref()[i].wrapping_mul(2))
            .wrapping_add(stages[2].output.as_ref()[i]);
    }
    *combined.get_mut_body().data = combined.get_body().data.wrapping_sub(SCORE_DELTA / 2);
    stages.push(pbs("final/control", combined, true, sk));
    stages
}

pub(super) fn lwe(ct: &Lwe, secret: &LweSecretKeyView<'_, u64>) -> serde_json::Value {
    assert_eq!(ct.as_ref().len(), secret.as_ref().len() + 1);
    assert!(secret.as_ref().iter().all(|&s| s <= 1));
    let dot = ct
        .get_mask()
        .as_ref()
        .iter()
        .zip(secret.as_ref())
        .fold(0u64, |v, (&a, &s)| v.wrapping_add(a.wrapping_mul(s)));
    let phase = decrypt_lwe_ciphertext(secret, ct).0;
    json!({"words":ct.as_ref(),"sha256":hash_lwe(ct),"phase":phase,
        "client_mask_dot":dot,"direct_phase_matches":ct.get_body().data.wrapping_sub(dot)==phase})
}

pub(super) fn switched(
    input: &Lwe,
    small: &Lwe,
    big: &LweSecretKeyView<'_, u64>,
    secret: &LweSecretKeyView<'_, u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
) -> serde_json::Value {
    let input_node = lwe(input, big);
    let small_node = lwe(small, secret);
    let ip = input_node["phase"].as_u64().unwrap();
    let sp = small_node["phase"].as_u64().unwrap();
    let decomp = SignedDecomposer::<u64>::new(
        ksk.decomposition_base_log(),
        ksk.decomposition_level_count(),
    );
    let remainder: i128 = input
        .get_mask()
        .as_ref()
        .iter()
        .zip(big.as_ref())
        .map(|(&a, &s)| {
            (a.wrapping_sub(decomp.closest_representable(a)) as i64 as i128) * s as i128
        })
        .sum();
    let increment = sp.wrapping_sub(ip) as i64;
    let inferred = (increment as u64).wrapping_sub(remainder as u64) as i64;
    let degrees: Vec<usize> = small
        .as_ref()
        .iter()
        .map(|&w| pbs_modulus_switch(w, PolynomialSize(2048)))
        .collect();
    let masks = &degrees[..degrees.len() - 1];
    let bd = *degrees.last().unwrap();
    let wd: i128 = masks
        .iter()
        .zip(secret.as_ref())
        .map(|(&d, &s)| d as i128 * s as i128)
        .sum();
    let wr: i128 = small
        .get_mask()
        .as_ref()
        .iter()
        .zip(masks)
        .zip(secret.as_ref())
        .map(|((&a, &d), &s)| {
            a.wrapping_sub((d as u64).wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE)) as i64 as i128
                * s as i128
        })
        .sum();
    let rb = small
        .get_body()
        .data
        .wrapping_sub((bd as u64).wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE))
        as i64;
    let address = (bd as i128 - wd).rem_euclid(4096) as usize;
    let closure = (address as u64)
        .wrapping_mul(TORUS_PER_BLIND_ROTATION_DEGREE)
        .wrapping_add(rb as u64)
        .wrapping_sub(wr as u64)
        == sp;
    json!({"input":input_node,"small":small_node,"ks_base_log":ksk.decomposition_base_log().0,
        "ks_level_count":ksk.decomposition_level_count().0,"ks_increment":increment,
        "ks_remainder_decimal":remainder.to_string(),"inferred_signed_row_term":inferred,
        "body_degree":bd,"mask_degrees":masks,"raw_mask_nonzero":small.get_mask().as_ref().iter().map(|&x|x!=0).collect::<Vec<_>>(),
        "client_weighted_degrees_decimal":wd.to_string(),"client_weighted_residues_decimal":wr.to_string(),
        "body_residue":rb,"actual_address":address,"phase_only_address":modulus_switch_degree(sp),
        "coefficient_identity_pass":closure,"native_ks_plus_remainder_convention":true,
        "client_aggregate_key_membership_attested":false,"row_errors_independently_measured":false,
        "internal_br_receipt_returned":false,"extra_crypto_ms_calls":0})
}

pub(super) fn observe(
    stage: &Stage,
    expected_raw: i64,
    expected_output: u64,
    big: &LweSecretKeyView<'_, u64>,
    small: &LweSecretKeyView<'_, u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
) -> (serde_json::Value, bool) {
    let ks = switched(&stage.input, &stage.small, big, small, ksk);
    let degree = ks["actual_address"].as_u64().unwrap() as usize;
    let raw = lwe(&stage.raw, big);
    let output = lwe(&stage.output, big);
    let actual_lut = value(stage.final_control, degree);
    let raw_phase = raw["phase"].as_u64().unwrap();
    let output_phase = output["phase"].as_u64().unwrap();
    let error = raw_phase.wrapping_sub((actual_lut as u64).wrapping_mul(SCORE_DELTA)) as i64;
    let native =
        (output_phase.wrapping_sub(expected_output) as i64).unsigned_abs() < SCORE_DELTA / 2;
    let preimage = actual_lut == expected_raw;
    let at_address = error.unsigned_abs() < SCORE_DELTA / 2;
    let closure = ks["coefficient_identity_pass"] == true
        && ks["input"]["direct_phase_matches"] == true
        && ks["small"]["direct_phase_matches"] == true
        && raw["direct_phase_matches"] == true
        && output["direct_phase_matches"] == true;
    let pass = preimage
        && at_address
        && native
        && closure
        && stage.ks == 1
        && stage.br == 1
        && stage.samples == 1;
    (
        json!({"record":"comparator_stage","schema":"a191.comparator_pfks.v1","keyset":0,
        "stage":stage.name,"kind":if stage.final_control {"control"} else {"ternary"},
        "ks_observation":ks,"raw":raw,"output":output,"body_sha256":observer::hash_words(&stage.body),
        "expected_raw":expected_raw,"expected_output_phase":expected_output,"actual_lut":actual_lut,
        "output_error_at_actual_address":error,"preimage_pass":preimage,"output_at_address_pass":at_address,
        "native_output_pass":native,"observer_pass":closure,"pass":pass,
        "ks":stage.ks,"br":stage.br,"samples":stage.samples}),
        pass,
    )
}

// Append-only three-PBS prefix; no fourth control PBS.
pub(super) fn prefix(left: &[Lwe], right: &[Lwe], sk: &ServerKey) -> (Vec<Stage>, Lwe) {
    assert_eq!(left.len(), 4);
    assert_eq!(right.len(), 4);
    let mut stages = Vec::with_capacity(3);
    for (j, name) in ["ternary/top", "ternary/middle", "ternary/low"]
        .into_iter()
        .enumerate()
    {
        let mut difference = left[j].clone();
        for (word, r) in difference.as_mut().iter_mut().zip(right[j].as_ref()) {
            *word = word.wrapping_sub(*r);
        }
        stages.push(pbs(name, difference, false, sk));
    }
    let mut combined = stages[0].output.clone();
    for (i, word) in combined.as_mut().iter_mut().enumerate() {
        *word = stages[0].output.as_ref()[i]
            .wrapping_mul(4)
            .wrapping_add(stages[1].output.as_ref()[i].wrapping_mul(2))
            .wrapping_add(stages[2].output.as_ref()[i]);
    }
    *combined.get_mut_body().data = combined.get_body().data.wrapping_sub(SCORE_DELTA / 2);
    (stages, combined)
}
