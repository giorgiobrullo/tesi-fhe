use selector_four_core_20260920::{
    composite, first_level_pfks_profile,
    raw_threshold_probe::{FullArm, FullStage},
    service::{self, EvaluationKeys, ExecutionMode, ScoreDomain, TemplateView, ThresholdMode},
};
use serde::Deserialize;
use serde_json::json;
use std::time::Instant;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::{client_key::atomic_pattern::AtomicPatternClientKey, ClientKey, ServerKey};

const PROBE: &str = "first-level-stock-pfks-profile.20261005.v1";
const DELTA: u64 = 1 << 59;

#[derive(Clone, Deserialize)]
struct Entry {
    vettore: Vec<i64>,
    soglia: i64,
}
#[derive(Deserialize)]
struct Gallery {
    schema: String,
    entries: Vec<Entry>,
}
#[derive(Deserialize)]
struct Expected {
    selected_id: usize,
    winner_id: usize,
    scores: Vec<i64>,
    tied_minimum_ids: Vec<usize>,
}
#[derive(Deserialize)]
struct Probe {
    schema: String,
    query: Vec<i64>,
    query_norm2: i64,
    expected: Expected,
}
struct Case {
    name: &'static str,
    query: usize,
    expected: usize,
}

fn oracle(query: &[i64], gallery: &[Entry]) -> (usize, usize, Vec<i64>, Vec<usize>) {
    let scores: Vec<i64> = gallery
        .iter()
        .map(|row| {
            row.vettore.iter().map(|x| x * x).sum::<i64>()
                - 2 * row
                    .vettore
                    .iter()
                    .zip(query)
                    .map(|(x, q)| x * q)
                    .sum::<i64>()
        })
        .collect();
    let mut winner = 0;
    for i in 1..scores.len() {
        if scores[i] < scores[winner] {
            winner = i;
        }
    }
    let ties = scores
        .iter()
        .enumerate()
        .filter(|(_, s)| **s == scores[winner])
        .map(|(i, _)| i + 1)
        .collect();
    let selected = if scores[winner] <= gallery[winner].soglia {
        winner + 1
    } else {
        0
    };
    (selected, winner + 1, scores, ties)
}
fn encode(query: &[i64]) -> Result<Vec<u64>, String> {
    if query.len() != 512
        || query.iter().any(|x| !(-3..=3).contains(x))
        || query.iter().map(|x| x * x).sum::<i64>() > 1024
    {
        return Err("public query violates exact Head51 admission".into());
    }
    let mut coefficients = vec![0u64; 2048];
    for (j, &q) in query.iter().enumerate() {
        coefficients[j] = (q as u64).wrapping_mul(1 << 51);
        coefficients[1024 + j] = (q.rem_euclid(16) as u64).wrapping_mul(1 << 60);
    }
    Ok(coefficients)
}
fn templates(gallery: &[Entry]) -> Vec<TemplateView<'_>> {
    gallery
        .iter()
        .map(|row| TemplateView {
            template: &row.vettore,
            norm2: row.vettore.iter().map(|x| x * x).sum(),
            threshold: row.soglia,
        })
        .collect()
}
fn decode<KeyCont: Container<Element = u64>>(
    key: &LweSecretKey<KeyCont>,
    digits: &[LweCiphertextOwned<u64>; 3],
) -> Result<usize, String> {
    let d: [u64; 3] = std::array::from_fn(|i| {
        decrypt_lwe_ciphertext(key, &digits[i])
            .0
            .wrapping_add(DELTA / 2)
            >> 59
    });
    if d.iter().any(|&v| v >= 15) || d[2] != 0 {
        return Err("noncanonical final radix15 digit".into());
    }
    let id = (d[0] + 15 * d[1]) as usize;
    if id > 120 {
        return Err("final ID outside N120".into());
    }
    Ok(id)
}
struct Evaluation {
    digits: [LweCiphertextOwned<u64>; 3],
    counts: service::Counts,
    terminal: FullStage,
    whole_ns: u64,
    profile: first_level_pfks_profile::Report,
    full_routes: serde_json::Value,
}
fn evaluate(
    keys: &EvaluationKeys,
    input: &GlweCiphertextOwned<u64>,
    gallery: &[TemplateView<'_>],
    domain: ScoreDomain,
    profiling: bool,
) -> Result<Evaluation, String> {
    let profile_guard = first_level_pfks_profile::QueryGuard::begin(profiling)?;
    // The real caller resets its factory once before each serialized whole query, never inside a worker.
    composite::begin_query(composite::Mode::PublicParallel, false);
    let started = Instant::now();
    let (low, middle, high, counts, terminal) =
        keys.raw_threshold_fullquery_probe(input, gallery, domain, FullArm::Baseline)?;
    let whole_ns = started
        .elapsed()
        .as_nanos()
        .try_into()
        .map_err(|_| "duration range")?;
    let profile = profile_guard.finish()?;
    let full_routes = json!({
        "comparator": selector_four_core_20260920::classic_batch::report(),
        "selectors": selector_four_core_20260920::selector_parallel::report(),
    });
    Ok(Evaluation {
        digits: [low, middle, high],
        counts,
        terminal,
        whole_ns,
        profile,
        full_routes,
    })
}
fn verify<KeyCont: Container<Element = u64>>(
    key: &LweSecretKey<KeyCont>,
    out: &Evaluation,
    expected: usize,
) -> Result<usize, String> {
    let id = decode(key, &out.digits)?;
    if id != expected {
        return Err("fullquery ID differs from clear first-minimum oracle".into());
    }
    if (
        out.counts.br,
        out.counts.ks,
        out.counts.pfks,
        out.counts.marginals,
        out.counts.initial_samples,
    ) != (1111, 1080, 509, 1709, 120)
    {
        return Err("actual stock full-query work differs from1111/1080/509/1709+120".into());
    }
    let full = &out.profile.full_work;
    if !full.as_object().is_some_and(|fields| fields.len() == 15)
        || full["br"].as_u64() != Some(out.counts.br)
        || full["ks"].as_u64() != Some(out.counts.ks)
        || full["pfks"].as_u64() != Some(out.counts.pfks)
        || full["marginals"].as_u64() != Some(out.counts.marginals)
        || full["initial_score_samples"].as_u64() != Some(out.counts.initial_samples)
    {
        return Err("actual full15 work does not match the returned service projection".into());
    }
    if out.terminal.duration_ns == 0 || out.whole_ns < out.terminal.duration_ns {
        return Err("invalid terminal/whole timer containment".into());
    }
    Ok(id)
}

fn print_evaluation(stage: &str, case: &Case, round: Option<usize>, id: usize, out: &Evaluation) {
    println!(
        "{}",
        json!({
            "probe": PROBE, "stage": stage, "case": case.name, "round": round,
            "pass": true, "id": id, "whole_duration_ns": out.whole_ns,
            "counts": &out.profile.full_work,
            "service_counts": {
                "br": out.counts.br, "ks": out.counts.ks, "pfks": out.counts.pfks,
                "marginals": out.counts.marginals, "initial_samples": out.counts.initial_samples
            },
            "terminal": &out.terminal,
            "full_scheduling": &out.full_routes,
            "first_level_stock_pfks": &out.profile,
        })
    );
}

fn main() -> Result<(), String> {
    if std::env::var_os("VARCO_PROFILE_PHASES").is_some() {
        return Err("phase-profile environment must be absent".into());
    }
    let gallery: Gallery = serde_json::from_str(include_str!("../../fixtures/gallery.json"))
        .map_err(|_| "invalid immutable public gallery")?;
    if gallery.schema != "web-thread-scaling-gallery.v1"
        || gallery.entries.len() != 120
        || gallery.entries.iter().any(|row| {
            row.vettore.len() != 512
                || row.soglia != 273
                || row.vettore.iter().any(|x| !(-3..=3).contains(x))
        })
    {
        return Err("immutable gallery violates N120/D512/T273".into());
    }
    let probes: Vec<Probe> = [
        include_str!("../../fixtures/einstein.json"),
        include_str!("../../fixtures/curie.json"),
        include_str!("../../fixtures/turing.json"),
    ]
    .into_iter()
    .map(|text| serde_json::from_str(text).map_err(|_| "invalid immutable public query".to_owned()))
    .collect::<Result<_, _>>()?;
    for (i, probe) in probes.iter().enumerate() {
        encode(&probe.query)?;
        if probe.schema != "web-thread-scaling-probe.v1"
            || probe.query.iter().map(|x| x * x).sum::<i64>() != probe.query_norm2
        {
            return Err("immutable query schema/norm mismatch".into());
        }
        let (selected, winner, scores, ties) = oracle(&probe.query, &gallery.entries);
        if selected != i + 1
            || selected != probe.expected.selected_id
            || winner != probe.expected.winner_id
            || scores != probe.expected.scores
            || ties != probe.expected.tied_minimum_ids
        {
            return Err("immutable oracle does not match primary integer formula".into());
        }
    }
    let queries: Vec<_> = probes.into_iter().map(|p| p.query).collect();
    let cases = [
        Case {
            name: "einstein",
            query: 0,
            expected: 1,
        },
        Case {
            name: "curie",
            query: 1,
            expected: 2,
        },
        Case {
            name: "turing",
            query: 2,
            expected: 3,
        },
    ];
    let template_views = templates(&gallery.entries);
    let plan = service::plan(&template_views)?;
    let sentinel = match plan.mode {
        ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score }) => score,
        _ => return Err("actual plan must retain the represented uniform sentinel".into()),
    };
    if !(1..=4096).contains(
        &(i128::from(plan.execution_domain.upper) - i128::from(plan.execution_domain.lower) + 1),
    ) {
        return Err("invalid actual score domain".into());
    }
    // This checks the maintained public plan's selected lane counts before any keys.
    first_level_pfks_profile::validate_source_layout()?;
    println!(
        "{}",
        json!({
            "probe": PROBE, "stage": "public_plan", "gallery_size": 120,
            "execution_lower": plan.execution_domain.lower,
            "execution_upper": plan.execution_domain.upper, "sentinel": sentinel,
            "first_level_stock_pfks_calls": 244,
            "first_level_roles": {"score": 180, "id_low": 60, "id_middle": 4}
        })
    );
    setup_custom_fft_plan(Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    ));
    rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build_global()
        .map_err(|_| "global16 pool initialization")?;
    if rayon::current_num_threads() != 16 {
        return Err("16-thread pool required".into());
    }
    println!(
        "{}",
        json!({
            "probe": PROBE, "stage": "fresh_key_generation", "key_families": 1,
            "unique_queries": 3, "rayon_threads": 16,
            "fft_policy": "user-provided-dif4-polynomial2048-base1024-v1",
        })
    );
    let client = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
    let keys =
        EvaluationKeys::from_bundle(service::generate_bundle(&client, ServerKey::new(&client))?)?;
    let (glwe, _small, params, _wopbs) = match client.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return Err("standard Gaussian client required".into()),
    };
    let big = glwe.as_lwe_secret_key();
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let encrypted: Vec<_> = queries
        .iter()
        .map(|query| {
            let values = encode(query)?;
            let mut output = GlweCiphertext::new(
                0u64,
                glwe.glwe_dimension().to_glwe_size(),
                glwe.polynomial_size(),
                CiphertextModulus::new_native(),
            );
            encrypt_glwe_ciphertext(
                &glwe,
                &mut output,
                &PlaintextList::from_container(values),
                params.glwe_noise_distribution(),
                &mut generator,
            );
            if !output.get_mask().as_ref().iter().any(|v| *v != 0) {
                return Err("fresh packed query mask is trivial".into());
            }
            Ok(output)
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut decoded = 0;
    for case in &cases {
        let out = evaluate(
            &keys,
            &encrypted[case.query],
            &template_views,
            plan.execution_domain,
            false,
        )?;
        let id = verify(&big, &out, case.expected)?;
        if out.profile.enabled || out.profile.calls != 0 {
            return Err("profile-OFF correctness gate must contain no primitive records".into());
        }
        decoded += 1;
        print_evaluation("correctness_profile_off", case, None, id, &out);
    }
    if decoded != 3 {
        return Err("three profile-OFF IDs required before profiling".into());
    }
    println!(
        "{}",
        json!({
            "probe": PROBE, "stage": "correctness_complete", "pass": true,
            "decoded_id_outputs": 3,
        })
    );
    for case in &cases {
        let out = evaluate(
            &keys,
            &encrypted[case.query],
            &template_views,
            plan.execution_domain,
            true,
        )?;
        let id = verify(&big, &out, case.expected)?;
        if !out.profile.enabled || out.profile.calls != 244 {
            return Err("profile-ON warmup requires244 stock primitive calls".into());
        }
        decoded += 1;
        print_evaluation("profiled_warmup", case, None, id, &out);
    }
    for round in 0..2 {
        for case in &cases {
            let out = evaluate(
                &keys,
                &encrypted[case.query],
                &template_views,
                plan.execution_domain,
                true,
            )?;
            let id = verify(&big, &out, case.expected)?;
            if !out.profile.enabled || out.profile.calls != 244 {
                return Err("measured request requires244 stock primitive calls".into());
            }
            decoded += 1;
            print_evaluation("profiled_request", case, Some(round), id, &out);
        }
    }
    if decoded != 12 {
        return Err("exactly12 checked IDs required".into());
    }
    println!(
        "{}",
        json!({
            "probe": PROBE, "stage": "complete", "pass": true,
            "decoded_id_outputs": decoded, "profile_off_correctness_ids": 3,
            "profiled_warmup_ids": 3, "measured_profiled_ids": 6,
            "primitive_timing_boundary": "stock serial PFKS call after input/output construction; mask check before timer; report append after timer",
            "whole_timing_boundary": "R Baseline full-query diagnostic incl primitive profiling overhead; excludes coordinator reset/keygen/encryption/decode/stdout/report extraction",
            "scope": "one fresh family/three immutable accept queries; worker primitive durations overlap and their sums are not request latency; no optimized arm/speedup/noise/security/biometric/adoption claim",
        })
    );
    Ok(())
}
