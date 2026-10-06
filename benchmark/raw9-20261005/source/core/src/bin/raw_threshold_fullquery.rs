use selector_four_core_20260920::{
    composite,
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

const PROBE: &str = "raw-threshold-fullquery.20261005.v1";
const ARMS: [FullArm; 2] = [FullArm::Baseline, FullArm::RawParallel9];
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
    gallery: usize,
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
}
fn evaluate(
    keys: &EvaluationKeys,
    input: &GlweCiphertextOwned<u64>,
    gallery: &[TemplateView<'_>],
    domain: ScoreDomain,
    arm: FullArm,
) -> Result<Evaluation, String> {
    // The real caller resets its factory once before each serialized whole query, never inside a worker.
    composite::begin_query(composite::Mode::PublicParallel, false);
    let started = Instant::now();
    let (low, middle, high, counts, terminal) =
        keys.raw_threshold_fullquery_probe(input, gallery, domain, arm)?;
    let whole_ns = started
        .elapsed()
        .as_nanos()
        .try_into()
        .map_err(|_| "duration range")?;
    Ok(Evaluation {
        digits: [low, middle, high],
        counts,
        terminal,
        whole_ns,
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
    if out.terminal.duration_ns == 0 || out.whole_ns < out.terminal.duration_ns {
        return Err("invalid terminal/whole timer containment".into());
    }
    Ok(id)
}
fn main() -> Result<(), String> {
    if std::env::var_os("VARCO_PROFILE_PHASES").is_some() {
        return Err("phase-profile environment must be absent".into());
    }
    let original: Gallery = serde_json::from_str(include_str!("../../fixtures/gallery.json"))
        .map_err(|_| "invalid public gallery")?;
    if original.schema != "web-thread-scaling-gallery.v1"
        || original.entries.len() != 120
        || original.entries.iter().any(|row| {
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
    .map(|text| serde_json::from_str(text).map_err(|_| "invalid public probe".to_owned()))
    .collect::<Result<_, _>>()?;
    for (i, probe) in probes.iter().enumerate() {
        encode(&probe.query)?;
        if probe.schema != "web-thread-scaling-probe.v1"
            || probe.query.iter().map(|x| x * x).sum::<i64>() != probe.query_norm2
        {
            return Err("probe schema/norm mismatch".into());
        }
        let (selected, winner, scores, ties) = oracle(&probe.query, &original.entries);
        if selected != i + 1
            || selected != probe.expected.selected_id
            || winner != probe.expected.winner_id
            || scores != probe.expected.scores
            || ties != probe.expected.tied_minimum_ids
        {
            return Err("immutable public oracle does not match primary integer formula".into());
        }
    }
    let mut cross = original.entries.clone();
    cross[64].vettore = original.entries[0].vettore.clone();
    let galleries = [original.entries, cross];
    let queries: Vec<Vec<i64>> = probes
        .into_iter()
        .map(|p| p.query)
        .chain([galleries[0][82].vettore.clone(), vec![0; 512]])
        .collect();
    let cases = [
        Case {
            name: "einstein",
            query: 0,
            gallery: 0,
            expected: 1,
        },
        Case {
            name: "curie",
            query: 1,
            gallery: 0,
            expected: 2,
        },
        Case {
            name: "turing",
            query: 2,
            gallery: 0,
            expected: 3,
        },
        Case {
            name: "right83",
            query: 3,
            gallery: 0,
            expected: 83,
        },
        Case {
            name: "zero-reject",
            query: 4,
            gallery: 0,
            expected: 0,
        },
        Case {
            name: "crossroot-tie",
            query: 0,
            gallery: 1,
            expected: 1,
        },
    ];
    for case in &cases {
        encode(&queries[case.query])?;
        let (selected, _, _, ties) = oracle(&queries[case.query], &galleries[case.gallery]);
        if selected != case.expected || (case.name == "crossroot-tie" && ties != vec![1, 65]) {
            return Err("derived public gate differs from preregistered expected ID".into());
        }
    }
    let template_views: Vec<_> = galleries.iter().map(|g| templates(g)).collect();
    let plans: Vec<_> = template_views
        .iter()
        .map(|t| service::plan(t))
        .collect::<Result<_, _>>()?;
    for (i, plan) in plans.iter().enumerate() {
        let score = match plan.mode {
            ExecutionMode::Uniform(ThresholdMode::CompareSentinel { score }) => score,
            _ => {
                return Err("fresh actual plan must retain the represented uniform sentinel".into())
            }
        };
        if !(1..=4096).contains(&(i128::from(plan.execution_domain.upper) - i128::from(plan.execution_domain.lower) + 1)) {
            return Err("invalid actual score domain".into());
        }
        println!(
            "{}",
            json!({"probe":PROBE,"stage":"public_plan","gallery_index":i,
            "execution_lower":plan.execution_domain.lower,"execution_upper":plan.execution_domain.upper,"sentinel":score})
        );
    }
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
        json!({"probe":PROBE,"stage":"fresh_key_generation","key_families":1,"unique_queries":5,"rayon_threads":16,
        "fft_policy":"user-provided-dif4-polynomial2048-base1024-v1"})
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
        .map(|q| {
            let values = encode(q)?;
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
        let mut results = Vec::new();
        for arm in ARMS {
            let out = evaluate(
                &keys,
                &encrypted[case.query],
                &template_views[case.gallery],
                plans[case.gallery].execution_domain,
                arm,
            )?;
            let id = verify(&big, &out, case.expected)?;
            decoded += 1;
            results.push(json!({"arm":arm,"id":id,"counts":{"br":out.counts.br,"ks":out.counts.ks,"pfks":out.counts.pfks,
                "marginals":out.counts.marginals,"initial_samples":out.counts.initial_samples},"terminal":out.terminal}));
        }
        println!(
            "{}",
            json!({"probe":PROBE,"stage":"correctness","case":case.name,"pass":true,"arms":results})
        );
    }
    if decoded != 12 {
        return Err("12-ID correctness gate required".into());
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"correctness_complete","pass":true,"decoded_id_outputs":12})
    );
    for case in &cases[..3] {
        for arm in ARMS {
            let out = evaluate(
                &keys,
                &encrypted[case.query],
                &template_views[case.gallery],
                plans[case.gallery].execution_domain,
                arm,
            )?;
            verify(&big, &out, case.expected)?;
            decoded += 1;
        }
    }
    for case in &cases[..3] {
        for repeat in 0..3 {
            for (order_index, order) in [[0usize, 1usize], [1, 0]].into_iter().enumerate() {
                let mut whole = [0u64; 2];
                let mut terminal = [0u64; 2];
                let mut ids = [0usize; 2];
                let mut reports = [json!(null), json!(null)];
                for i in order {
                    let out = evaluate(
                        &keys,
                        &encrypted[case.query],
                        &template_views[case.gallery],
                        plans[case.gallery].execution_domain,
                        ARMS[i],
                    )?;
                    whole[i] = out.whole_ns;
                    terminal[i] = out.terminal.duration_ns;
                    ids[i] = verify(&big, &out, case.expected)?;
                    decoded += 1;
                    reports[i] = json!({"counts":{"br":out.counts.br,"ks":out.counts.ks,"pfks":out.counts.pfks,
                        "marginals":out.counts.marginals,"initial_samples":out.counts.initial_samples},
                        "terminal_work":out.terminal.work,"terminal_scheduling":out.terminal.scheduling});
                }
                println!(
                    "{}",
                    json!({"probe":PROBE,"stage":"paired_cost","case":case.name,"repeat":repeat,"order_index":order_index,
                    "arm_order":order,"whole_duration_ns":whole,"terminal_duration_ns":terminal,"final_ids":ids,"arm_reports":reports,"pass":true})
                );
            }
        }
    }
    if decoded != 54 {
        return Err("54 decoded outputs required".into());
    }
    println!(
        "{}",
        json!({"probe":PROBE,"stage":"complete","pass":true,"decoded_id_outputs":decoded,
        "correctness_id_outputs":12,"warmup_id_outputs":6,"timed_id_outputs":36,
        "timing_boundary":"isolated fullquery diagnostic evaluation incl validation/work/report checks; terminal from last-root precomparison through threshold/report checks; excludes factory reset/keygen/encryption/decode/stdout; no HTTP/e2e",
        "scope":"one fresh family/three fixed same-source accept workloads; additional right/reject/tie correctness; no rare-failure/security/biometric/adoption guarantee"})
    );
    Ok(())
}
