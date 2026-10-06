//! Harness locale per A62: core A44 e scan A53 radix-15 group-of-four con due radici p16.
//!
//! Senza `--run` stampa soltanto il piano. Con `--run` genera una chiave effimera in memoria,
//! cifra un probe nullo fresco per ogni fixture ed esegue il core integrato. Non serializza chiavi
//! o ciphertext. Il core non decifra checkpoint: soltanto questo harness diagnostico possiede la
//! chiave client e verifica il solo codice finale e i confini fra A34-top, A36 e scan A53.

use a62_a53_a44_integrated_prototype::{
    a44_parameter_fingerprint_sha256, a62_aligned_operation_counts, clear_private_argmin,
    plan_private_argmin_execution, private_argmin_a62_with_trace,
    validate_a44_parameter_binding_text, ScoreDomain, TemplateView, A44_PARAMETER_BINDING,
    A44_PARAMETER_FINGERPRINT_SHA256, A44_PARAMS_ID, BOOL_DELTA_LOG, FULL_DELTA_LOG,
    LOW_MOD16_DELTA_LOG, LOW_MOD16_POLYNOMIAL_OFFSET, PROBE_DIM,
};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::{ClientKey, ServerKey};

const RADIX: usize = 15;
const GROUP_SIZE: usize = 4;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone, Debug)]
struct CaseSpec {
    name: String,
    threshold: i64,
    translated_scores: Vec<u64>,
    expected_code: u64,
    full_only: bool,
}

fn cases() -> Vec<CaseSpec> {
    let mut result: Vec<CaseSpec> = (0..16u64)
        .map(|high| {
            let translated = high << 8;
            CaseSpec {
                name: format!("n1_high_category_{high}"),
                threshold: 1023 - translated as i64,
                translated_scores: vec![translated],
                expected_code: u64::from(high <= 3),
                full_only: false,
            }
        })
        .collect();
    result.extend([
        CaseSpec {
            name: "n1_accept_boundary_1023".into(),
            threshold: 0,
            translated_scores: vec![1023],
            expected_code: 1,
            full_only: false,
        },
        CaseSpec {
            name: "n1_reject_boundary_1024".into(),
            threshold: -1,
            translated_scores: vec![1024],
            expected_code: 0,
            full_only: false,
        },
        CaseSpec {
            name: "n3_first_tie".into(),
            threshold: 4,
            translated_scores: vec![1019, 1019, 1020],
            expected_code: 1,
            full_only: false,
        },
        CaseSpec {
            name: "n3_second_identity".into(),
            threshold: 4,
            translated_scores: vec![1020, 1019, 1020],
            expected_code: 2,
            full_only: false,
        },
        CaseSpec {
            name: "n3_all_reject".into(),
            threshold: -1,
            translated_scores: vec![1024; 3],
            expected_code: 0,
            full_only: false,
        },
        last_identity_case(4),
        CaseSpec {
            name: "n4_tie_first".into(),
            threshold: 4,
            translated_scores: vec![1019, 1019, 1020, 1020],
            expected_code: 1,
            full_only: false,
        },
        last_identity_case(60),
        last_identity_case(64),
        last_identity_case(127),
        last_identity_case(128),
        CaseSpec {
            name: "n127_first_identity".into(),
            threshold: 4,
            translated_scores: {
                let mut scores = vec![1020; 127];
                scores[0] = 1019;
                scores
            },
            expected_code: 1,
            full_only: true,
        },
        CaseSpec {
            name: "n127_interior_tie_first_64".into(),
            threshold: 4,
            translated_scores: {
                let mut scores = vec![1020; 127];
                scores[63] = 1019;
                scores[126] = 1019;
                scores
            },
            expected_code: 64,
            full_only: true,
        },
        CaseSpec {
            name: "n127_accept_boundary_1023".into(),
            threshold: 0,
            translated_scores: vec![1023; 127],
            expected_code: 1,
            full_only: true,
        },
        CaseSpec {
            name: "n127_all_reject".into(),
            threshold: -1,
            translated_scores: vec![1024; 127],
            expected_code: 0,
            full_only: true,
        },
        CaseSpec {
            name: "n128_tail_tie_first_127".into(),
            threshold: 4,
            translated_scores: {
                let mut scores = vec![1020; 128];
                scores[126..].fill(1019);
                scores
            },
            expected_code: 127,
            full_only: true,
        },
    ]);
    result
}

fn last_identity_case(gallery_size: usize) -> CaseSpec {
    let mut translated_scores = vec![1020; gallery_size];
    translated_scores[gallery_size - 1] = 1019;
    CaseSpec {
        name: format!("n{gallery_size}_last_identity"),
        threshold: 4,
        translated_scores,
        expected_code: gallery_size as u64,
        full_only: true,
    }
}

fn squared_norm(vector: &[i64]) -> i64 {
    vector.iter().map(|value| value * value).sum()
}

fn template_for_raw_score(score: i64) -> Vec<i64> {
    let mut template = vec![0i64; PROBE_DIM];
    match score {
        0 => {}
        1 => template[0] = 1,
        _ => panic!("fixture A62 rappresentabile soltanto con score raw 0/1, ricevuto {score}"),
    }
    template
}

fn make_gallery(case: &CaseSpec, execution_lower: i64) -> Vec<Vec<i64>> {
    case.translated_scores
        .iter()
        .map(|translated| template_for_raw_score(*translated as i64 + execution_lower))
        .collect()
}

fn encrypt_zero_probe(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise_distribution: DynamicDistribution<u64>,
    polynomial_size: PolynomialSize,
    modulus: CiphertextModulus<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> Glwe {
    let mut plaintext = vec![0u64; polynomial_size.0];
    for coordinate in 0..PROBE_DIM {
        plaintext[coordinate] = 0u64 << FULL_DELTA_LOG;
        plaintext[LOW_MOD16_POLYNOMIAL_OFFSET + coordinate] = 0u64 << LOW_MOD16_DELTA_LOG;
    }
    let mut encrypted = GlweCiphertext::new(
        0u64,
        glwe_secret_key.glwe_dimension().to_glwe_size(),
        polynomial_size,
        modulus,
    );
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut encrypted,
        &PlaintextList::from_container(plaintext),
        noise_distribution,
        generator,
    );
    encrypted
}

fn decode(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe, delta_log: u32) -> u64 {
    decrypt_lwe_ciphertext(secret_key, ciphertext)
        .0
        .wrapping_add(1u64 << (delta_log - 1))
        >> delta_log
}

fn expected_top_candidates(scores: &[u64]) -> Vec<u64> {
    let minimum_category = scores
        .iter()
        .filter(|score| **score <= 1023)
        .map(|score| score >> 8)
        .min();
    scores
        .iter()
        .map(|score| {
            u64::from(
                minimum_category.is_some_and(|minimum| *score <= 1023 && (*score >> 8) == minimum),
            )
        })
        .collect()
}

fn expected_final_candidates(scores: &[u64]) -> Vec<u64> {
    let minimum = scores.iter().copied().min().expect("galleria non vuota");
    scores
        .iter()
        .map(|score| u64::from(minimum <= 1023 && *score == minimum))
        .collect()
}

fn reduction_nodes(mut items: usize) -> u64 {
    let mut nodes = 0u64;
    while items > 1 {
        let full = items / RADIX;
        let tail = items % RADIX;
        nodes += full as u64 + u64::from(tail >= 2);
        items = full + usize::from(tail > 0);
    }
    nodes
}

fn expected_stage_pbs(gallery_size: usize) -> [u64; 7] {
    let groups = gallery_size.div_ceil(GROUP_SIZE);
    let group_nodes = (0..gallery_size)
        .step_by(GROUP_SIZE)
        .filter(|&start| (gallery_size - start).min(GROUP_SIZE) > 1)
        .count() as u64;
    let prefix_nodes = {
        fn count(items: usize) -> u64 {
            if items <= 2 {
                return 0;
            }
            if items <= RADIX {
                return (items - 2) as u64;
            }
            let mut totals = 0u64;
            let mut expansion = 0u64;
            let mut blocks = 0usize;
            for start in (0..items).step_by(RADIX) {
                let len = (items - start).min(RADIX);
                blocks += 1;
                totals += u64::from(len > 1);
                expansion += if start == 0 {
                    len.saturating_sub(2) as u64
                } else {
                    (len - 1) as u64
                };
            }
            totals + expansion + count(blocks)
        }
        count(groups)
    };
    let extract = 13 * gallery_size as u64;
    let select = 12 * gallery_size as u64 + 8 * reduction_nodes(gallery_size) - 1;
    let scan = 2 * group_nodes + prefix_nodes + groups as u64 + 2 * reduction_nodes(groups);
    [0, 0, extract, select, scan, 0, 0]
}

fn validate_case(
    case: &CaseSpec,
    key_block: usize,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    secret_key: &LweSecretKeyView<'_, u64>,
) {
    let raw_scores = case
        .translated_scores
        .iter()
        .map(|score| *score as i64 + domain.lower)
        .collect::<Vec<_>>();
    let clear = clear_private_argmin(&raw_scores, templates).expect("oracolo clear A62");
    assert_eq!(clear.code, case.expected_code, "{} clear", case.name);

    let started = Instant::now();
    let (output, trace) = private_argmin_a62_with_trace(
        A44_PARAMETER_BINDING,
        server_key,
        packed_probe,
        templates,
        domain,
    )
    .expect("core A62 ha rifiutato una fixture valida");
    validate_a44_parameter_binding_text(output.parameter_binding)
        .expect("binding risposta A44 non valido");
    assert_eq!(output.parameter_binding, A44_PARAMETER_BINDING);
    let counts = a62_aligned_operation_counts(templates.len()).expect("conteggio A62");
    let stages = [
        output.metrics.setup.pbs_count,
        output.metrics.score.pbs_count,
        output.metrics.extract.pbs_count,
        output.metrics.select.pbs_count,
        output.metrics.scan.pbs_count,
        output.metrics.threshold.pbs_count,
        output.metrics.output.pbs_count,
    ];
    assert_eq!(stages, expected_stage_pbs(templates.len()));
    assert_eq!(stages.iter().sum::<u64>(), counts.blind_rotations);
    assert_eq!(output.metrics.total_pbs_count, counts.blind_rotations);

    let low = decode(secret_key, &output.low_digit, BOOL_DELTA_LOG) & 15;
    let high = decode(secret_key, &output.high_digit, BOOL_DELTA_LOG) & 15;
    let code = low + 15 * high;
    assert_eq!(code, case.expected_code, "{} FHE", case.name);
    let decoded_top = trace
        .aligned_initial_candidates
        .iter()
        .map(|candidate| decode(secret_key, candidate, BOOL_DELTA_LOG) & 1)
        .collect::<Vec<_>>();
    assert_eq!(
        decoded_top,
        expected_top_candidates(&case.translated_scores),
        "{} confine A34-top/A36",
        case.name
    );
    let decoded_final = trace
        .candidates_by_level
        .last()
        .expect("otto livelli A36")
        .iter()
        .map(|candidate| decode(secret_key, candidate, BOOL_DELTA_LOG) & 1)
        .collect::<Vec<_>>();
    assert_eq!(
        decoded_final,
        expected_final_candidates(&case.translated_scores),
        "{} confine A36/scan",
        case.name
    );
    assert_eq!(
        decode(
            secret_key,
            trace.a53_low_digit.as_ref().expect("radice low A53"),
            BOOL_DELTA_LOG,
        ) & 15,
        low,
        "{} trace low",
        case.name
    );
    assert_eq!(
        decode(
            secret_key,
            trace.a53_high_digit.as_ref().expect("radice high A53"),
            BOOL_DELTA_LOG,
        ) & 15,
        high,
        "{} trace high",
        case.name
    );
    assert!(trace.final_code.is_none());
    assert_eq!(trace.candidates_by_level.len(), 8);
    assert!(trace.a38_scan_group_flags.is_empty());
    assert!(trace.a38_scan_local_first.is_empty());
    assert!(trace.a38_scan_low_digits.is_empty());
    assert!(trace.a38_scan_high_digits.is_empty());
    let expected_scan = trace.a53_expected_counts.expect("contatori A53 attesi");
    let observed_scan = trace.a53_observed_counts.expect("contatori A53 osservati");
    assert_eq!(expected_scan, observed_scan);
    assert_eq!(expected_scan.blind_rotations, stages[4]);
    assert!(trace.winners.is_empty());
    println!(
        "PASS,case={},key_block={},N={},code={},low={},high={},pbs={},ks={},marginals={},wire_lwes=2,root_delta_log={},internal_radix=15,group_size=4,server_recomposition=false,client_reconstruction=low+15*high,params_id={},params_fingerprint_sha256={},eval_s={:.6}",
        case.name,
        key_block,
        templates.len(),
        code,
        low,
        high,
        counts.blind_rotations,
        counts.key_switches,
        counts.output_marginals,
        BOOL_DELTA_LOG,
        A44_PARAMS_ID,
        A44_PARAMETER_FINGERPRINT_SHA256,
        started.elapsed().as_secs_f64()
    );
}

fn main() {
    let n127 = a62_aligned_operation_counts(127).expect("fixture N=127");
    assert_eq!(n127.blind_rotations, 3390);
    assert_eq!(n127.key_switches, 3009);
    assert_eq!(n127.output_marginals, 3930);
    assert_eq!(
        a44_parameter_fingerprint_sha256(),
        A44_PARAMETER_FINGERPRINT_SHA256
    );
    validate_a44_parameter_binding_text(A44_PARAMETER_BINDING)
        .expect("binding parametro A44 compilato");
    assert_eq!(PARAMS.message_modulus.0, 2);
    assert_eq!(PARAMS.carry_modulus.0, 8);
    assert_eq!(PARAMS.max_noise_level.get(), 15);
    assert_eq!(PARAMS.lwe_dimension.0, 859);
    assert_eq!(PARAMS.glwe_dimension.0, 1);
    assert_eq!(PARAMS.polynomial_size.0, 2048);
    assert_eq!(PARAMS.pbs_base_log.0, 23);
    assert_eq!(PARAMS.pbs_level.0, 1);
    assert_eq!(PARAMS.ks_base_log.0, 3);
    assert_eq!(PARAMS.ks_level.0, 5);
    assert_eq!(PARAMS.log2_p_fail, -64.088);
    let args = std::env::args().collect::<Vec<_>>();
    let key_blocks = args
        .iter()
        .find_map(|argument| argument.strip_prefix("--keys="))
        .map(|value| value.parse::<usize>().expect("--keys richiede un intero"))
        .unwrap_or(1);
    assert!(
        (1..=16).contains(&key_blocks),
        "--keys deve essere in 1..=16"
    );
    if !args.iter().any(|argument| argument == "--run") {
        println!(
            "PLAN,variant=a62_a53_a44_integrated,source_graph=a44_plus_a50_selection_plus_a53_scan,implemented=true,compiled=false,component_fhe_validated=false,N127_BR=3390,N127_KS=3009,N127_marginals=3930,wire_output_lwes=2,root_delta_log=59,server_recomposition=false,client_reconstruction=low+15*high,params_id={},params_fingerprint_sha256={},max_noise_level=15,requested_key_blocks={}",
            A44_PARAMS_ID,
            A44_PARAMETER_FINGERPRINT_SHA256,
            key_blocks
        );
        return;
    }
    let small_only = args.iter().any(|argument| argument == "--small-only");
    let requested_cases = args
        .iter()
        .filter_map(|argument| argument.strip_prefix("--case="))
        .collect::<Vec<_>>();
    let selected = cases()
        .into_iter()
        .filter(|case| {
            (!small_only || !case.full_only)
                && (requested_cases.is_empty()
                    || requested_cases
                        .iter()
                        .any(|requested| *requested == case.name))
        })
        .collect::<Vec<_>>();
    assert!(
        !selected.is_empty(),
        "nessuna fixture A62 corrisponde ai filtri richiesti"
    );

    println!(
        "PARAMETER,params_id={},fingerprint_sha256={},tfhe=0.11.3,symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,message_modulus=2,carry_modulus=8,max_noise_level=15,lwe_dimension=859,glwe_dimension=1,polynomial_size=2048,log2_p_fail=-64.088,cross_decrypt_compatible=false",
        A44_PARAMS_ID, A44_PARAMETER_FINGERPRINT_SHA256
    );

    for key_block in 0..key_blocks {
        let key_started = Instant::now();
        let client_key = ClientKey::new(PARAMS);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let polynomial_size = glwe_secret_key.polynomial_size();
        let modulus = CiphertextModulus::<u64>::new_native();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        println!(
            "KEY,key_block={},generation_s={:.6},ephemeral=true,secret_material_persisted=false,params_id={},params_fingerprint_sha256={}",
            key_block,
            key_started.elapsed().as_secs_f64(),
            A44_PARAMS_ID,
            A44_PARAMETER_FINGERPRINT_SHA256
        );

        for case in &selected {
            let execution_lower = case.threshold - 1023;
            let gallery = make_gallery(case, execution_lower);
            let templates = gallery
                .iter()
                .map(|template| TemplateView {
                    template,
                    norm2: squared_norm(template),
                    threshold: case.threshold,
                })
                .collect::<Vec<_>>();
            let plan = plan_private_argmin_execution(&templates).expect("planner A62");
            assert!(
                plan.aligned_fast_path,
                "{} non allineato per A62",
                case.name
            );
            assert_eq!(plan.execution_domain.lower, execution_lower);
            let packed_probe = encrypt_zero_probe(
                &glwe_secret_key,
                client_params.glwe_noise_distribution(),
                polynomial_size,
                modulus,
                &mut generator,
            );
            validate_case(
                case,
                key_block,
                &server_key,
                &packed_probe,
                &templates,
                plan.execution_domain,
                &big_secret_key,
            );
        }
    }
    println!(
        "SUMMARY,status=PASS,variant=a62_a53_a44_integrated,cases_per_key={},key_blocks={},total_evaluations={},keys=ephemeral_in_memory,secret_material_persisted=false,params_id={},params_fingerprint_sha256={}",
        selected.len(),
        key_blocks,
        selected.len() * key_blocks,
        A44_PARAMS_ID,
        A44_PARAMETER_FINGERPRINT_SHA256
    );
}
