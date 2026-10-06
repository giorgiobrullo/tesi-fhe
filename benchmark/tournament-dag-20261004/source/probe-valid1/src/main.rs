use core_runtime::{
    classic_batch, composite, dag_scheduler, selector_parallel,
    service::{self, EvaluationKeys, TemplateView},
    smallcuts,
};
use rayon::ThreadPoolBuilder;
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    time::Instant,
};
use tfhe::{
    core_crypto::prelude::*,
    shortint::{
        client_key::atomic_pattern::AtomicPatternClientKey,
        parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        ClientKey, ServerKey,
    },
};
fn emit(v: Value) {
    println!("{v}");
    io::stdout().flush().unwrap();
}
struct Fixture {
    name: &'static str,
    templates: Vec<Vec<i64>>,
    thresholds: Vec<i64>,
}
fn fixture(name: &'static str) -> Fixture {
    let mut templates = Vec::new();
    let mut thresholds = Vec::new();
    for i in 0..120 {
        let mut t = vec![0; 512];
        for (j, x) in t.iter_mut().take(16).enumerate() {
            *x = if j % 2 == 0 { 1 } else { -1 };
        }
        if i != 75 && i != 119 {
            t[16 + i % 64] = (1 + i % 3) as i64;
        }
        templates.push(t);
        thresholds.push(match name {
            "uniform_reject" => -17,
            "all_reject" => i64::MIN,
            "mixed" | "mixed_reject" => [-17, -16, 0][i % 3],
            _ => -16,
        });
    }
    if name == "mixed" {
        thresholds[75] = -16;
        thresholds[119] = 0;
    }
    if name == "mixed_reject" {
        thresholds[75] = -17;
        thresholds[119] = 0;
    }
    Fixture {
        name,
        templates,
        thresholds,
    }
}
fn decode(p: u64) -> usize {
    let r = (u128::from(p) + (1u128 << 58)) >> 59;
    let d = if r == 32 { 0 } else { r as usize };
    assert!(d < 15, "decoded digit outside base15");
    d
}
fn run(
    f: &Fixture,
    dag: bool,
    keys: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    secret: &LweSecretKeyView<'_, u64>,
    round: usize,
    kind: &str,
) -> Value {
    composite::begin_query(composite::Mode::PublicParallel, false);
    smallcuts::set_profiling(false);
    dag_scheduler::set_enabled(dag);
    let entries: Vec<_> = f
        .templates
        .iter()
        .zip(&f.thresholds)
        .map(|(template, &threshold)| TemplateView {
            template,
            norm2: template.iter().map(|x| x * x).sum(),
            threshold,
        })
        .collect();
    let domain = service::plan(&entries).unwrap().execution_domain;
    let scores: Vec<i64> = f
        .templates
        .iter()
        .map(|t| {
            t.iter().map(|x| x * x).sum::<i64>()
                - 2 * t
                    .iter()
                    .take(16)
                    .enumerate()
                    .map(|(j, x)| x * if j % 2 == 0 { 1 } else { -1 })
                    .sum::<i64>()
        })
        .collect();
    let winner = scores
        .iter()
        .enumerate()
        .min_by_key(|&(i, &s)| (s, i))
        .unwrap()
        .0;
    let expected = if scores[winner] <= f.thresholds[winner] {
        winner + 1
    } else {
        0
    };
    let start = Instant::now();
    let (lo, mi, hi, c) = keys
        .evaluate_public_thresholds(packed, &entries, domain, true)
        .unwrap();
    let ns = start.elapsed().as_nanos() as u64;
    // Decode only the public synthetic result; no phase values or ciphertext words are logged.
    let got = decode(decrypt_lwe_ciphertext(secret, &lo).0)
        + 15 * decode(decrypt_lwe_ciphertext(secret, &mi).0)
        + 225 * decode(decrypt_lwe_ciphertext(secret, &hi).0);
    let ok = got == expected;
    let result = json!({"kind":kind,"family":f.name,"round":round,"arm":if dag{"dag"}else{"barrier"},"ns":ns,"expected":expected,"got":got,"correct":ok,"counts":{"br":c.br,"ks":c.ks,"pfks":c.pfks,"marginals":c.marginals,"initial_samples":c.initial_samples},"classic":classic_batch::report(),"selector":selector_parallel::report()});
    emit(result.clone());
    assert!(ok, "first correctness failure stops this one-key campaign");
    result
}
fn matching(a: &Value, b: &Value) {
    for field in ["counts", "classic", "selector", "expected", "got"] {
        assert_eq!(a[field], b[field], "scheduler changed invariant {field}");
    }
}
fn main() {
    ThreadPoolBuilder::new().num_threads(16).build().unwrap().install(|| {
  emit(json!({"kind":"start","n":120,"d":512,"threads":rayon::current_num_threads(),"key_families":1,"rounds":4,"g4":false,"profiling":false,"private_payload_logging":false}));
  // Admit every deterministic synthetic gallery before generating any key.
  for name in ["uniform", "uniform_reject", "mixed", "mixed_reject", "all_reject"] {
    let f=fixture(name);
    let entries:Vec<_>=f.templates.iter().zip(&f.thresholds).map(|(template,&threshold)|TemplateView{template,norm2:template.iter().map(|x|x*x).sum(),threshold}).collect();
    let plan=service::plan(&entries).expect("public fixture must be admitted before keygen");
    assert!(f.templates.iter().flatten().all(|x|(-3..=3).contains(x)));
    emit(json!({"kind":"fixture_admitted","family":name,"n":entries.len(),"domain_lower":plan.execution_domain.lower,"domain_upper":plan.execution_domain.upper,"keys_generated":0}));
  }
  let begin=Instant::now();let client=ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);let ordinary=ServerKey::new(&client);
  let (glwe,_,params,_)=match client.clone().atomic_pattern {AtomicPatternClientKey::Standard(k)=>k.into_raw_parts(),_=>panic!("Standard required")};
  let keys=EvaluationKeys::from_bundle(service::generate_bundle(&client,ordinary).unwrap()).unwrap();
  let mut coeff=vec![0u64;2048];for j in 0..16 {let v=if j%2==0{1i64}else{-1};coeff[j]=(v as u64).wrapping_mul(1u64<<51);coeff[1024+j]=(v.rem_euclid(16) as u64).wrapping_mul(1u64<<60);}
  let mut packed=GlweCiphertextOwned::new(0,GlweSize(2),PolynomialSize(2048),CiphertextModulus::new_native());
  let mut boxseed=new_seeder();let seeder=boxseed.as_mut();let mut rng=EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(),seeder);
  encrypt_glwe_ciphertext(&glwe,&mut packed,&PlaintextList::from_container(coeff),params.glwe_noise_distribution(),&mut rng);
  emit(json!({"kind":"keys_ready","keygen_encrypt_ns":begin.elapsed().as_nanos() as u64,"fixed_family":"1.8.1/v0_11/M1C3/small859/GLWE1/N2048","serialized_keys":0}));
  let secret=glwe.as_lwe_secret_key();
  for name in ["uniform","uniform_reject","mixed","mixed_reject","all_reject"] {
   let f=fixture(name);let a=run(&f,false,&keys,&packed,&secret,0,"correctness");let b=run(&f,true,&keys,&packed,&secret,0,"correctness");matching(&a,&b);
  }
  let families=[fixture("uniform"),fixture("mixed")];
  for f in &families {let a=run(f,false,&keys,&packed,&secret,0,"warmup");let b=run(f,true,&keys,&packed,&secret,0,"warmup");matching(&a,&b);}
  for round in 0..4 {for f in &families {
   let order=if round%2==0{[false,true]}else{[true,false]};let a=run(f,order[0],&keys,&packed,&secret,round,"timed");let b=run(f,order[1],&keys,&packed,&secret,round,"timed");matching(&a,&b);
  }}
  emit(json!({"kind":"complete","queries":30,"timed_queries":16,"all_correct":true,"matching_ledgers_and_counters":true,"key_families":1,"no_retry":true}));
 });
}
