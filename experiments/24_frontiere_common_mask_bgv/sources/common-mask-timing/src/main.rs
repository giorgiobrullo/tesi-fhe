//! Fixed complete-query timing pilot. All three clocks stop before client observation.
#![allow(dead_code)]
#![recursion_limit = "256"]
mod crypto;
mod endpoint;
mod gate_observer;
mod ingress;
mod joint_untraced;
mod model;
mod observe;
mod records;
mod scan_bridge;
mod timing_observers;
mod witness;
mod zero_pool;

use endpoint::Output;
use model::A44_DELTA;
use rayon::ThreadPoolBuilder;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};
use timing_observers::{ledger, physical};

const FIXTURE: &str = include_str!("../../fixture.json");
const PLAN: &str = include_str!("../../PLAN.json");
const SOURCE: &str = include_str!("../SOURCE_DIGEST.txt");
const ACK: &str = "ROOT_EXCLUSIVE_CM_NIBBLE_N16_TIMING";
const SCHEDULE: [[&str; 3]; 6] = [
    ["J", "R", "C"],
    ["C", "R", "J"],
    ["J", "C", "R"],
    ["R", "C", "J"],
    ["C", "J", "R"],
    ["R", "J", "C"],
];
fn emit(file: &mut BufWriter<std::fs::File>, row: Value) {
    serde_json::to_writer(&mut *file, &row).unwrap();
    file.write_all(b"\n").unwrap();
}
fn durable(file: &mut BufWriter<std::fs::File>) {
    file.flush().unwrap();
    file.get_ref().sync_all().unwrap();
}
fn integers(v: &Value) -> Vec<i64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_i64().unwrap())
        .collect()
}
fn unsigned(v: &Value) -> Vec<u64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect()
}
fn summary(file: &mut BufWriter<std::fs::File>, blocks: usize, failures: usize, precheck: bool) {
    emit(
        file,
        json!({"type":"summary","completed_blocks":blocks,"completed_calls":3*blocks,
        "precheck_pass":precheck,"failures":failures,"pass":precheck&&failures==0,
        "physical_ledger":physical(blocks),"key_resampling":false,"stop_after_first_completed_negative":true,
        "actual_p_fail":null,"timing_qualified":false}),
    );
    durable(file);
}
fn run(path: &Path) -> bool {
    assert!(path.is_absolute());
    let parent = fs::symlink_metadata(path.parent().unwrap()).unwrap();
    assert!(parent.is_dir() && !parent.file_type().is_symlink());
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::env::var("CM_NIBBLE_N16_TIMING_ACK").as_deref(),
        Ok(ACK)
    );
    assert_eq!(
        std::env::var("CM_NIBBLE_N16_TIMING_SOURCE").as_deref(),
        Ok(SOURCE.trim())
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("8"));
    let binary = observe::bytes_hash(&fs::read(std::env::current_exe().unwrap()).unwrap());
    assert_eq!(
        std::env::var("CM_NIBBLE_N16_TIMING_BINARY").as_deref(),
        Ok(binary.as_str())
    );
    let mut file = BufWriter::with_capacity(
        256 * 1024,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap(),
    );
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let plan_json: Value = serde_json::from_str(PLAN).unwrap();
    assert_eq!(plan_json["schedule"], json!(SCHEDULE));
    assert_eq!(fixture["id"], "changing_actives_id16");
    assert_eq!(fixture["expected"], 16);
    let query = integers(&fixture["query"]);
    let gallery: Vec<_> = fixture["gallery"]
        .as_array()
        .unwrap()
        .iter()
        .map(integers)
        .collect();
    let threshold = fixture["threshold"].as_i64().unwrap();
    let active = unsigned(&fixture["active"]);
    let values = unsigned(&fixture["values"]);
    let flags = unsigned(&fixture["flags"]);
    assert_eq!(query.len(), 512);
    assert_eq!(gallery.len(), 16);
    let templates: Vec<_> = gallery
        .iter()
        .map(|g| r3::TemplateView {
            template: g,
            norm2: g.iter().map(|x| x * x).sum(),
            threshold,
        })
        .collect();
    let cm_templates: Vec<_> = templates
        .iter()
        .map(|t| prefix::TemplateView {
            template: t.template,
            norm2: t.norm2,
            threshold: t.threshold,
        })
        .collect();
    let scores: Vec<_> = templates
        .iter()
        .map(|t| {
            t.norm2
                - 2 * t
                    .template
                    .iter()
                    .zip(&query)
                    .map(|(x, y)| x * y)
                    .sum::<i64>()
        })
        .collect();
    assert_eq!(scores, integers(&fixture["scores"]));
    assert_eq!(
        r3::clear_private_argmin(&scores, &templates).unwrap().code,
        16
    );
    let plan = r3::plan_private_argmin_execution(&templates).unwrap();
    assert!(plan.aligned_fast_path);
    assert_eq!(
        (plan.execution_domain.lower, plan.execution_domain.upper),
        (-1024, 1280)
    );
    emit(
        &mut file,
        json!({"type":"meta","schema":"cm-nibble-n16-timing.v1","source":SOURCE.trim(),
        "binary":binary,"pid":std::process::id(),"fixture_sha256":observe::bytes_hash(FIXTURE.as_bytes()),
        "plan_sha256":observe::bytes_hash(PLAN.as_bytes()),"n":16,"keys":1,"threads":8,"blocks":6,
        "warmup_blocks":2,"measured_blocks":4,"schedule":SCHEDULE,"arms":["J","C","R"],"packed_encryptions":6,"preclock_operations":5,
        "same_packed_bytes_within_block":true,"same_ordinary_key":true,"all_clocks_before_observations":true,
        "clock_scope":"complete packed query to two encrypted ID digits; required prefix, per-query LUTs, bridges and scan",
        "actual_p_fail":null,"timing_qualified":false}),
    );
    durable(&mut file);
    let pool = ThreadPoolBuilder::new().num_threads(8).build().unwrap();
    let total_setup_started = Instant::now();
    let started = Instant::now();
    let ordinary_client = ClientKey::new(crypto::A44);
    let server = pool.install(|| ServerKey::new(&ordinary_client));
    let ordinary_setup_ns = started.elapsed().as_nanos() as u64;
    r3::validate_a44_parameter_binding(r3::A44_PARAMETER_BINDING, &server).unwrap();
    prefix::validate_a44_parameter_binding(prefix::A44_PARAMETER_BINDING, &server).unwrap();
    let (ordinary_glwe, ordinary_small, parameters, _) = match ordinary_client.atomic_pattern {
        AtomicPatternClientKey::Standard(k) => k.into_raw_parts(),
        _ => panic!("standard client family required"),
    };
    let adapter_started = Instant::now();
    let (fbsk, ksk) = match &server.atomic_pattern {
        AtomicPatternServerKey::Standard(k) => match &k.bootstrapping_key {
            ShortintBootstrappingKey::Classic { bsk, .. } => {
                (bsk.clone(), k.key_switching_key.clone())
            }
            _ => panic!("classic bootstrap required"),
        },
        _ => panic!("standard server family required"),
    };
    let ordinary_adapter_clone_ns = adapter_started.elapsed().as_nanos() as u64;
    let ordinary_payload = [
        fbsk.as_view().data().len() * 16,
        std::mem::size_of_val(ksk.as_ref()),
    ];
    let ordinary_ksk_hash = observe::words_hash(ksk.as_ref());
    let started = Instant::now();
    let (client, key) = pool.install(|| {
        crypto::generate_keys_with_ordinary(ordinary_glwe.clone(), ordinary_small, fbsk, ksk)
    });
    let cm_setup_ns = started.elapsed().as_nanos() as u64;
    let total_key_materialization_ns = total_setup_started.elapsed().as_nanos() as u64;
    assert_eq!(
        client.ordinary_big.as_ref(),
        ordinary_glwe.as_lwe_secret_key().as_ref()
    );
    let bindings = crypto::persistent::key_bindings(&key);
    assert_eq!(bindings["ordinary_ksk_sha256"], ordinary_ksk_hash);
    let family = observe::bytes_hash(bindings.to_string().as_bytes());
    emit(
        &mut file,
        json!({"type":"key","family":family,"bindings":bindings,"ordinary_setup_ns":ordinary_setup_ns,
        "cm_setup_ns":cm_setup_ns,"ordinary_adapter_clone_ns":ordinary_adapter_clone_ns,
        "total_key_materialization_ns":total_key_materialization_ns,"ordinary_payload_bytes":ordinary_payload,
        "duplicate_ordinary_adapter_payload_bytes":ordinary_payload,"retained_ordinary_container_copies":2,
        "additional_cm_payload_bytes":key.added_payload_bytes,"unused_zero_pool_bytes":key.zero_pool_payload_bytes,
        "cm_setup_includes_unused_zero_pool":true,"payload_is_container_bytes_not_rss":true,"secrets_serialized":false}),
    );
    durable(&mut file);
    let mut plain = vec![0u64; 2048];
    for (i, &q) in query.iter().enumerate() {
        plain[i] = (q as u64).wrapping_mul(1 << r3::FULL_DELTA_LOG);
        plain[r3::LOW_MOD16_POLYNOMIAL_OFFSET + i] =
            (q as u64).wrapping_mul(1 << r3::LOW_MOD16_DELTA_LOG);
    }
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut packed_inputs = Vec::with_capacity(6);
    let mut packed_hashes = Vec::with_capacity(6);
    for index in 0..6 {
        let mut packed = GlweCiphertext::new(
            0u64,
            GlweSize(2),
            PolynomialSize(2048),
            CiphertextModulus::new_native(),
        );
        encrypt_glwe_ciphertext(
            &ordinary_glwe,
            &mut packed,
            &PlaintextList::from_container(plain.clone()),
            parameters.glwe_noise_distribution(),
            &mut generator,
        );
        assert!(packed.get_mask().as_ref().iter().any(|x| *x != 0));
        let hash = observe::words_hash(packed.as_ref());
        assert!(
            !packed_hashes.contains(&hash),
            "six distinct actual encryptions"
        );
        emit(
            &mut file,
            json!({"type":"input","index":index,"packed_words":packed.as_ref(),"packed_sha256":hash,
            "scores":scores,"domain":[plan.execution_domain.lower,plan.execution_domain.upper],"expected":16,"encryptions":1}),
        );
        packed_inputs.push(packed);
        packed_hashes.push(hash);
    }
    durable(&mut file);
    let packed = &packed_inputs[0];
    let joint = pool.install(|| endpoint::joint_materialize(&server, &key, packed, &cm_templates));
    let control = pool.install(|| endpoint::cm_materialize(&server, &key, packed, &cm_templates));
    let reference = pool
        .install(|| r3::nibble::parallel_diagnostic(&server, packed, &templates))
        .unwrap();
    let ordinary = match &server.atomic_pattern {
        AtomicPatternServerKey::Standard(k) => k,
        _ => panic!("Standard required"),
    };
    let bsk = match &ordinary.bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => bsk,
        _ => panic!("Classic required"),
    };
    let traced_keys = ingress::Keys {
        ksk: &ordinary.key_switching_key,
        bsk,
    };
    let traced = pool
        .install(|| ingress::prefix(&joint.full, &joint.low, ingress::Mode::Joint4, &traced_keys));
    let serial_keys = joint_untraced::Keys {
        ksk: &ordinary.key_switching_key,
        bsk,
    };
    let serial = pool.install(|| {
        joint_untraced::prefix(
            &joint.full,
            &joint.low,
            joint_untraced::Mode::Joint4,
            &serial_keys,
            false,
        )
    });
    // All six encryptions and all five preclock operations complete before any client observation.
    let mut inputs_pass = true;
    for (index, input) in packed_inputs.iter().enumerate() {
        let row = timing_observers::input_record(&ordinary_glwe, input, &plain, index);
        inputs_pass &= row["pass"] == true;
        emit(&mut file, row);
    }
    let normalized: Vec<_> = scores
        .iter()
        .map(|s| (s - plan.execution_domain.lower) as u64)
        .collect();
    let j_scores = timing_observers::score_record(&client, &joint.full, &joint.low, &normalized);
    let r_scores = timing_observers::score_record(
        &client,
        &reference.full,
        &reference.packed_low,
        &normalized,
    );
    let score_words_equal = timing_observers::vector_equal(&joint.full, &reference.full)
        && timing_observers::vector_equal(&joint.low, &reference.packed_low);
    let traced_serial_equal = timing_observers::prefix_equal(
        &traced.initial_candidates,
        &traced.bits_by_level,
        &serial.initial_candidates,
        &serial.bits_by_level,
    );
    let serial_parallel_equal = timing_observers::prefix_equal(
        &serial.initial_candidates,
        &serial.bits_by_level,
        &joint.producer.initial_candidates,
        &joint.producer.bits_by_level,
    );
    let j_producer = timing_observers::prefix_record(
        &client,
        &joint.producer.initial_candidates,
        &joint.producer.bits_by_level,
        &active,
        &values,
        (127, 127, 255),
    );
    let c_producer = timing_observers::prefix_record(
        &client,
        &control.producer.initial_candidates,
        &control.producer.bits_by_level,
        &active,
        &values,
        (239, 191, 303),
    );
    let j_flags = records::ordinary_vector(&client, &joint.flags, &flags, A44_DELTA);
    let c_flags = records::ordinary_vector(&client, &control.flags, &flags, A44_DELTA);
    let r_flags = records::ordinary_vector(
        &client,
        &reference.state.evaluation.flags,
        &flags,
        A44_DELTA,
    );
    let r_output = endpoint::r3_output(reference.endpoint);
    let j_digits = records::digits(&client, &joint.output.low, &joint.output.high, 16);
    let c_digits = records::digits(&client, &control.output.low, &control.output.high, 16);
    let r_digits = records::digits(&client, &r_output.low, &r_output.high, 16);
    let count_record = |br, ks, samples, scalar_muls, lwe_adds, lwe_subs, body_offsets| json!({"br":br,"ks":ks,"samples":samples,"scalar_muls":scalar_muls,"lwe_adds":lwe_adds,"lwe_subs":lwe_subs,"body_offsets":body_offsets});
    let t = &traced.counts;
    let s = &serial.counts;
    let p = &joint.producer.counts;
    let traced_counts = count_record(
        t.br,
        t.ks,
        t.samples,
        t.scalar_muls,
        t.lwe_adds,
        t.lwe_subs,
        t.body_offsets,
    );
    let serial_counts = count_record(
        s.br,
        s.ks,
        s.samples,
        s.scalar_muls,
        s.lwe_adds,
        s.lwe_subs,
        s.body_offsets,
    );
    let parallel_counts = count_record(
        p.br,
        p.ks,
        p.samples,
        p.scalar_muls,
        p.lwe_adds,
        p.lwe_subs,
        p.body_offsets,
    );
    let counts_equal = traced_counts == serial_counts && serial_counts == parallel_counts;
    let unchanged = packed_inputs
        .iter()
        .zip(&packed_hashes)
        .all(|(input, hash)| observe::words_hash(input.as_ref()) == *hash);
    let pass = inputs_pass
        && j_scores["pass"] == true
        && r_scores["pass"] == true
        && score_words_equal
        && traced_serial_equal
        && serial_parallel_equal
        && counts_equal
        && unchanged
        && j_producer["pass"] == true
        && c_producer["pass"] == true
        && records::canonical(&j_flags)
        && records::canonical(&c_flags)
        && records::canonical(&r_flags)
        && j_digits["pass"] == true
        && c_digits["pass"] == true
        && r_digits["pass"] == true;
    emit(
        &mut file,
        json!({"type":"precheck","key_family":family,"packed_sha256":packed_hashes[0],"all_inputs_unchanged":unchanged,
        "J_scores":j_scores,"R_scores":r_scores,"J_R_score_words_equal":score_words_equal,"C_scores_observed":false,
        "J_producer":j_producer,"C_producer":c_producer,
        "traced_prefix":timing_observers::prefix_words(&traced.initial_candidates,&traced.bits_by_level),
        "serial_prefix":timing_observers::prefix_words(&serial.initial_candidates,&serial.bits_by_level),
        "traced_serial_equal":traced_serial_equal,"serial_parallel_equal":serial_parallel_equal,
        "traced_counts":traced_counts,"serial_counts":serial_counts,"parallel_counts":parallel_counts,
        "counts_equal":counts_equal,"traced_event_count":traced.counts.events.len(),
        "J_flags":j_flags,"C_flags":c_flags,"R_flags":r_flags,"J_digits":j_digits,"C_digits":c_digits,"R_digits":r_digits,
        "J_ledger":ledger(&joint.output),"C_ledger":ledger(&control.output),"R_ledger":ledger(&r_output),
        "physical_ledger":physical(0),"pass":pass}),
    );
    durable(&mut file);
    drop((
        joint,
        control,
        r_output,
        reference.state,
        reference.full,
        reference.packed_low,
        traced,
        serial,
    ));
    if !pass {
        summary(&mut file, 0, 0, false);
        return false;
    }
    let mut failures = 0;
    let mut blocks = 0;
    for (block, order) in SCHEDULE.into_iter().enumerate() {
        let packed = &packed_inputs[block];
        let packed_hash = &packed_hashes[block];
        let mut completed = Vec::with_capacity(3);
        for (position, arm) in order.into_iter().enumerate() {
            let started = Instant::now();
            let out = pool.install(|| match arm {
                "J" => endpoint::joint_id(&server, &key, packed, &cm_templates),
                "C" => endpoint::cm_id(&server, &key, packed, &cm_templates),
                "R" => endpoint::r3_id(&server, packed, &templates),
                _ => unreachable!(),
            });
            let elapsed_ns = started.elapsed().as_nanos() as u64;
            completed.push((position, arm, out, elapsed_ns));
        }
        // Retain and charge the entire completed block even if the first output is negative.
        emit(
            &mut file,
            json!({"type":"block","index":block,"order":order,"warmup":block<2,"clocks_completed":3,"input_index":block}),
        );
        for (position, arm, out, elapsed_ns) in completed {
            let digits = records::digits(&client, &out.low, &out.high, 16);
            let unchanged = observe::words_hash(packed.as_ref()) == *packed_hash;
            let good = digits["pass"] == true && unchanged;
            failures += usize::from(!good);
            emit(
                &mut file,
                json!({"type":"call","block":block,"position":position,"arm":arm,"warmup":block<2,
                "key_family":family,"packed_sha256":packed_hash,"packed_unchanged":unchanged,"elapsed_ns":elapsed_ns,
                "digits":digits,"ledger":ledger(&out),"pass":good}),
            );
        }
        blocks += 1;
        emit(
            &mut file,
            json!({"type":"block_end","index":block,"pass":failures==0,"physical_ledger":physical(blocks)}),
        );
        durable(&mut file);
        if failures != 0 {
            break;
        }
    }
    summary(&mut file, blocks, failures, true);
    failures == 0
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--run" {
        match std::panic::catch_unwind(|| run(Path::new(&args[2]))) {
            Ok(true) => std::process::ExitCode::SUCCESS,
            Ok(false) => std::process::ExitCode::FAILURE,
            Err(_) => std::process::ExitCode::from(2),
        }
    } else {
        println!(
            "{}",
            json!({"schema":"cm-nibble-n16-timing.recipe.v1","source":SOURCE.trim(),"native_execution":false,
            "keys":1,"packed_encryptions":6,"blocks":6,"warmup_blocks":2,"measured_blocks":4,"schedule":SCHEDULE})
        );
        std::process::ExitCode::SUCCESS
    }
}
