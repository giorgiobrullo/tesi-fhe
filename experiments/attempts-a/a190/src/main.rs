mod crypto;
mod model;
mod observe;
mod zero_pool;
use crypto::{ordinary, persistent};
use crypto::{Domain, Mutation};
use serde_json::{json, Value};
use std::io::{self, Write};
use zero_pool::Policy;
const SOURCE: &str = include_str!("../SOURCE_DIGEST.txt");
const ACK: &str = "A190_FIXED_N4_PERSISTENT_AUTHORIZED";
const ACTIVE: [u64; 4] = [1, 1, 1, 0];
const VALUES: [u64; 4] = [173, 174, 173, 0];
const EXPECTED: [u64; 4] = [1, 0, 1, 0];
const RESET: [u64; 4] = [0, 1, 0, 0];
fn emit(v: Value) {
    let mut o = io::stdout().lock();
    writeln!(o, "{v}").unwrap();
    o.flush().unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--plan"] {
        emit(
            json!({"type":"plan","status":"NO_KEYGEN_SOURCE_ONLY_PLAN","source":SOURCE.trim(),"fixture":"n4_tie_dead_feedback_173_174","fresh_keys":1,"arms":["ordinary_u8","plain","shared_zero","reset_plain"],"automatic_expansion":false}),
        );
        return;
    }
    if args != ["--run-first"]
        || std::env::var("A190_RUN_ACK").unwrap_or_default() != ACK
        || std::env::var("A190_SOURCE_SHA256").unwrap_or_default() != SOURCE.trim()
    {
        eprintln!("invalid explicit A190 invocation");
        std::process::exit(2);
    }
    let binary = std::env::var("A190_BINARY_SHA256").unwrap_or_default();
    if binary.len() != 64 || !binary.bytes().all(|x| x.is_ascii_hexdigit()) {
        eprintln!("missing binary binding");
        std::process::exit(2);
    }
    let executable = std::env::current_exe().expect("actual executable");
    if !executable
        .components()
        .any(|x| x.as_os_str() == "target-a190-only")
        || observe::bytes_hash(&std::fs::read(&executable).expect("actual binary bytes")) != binary
        || std::env::var("RAYON_NUM_THREADS").unwrap_or_default() != "1"
    {
        eprintln!("actual isolated binary/thread binding failed");
        std::process::exit(2);
    }
    emit(
        json!({"type":"meta","schema":"a190-persistent-v1","source":SOURCE.trim(),"binary":binary,"pid":std::process::id(),"fixture":"n4_tie_dead_feedback_173_174","active":ACTIVE,"values":VALUES,"expected":EXPECTED,"reset_expected":RESET,"fresh_keys":1,"timing_claim":false,"full_id_claim":false,"actual_p_fail":null,"client_local":true,"actual_u8_extraction_inputs":false}),
    );
    let (client, key) = crypto::generate_keys();
    let bindings = persistent::key_bindings(&key);
    let family = observe::bytes_hash(bindings.to_string().as_bytes());
    emit(
        json!({"type":"key","family":family,"bindings":bindings,"domains":{"ordinary_small":859,"ordinary_big":2048,"cm_small":772,"cm_big":1536,"lanes":4},"secret_serialized":false,"membership_attested":false}),
    );
    let aa = crypto::client_encrypt(&client, &ACTIVE);
    let bb: Vec<_> = model::LAYOUTS
        .iter()
        .map(|l| crypto::client_encrypt(&client, &VALUES.map(|x| (x >> l.bit) & 1)))
        .collect();
    let (active, bits, prepared, preparation_pbs) = persistent::prepare(&key, &aa, &bb);
    let saved_active: Vec<_> = active.iter().map(|x| x.as_ref().to_vec()).collect();
    let saved_bits: Vec<Vec<_>> = bits
        .iter()
        .map(|r| r.iter().map(|x| x.as_ref().to_vec()).collect())
        .collect();
    // Four whole server paths finish before any client phase/degree observation.
    let ordinary = ordinary::run(&key, &active, &bits);
    let plain = persistent::run(&key, &active, &bits, Policy::Plain, false);
    let shared = persistent::run(
        &key,
        &active,
        &bits,
        Policy::SharedZerosStockAssumption,
        false,
    );
    let reset = persistent::run(&key, &active, &bits, Policy::Plain, true);
    let unchanged = active
        .iter()
        .zip(&saved_active)
        .all(|(a, b)| a.as_ref() == b)
        && bits
            .iter()
            .zip(&saved_bits)
            .all(|(r, s)| r.iter().zip(s).all(|(a, b)| a.as_ref() == b));
    emit(
        json!({"type":"preparation","ordinary_pbs":preparation_pbs,"small_encrypted":36,"active":active.iter().map(|x|observe::lwe(&client,x,Domain::A44Big,0)).collect::<Vec<_>>(),"bits":bits.iter().map(|r|r.iter().map(|x|observe::lwe(&client,x,Domain::A44Big,0)).collect::<Vec<_>>()).collect::<Vec<_>>(),"traces":observe::traces(&client,&prepared),"inputs_unchanged":unchanged}),
    );
    let ordinary_decoded = observe::canonical(&client, &ordinary.outputs);
    emit(
        json!({"type":"ordinary","arm":"ordinary_u8","original_active_sha256":ordinary.original_active.iter().map(|x|observe::words_hash(x.as_ref())).collect::<Vec<_>>(),"original_bits_sha256":ordinary.original_bits.iter().map(|r|r.iter().map(|x|observe::words_hash(x.as_ref())).collect::<Vec<_>>()).collect::<Vec<_>>(),"key_family":family,"ordinary_ks":ordinary.ordinary_ks,"ordinary_pbs":ordinary.ordinary_pbs,
  "states":ordinary.states.iter().map(|s|json!({"tag":s.tag,"values":s.values.iter().map(|x|observe::lwe(&client,x,Domain::A44Big,0)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
  "events":ordinary.events.iter().map(|e|json!({"tag":e.tag,"input":observe::lwe(&client,&e.input,Domain::A44Big,0),"small":observe::lwe(&client,&e.small,Domain::A44Small,0),"output":observe::lwe(&client,&e.output,Domain::A44Big,0),"lut_words":e.lut.as_ref(),"lut_sha256":observe::words_hash(e.lut.as_ref())})).collect::<Vec<_>>(),"decoded":ordinary_decoded}),
    );
    for (name, r) in [
        ("plain", &plain),
        ("shared_zero", &shared),
        ("reset_plain", &reset),
    ] {
        emit(observe::chain(&client, r, name, &family));
    }
    let expected_counts = model::Counts {
        packing: 17,
        cm_ks: 16,
        cm_pbs: 17,
        ordinary_ks: 44,
        ordinary_pbs: 28,
        extraction: 36,
    };
    let predicates = json!({"input_bytes_unchanged":unchanged,"preparation_exact_36":preparation_pbs==36,"ordinary_graph_48":ordinary.ordinary_ks==48&&ordinary.ordinary_pbs==48,
   "ordinary_flags":ordinary_decoded==EXPECTED,"plain_complete":plain.completed,"shared_complete":shared.completed,"reset_complete":reset.completed,
   "plain_flags":observe::canonical(&client,&plain.outputs)==EXPECTED,"shared_flags":observe::canonical(&client,&shared.outputs)==EXPECTED,
   "reset_wrong_flags_detected":observe::canonical(&client,&reset.outputs)==RESET&&RESET!=EXPECTED,
   "three_cm_ledgers":plain.counts==expected_counts&&shared.counts==expected_counts&&reset.counts==expected_counts});
    let pass = predicates
        .as_object()
        .unwrap()
        .values()
        .all(|x| x.as_bool() == Some(true));
    emit(
        json!({"type":"summary","predicates":predicates,"gate_pass":pass,"status":if pass{"FIRST_N4_NATIVE_FLAGS_COMPLETE_REPLAY_REQUIRED"}else{"FAILED_OR_REFUSED_FIRST_N4"},"output_flags":ordinary.outputs.len()+plain.outputs.len()+shared.outputs.len()+reset.outputs.len(),"key_resampling":false,"stock_variance_justified":false,"full_id_claim":false,"timing_claim":false,"actual_p_fail":null}),
    );
    let _ = Mutation::None; // Frozen upstream control type remains in preserved module.
    if !pass {
        std::process::exit(1);
    }
}
