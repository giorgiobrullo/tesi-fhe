//! Fixed binary tie-left primitive probe; no timing, secret observations or key retries.
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::Path, process::ExitCode};
use tfhe::core_crypto::{prelude::*, fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan}};
use tfhe::shortint::{atomic_pattern::AtomicPatternServerKey,
    client_key::atomic_pattern::AtomicPatternClientKey,
    parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS,
    server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey}};

type Ct = LweCiphertextOwned<u64>;
const DELTA: u64 = 1 << 59;
const CASES: [([u64; 2], [u64; 2]); 8] = [
    ([0,0],[0,0]), ([0,0],[0,1]), ([0,1],[0,0]), ([1,0],[0,15]),
    ([0,15],[1,0]), ([15,15],[0,0]), ([0,0],[15,15]), ([15,15],[15,15]),
];

fn save<T: Serialize>(dir: &Path, name: &str, value: &T) -> Value {
    let path = dir.join(name);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    bincode::serialize_into(&mut file, value).unwrap();
    file.sync_all().unwrap();
    let bytes = file.metadata().unwrap().len();
    let mut reader = File::open(&path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop { let n = reader.read(&mut buffer).unwrap(); if n == 0 { break; } hash.update(&buffer[..n]); }
    json!({"path":name,"bytes":bytes,"sha256":format!("{:x}",hash.finalize()),"encoding":"bincode-1.3.3"})
}

fn emit(log: &mut File, value: Value) {
    let line = serde_json::to_string(&value).unwrap();
    writeln!(log, "{line}").unwrap(); log.flush().unwrap(); println!("{line}");
}

fn encrypt(cks: &tfhe::shortint::ClientKey, value: u64, delta: u64,
           rng: &mut EncryptionRandomGenerator<DefaultRandomGenerator>) -> Ct {
    let (key, noise) = cks.encryption_key_and_noise();
    allocate_and_encrypt_new_lwe_ciphertext(&key, Plaintext(value.wrapping_mul(delta)),
        noise, CiphertextModulus::new_native(), rng)
}

fn difference(left: &Ct, right: &Ct) -> Ct {
    let mut result = left.clone();
    for (word, &other) in result.as_mut().iter_mut().zip(right.as_ref()) { *word = word.wrapping_sub(other); }
    result
}

fn ks(input: &Ct, key: &LweKeyswitchKeyOwned<u64>) -> Ct {
    let mut result = Ct::new(0, key.output_key_lwe_dimension().to_lwe_size(), input.ciphertext_modulus());
    keyswitch_lwe_ciphertext(key, input, &mut result); result
}

fn pbs(small: &Ct, bsk: &FourierLweBootstrapKeyOwned, binary: bool) -> Ct {
    let mut acc = GlweCiphertextOwned::new(0, GlweSize(2), PolynomialSize(2048), small.ciphertext_modulus());
    for (i, word) in acc.get_mut_body().as_mut().iter_mut().enumerate() {
        *word = if binary { match i { 0..=3 => DELTA.wrapping_neg(), 4 => 0, _ => DELTA } }
                else if (64..1984).contains(&i) { DELTA } else { 0 };
    }
    let switched = ModulusSwitchConfiguration::<u64>::Standard.lwe_ciphertext_modulus_switch::<usize,_>(
        small, bsk.polynomial_size().to_blind_rotation_input_modulus_log());
    blind_rotate_assign(&switched, &mut acc, bsk);
    let mut output = Ct::new(0, bsk.output_lwe_dimension().to_lwe_size(), small.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(&acc, &mut output, MonomialDegree(0)); output
}

fn centered(small: &Ct) -> Ct {
    assert_eq!(small.lwe_size().0, 860); assert!(small.ciphertext_modulus().is_native_modulus());
    let (_, correction, log) = lwe_ciphertext_centered_binary_modulus_switch::<u64,usize,_>(
        small.as_view(), CiphertextModulusLog(12)).into_raw_parts();
    assert_eq!(log.0, 12);
    let mut result = small.clone();
    *result.get_mut_body().data = small.get_body().data.wrapping_add(correction).wrapping_add(1 << 51);
    result
}

fn decode(cks: &tfhe::shortint::ClientKey, output: &Ct) -> Option<i8> {
    // Ordinary decryption only; expose only the rounded ternary, never the unrounded phase.
    let message = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1))
        .closest_representable(decrypt_lwe_ciphertext(&cks.encryption_key(), output).0) >> 59;
    match message { 0 => Some(0), 1 => Some(1), 31 => Some(-1), _ => None }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 2, "usage: probe NEW_OUTPUT_DIRECTORY");
    let dir = Path::new(&args[1]); fs::create_dir(dir).unwrap();
    let mut log = OpenOptions::new().write(true).create_new(true).open(dir.join("rows.jsonl")).unwrap();
    setup_custom_fft_plan(Plan::new(1024, Method::UserProvided { base_algo:FftAlgo::Dif4, base_n:1024 }));
    let cks = tfhe::shortint::ClientKey::new(PARAMS);
    assert!(matches!(&cks.atomic_pattern, AtomicPatternClientKey::Standard(_)));
    let sks = tfhe::shortint::ServerKey::new(&cks);
    let keys = [save(dir,"client-key.bin",&cks), save(dir,"server-key.bin",&sks)];
    assert_eq!(sks.message_modulus.0,2); assert_eq!(sks.carry_modulus.0,8);
    assert!(sks.ciphertext_modulus.is_native_modulus());
    let standard = match sks.atomic_pattern { AtomicPatternServerKey::Standard(k) => k, _ => panic!("not Standard") };
    assert_eq!(standard.pbs_order, tfhe::shortint::PBSOrder::KeyswitchBootstrap);
    let bsk = match standard.bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, modulus_switch_noise_reduction_key } => {
            assert!(matches!(modulus_switch_noise_reduction_key, ModulusSwitchConfiguration::Standard)); bsk
        }, _ => panic!("not Classic"),
    };
    let ksk = standard.key_switching_key;
    assert_eq!(bsk.input_lwe_dimension().0,859); assert_eq!(bsk.glwe_size().0,2);
    assert_eq!(bsk.polynomial_size().0,2048); assert_eq!(bsk.output_lwe_dimension().0,2048);
    assert_eq!(ksk.input_key_lwe_dimension().0,2048); assert_eq!(ksk.output_key_lwe_dimension().0,859);
    assert_eq!(cks.encryption_key().lwe_dimension().0,2048);
    emit(&mut log,json!({"kind":"metadata","schema":"binary-comparator-probe.v1","tfhe":"1.8.1",
        "rustc":option_env!("SCRATCH_BUILD_RUSTC").unwrap_or("external build receipt required"),
        "params":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64","small_lwe_dimension":859,
        "glwe_size":2,"polynomial_size":2048,"fft":"Dif4/base1024","keys":keys,
        "max_rows":8,"rounds":1,"reference_delta_bits":59,"candidate_delta_bits":55,"output_delta_bits":59,
        "lut":"binary-tie-left","candidate_body":{"negative":[0,3],"zero":[4],"positive":[5,2047]},
        "reference_pbs_per_case":3,"candidate_pbs_per_case":1,"mean_center":"stock public correction + 2^51 after KS",
        "scope":"fresh ordinary primitive only; no control refresh, Head, tournament, timing or failure bound"}));
    let mut seeder = new_seeder(); let seeder = seeder.as_mut();
    let mut rng = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(),seeder);
    let round = 0;
    for (index, &(left,right)) in CASES.iter().enumerate() {
        let difference_value = (16*left[0]+left[1]) as i64 - (16*right[0]+right[1]) as i64;
        let oracle = difference_value.signum() as i8;
        let oracle_binary: i8 = if difference_value > 0 { 1 } else { -1 };
        let mut reference_inputs = Vec::new(); let mut reference_outputs = Vec::new();
        let mut reference_decoded = Vec::new(); let mut reference_correct = true;
        for (l,r) in [(0,0),(left[0],right[0]),(left[1],right[1])] {
            let lct = encrypt(&cks,l,DELTA,&mut rng); let rct = encrypt(&cks,r,DELTA,&mut rng);
            let input = difference(&lct,&rct); let output = pbs(&ks(&input,&ksk),&bsk,false);
            let decoded = decode(&cks,&output);
            reference_correct &= decoded == Some((l as i64-r as i64).signum() as i8);
            reference_decoded.push(decoded); reference_inputs.extend([lct,rct,input]); reference_outputs.push(output);
        }
        let reference_sign = reference_decoded.iter().flatten().copied().find(|&x| x!=0).unwrap_or(0);
        reference_correct &= reference_sign == oracle;
        if !reference_correct {
            let preserved = [save(dir,"reference-failure-inputs.bin",&reference_inputs),save(dir,"reference-failure-outputs.bin",&reference_outputs)];
            emit(&mut log,json!({"kind":"case","status":"REFERENCE_FAILED","round":round,"case":index,
                "left":left,"right":right,"oracle":oracle,"oracle_binary":oracle_binary,"reference":reference_decoded,"preserved":preserved}));
            emit(&mut log,json!({"kind":"complete","status":"REFERENCE_FAILED","passed":false,"rows":index+1}));
            return ExitCode::from(1);
        }
        let inputs: Vec<_> = [left[0],right[0],left[1],right[1]].into_iter().map(|v|encrypt(&cks,v,1<<55,&mut rng)).collect();
        let mut packed = difference(&inputs[0],&inputs[1]); let low = difference(&inputs[2],&inputs[3]);
        for (word,&low_word) in packed.as_mut().iter_mut().zip(low.as_ref()) { *word = word.wrapping_mul(16).wrapping_add(low_word); }
        let small = ks(&packed,&ksk); let mean = centered(&small);
        let output = pbs(&mean,&bsk,true);
        let decoded = decode(&cks,&output); let candidate_correct = decoded == Some(oracle_binary);
        let mut preserved = Vec::new();
        if !candidate_correct {
            let mut all_inputs = inputs; all_inputs.extend([packed,small,mean]); all_inputs.extend(reference_inputs);
            let mut all_outputs = vec![output]; all_outputs.extend(reference_outputs);
            preserved.push(save(dir,"candidate-first-failure-inputs.bin",&all_inputs));
            preserved.push(save(dir,"candidate-first-failure-outputs.bin",&all_outputs));
        }
        emit(&mut log,json!({"kind":"case","status":if candidate_correct {"CANDIDATE_PASS"} else {"CANDIDATE_REJECTED"},
            "round":round,"case":index,"left":left,"right":right,"difference":difference_value,"oracle":oracle,
            "oracle_binary":oracle_binary,"reference":reference_decoded,"reference_correct":true,
            "candidate":decoded,"candidate_correct":candidate_correct,"preserved":preserved}));
        if !candidate_correct {
            emit(&mut log,json!({"kind":"complete","status":"CANDIDATE_REJECTED","passed":false,
                "rows":index+1})); return ExitCode::from(2);
        }
    }
    emit(&mut log,json!({"kind":"complete","status":"PRIMITIVE_PASS_8_CASES","passed":true,
        "rows":8})); ExitCode::SUCCESS
}
