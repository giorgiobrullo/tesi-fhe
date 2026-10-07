use std::env;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    cm_fft64::programmable_bootstrap_cm_lwe_ciphertext,
    cm_generate_programmable_bootstrap_glwe_lut,
    cm_lwe_keyswitch_key_generation::allocate_and_generate_new_cm_lwe_keyswitch_key,
    par_generate_cm_lwe_bootstrap_key, CM_PARAM_4_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v1_6::classic::tuniform::p_fail_2_minus_64::ks_pbs::V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::ClassicPBSParameters;

const LANES: usize = 4;

#[derive(Clone, Copy)]
struct Config {
    fresh_keys: usize,
    warmups: usize,
    samples: usize,
    benchmark: bool,
}

impl Config {
    fn parse() -> Self {
        let mut config = Self {
            fresh_keys: 1,
            warmups: 1,
            samples: 3,
            benchmark: true,
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--keys" => {
                    config.fresh_keys = args.next().expect("missing --keys value").parse().unwrap()
                }
                "--warmups" => {
                    config.warmups = args
                        .next()
                        .expect("missing --warmups value")
                        .parse()
                        .unwrap()
                }
                "--samples" => {
                    config.samples = args
                        .next()
                        .expect("missing --samples value")
                        .parse()
                        .unwrap()
                }
                "--no-bench" => config.benchmark = false,
                other => panic!("unknown argument: {other}"),
            }
        }
        assert!(config.fresh_keys > 0);
        assert!(config.samples > 0);
        config
    }
}

#[derive(Default, Clone, Copy)]
struct CommonTiming {
    initial_pack: Duration,
    bridge_stage1: Duration,
    repack_stage1: Duration,
    pbs_stage1: Duration,
    cm_ks: Duration,
    bridge_stage2: Duration,
    repack_stage2: Duration,
    pbs_stage2: Duration,
    total: Duration,
}

#[derive(Default, Clone, Copy)]
struct DirectTiming {
    initial_pack: Duration,
    mix_stage1: Duration,
    pbs_stage1: Duration,
    cm_ks: Duration,
    mix_stage2: Duration,
    pbs_stage2: Duration,
    total: Duration,
}

#[derive(Default, Clone, Copy)]
struct OrdinaryTiming {
    ks_stage1: Duration,
    pbs_stage1: Duration,
    ks_stage2: Duration,
    pbs_stage2: Duration,
    total: Duration,
}

struct KeyBytes {
    cm_fourier_bsk: usize,
    cm_ksk: usize,
    cm_packing: usize,
    cm_lane_to_bridge_ksks: usize,
    ordinary_fourier_bsk: usize,
    ordinary_ksk: usize,
}

struct Keys {
    bridge_sk: LweSecretKeyOwned<u64>,
    ordinary_fbsk: FourierLweBootstrapKeyOwned,
    ordinary_ksk: LweKeyswitchKeyOwned<u64>,
    ordinary_accumulator: GlweCiphertextOwned<u64>,
    cm_big_sks: Vec<LweSecretKeyOwned<u64>>,
    cm_fbsk: FourierCmLweBootstrapKeyOwned,
    cm_ksk: CmLweKeyswitchKeyOwned<u64>,
    cm_packing: CmLwePackingKeyOwned<u64>,
    cm_lane_to_bridge_ksks: Vec<LweKeyswitchKeyOwned<u64>>,
    cm_accumulator: CmGlweCiphertextOwned<u64>,
    bytes: KeyBytes,
    keygen_wall: Duration,
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn median_common(values: &[CommonTiming]) -> CommonTiming {
    CommonTiming {
        initial_pack: median(values.iter().map(|v| v.initial_pack).collect()),
        bridge_stage1: median(values.iter().map(|v| v.bridge_stage1).collect()),
        repack_stage1: median(values.iter().map(|v| v.repack_stage1).collect()),
        pbs_stage1: median(values.iter().map(|v| v.pbs_stage1).collect()),
        cm_ks: median(values.iter().map(|v| v.cm_ks).collect()),
        bridge_stage2: median(values.iter().map(|v| v.bridge_stage2).collect()),
        repack_stage2: median(values.iter().map(|v| v.repack_stage2).collect()),
        pbs_stage2: median(values.iter().map(|v| v.pbs_stage2).collect()),
        total: median(values.iter().map(|v| v.total).collect()),
    }
}

fn median_direct(values: &[DirectTiming]) -> DirectTiming {
    DirectTiming {
        initial_pack: median(values.iter().map(|v| v.initial_pack).collect()),
        mix_stage1: median(values.iter().map(|v| v.mix_stage1).collect()),
        pbs_stage1: median(values.iter().map(|v| v.pbs_stage1).collect()),
        cm_ks: median(values.iter().map(|v| v.cm_ks).collect()),
        mix_stage2: median(values.iter().map(|v| v.mix_stage2).collect()),
        pbs_stage2: median(values.iter().map(|v| v.pbs_stage2).collect()),
        total: median(values.iter().map(|v| v.total).collect()),
    }
}

fn median_ordinary(values: &[OrdinaryTiming]) -> OrdinaryTiming {
    OrdinaryTiming {
        ks_stage1: median(values.iter().map(|v| v.ks_stage1).collect()),
        pbs_stage1: median(values.iter().map(|v| v.pbs_stage1).collect()),
        ks_stage2: median(values.iter().map(|v| v.ks_stage2).collect()),
        pbs_stage2: median(values.iter().map(|v| v.pbs_stage2).collect()),
        total: median(values.iter().map(|v| v.total).collect()),
    }
}

fn ms(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

fn generate_keys() -> Keys {
    let started = Instant::now();
    let cm = CM_PARAM_4_2_MINUS_64;
    let ordinary: ClassicPBSParameters = V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;
    assert_eq!(cm.cm_dimension.0, LANES);
    assert_eq!(cm.precision, 2);
    assert_eq!(ordinary.message_modulus.0 * ordinary.carry_modulus.0, 4);

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    // The ordinary large key is also the common-mask bridge key, so both paths consume the
    // exact same four input ciphertexts.
    let ordinary_big_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        ordinary.glwe_dimension,
        ordinary.polynomial_size,
        &mut secret_generator,
    );
    let bridge_sk = ordinary_big_glwe_sk.clone().into_lwe_secret_key();
    let ordinary_small_sk = allocate_and_generate_new_binary_lwe_secret_key(
        ordinary.lwe_dimension,
        &mut secret_generator,
    );

    let mut ordinary_bsk = LweBootstrapKey::new(
        0u64,
        ordinary.glwe_dimension.to_glwe_size(),
        ordinary.polynomial_size,
        ordinary.pbs_base_log,
        ordinary.pbs_level,
        ordinary.lwe_dimension,
        ordinary.ciphertext_modulus,
    );
    par_generate_lwe_bootstrap_key(
        &ordinary_small_sk,
        &ordinary_big_glwe_sk,
        &mut ordinary_bsk,
        ordinary.glwe_noise_distribution,
        &mut encryption_generator,
    );
    let mut ordinary_fbsk = FourierLweBootstrapKey::new(
        ordinary.lwe_dimension,
        ordinary.glwe_dimension.to_glwe_size(),
        ordinary.polynomial_size,
        ordinary.pbs_base_log,
        ordinary.pbs_level,
    );
    par_convert_standard_lwe_bootstrap_key_to_fourier(&ordinary_bsk, &mut ordinary_fbsk);
    drop(ordinary_bsk);

    let ordinary_ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &bridge_sk,
        &ordinary_small_sk,
        ordinary.ks_base_log,
        ordinary.ks_level,
        ordinary.lwe_noise_distribution,
        ordinary.ciphertext_modulus,
        &mut encryption_generator,
    );

    let delta = (1u64 << 63) / 4;
    let ordinary_accumulator = generate_programmable_bootstrap_glwe_lut(
        ordinary.polynomial_size,
        ordinary.glwe_dimension.to_glwe_size(),
        4,
        ordinary.ciphertext_modulus,
        delta,
        |x| u64::from(x != 0),
    );

    // Independent lane keys are mandatory: reusing one lane key makes b_i-b_j cancel the mask
    // and reveal a rounded plaintext difference.
    let cm_small_sks: Vec<_> = (0..LANES)
        .map(|_| {
            allocate_and_generate_new_binary_lwe_secret_key(cm.lwe_dimension, &mut secret_generator)
        })
        .collect();
    let cm_big_glwe_sks: Vec<_> = (0..LANES)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                cm.glwe_dimension,
                cm.polynomial_size,
                &mut secret_generator,
            )
        })
        .collect();
    let cm_big_sks: Vec<_> = cm_big_glwe_sks
        .iter()
        .cloned()
        .map(GlweSecretKey::into_lwe_secret_key)
        .collect();

    let mut cm_bsk = CmLweBootstrapKey::new(
        0u64,
        cm.glwe_dimension,
        cm.cm_dimension,
        cm.polynomial_size,
        cm.base_log_bs,
        cm.level_bs,
        cm.lwe_dimension,
        cm.ciphertext_modulus,
    );
    par_generate_cm_lwe_bootstrap_key(
        &cm_small_sks,
        &cm_big_glwe_sks,
        &mut cm_bsk,
        cm.glwe_noise_distribution,
        &mut encryption_generator,
    );
    let mut cm_fbsk = FourierCmLweBootstrapKey::new(
        cm.lwe_dimension,
        cm.glwe_dimension,
        cm.cm_dimension,
        cm.polynomial_size,
        cm.base_log_bs,
        cm.level_bs,
    );
    par_convert_standard_cm_lwe_bootstrap_key_to_fourier(&cm_bsk, &mut cm_fbsk);
    drop(cm_bsk);

    let cm_ksk = allocate_and_generate_new_cm_lwe_keyswitch_key(
        &cm_big_sks,
        &cm_small_sks,
        cm.cm_dimension,
        cm.base_log_ks,
        cm.level_ks,
        cm.lwe_noise_distribution,
        cm.ciphertext_modulus,
        &mut encryption_generator,
    );
    let cm_packing = allocate_and_generate_new_cm_lwe_packing_key(
        &bridge_sk,
        &cm_small_sks,
        cm.base_log_ks,
        cm.level_ks,
        cm.lwe_noise_distribution,
        cm.ciphertext_modulus,
        &mut encryption_generator,
    );

    // Public re-keying is the compatibility bridge forced by independent lane secrets.
    let cm_lane_to_bridge_ksks: Vec<_> = cm_small_sks
        .iter()
        .map(|lane_sk| {
            allocate_and_generate_new_lwe_keyswitch_key(
                lane_sk,
                &bridge_sk,
                cm.base_log_ks,
                cm.level_ks,
                ordinary.glwe_noise_distribution,
                cm.ciphertext_modulus,
                &mut encryption_generator,
            )
        })
        .collect();

    let cm_accumulator = cm_generate_programmable_bootstrap_glwe_lut(
        cm.polynomial_size,
        cm.glwe_dimension,
        cm.cm_dimension,
        4,
        cm.ciphertext_modulus,
        delta,
        |x| u64::from(x != 0),
    );

    let bytes = KeyBytes {
        cm_fourier_bsk: cm_fbsk.as_view().data().len() * 16,
        cm_ksk: std::mem::size_of_val(cm_ksk.as_ref()),
        cm_packing: std::mem::size_of_val(cm_packing.as_ref()),
        cm_lane_to_bridge_ksks: cm_lane_to_bridge_ksks
            .iter()
            .map(|key| std::mem::size_of_val(key.as_ref()))
            .sum(),
        ordinary_fourier_bsk: ordinary_fbsk.as_view().data().len() * 16,
        ordinary_ksk: std::mem::size_of_val(ordinary_ksk.as_ref()),
    };

    Keys {
        bridge_sk,
        ordinary_fbsk,
        ordinary_ksk,
        ordinary_accumulator,
        cm_big_sks,
        cm_fbsk,
        cm_ksk,
        cm_packing,
        cm_lane_to_bridge_ksks,
        cm_accumulator,
        bytes,
        keygen_wall: started.elapsed(),
    }
}

fn encrypt_inputs(bits: [u64; LANES], keys: &Keys) -> Vec<LweCiphertextOwned<u64>> {
    let ordinary = V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;
    let delta = (1u64 << 63) / 4;
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    bits.into_iter()
        .map(|bit| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &keys.bridge_sk,
                Plaintext(bit * delta),
                ordinary.glwe_noise_distribution,
                ordinary.ciphertext_modulus,
                &mut encryption_generator,
            )
        })
        .collect()
}

fn add_lwe(
    lhs: &LweCiphertextOwned<u64>,
    rhs: &LweCiphertextOwned<u64>,
) -> LweCiphertextOwned<u64> {
    let mut output = lhs.clone();
    lwe_ciphertext_add_assign(&mut output, rhs);
    output
}

fn rekey_lanes_to_bridge(
    input: &CmLweCiphertextOwned<u64>,
    lanes: &[usize],
    keys: &Keys,
) -> Vec<LweCiphertextOwned<u64>> {
    lanes
        .par_iter()
        .map(|&lane| {
            let extracted = input.extract_lwe_ciphertext(lane);
            let key = &keys.cm_lane_to_bridge_ksks[lane];
            let mut output = LweCiphertext::new(
                0u64,
                key.output_key_lwe_dimension().to_lwe_size(),
                input.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(key, &extracted, &mut output);
            output
        })
        .collect()
}

fn secure_cm_reduce(
    inputs: &[LweCiphertextOwned<u64>],
    keys: &Keys,
) -> (CmLweCiphertextOwned<u64>, CommonTiming) {
    let cm = CM_PARAM_4_2_MINUS_64;
    let started_total = Instant::now();
    let mut timing = CommonTiming::default();

    let mut packed = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    pack_lwe_ciphertexts_into_cm(&keys.cm_packing, inputs, &mut packed);
    timing.initial_pack = started.elapsed();

    let started = Instant::now();
    let bridge = rekey_lanes_to_bridge(&packed, &[0, 1, 2, 3], keys);
    let pair01 = add_lwe(&bridge[0], &bridge[1]);
    let pair23 = add_lwe(&bridge[2], &bridge[3]);
    let packed_inputs = vec![
        pair01.clone(),
        pair23.clone(),
        pair01.clone(),
        pair23.clone(),
    ];
    timing.bridge_stage1 = started.elapsed();

    let mut stage1_small = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    pack_lwe_ciphertexts_into_cm(&keys.cm_packing, &packed_inputs, &mut stage1_small);
    timing.repack_stage1 = started.elapsed();

    let mut stage1_big = CmLweCiphertext::new(
        0u64,
        keys.cm_fbsk.output_lwe_dimension(),
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    programmable_bootstrap_cm_lwe_ciphertext(
        &stage1_small,
        &mut stage1_big,
        &keys.cm_accumulator,
        &keys.cm_fbsk,
    );
    timing.pbs_stage1 = started.elapsed();

    let mut stage1_refreshed = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    cm_keyswitch_lwe_ciphertext(&keys.cm_ksk, &stage1_big, &mut stage1_refreshed);
    timing.cm_ks = started.elapsed();

    let started = Instant::now();
    let bridge = rekey_lanes_to_bridge(&stage1_refreshed, &[0, 1], keys);
    let reduced = add_lwe(&bridge[0], &bridge[1]);
    let packed_inputs = vec![reduced.clone(), reduced.clone(), reduced.clone(), reduced];
    timing.bridge_stage2 = started.elapsed();

    let mut stage2_small = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    pack_lwe_ciphertexts_into_cm(&keys.cm_packing, &packed_inputs, &mut stage2_small);
    timing.repack_stage2 = started.elapsed();

    let mut output = CmLweCiphertext::new(
        0u64,
        keys.cm_fbsk.output_lwe_dimension(),
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    programmable_bootstrap_cm_lwe_ciphertext(
        &stage2_small,
        &mut output,
        &keys.cm_accumulator,
        &keys.cm_fbsk,
    );
    timing.pbs_stage2 = started.elapsed();
    timing.total = started_total.elapsed();
    (output, timing)
}

fn mix_pair_rows(
    input: &CmLweCiphertextOwned<u64>,
    second_stage: bool,
) -> CmLweCiphertextOwned<u64> {
    let mask = input.get_mask().as_ref().to_vec();
    let bodies = input.get_bodies().as_ref().to_vec();
    let mut output = CmLweCiphertext::new(
        0u64,
        input.lwe_dimension(),
        input.cm_dimension(),
        input.ciphertext_modulus(),
    );
    output
        .get_mut_mask()
        .as_mut()
        .iter_mut()
        .zip(mask)
        .for_each(|(dst, src)| *dst = src.wrapping_add(src));
    let mut output_bodies = output.get_mut_bodies();
    if second_stage {
        let sum = bodies[0].wrapping_add(bodies[1]);
        output_bodies.as_mut().fill(sum);
    } else {
        let pair01 = bodies[0].wrapping_add(bodies[1]);
        let pair23 = bodies[2].wrapping_add(bodies[3]);
        output_bodies
            .as_mut()
            .copy_from_slice(&[pair01, pair23, pair01, pair23]);
    }
    output
}

// This is the tempting no-repack construction. It is intentionally evaluated with independent
// lane keys. Equal row sums transform the shared mask, but do not transform the four independent
// secrets, so this candidate must fail correctness unless the keys are (insecurely) repeated.
fn direct_cm_reduce(
    inputs: &[LweCiphertextOwned<u64>],
    keys: &Keys,
) -> (CmLweCiphertextOwned<u64>, DirectTiming) {
    let cm = CM_PARAM_4_2_MINUS_64;
    let started_total = Instant::now();
    let mut timing = DirectTiming::default();
    let mut packed = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    pack_lwe_ciphertexts_into_cm(&keys.cm_packing, inputs, &mut packed);
    timing.initial_pack = started.elapsed();

    let started = Instant::now();
    let stage1_small = mix_pair_rows(&packed, false);
    timing.mix_stage1 = started.elapsed();
    let mut stage1_big = CmLweCiphertext::new(
        0u64,
        keys.cm_fbsk.output_lwe_dimension(),
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    programmable_bootstrap_cm_lwe_ciphertext(
        &stage1_small,
        &mut stage1_big,
        &keys.cm_accumulator,
        &keys.cm_fbsk,
    );
    timing.pbs_stage1 = started.elapsed();
    let mut stage1_refreshed = CmLweCiphertext::new(
        0u64,
        cm.lwe_dimension,
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    cm_keyswitch_lwe_ciphertext(&keys.cm_ksk, &stage1_big, &mut stage1_refreshed);
    timing.cm_ks = started.elapsed();
    let started = Instant::now();
    let stage2_small = mix_pair_rows(&stage1_refreshed, true);
    timing.mix_stage2 = started.elapsed();
    let mut output = CmLweCiphertext::new(
        0u64,
        keys.cm_fbsk.output_lwe_dimension(),
        cm.cm_dimension,
        cm.ciphertext_modulus,
    );
    let started = Instant::now();
    programmable_bootstrap_cm_lwe_ciphertext(
        &stage2_small,
        &mut output,
        &keys.cm_accumulator,
        &keys.cm_fbsk,
    );
    timing.pbs_stage2 = started.elapsed();
    timing.total = started_total.elapsed();
    (output, timing)
}

fn ordinary_reduce(
    inputs: &[LweCiphertextOwned<u64>],
    keys: &Keys,
) -> (LweCiphertextOwned<u64>, OrdinaryTiming) {
    let ordinary = V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;
    let started_total = Instant::now();
    let mut timing = OrdinaryTiming::default();

    let started = Instant::now();
    let small_inputs: Vec<_> = inputs
        .par_iter()
        .map(|input| {
            let mut output = LweCiphertext::new(
                0u64,
                keys.ordinary_ksk.output_key_lwe_dimension().to_lwe_size(),
                ordinary.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&keys.ordinary_ksk, input, &mut output);
            output
        })
        .collect();
    let pair_inputs = vec![
        add_lwe(&small_inputs[0], &small_inputs[1]),
        add_lwe(&small_inputs[2], &small_inputs[3]),
    ];
    timing.ks_stage1 = started.elapsed();

    let started = Instant::now();
    let pair_outputs: Vec<_> = pair_inputs
        .par_iter()
        .map(|input| {
            let mut output = LweCiphertext::new(
                0u64,
                keys.ordinary_fbsk.output_lwe_dimension().to_lwe_size(),
                ordinary.ciphertext_modulus,
            );
            programmable_bootstrap_lwe_ciphertext(
                input,
                &mut output,
                &keys.ordinary_accumulator,
                &keys.ordinary_fbsk,
            );
            output
        })
        .collect();
    timing.pbs_stage1 = started.elapsed();

    let started = Instant::now();
    let pair_small: Vec<_> = pair_outputs
        .par_iter()
        .map(|input| {
            let mut output = LweCiphertext::new(
                0u64,
                keys.ordinary_ksk.output_key_lwe_dimension().to_lwe_size(),
                ordinary.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&keys.ordinary_ksk, input, &mut output);
            output
        })
        .collect();
    let final_input = add_lwe(&pair_small[0], &pair_small[1]);
    timing.ks_stage2 = started.elapsed();

    let mut output = LweCiphertext::new(
        0u64,
        keys.ordinary_fbsk.output_lwe_dimension().to_lwe_size(),
        ordinary.ciphertext_modulus,
    );
    let started = Instant::now();
    programmable_bootstrap_lwe_ciphertext(
        &final_input,
        &mut output,
        &keys.ordinary_accumulator,
        &keys.ordinary_fbsk,
    );
    timing.pbs_stage2 = started.elapsed();
    timing.total = started_total.elapsed();
    (output, timing)
}

fn decode(value: u64) -> u64 {
    let delta = (1u64 << 63) / 4;
    value.wrapping_add(delta / 2) / delta % 4
}

fn decrypt_cm(output: &CmLweCiphertextOwned<u64>, keys: &Keys) -> [u64; LANES] {
    let decoded: Vec<_> = decrypt_cm_lwe_ciphertext(&keys.cm_big_sks, output)
        .into_iter()
        .map(|plaintext| decode(plaintext.0))
        .collect();
    decoded.try_into().unwrap()
}

fn decrypt_ordinary(output: &LweCiphertextOwned<u64>, keys: &Keys) -> u64 {
    decode(decrypt_lwe_ciphertext(&keys.bridge_sk, output).0)
}

fn pattern_bits(pattern: usize) -> [u64; LANES] {
    std::array::from_fn(|lane| ((pattern >> lane) & 1) as u64)
}

fn main() {
    let config = Config::parse();
    println!(
        "CONFIG fresh_keys={} warmups={} samples={} rayon_threads={} benchmark={}",
        config.fresh_keys,
        config.warmups,
        config.samples,
        rayon::current_num_threads(),
        config.benchmark
    );
    println!("PARAM cm=CM_PARAM_4_2_MINUS_64 ordinary=V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64 plaintext_states=4");
    println!("ROUTE secure_independent initial_pack=1 repacks=2 cm_pbs=2 cm_ks=1 extracted_lwes=6 ordinary_bridge_ks=6 pfks=0");
    println!("ROUTE direct_independent initial_pack=1 repacks=0 cm_pbs=2 cm_ks=1 extracted_lwes=0 ordinary_bridge_ks=0 pfks=0 expected_valid=false");
    println!("ROUTE ordinary_minimal initial_pack=0 ordinary_pbs=3 ordinary_ks=6 pfks=0");

    let whole_run = Instant::now();
    let mut total_secure_mismatches = 0usize;
    let mut total_direct_mismatches = 0usize;
    let mut total_ordinary_mismatches = 0usize;
    let mut benchmark_done = false;

    for key_index in 0..config.fresh_keys {
        let keys = generate_keys();
        println!(
            "KEYGEN key={} wall_s={:.6} cm_fourier_bsk_bytes={} cm_ksk_bytes={} cm_packing_bytes={} cm_lane_to_bridge_ksks_bytes={} ordinary_fourier_bsk_bytes={} ordinary_ksk_bytes={}",
            key_index,
            keys.keygen_wall.as_secs_f64(),
            keys.bytes.cm_fourier_bsk,
            keys.bytes.cm_ksk,
            keys.bytes.cm_packing,
            keys.bytes.cm_lane_to_bridge_ksks,
            keys.bytes.ordinary_fourier_bsk,
            keys.bytes.ordinary_ksk,
        );

        let mut secure_mismatches = 0usize;
        let mut direct_mismatches = 0usize;
        let mut ordinary_mismatches = 0usize;
        for pattern in 0..16 {
            let bits = pattern_bits(pattern);
            let expected = u64::from(bits.into_iter().any(|bit| bit != 0));
            let inputs = encrypt_inputs(bits, &keys);

            // No intermediate decryption: each output is decrypted only after its complete route.
            let (secure_output, _) = secure_cm_reduce(&inputs, &keys);
            let secure_decoded = decrypt_cm(&secure_output, &keys);
            secure_mismatches += secure_decoded
                .into_iter()
                .filter(|&value| value != expected)
                .count();

            let (direct_output, _) = direct_cm_reduce(&inputs, &keys);
            let direct_decoded = decrypt_cm(&direct_output, &keys);
            direct_mismatches += direct_decoded
                .into_iter()
                .filter(|&value| value != expected)
                .count();

            let (ordinary_output, _) = ordinary_reduce(&inputs, &keys);
            let ordinary_decoded = decrypt_ordinary(&ordinary_output, &keys);
            ordinary_mismatches += usize::from(ordinary_decoded != expected);
        }
        total_secure_mismatches += secure_mismatches;
        total_direct_mismatches += direct_mismatches;
        total_ordinary_mismatches += ordinary_mismatches;
        println!(
            "CORRECTNESS key={} patterns=16 secure_outputs=64 secure_mismatches={} direct_outputs=64 direct_mismatches={} ordinary_outputs=16 ordinary_mismatches={}",
            key_index,
            secure_mismatches,
            direct_mismatches,
            ordinary_mismatches
        );

        if config.benchmark && !benchmark_done {
            let inputs = encrypt_inputs([1, 0, 1, 1], &keys);
            for _ in 0..config.warmups {
                std::hint::black_box(secure_cm_reduce(&inputs, &keys).0);
                std::hint::black_box(direct_cm_reduce(&inputs, &keys).0);
                std::hint::black_box(ordinary_reduce(&inputs, &keys).0);
            }
            let mut common_samples = Vec::with_capacity(config.samples);
            let mut direct_samples = Vec::with_capacity(config.samples);
            let mut ordinary_samples = Vec::with_capacity(config.samples);
            for _ in 0..config.samples {
                let (output, timing) = secure_cm_reduce(&inputs, &keys);
                std::hint::black_box(output);
                common_samples.push(timing);
                let (output, timing) = direct_cm_reduce(&inputs, &keys);
                std::hint::black_box(output);
                direct_samples.push(timing);
                let (output, timing) = ordinary_reduce(&inputs, &keys);
                std::hint::black_box(output);
                ordinary_samples.push(timing);
            }
            let common = median_common(&common_samples);
            let direct = median_direct(&direct_samples);
            let ordinary = median_ordinary(&ordinary_samples);
            println!(
                "BENCH_SECURE_MEDIAN_MS total={:.6} initial_pack={:.6} bridge_stage1={:.6} repack_stage1={:.6} cm_pbs_stage1={:.6} cm_ks={:.6} bridge_stage2={:.6} repack_stage2={:.6} cm_pbs_stage2={:.6}",
                ms(common.total),
                ms(common.initial_pack),
                ms(common.bridge_stage1),
                ms(common.repack_stage1),
                ms(common.pbs_stage1),
                ms(common.cm_ks),
                ms(common.bridge_stage2),
                ms(common.repack_stage2),
                ms(common.pbs_stage2),
            );
            println!(
                "BENCH_DIRECT_INVALID_MEDIAN_MS total={:.6} initial_pack={:.6} mix_stage1={:.6} cm_pbs_stage1={:.6} cm_ks={:.6} mix_stage2={:.6} cm_pbs_stage2={:.6}",
                ms(direct.total),
                ms(direct.initial_pack),
                ms(direct.mix_stage1),
                ms(direct.pbs_stage1),
                ms(direct.cm_ks),
                ms(direct.mix_stage2),
                ms(direct.pbs_stage2),
            );
            println!(
                "BENCH_ORDINARY_MEDIAN_MS total={:.6} ks_stage1={:.6} pbs_stage1={:.6} ks_stage2={:.6} pbs_stage2={:.6}",
                ms(ordinary.total),
                ms(ordinary.ks_stage1),
                ms(ordinary.pbs_stage1),
                ms(ordinary.ks_stage2),
                ms(ordinary.pbs_stage2),
            );
            println!(
                "BENCH_RATIO secure_over_ordinary={:.6} ordinary_over_secure={:.6} direct_invalid_over_ordinary={:.6}",
                common.total.as_secs_f64() / ordinary.total.as_secs_f64(),
                ordinary.total.as_secs_f64() / common.total.as_secs_f64(),
                direct.total.as_secs_f64() / ordinary.total.as_secs_f64(),
            );
            println!(
                "BENCH_RAW_COMMON_TOTAL_MS {:?}",
                common_samples
                    .iter()
                    .map(|sample| ms(sample.total))
                    .collect::<Vec<_>>()
            );
            println!(
                "BENCH_RAW_DIRECT_INVALID_TOTAL_MS {:?}",
                direct_samples
                    .iter()
                    .map(|sample| ms(sample.total))
                    .collect::<Vec<_>>()
            );
            println!(
                "BENCH_RAW_ORDINARY_TOTAL_MS {:?}",
                ordinary_samples
                    .iter()
                    .map(|sample| ms(sample.total))
                    .collect::<Vec<_>>()
            );
            benchmark_done = true;
        }
    }

    println!(
        "SUMMARY fresh_keys={} patterns_per_key=16 secure_outputs={} secure_mismatches={} direct_outputs={} direct_mismatches={} ordinary_outputs={} ordinary_mismatches={} wall_s={:.6}",
        config.fresh_keys,
        config.fresh_keys * 16 * LANES,
        total_secure_mismatches,
        config.fresh_keys * 16 * LANES,
        total_direct_mismatches,
        config.fresh_keys * 16,
        total_ordinary_mismatches,
        whole_run.elapsed().as_secs_f64(),
    );
    assert_eq!(total_secure_mismatches, 0, "secure fallback is not exact");
    assert_eq!(
        total_ordinary_mismatches, 0,
        "ordinary baseline is not exact"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_have_expected_boolean_or() {
        for pattern in 0..16 {
            let bits = pattern_bits(pattern);
            let expected = u64::from(pattern != 0);
            assert_eq!(u64::from(bits.into_iter().any(|bit| bit != 0)), expected);
        }
    }

    #[test]
    fn pair_matrix_has_uniform_row_sum_two() {
        let stage1 = [[1u8, 1, 0, 0], [0, 0, 1, 1], [1, 1, 0, 0], [0, 0, 1, 1]];
        let stage2 = [[1u8, 1, 0, 0]; 4];
        assert!(stage1.iter().all(|row| row.iter().sum::<u8>() == 2));
        assert!(stage2.iter().all(|row| row.iter().sum::<u8>() == 2));
    }
}
