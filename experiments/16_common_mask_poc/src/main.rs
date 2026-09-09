use std::time::Instant;

use rayon::prelude::*;
use tfhe::core_crypto::experimental::algorithms::common_mask_algorithms::{
    cm_fft64::programmable_bootstrap_cm_lwe_ciphertext,
    cm_generate_programmable_bootstrap_glwe_lut,
    cm_lwe_keyswitch_key_generation::allocate_and_generate_new_cm_lwe_keyswitch_key,
    par_generate_cm_lwe_bootstrap_key, CmApParams, CM_PARAM_2_2_MINUS_64, CM_PARAM_2_4_MINUS_64,
    CM_PARAM_4_2_MINUS_64, CM_PARAM_4_4_MINUS_64, CM_PARAM_6_2_MINUS_64, CM_PARAM_8_2_MINUS_64,
};
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;

fn main() {
    let requested = std::env::args().nth(1).unwrap_or_else(|| "2x2".to_owned());
    let params: CmApParams = match requested.as_str() {
        "2x2" => CM_PARAM_2_2_MINUS_64,
        "2x4" => CM_PARAM_2_4_MINUS_64,
        "4x2" => CM_PARAM_4_2_MINUS_64,
        "4x4" => CM_PARAM_4_4_MINUS_64,
        "6x2" => CM_PARAM_6_2_MINUS_64,
        "8x2" => CM_PARAM_8_2_MINUS_64,
        other => panic!("unknown configuration {other}"),
    };
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let small_keys: Vec<_> = (0..params.cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension,
                &mut secret_generator,
            )
        })
        .collect();
    let big_glwe_keys: Vec<_> = (0..params.cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            )
        })
        .collect();
    let big_lwe_keys: Vec<_> = big_glwe_keys
        .iter()
        .cloned()
        .map(GlweSecretKey::into_lwe_secret_key)
        .collect();

    let key_start = Instant::now();
    let mut bsk = CmLweBootstrapKey::new(
        0u64,
        params.glwe_dimension,
        params.cm_dimension,
        params.polynomial_size,
        params.base_log_bs,
        params.level_bs,
        params.lwe_dimension,
        params.ciphertext_modulus,
    );
    par_generate_cm_lwe_bootstrap_key(
        &small_keys,
        &big_glwe_keys,
        &mut bsk,
        params.glwe_noise_distribution,
        &mut encryption_generator,
    );
    let standard_bsk_bytes = bsk.as_ref().len() * std::mem::size_of::<u64>();

    let mut fbsk = FourierCmLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension,
        params.cm_dimension,
        params.polynomial_size,
        params.base_log_bs,
        params.level_bs,
    );
    par_convert_standard_cm_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);
    let fourier_bsk_bytes = fbsk.as_view().data().len() * 16;
    drop(bsk);
    eprintln!(
        "keygen_s={:.3},standard_bsk_bytes={},fourier_storage_bytes={}",
        key_start.elapsed().as_secs_f64(),
        standard_bsk_bytes,
        fourier_bsk_bytes,
    );

    let modulus = params.ciphertext_modulus;
    let encoding_with_padding = 1u64 << 63;
    let msg_modulus = 1u64 << params.precision;
    let delta = encoding_with_padding / msg_modulus;
    let accumulator = cm_generate_programmable_bootstrap_glwe_lut(
        params.polynomial_size,
        params.glwe_dimension,
        params.cm_dimension,
        msg_modulus as usize,
        modulus,
        delta,
        |x| x,
    );
    let plaintexts = PlaintextList::from_container(
        (0..params.cm_dimension.0)
            .map(|i| ((i as u64) % msg_modulus) * delta)
            .collect::<Vec<_>>(),
    );
    let input = allocate_and_encrypt_new_cm_lwe_ciphertext(
        &small_keys,
        &plaintexts,
        params.lwe_noise_distribution,
        modulus,
        &mut encryption_generator,
    );

    let bridge_input_key =
        allocate_and_generate_new_binary_lwe_secret_key(LweDimension(2048), &mut secret_generator);
    let packing_key_start = Instant::now();
    let packing_key = allocate_and_generate_new_cm_lwe_packing_key(
        &bridge_input_key,
        &small_keys,
        params.base_log_ks,
        params.level_ks,
        params.lwe_noise_distribution,
        modulus,
        &mut encryption_generator,
    );
    eprintln!(
        "packing_keygen_s={:.3},packing_key_bytes={}",
        packing_key_start.elapsed().as_secs_f64(),
        packing_key.as_ref().len() * std::mem::size_of::<u64>(),
    );
    let bridge_inputs: Vec<_> = (0..params.cm_dimension.0)
        .map(|i| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &bridge_input_key,
                Plaintext(((i as u64) % msg_modulus) * delta),
                params.lwe_noise_distribution,
                modulus,
                &mut encryption_generator,
            )
        })
        .collect();
    let mut bridge_output =
        CmLweCiphertext::new(0u64, params.lwe_dimension, params.cm_dimension, modulus);
    pack_lwe_ciphertexts_into_cm(&packing_key, &bridge_inputs, &mut bridge_output);
    let mut pack_samples = Vec::new();
    for _ in 0..25 {
        let start = Instant::now();
        pack_lwe_ciphertexts_into_cm(&packing_key, &bridge_inputs, &mut bridge_output);
        pack_samples.push(start.elapsed().as_secs_f64());
    }
    pack_samples.sort_by(|a, b| a.total_cmp(b));
    println!(
        "pack_width={},median_s={:.6},p10_s={:.6},p90_s={:.6}",
        params.cm_dimension.0,
        pack_samples[pack_samples.len() / 2],
        pack_samples[pack_samples.len() / 10],
        pack_samples[pack_samples.len() * 9 / 10],
    );
    let mut output = CmLweCiphertext::new(
        0u64,
        fbsk.output_lwe_dimension(),
        params.cm_dimension,
        modulus,
    );

    programmable_bootstrap_cm_lwe_ciphertext(&input, &mut output, &accumulator, &fbsk);

    let cm_ksk_start = Instant::now();
    let cm_ksk = allocate_and_generate_new_cm_lwe_keyswitch_key(
        &big_lwe_keys,
        &small_keys,
        params.cm_dimension,
        params.base_log_ks,
        params.level_ks,
        params.lwe_noise_distribution,
        modulus,
        &mut encryption_generator,
    );
    eprintln!(
        "cm_ksk_keygen_s={:.3},cm_ksk_bytes={}",
        cm_ksk_start.elapsed().as_secs_f64(),
        cm_ksk.as_ref().len() * std::mem::size_of::<u64>(),
    );
    let mut ks_output =
        CmLweCiphertext::new(0u64, params.lwe_dimension, params.cm_dimension, modulus);
    cm_keyswitch_lwe_ciphertext(&cm_ksk, &output, &mut ks_output);
    let mut ks_samples = Vec::new();
    for _ in 0..25 {
        let start = Instant::now();
        cm_keyswitch_lwe_ciphertext(&cm_ksk, &output, &mut ks_output);
        ks_samples.push(start.elapsed().as_secs_f64());
    }
    ks_samples.sort_by(|a, b| a.total_cmp(b));
    println!(
        "cm_ks_width={},median_s={:.6},p10_s={:.6},p90_s={:.6}",
        params.cm_dimension.0,
        ks_samples[ks_samples.len() / 2],
        ks_samples[ks_samples.len() / 10],
        ks_samples[ks_samples.len() * 9 / 10],
    );
    let mut samples = Vec::new();
    for _ in 0..25 {
        let start = Instant::now();
        programmable_bootstrap_cm_lwe_ciphertext(&input, &mut output, &accumulator, &fbsk);
        samples.push(start.elapsed().as_secs_f64());
    }
    samples.sort_by(|a, b| a.total_cmp(b));
    println!(
        "cm_width={},median_s={:.6},p10_s={:.6},p90_s={:.6},all={:?}",
        params.cm_dimension.0,
        samples[samples.len() / 2],
        samples[samples.len() / 10],
        samples[samples.len() * 9 / 10],
        samples,
    );

    let group_count = 128usize.div_ceil(params.cm_dimension.0);
    for rep in 0..7 {
        let start = Instant::now();
        let checks: Vec<_> = (0..group_count)
            .into_par_iter()
            .map(|_| {
                let mut group_output = CmLweCiphertext::new(
                    0u64,
                    fbsk.output_lwe_dimension(),
                    params.cm_dimension,
                    modulus,
                );
                programmable_bootstrap_cm_lwe_ciphertext(
                    &input,
                    &mut group_output,
                    &accumulator,
                    &fbsk,
                );
                group_output.get_bodies().as_ref()[0]
            })
            .collect();
        println!(
            "outer_parallel_rep={rep},logical_slots={},groups={},elapsed_s={:.6},check={}",
            group_count * params.cm_dimension.0,
            group_count,
            start.elapsed().as_secs_f64(),
            checks.len(),
        );
    }

    for rep in 0..7 {
        let start = Instant::now();
        let checks: Vec<_> = (0..group_count)
            .into_par_iter()
            .map(|_| {
                let mut small =
                    CmLweCiphertext::new(0u64, params.lwe_dimension, params.cm_dimension, modulus);
                cm_keyswitch_lwe_ciphertext(&cm_ksk, &output, &mut small);
                let mut big = CmLweCiphertext::new(
                    0u64,
                    fbsk.output_lwe_dimension(),
                    params.cm_dimension,
                    modulus,
                );
                programmable_bootstrap_cm_lwe_ciphertext(&small, &mut big, &accumulator, &fbsk);
                big.get_bodies().as_ref()[0]
            })
            .collect();
        println!(
            "outer_parallel_cm_ks_pbs_rep={rep},logical_slots={},groups={},elapsed_s={:.6},check={}",
            group_count * params.cm_dimension.0,
            group_count,
            start.elapsed().as_secs_f64(),
            checks.len(),
        );
    }

    for rep in 0..7 {
        let start = Instant::now();
        let checks: Vec<_> = (0..group_count)
            .into_par_iter()
            .map(|_| {
                let mut group_output =
                    CmLweCiphertext::new(0u64, params.lwe_dimension, params.cm_dimension, modulus);
                pack_lwe_ciphertexts_into_cm(&packing_key, &bridge_inputs, &mut group_output);
                group_output.get_bodies().as_ref()[0]
            })
            .collect();
        println!(
            "outer_parallel_pack_rep={rep},logical_slots={},groups={},elapsed_s={:.6},check={}",
            group_count * params.cm_dimension.0,
            group_count,
            start.elapsed().as_secs_f64(),
            checks.len(),
        );
    }
}
