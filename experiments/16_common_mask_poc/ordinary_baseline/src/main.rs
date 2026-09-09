use rayon::prelude::*;
use std::time::{Duration, Instant};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::parameters::v0_11::classic::tuniform::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::v1_6::classic::tuniform::p_fail_2_minus_64::ks_pbs::V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::ClassicPBSParameters;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

fn main() {
    let params: ClassicPBSParameters = match std::env::args().nth(1).as_deref() {
        Some("1x1") => V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        _ => V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    };
    let counts = [1usize, 2, 4, 8, 16, 32, 64, 128];
    let repeats = 3usize;

    let key_started = Instant::now();
    let client_key = ClientKey::new(params);
    let server_key = ServerKey::new(&client_key);
    eprintln!("keygen_s={:.3}", key_started.elapsed().as_secs_f64());

    let standard_key = match &server_key.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => panic!("standard atomic pattern expected"),
    };
    let fbsk = match &standard_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => bsk,
        _ => panic!("classic PBS expected"),
    };
    let ksk = &standard_key.key_switching_key;
    let modulus = params.ciphertext_modulus;
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let big_size = fbsk.output_lwe_dimension().to_lwe_size();
    let polynomial_size = fbsk.polynomial_size();
    let glwe_size = fbsk.glwe_size();
    let plaintext_modulus = params.message_modulus.0 * params.carry_modulus.0;
    let delta = (1u64 << 63) / plaintext_modulus;
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        plaintext_modulus as usize,
        modulus,
        delta,
        |x| x & 1,
    );

    let max_count = *counts.last().unwrap();
    let encrypted: Vec<_> = (0..max_count)
        .map(|i| client_key.encrypt((i & 1) as u64).ct)
        .collect();
    let small_inputs: Vec<LweCiphertextOwned<u64>> = encrypted
        .par_iter()
        .map(|input| {
            let mut output = LweCiphertext::new(0u64, small_size, modulus);
            keyswitch_lwe_ciphertext(ksk, input, &mut output);
            output
        })
        .collect();

    println!("count,scalar_parallel_s,batch_serial_s,batch_over_scalar");
    for count in counts {
        let inputs = &small_inputs[..count];

        // Warm both paths once.
        let _: Vec<_> = inputs
            .par_iter()
            .map(|input| {
                let mut output = LweCiphertext::new(0u64, big_size, modulus);
                programmable_bootstrap_lwe_ciphertext(input, &mut output, &accumulator, fbsk);
                output
            })
            .collect();
        run_batch(inputs, fbsk, &accumulator, small_size, big_size, modulus);

        let mut scalar_times = Vec::with_capacity(repeats);
        let mut batch_times = Vec::with_capacity(repeats);
        for _ in 0..repeats {
            let started = Instant::now();
            let outputs: Vec<_> = inputs
                .par_iter()
                .map(|input| {
                    let mut output = LweCiphertext::new(0u64, big_size, modulus);
                    programmable_bootstrap_lwe_ciphertext(input, &mut output, &accumulator, fbsk);
                    output
                })
                .collect();
            std::hint::black_box(outputs);
            scalar_times.push(started.elapsed());

            let started = Instant::now();
            let outputs = run_batch(inputs, fbsk, &accumulator, small_size, big_size, modulus);
            std::hint::black_box(outputs);
            batch_times.push(started.elapsed());
        }
        let scalar = median(scalar_times).as_secs_f64();
        let batch = median(batch_times).as_secs_f64();
        println!("{count},{scalar:.6},{batch:.6},{:.3}", batch / scalar);
    }
}

fn run_batch(
    inputs: &[LweCiphertextOwned<u64>],
    fbsk: &FourierLweBootstrapKeyOwned,
    accumulator: &GlweCiphertextOwned<u64>,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
) -> LweCiphertextListOwned<u64> {
    let count = inputs.len();
    let input_list = LweCiphertextList::from_container(
        inputs
            .iter()
            .flat_map(|ct| ct.as_ref().iter().copied())
            .collect::<Vec<_>>(),
        small_size,
        modulus,
    );
    let accumulator_list = GlweCiphertextList::from_container(
        (0..count)
            .flat_map(|_| accumulator.as_ref().iter().copied())
            .collect::<Vec<_>>(),
        fbsk.glwe_size(),
        fbsk.polynomial_size(),
        modulus,
    );
    let mut output_list =
        LweCiphertextList::new(0u64, big_size, LweCiphertextCount(count), modulus);
    let fft = Fft::new(fbsk.polynomial_size());
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
            fbsk.glwe_size(),
            fbsk.polynomial_size(),
            CiphertextCount(count),
            fft,
        )
        .unaligned_bytes_required(),
    );
    batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &input_list,
        &mut output_list,
        &accumulator_list,
        fbsk,
        fft,
        buffers.stack(),
    );
    output_list
}
