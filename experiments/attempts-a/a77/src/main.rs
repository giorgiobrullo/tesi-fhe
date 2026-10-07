use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const PARAMS_ID: &str = "tfhe-rs-0.11.3-v0_11-m1c3-classic-ks-pbs-gaussian-2m64";
const DEFAULT_WARMUP: usize = 20;
const DEFAULT_ITERATIONS: usize = 240;
const EXPECTED_MESSAGE: u64 = 1;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let resized = unsafe { System.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocationSnapshot {
    alloc_calls: u64,
    realloc_calls: u64,
    dealloc_calls: u64,
    allocated_bytes: u64,
}

impl AllocationSnapshot {
    fn now() -> Self {
        Self {
            alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
            realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
            dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        }
    }

    fn difference(self, earlier: Self) -> AllocationDelta {
        AllocationDelta {
            alloc_calls: self.alloc_calls - earlier.alloc_calls,
            realloc_calls: self.realloc_calls - earlier.realloc_calls,
            dealloc_calls: self.dealloc_calls - earlier.dealloc_calls,
            allocated_bytes: self.allocated_bytes - earlier.allocated_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllocationDelta {
    alloc_calls: u64,
    realloc_calls: u64,
    dealloc_calls: u64,
    allocated_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct Observation {
    elapsed: Duration,
    allocations: AllocationDelta,
}

#[derive(Default)]
struct Samples {
    nanoseconds: Vec<u128>,
    alloc_calls: Vec<u64>,
    realloc_calls: Vec<u64>,
    dealloc_calls: Vec<u64>,
    allocated_bytes: Vec<u64>,
}

impl Samples {
    fn push(&mut self, observation: Observation) {
        self.nanoseconds.push(observation.elapsed.as_nanos());
        self.alloc_calls.push(observation.allocations.alloc_calls);
        self.realloc_calls
            .push(observation.allocations.realloc_calls);
        self.dealloc_calls
            .push(observation.allocations.dealloc_calls);
        self.allocated_bytes
            .push(observation.allocations.allocated_bytes);
    }
}

fn measure_call(operation: impl FnOnce()) -> Observation {
    let allocations_before = AllocationSnapshot::now();
    let started = Instant::now();
    operation();
    let elapsed = started.elapsed();
    let allocations_after = AllocationSnapshot::now();
    Observation {
        elapsed,
        allocations: allocations_after.difference(allocations_before),
    }
}

fn percentile_u128(values: &[u128], numerator: usize, denominator: usize) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() - 1) * numerator / denominator;
    sorted[index]
}

fn percentile_u64(values: &[u64], numerator: usize, denominator: usize) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() - 1) * numerator / denominator;
    sorted[index]
}

fn mean_u128(values: &[u128]) -> f64 {
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}

fn paired_deltas(wrapper: &[u128], reuse: &[u128]) -> Vec<i128> {
    assert_eq!(wrapper.len(), reuse.len());
    wrapper
        .iter()
        .zip(reuse)
        .map(|(wrapper, reuse)| *wrapper as i128 - *reuse as i128)
        .collect()
}

fn median_i128(values: &[i128]) -> i128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[(sorted.len() - 1) / 2]
}

fn mean_i128(values: &[i128]) -> f64 {
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}

fn json_u128(values: &[u128]) -> String {
    values
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn json_u64(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_output(client_key: &ClientKey, ciphertext: &LweCiphertextOwned<u64>) -> u64 {
    let (decryption_key, _) = client_key.encryption_key_and_noise();
    let decrypted = decrypt_lwe_ciphertext(&decryption_key, ciphertext).0;
    let modulus = PARAMS.message_modulus.0 * PARAMS.carry_modulus.0;
    let delta = (1u64 << 63) / modulus;
    let rounding_bit = delta >> 1;
    let rounding = (decrypted & rounding_bit) << 1;
    decrypted.wrapping_add(rounding) / delta % PARAMS.message_modulus.0
}

fn extracted_degree_zero(
    rotated: &GlweCiphertextOwned<u64>,
    output_lwe_size: LweSize,
) -> LweCiphertextOwned<u64> {
    let mut extracted = LweCiphertext::new(0u64, output_lwe_size, rotated.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(rotated, &mut extracted, MonomialDegree(0));
    extracted
}

fn print_samples(name: &str, samples: &Samples) {
    let median_ns = percentile_u128(&samples.nanoseconds, 1, 2);
    let p10_ns = percentile_u128(&samples.nanoseconds, 1, 10);
    let p90_ns = percentile_u128(&samples.nanoseconds, 9, 10);
    println!("    \"{name}\": {{");
    println!("      \"median_ns\": {median_ns},");
    println!("      \"mean_ns\": {:.3},", mean_u128(&samples.nanoseconds));
    println!("      \"p10_ns\": {p10_ns},");
    println!("      \"p90_ns\": {p90_ns},");
    println!(
        "      \"median_alloc_calls\": {},",
        percentile_u64(&samples.alloc_calls, 1, 2)
    );
    println!(
        "      \"median_realloc_calls\": {},",
        percentile_u64(&samples.realloc_calls, 1, 2)
    );
    println!(
        "      \"median_dealloc_calls\": {},",
        percentile_u64(&samples.dealloc_calls, 1, 2)
    );
    println!(
        "      \"median_allocated_bytes\": {},",
        percentile_u64(&samples.allocated_bytes, 1, 2)
    );
    println!(
        "      \"nanoseconds\": [{}],",
        json_u128(&samples.nanoseconds)
    );
    println!(
        "      \"alloc_calls\": [{}],",
        json_u64(&samples.alloc_calls)
    );
    println!(
        "      \"realloc_calls\": [{}],",
        json_u64(&samples.realloc_calls)
    );
    println!(
        "      \"dealloc_calls\": [{}],",
        json_u64(&samples.dealloc_calls)
    );
    println!(
        "      \"allocated_bytes\": [{}]",
        json_u64(&samples.allocated_bytes)
    );
    println!("    }}");
}

fn parse_count(flag: &str, default: usize) -> usize {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].parse::<usize>().expect("count must be an integer"))
        .unwrap_or(default)
}

fn main() {
    let warmup = parse_count("--warmup", DEFAULT_WARMUP);
    let iterations = parse_count("--iterations", DEFAULT_ITERATIONS);
    assert!(warmup > 0 && iterations >= 20);
    assert_eq!(
        std::env::var("RAYON_NUM_THREADS").as_deref(),
        Ok("1"),
        "A77 is intentionally a scalar/single-thread causal benchmark"
    );

    let setup_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let encrypted = client_key.encrypt(EXPECTED_MESSAGE);
    let fourier_bsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        ShortintBootstrappingKey::MultiBit { .. } => panic!("A77 requires a classic BSK"),
    };
    let mut switched = LweCiphertext::new(
        0u64,
        fourier_bsk.input_lwe_dimension().to_lwe_size(),
        server_key.ciphertext_modulus,
    );
    keyswitch_lwe_ciphertext(&server_key.key_switching_key, &encrypted.ct, &mut switched);
    let accumulator = server_key.generate_lookup_table(|value| value).acc;
    let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

    // Create/cache the FFT plan once and resize one reusable buffer to the larger requirement.
    // This intentionally measures steady-state calls, not first-use FFT planning.
    let fft_owner = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft_owner.as_view();
    let pbs_requirement = programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
        fourier_bsk.glwe_size(),
        fourier_bsk.polynomial_size(),
        fft,
    )
    .expect("PBS scratch requirement")
    .unaligned_bytes_required();
    let blind_rotate_requirement = blind_rotate_assign_mem_optimized_requirement::<u64>(
        fourier_bsk.glwe_size(),
        fourier_bsk.polynomial_size(),
        fft,
    )
    .expect("blind-rotate scratch requirement")
    .unaligned_bytes_required();
    let reusable_capacity = pbs_requirement.max(blind_rotate_requirement);
    let mut buffers = ComputationBuffers::new();
    buffers.resize(reusable_capacity);

    let mut pbs_wrapper = LweCiphertext::new(0u64, output_lwe_size, server_key.ciphertext_modulus);
    let mut pbs_reuse = pbs_wrapper.clone();
    let mut rotate_wrapper = accumulator.clone();
    let mut rotate_reuse = accumulator.clone();

    // Correctness gate before timing: identical bit-exact inputs, LUT, BSK and output geometry.
    programmable_bootstrap_lwe_ciphertext(&switched, &mut pbs_wrapper, &accumulator, fourier_bsk);
    programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &switched,
        &mut pbs_reuse,
        &accumulator,
        fourier_bsk,
        fft,
        buffers.stack(),
    );
    assert_eq!(pbs_wrapper.as_ref(), pbs_reuse.as_ref());
    assert_eq!(decode_output(&client_key, &pbs_wrapper), EXPECTED_MESSAGE);
    assert_eq!(decode_output(&client_key, &pbs_reuse), EXPECTED_MESSAGE);

    blind_rotate_assign(&switched, &mut rotate_wrapper, fourier_bsk);
    blind_rotate_assign_mem_optimized(
        &switched,
        &mut rotate_reuse,
        fourier_bsk,
        fft,
        buffers.stack(),
    );
    assert_eq!(rotate_wrapper.as_ref(), rotate_reuse.as_ref());
    let initial_wrapper_extract = extracted_degree_zero(&rotate_wrapper, output_lwe_size);
    let initial_reuse_extract = extracted_degree_zero(&rotate_reuse, output_lwe_size);
    assert_eq!(
        initial_wrapper_extract.as_ref(),
        initial_reuse_extract.as_ref()
    );
    assert_eq!(
        decode_output(&client_key, &initial_wrapper_extract),
        EXPECTED_MESSAGE
    );
    assert_eq!(
        decode_output(&client_key, &initial_reuse_extract),
        EXPECTED_MESSAGE
    );
    let setup_and_correctness_s = setup_started.elapsed().as_secs_f64();

    for _ in 0..warmup {
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut pbs_wrapper,
            &accumulator,
            fourier_bsk,
        );
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &switched,
            &mut pbs_reuse,
            &accumulator,
            fourier_bsk,
            fft,
            buffers.stack(),
        );
        rotate_wrapper.clone_from(&accumulator);
        rotate_reuse.clone_from(&accumulator);
        blind_rotate_assign(&switched, &mut rotate_wrapper, fourier_bsk);
        blind_rotate_assign_mem_optimized(
            &switched,
            &mut rotate_reuse,
            fourier_bsk,
            fft,
            buffers.stack(),
        );
    }

    let mut pbs_wrapper_samples = Samples::default();
    let mut pbs_reuse_samples = Samples::default();
    let mut rotate_wrapper_samples = Samples::default();
    let mut rotate_reuse_samples = Samples::default();

    for iteration in 0..iterations {
        if iteration % 2 == 0 {
            pbs_wrapper_samples.push(measure_call(|| {
                programmable_bootstrap_lwe_ciphertext(
                    &switched,
                    &mut pbs_wrapper,
                    &accumulator,
                    fourier_bsk,
                )
            }));
            pbs_reuse_samples.push(measure_call(|| {
                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    &switched,
                    &mut pbs_reuse,
                    &accumulator,
                    fourier_bsk,
                    fft,
                    buffers.stack(),
                )
            }));
        } else {
            pbs_reuse_samples.push(measure_call(|| {
                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    &switched,
                    &mut pbs_reuse,
                    &accumulator,
                    fourier_bsk,
                    fft,
                    buffers.stack(),
                )
            }));
            pbs_wrapper_samples.push(measure_call(|| {
                programmable_bootstrap_lwe_ciphertext(
                    &switched,
                    &mut pbs_wrapper,
                    &accumulator,
                    fourier_bsk,
                )
            }));
        }
        black_box(&pbs_wrapper);
        black_box(&pbs_reuse);
        assert_eq!(pbs_wrapper.as_ref(), pbs_reuse.as_ref());
        assert_eq!(decode_output(&client_key, &pbs_wrapper), EXPECTED_MESSAGE);
        assert_eq!(decode_output(&client_key, &pbs_reuse), EXPECTED_MESSAGE);

        rotate_wrapper.clone_from(&accumulator);
        rotate_reuse.clone_from(&accumulator);
        if iteration % 2 == 0 {
            rotate_wrapper_samples.push(measure_call(|| {
                blind_rotate_assign(&switched, &mut rotate_wrapper, fourier_bsk)
            }));
            rotate_reuse_samples.push(measure_call(|| {
                blind_rotate_assign_mem_optimized(
                    &switched,
                    &mut rotate_reuse,
                    fourier_bsk,
                    fft,
                    buffers.stack(),
                )
            }));
        } else {
            rotate_reuse_samples.push(measure_call(|| {
                blind_rotate_assign_mem_optimized(
                    &switched,
                    &mut rotate_reuse,
                    fourier_bsk,
                    fft,
                    buffers.stack(),
                )
            }));
            rotate_wrapper_samples.push(measure_call(|| {
                blind_rotate_assign(&switched, &mut rotate_wrapper, fourier_bsk)
            }));
        }
        black_box(&rotate_wrapper);
        black_box(&rotate_reuse);
        assert_eq!(rotate_wrapper.as_ref(), rotate_reuse.as_ref());
        let wrapper_extract = extracted_degree_zero(&rotate_wrapper, output_lwe_size);
        let reuse_extract = extracted_degree_zero(&rotate_reuse, output_lwe_size);
        assert_eq!(wrapper_extract.as_ref(), reuse_extract.as_ref());
        assert_eq!(
            decode_output(&client_key, &wrapper_extract),
            EXPECTED_MESSAGE
        );
        assert_eq!(decode_output(&client_key, &reuse_extract), EXPECTED_MESSAGE);
    }

    let pbs_wrapper_median = percentile_u128(&pbs_wrapper_samples.nanoseconds, 1, 2) as f64;
    let pbs_reuse_median = percentile_u128(&pbs_reuse_samples.nanoseconds, 1, 2) as f64;
    let rotate_wrapper_median = percentile_u128(&rotate_wrapper_samples.nanoseconds, 1, 2) as f64;
    let rotate_reuse_median = percentile_u128(&rotate_reuse_samples.nanoseconds, 1, 2) as f64;
    let pbs_paired_deltas = paired_deltas(
        &pbs_wrapper_samples.nanoseconds,
        &pbs_reuse_samples.nanoseconds,
    );
    let rotate_paired_deltas = paired_deltas(
        &rotate_wrapper_samples.nanoseconds,
        &rotate_reuse_samples.nanoseconds,
    );

    println!("{{");
    println!("  \"artifact\": \"A77 scalar PBS buffer-reuse microbenchmark\",");
    println!("  \"status\": \"PASS_SCALAR_CAUSAL_MICROBENCH\",");
    println!("  \"params_id\": \"{PARAMS_ID}\",");
    println!("  \"rayon_num_threads\": 1,");
    println!("  \"warmup_per_path\": {warmup},");
    println!("  \"iterations_per_path\": {iterations},");
    println!("  \"balanced_ab_ba_order\": true,");
    println!("  \"same_input_ciphertext\": true,");
    println!("  \"same_accumulator\": true,");
    println!("  \"same_fourier_bsk\": true,");
    println!("  \"bit_exact_outputs_equal\": true,");
    println!("  \"decrypted_message_all_paths\": {EXPECTED_MESSAGE},");
    println!("  \"setup_and_correctness_s\": {setup_and_correctness_s:.6},");
    println!("  \"scratch\": {{");
    println!("    \"pbs_required_bytes\": {pbs_requirement},");
    println!("    \"blind_rotate_required_bytes\": {blind_rotate_requirement},");
    println!("    \"reusable_capacity_bytes\": {reusable_capacity}");
    println!("  }},");
    println!("  \"geometry\": {{");
    println!(
        "    \"input_lwe_dimension\": {},",
        fourier_bsk.input_lwe_dimension().0
    );
    println!(
        "    \"output_lwe_dimension\": {},",
        fourier_bsk.output_lwe_dimension().0
    );
    println!("    \"glwe_size\": {},", fourier_bsk.glwe_size().0);
    println!(
        "    \"polynomial_size\": {}",
        fourier_bsk.polynomial_size().0
    );
    println!("  }},");
    println!("  \"comparison\": {{");
    println!(
        "    \"pbs_wrapper_over_reuse_median_ratio\": {:.6},",
        pbs_wrapper_median / pbs_reuse_median
    );
    println!(
        "    \"pbs_reuse_median_reduction_percent\": {:.6},",
        100.0 * (pbs_wrapper_median - pbs_reuse_median) / pbs_wrapper_median
    );
    println!(
        "    \"pbs_paired_median_wrapper_minus_reuse_ns\": {},",
        median_i128(&pbs_paired_deltas)
    );
    println!(
        "    \"pbs_paired_mean_wrapper_minus_reuse_ns\": {:.3},",
        mean_i128(&pbs_paired_deltas)
    );
    println!(
        "    \"pbs_reuse_wins\": {},",
        pbs_paired_deltas.iter().filter(|delta| **delta > 0).count()
    );
    println!(
        "    \"blind_rotate_wrapper_over_reuse_median_ratio\": {:.6},",
        rotate_wrapper_median / rotate_reuse_median
    );
    println!(
        "    \"blind_rotate_reuse_median_reduction_percent\": {:.6}",
        100.0 * (rotate_wrapper_median - rotate_reuse_median) / rotate_wrapper_median
    );
    println!(",");
    println!(
        "    \"blind_rotate_paired_median_wrapper_minus_reuse_ns\": {},",
        median_i128(&rotate_paired_deltas)
    );
    println!(
        "    \"blind_rotate_paired_mean_wrapper_minus_reuse_ns\": {:.3},",
        mean_i128(&rotate_paired_deltas)
    );
    println!(
        "    \"blind_rotate_reuse_wins\": {}",
        rotate_paired_deltas
            .iter()
            .filter(|delta| **delta > 0)
            .count()
    );
    println!("  }},");
    println!("  \"samples\": {{");
    print_samples("pbs_convenience_wrapper", &pbs_wrapper_samples);
    println!(",");
    print_samples("pbs_mem_optimized_reuse", &pbs_reuse_samples);
    println!(",");
    print_samples("blind_rotate_convenience_wrapper", &rotate_wrapper_samples);
    println!(",");
    print_samples("blind_rotate_mem_optimized_reuse", &rotate_reuse_samples);
    println!();
    println!("  }},");
    println!(
        "  \"claim_limit\": \"single-thread steady-state primitive benchmark; no exact-ID integration or parallel speedup claim\""
    );
    println!("}}");
}
