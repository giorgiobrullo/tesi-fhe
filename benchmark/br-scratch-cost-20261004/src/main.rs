//! Public scratch-buffer cost only: no keys, ciphertexts or cryptographic evaluation.
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde_json::{json, Value};
use std::{cell::RefCell, hint::black_box, sync::Barrier, time::Instant};
use tfhe::core_crypto::{
    algorithms::blind_rotate_assign_mem_optimized_requirement,
    commons::computation_buffers::ComputationBuffers,
    fft_impl::fft64::math::fft::{setup_custom_fft_plan, Fft, FftAlgo, Method, Plan},
    prelude::{GlweSize, PolynomialSize},
};

const WARMUP: usize = 256;
const CYCLES: usize = 8192;
thread_local! {
    static REUSED: RefCell<ComputationBuffers> = RefCell::new(ComputationBuffers::new());
}

#[derive(Clone, Copy)]
enum Arm { Fresh, Reuse }
impl Arm {
    fn name(self) -> &'static str { match self { Self::Fresh => "fresh", Self::Reuse => "reuse" } }
}
struct WorkerResult { index: usize, elapsed_ns: Option<u128>, checksum: u64 }

// Passing the entire mutable slice to black_box keeps all initialized bytes observable.
// The same two endpoint reads are used in both arms; there is no full-buffer traversal.
fn observe(buffers: &mut ComputationBuffers, bytes: usize) -> u64 {
    let (memory, _) = buffers.stack().make_aligned_raw::<u8>(bytes, 1);
    let memory = black_box(memory);
    u64::from(black_box(memory[0])) + u64::from(black_box(memory[bytes - 1]))
}

fn run_batch(pool: &ThreadPool, bytes: usize, arm: Arm, measured: bool, cycles: usize,
    block: Option<usize>, position: usize) -> Value {
    let workers = pool.current_num_threads();
    let barrier = Barrier::new(workers);
    let batch_started = measured.then(Instant::now);
    let results = pool.broadcast(|context| REUSED.with(|slot| {
        let mut reused = slot.borrow_mut();
        barrier.wait();
        let started = measured.then(Instant::now);
        let mut checksum = 0u64;
        match arm {
            Arm::Fresh => for _ in 0..cycles {
                let mut buffers = ComputationBuffers::new();
                buffers.resize(bytes);
                checksum = checksum.wrapping_add(observe(&mut buffers, bytes));
                drop(buffers); // Free is inside the worker timer.
            },
            Arm::Reuse => for _ in 0..cycles {
                reused.resize(bytes); // Same-size resize; preallocation happened before timing.
                checksum = checksum.wrapping_add(observe(&mut reused, bytes));
            },
        }
        let elapsed_ns = started.map(|clock| clock.elapsed().as_nanos());
        black_box(checksum);
        WorkerResult { index: context.index(), elapsed_ns, checksum }
    }));
    let batch_wall_ns = batch_started.map(|clock| clock.elapsed().as_nanos());
    assert_eq!(results.len(), workers);
    let rows: Vec<_> = results.into_iter().map(|result| {
        assert_eq!(result.checksum, 0, "public zero-buffer endpoint observation changed");
        json!({"worker_index": result.index, "worker_wall_ns": result.elapsed_ns,
            "worker_ns_per_cycle": result.elapsed_ns.map(|ns| ns as f64 / cycles as f64),
            "endpoint_checksum": result.checksum})
    }).collect();
    let total_cycles = workers * cycles;
    let fresh = matches!(arm, Arm::Fresh);
    json!({
        "schema": "current-br-scratch-cost.batch.v1", "phase": if measured { "measured" } else { "warmup" },
        "workers": workers, "block": block, "position": position, "arm": arm.name(),
        "cycles_per_worker": cycles, "total_cycles": total_cycles,
        "scratch_bytes": bytes, "batch_wall_ns": batch_wall_ns,
        "batch_wall_ns_per_total_cycle": batch_wall_ns.map(|ns| ns as f64 / total_cycles as f64),
        "worker_results": rows,
        "logical_scratch_buffer_constructions_in_loop": if fresh { total_cycles } else { 0 },
        "logical_scratch_buffer_drops_in_loop": if fresh { total_cycles } else { 0 },
        "logical_scratch_resize_calls_in_loop": total_cycles,
        "count_semantics": "source/schedule counts for scratch objects; not instrumented allocator calls or all process allocations",
        "timing_semantics": "worker loop starts after barrier; batch includes broadcast dispatch, TLS borrow, barrier and join; neither worker sum nor batch/total-cycle is individual call latency",
    })
}

fn main() {
    assert_eq!(std::env::args().len(), 1, "this helper uses the fixed physical protocol, no CLI overrides");
    let plan = Plan::new(1024, Method::UserProvided { base_algo: FftAlgo::Dif4, base_n: 1024 });
    let plan_description = format!("{plan:?}");
    setup_custom_fft_plan(plan); // Install before constructing the Fft owner.
    let fft = Fft::new(PolynomialSize(2048));
    let bytes = blind_rotate_assign_mem_optimized_requirement::<u64>(
        GlweSize(2), PolynomialSize(2048), fft.as_view(),
    ).unaligned_bytes_required();
    assert!(bytes > 0);
    println!("{}", json!({
        "schema": "current-br-scratch-cost.metadata.v1", "tfhe": "1.8.1",
        "rayon": "1.12.0", "serde_json": "1.0.150", "scalar": "u64",
        "glwe_size": 2, "polynomial_size": 2048, "fft_size": 1024,
        "fft_policy": "user-provided-dif4-polynomial2048-base1024-v1",
        "fft_plan": plan_description, "scratch_unaligned_bytes_required": bytes,
        "worker_configurations": [1, 16], "warmup_cycles_per_worker_per_arm": WARMUP,
        "measured_cycles_per_worker_per_arm_per_block": CYCLES, "blocks": 4,
        "orders": [["fresh", "reuse"], ["reuse", "fresh"], ["fresh", "reuse"], ["reuse", "fresh"]],
        "expected_warmup_rows": 4, "expected_measured_rows": 16,
        "target_arch": std::env::consts::ARCH, "target_os": std::env::consts::OS,
        "declared_release_profile": "opt3-cgu1-no-lto",
        "compiler_identity": option_env!("SCRATCH_BUILD_RUSTC").unwrap_or("external build receipt required"),
        "package_version": env!("CARGO_PKG_VERSION"),
        "scope": "public scratch allocation/zeroing/free versus reuse; no FHE, query savings or error bound",
    }));
    for workers in [1, 16] {
        let pool = ThreadPoolBuilder::new().num_threads(workers).build().expect("dedicated worker pool");
        // Construct, zero and first-touch every worker's private reused buffer outside all clocks.
        pool.broadcast(|_| REUSED.with(|slot| {
            let mut buffers = slot.borrow_mut();
            buffers.resize(bytes);
            black_box(observe(&mut buffers, bytes));
        }));
        for (position, arm) in [Arm::Fresh, Arm::Reuse].into_iter().enumerate() {
            println!("{}", run_batch(&pool, bytes, arm, false, WARMUP, None, position));
        }
        for block in 0..4 {
            let order = if block % 2 == 0 { [Arm::Fresh, Arm::Reuse] } else { [Arm::Reuse, Arm::Fresh] };
            for (position, arm) in order.into_iter().enumerate() {
                println!("{}", run_batch(&pool, bytes, arm, true, CYCLES, Some(block), position));
            }
        }
    }
}
