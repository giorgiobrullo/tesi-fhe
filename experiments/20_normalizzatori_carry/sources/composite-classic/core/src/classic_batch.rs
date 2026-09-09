//! Comparator scheduling experiment. Controls change only between synchronous evaluations.
//! The existing outer Rayon pool remains responsible for merge-level parallelism.
use super::*;
use dyn_stack::{PodBuffer, PodStack};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use tfhe::core_crypto::fft_impl::fft64::math::fft::Fft;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Scalar,
    Batch3,
    Parallel3,
}

static MODE: AtomicU8 = AtomicU8::new(Mode::Scalar as u8);
static READY: AtomicUsize = AtomicUsize::new(0);
static REQUESTED_PARALLEL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
static PARALLEL_CALLS: AtomicUsize = AtomicUsize::new(0);

pub fn set_mode(mode: Mode) {
    MODE.store(mode as u8, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    BATCH_CALLS.store(0, Ordering::Relaxed);
    PARALLEL_CALLS.store(0, Ordering::Relaxed);
}

pub(super) fn configure_level(ready_merges: usize, requested_parallel: bool) {
    READY.store(ready_merges, Ordering::Relaxed);
    REQUESTED_PARALLEL.store(requested_parallel, Ordering::Relaxed);
}

fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        0 => Mode::Scalar,
        1 => Mode::Batch3,
        2 if REQUESTED_PARALLEL.load(Ordering::Relaxed)
            && (1..=4).contains(&READY.load(Ordering::Relaxed)) =>
        {
            Mode::Parallel3
        }
        2 => Mode::Scalar,
        _ => unreachable!("only Mode values are stored"),
    }
}

pub fn report() -> Value {
    json!({"batch3_merges":BATCH_CALLS.load(Ordering::Relaxed),
           "parallel3_merges":PARALLEL_CALLS.load(Ordering::Relaxed),
           "parallel3_max_ready_merges":4,
           "additional_keys":0,"pbs_calls_saved":0,"ks_calls_saved":0})
}

pub(super) fn stages(
    left: &[Lwe],
    right: &[Lwe],
    sk: &ServerKey,
    scalar_pbs: impl Fn(Lwe) -> Lwe + Sync,
) -> Vec<Lwe> {
    let difference = |j: usize| {
        let mut difference = left[j].clone();
        for (word, r) in difference.as_mut().iter_mut().zip(right[j].as_ref()) {
            *word = word.wrapping_sub(*r);
        }
        difference
    };
    match mode() {
        Mode::Scalar => {
            let mut stages = Vec::with_capacity(3);
            for j in 0..3 {
                stages.push(scalar_pbs(difference(j)));
            }
            stages
        }
        Mode::Parallel3 => {
            PARALLEL_CALLS.fetch_add(1, Ordering::Relaxed);
            (0..3)
                .into_par_iter()
                .map(|j| scalar_pbs(difference(j)))
                .collect()
        }
        Mode::Batch3 => {
            BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
            let inputs: Vec<_> = (0..3).map(difference).collect();
            batch3(&inputs, sk)
        }
    }
}

fn batch3(inputs: &[Lwe], sk: &ServerKey) -> Vec<Lwe> {
    assert_eq!(inputs.len(), 3);
    let ShortintBootstrappingKey::Classic(bsk) = &sk.bootstrapping_key;
    assert_eq!(bsk.input_lwe_dimension(), LweDimension(859));
    assert_eq!(
        (bsk.glwe_size(), bsk.polynomial_size()),
        (GlweSize(2), PolynomialSize(2048))
    );
    let modulus = inputs[0].ciphertext_modulus();
    assert!(modulus.is_native_modulus());
    // Packing and every allocation occur inside keys.evaluate and its query timer.
    let mut small = LweCiphertextList::new(
        0u64,
        sk.key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size(),
        LweCiphertextCount(3),
        modulus,
    );
    for (input, mut output) in inputs.iter().zip(small.iter_mut()) {
        keyswitch_lwe_ciphertext(&sk.key_switching_key, input, &mut output);
    }
    let mut accumulators = GlweCiphertextList::new(
        0u64,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        GlweCiphertextCount(3),
        modulus,
    );
    for mut accumulator in accumulators.iter_mut() {
        #[cfg(not(feature = "opt-lut-cache"))]
        let body = comparator::body(false);
        #[cfg(feature = "opt-lut-cache")]
        let body = comparator::cached_body(false);
        accumulator.get_mut_body().as_mut().copy_from_slice(&body);
    }
    let mut outputs = LweCiphertextList::new(
        0u64,
        bsk.output_lwe_dimension().to_lwe_size(),
        LweCiphertextCount(3),
        modulus,
    );
    let fft = Fft::new(bsk.polynomial_size());
    let fft = fft.as_view();
    let requirement = batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
        bsk.glwe_size(),
        bsk.polynomial_size(),
        CiphertextCount(3),
        fft,
    );
    let mut memory = PodBuffer::new(requirement);
    batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(
        &small,
        &mut outputs,
        &accumulators,
        bsk,
        fft,
        PodStack::new(&mut memory),
    );
    outputs
        .iter()
        .map(|ct| Lwe::from_container(ct.as_ref().to_vec(), modulus))
        .collect()
}
