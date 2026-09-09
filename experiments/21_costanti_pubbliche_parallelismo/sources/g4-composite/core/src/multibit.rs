//! Experimental g4 comparator bridge. Evaluation holds public keys only.
//! Original big GLWE secret -> fresh catalog small904 -> SAME big GLWE secret.
//! The existing Head ingress, PFKS window and ordinary selection keys are retained.
use super::*;
use serde::{Deserialize, Serialize};
use std::mem::size_of_val;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex, OnceLock,
};
use std::time::Instant;
use tfhe::shortint::parameters::v1_7::V1_7_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128 as G4;

const THREAD_BUDGET: usize = 16;
static KEYS: OnceLock<BridgeKeys> = OnceLock::new();
static MAX_READY: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicUsize = AtomicUsize::new(0);
static PRODUCERS: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE: Mutex<Vec<Trace>> = Mutex::new(Vec::new());
static CONSUMERS: Mutex<Vec<ConsumerTrace>> = Mutex::new(Vec::new());

#[derive(Serialize, Deserialize)]
pub struct BridgeKeys {
    ksk: LweKeyswitchKeyOwned<u64>,
    bsk: FourierLweMultiBitBootstrapKeyOwned,
}

struct Trace {
    input: Lwe,
    small: Lwe,
    output: Lwe,
    ready_merges: usize,
    producers: usize,
}

struct ConsumerTrace {
    left: Vec<Lwe>,
    right: Vec<Lwe>,
    combined: Lwe,
    control: Lwe,
    output: Vec<Lwe>,
    lanes: Vec<usize>,
}

pub fn parameters() -> Value {
    let a44 = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
    json!({
        "schema":"g4-current-core-bridge.v1",
        "a44_constant":"V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64",
        "g4_constant":"V1_7_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128",
        "a44":a44,"g4_catalog":G4,"deterministic_execution":true,
        "input_profile":"native51/60", "comparator_delta":SCORE_DELTA,
        "key_path":"existing big2048 -> new independent small904 -> same existing big2048; then existing A44 small859 KS/mean/BR/PFKS consumer",
        "a44_small_dimension":a44.lwe_dimension.0,"g4_small_dimension":G4.lwe_dimension.0,
        "g4_ks_base_log":G4.ks_base_log.0,"g4_ks_levels":G4.ks_level.0,
        "g4_pbs_base_log":G4.pbs_base_log.0,"g4_pbs_levels":G4.pbs_level.0,
        "shared_binary_glwe_secret":true,"identical_glwe_noise":a44.glwe_noise_distribution==G4.glwe_noise_distribution,
        "catalog_failure_scope":"Catalog fields are premises only; no composed custom comparator/PFKS failure bound is established.",
        "scheduling_scope":"One evaluator at a time; each ready merge calls its three comparator PBS sequentially. Caller plus producers is budgeted; original PFKS remains on its caller."
    })
}

impl BridgeKeys {
    /// Setup only. The returned small secret is for terminal diagnostic observation.
    pub fn generate(big_glwe: &GlweSecretKeyOwned<u64>) -> (Self, LweSecretKeyOwned<u64>, Value) {
        let a44 = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
        assert_eq!(big_glwe.glwe_dimension(), G4.glwe_dimension);
        assert_eq!(big_glwe.polynomial_size(), G4.polynomial_size);
        assert_eq!(a44.glwe_noise_distribution, G4.glwe_noise_distribution);
        assert!(big_glwe.as_ref().iter().all(|&word| word <= 1));
        let mut seeder = new_seeder();
        let mut secret_random = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        let mut random = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder.as_mut(),
        );
        let small =
            allocate_and_generate_new_binary_lwe_secret_key(G4.lwe_dimension, &mut secret_random);
        let ks_start = Instant::now();
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_glwe.as_lwe_secret_key(),
            &small,
            G4.ks_base_log,
            G4.ks_level,
            G4.lwe_noise_distribution,
            G4.ciphertext_modulus,
            &mut random,
        );
        let ks_ns = ks_start.elapsed().as_nanos() as u64;
        let bsk_start = Instant::now();
        let mut standard = LweMultiBitBootstrapKeyOwned::new(
            0,
            G4.glwe_dimension.to_glwe_size(),
            G4.polynomial_size,
            G4.pbs_base_log,
            G4.pbs_level,
            G4.lwe_dimension,
            G4.grouping_factor,
            G4.ciphertext_modulus,
        );
        par_generate_lwe_multi_bit_bootstrap_key(
            &small,
            big_glwe,
            &mut standard,
            G4.glwe_noise_distribution,
            &mut random,
        );
        let bsk_ns = bsk_start.elapsed().as_nanos() as u64;
        let standard_sha256 = observer::hash_words(standard.as_ref());
        let conversion_start = Instant::now();
        let mut bsk = FourierLweMultiBitBootstrapKeyOwned::new(
            G4.lwe_dimension,
            G4.glwe_dimension.to_glwe_size(),
            G4.polynomial_size,
            G4.pbs_base_log,
            G4.pbs_level,
            G4.grouping_factor,
        );
        par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&standard, &mut bsk);
        let conversion_ns = conversion_start.elapsed().as_nanos() as u64;
        let metadata = json!({"parameters":parameters(),"ks_generation_ns":ks_ns,
            "bsk_generation_ns":bsk_ns,"fourier_conversion_ns":conversion_ns,
            "ksk_sha256":observer::hash_words(ksk.as_ref()),"standard_bsk_sha256":standard_sha256,
            "ksk_container_bytes":size_of_val(ksk.as_ref()),"standard_bsk_container_bytes":size_of_val(standard.as_ref()),
            "fourier_bsk_container_bytes":size_of_val(bsk.as_view().data()),
            "standard_bsk_released_after_setup":true});
        (Self { ksk, bsk }, small, metadata)
    }

    pub fn install(self) {
        assert_eq!(self.ksk.input_key_lwe_dimension().0, 2048);
        assert_eq!(self.ksk.output_key_lwe_dimension(), G4.lwe_dimension);
        assert_eq!(self.ksk.decomposition_base_log(), G4.ks_base_log);
        assert_eq!(self.ksk.decomposition_level_count(), G4.ks_level);
        assert_eq!(self.bsk.input_lwe_dimension(), G4.lwe_dimension);
        assert_eq!(self.bsk.output_lwe_dimension().0, 2048);
        assert_eq!(self.bsk.grouping_factor(), G4.grouping_factor);
        assert_eq!(self.bsk.polynomial_size(), G4.polynomial_size);
        assert_eq!(self.bsk.glwe_size(), G4.glwe_dimension.to_glwe_size());
        assert_eq!(self.bsk.decomposition_base_log(), G4.pbs_base_log);
        assert_eq!(self.bsk.decomposition_level_count(), G4.pbs_level);
        assert!(self.ksk.ciphertext_modulus().is_native_modulus());
        assert_eq!(size_of_val(self.ksk.as_ref()), 59_310_080);
        assert_eq!(size_of_val(self.bsk.as_view().data()), 236_978_176);
        assert!(KEYS.set(self).is_ok(), "one g4 key family per process");
    }
}

/// Explicit command boundary; this experimental process admits only one query at a time.
pub fn begin_query(max_ready: usize, trace: bool) {
    assert!([0, 1, 2, 4].contains(&max_ready));
    assert!(max_ready == 0 || KEYS.get().is_some());
    MAX_READY.store(max_ready, Ordering::Relaxed);
    PRODUCERS.store(0, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    TRACE_ENABLED.store(trace, Ordering::Relaxed);
    TRACE.lock().unwrap().clear();
    CONSUMERS.lock().unwrap().clear();
}

/// Called by the coordinator before each tournament level and final predicate.
pub(super) fn configure_level(ready_merges: usize, parallel: bool) {
    let max_ready = MAX_READY.load(Ordering::Relaxed);
    let producers = if ready_merges > 0 && ready_merges <= max_ready {
        let callers = if parallel { ready_merges } else { 1 };
        let producers = THREAD_BUDGET / callers - 1;
        assert!(callers * (producers + 1) <= THREAD_BUDGET);
        producers
    } else {
        0
    };
    READY.store(ready_merges, Ordering::Relaxed);
    PRODUCERS.store(producers, Ordering::Relaxed);
}

/// No secret key or phase observation is available on this homomorphic path.
pub(super) fn maybe_pbs(input: &Lwe, final_control: bool) -> Option<Lwe> {
    let producers = PRODUCERS.load(Ordering::Relaxed);
    if producers == 0 {
        return None;
    }
    assert!(
        !final_control,
        "current comparator uses only three ternary PBS"
    );
    let keys = KEYS.get().expect("g4 keys installed before evaluation");
    assert_eq!(input.lwe_size().0, 2049);
    let mut small = Lwe::new(
        0,
        G4.lwe_dimension.to_lwe_size(),
        input.ciphertext_modulus(),
    );
    keyswitch_lwe_ciphertext(&keys.ksk, input, &mut small);
    let mut accumulator = Glwe::new(
        0,
        GlweSize(2),
        PolynomialSize(2048),
        input.ciphertext_modulus(),
    );
    accumulator
        .get_mut_body()
        .as_mut()
        .copy_from_slice(&comparator::body(false));
    let mut output = Lwe::new(0, LweSize(2049), input.ciphertext_modulus());
    multi_bit_programmable_bootstrap_lwe_ciphertext(
        &small,
        &mut output,
        &accumulator,
        &keys.bsk,
        ThreadCount(producers),
        true,
    );
    CALLS.fetch_add(1, Ordering::Relaxed);
    if TRACE_ENABLED.load(Ordering::Relaxed) {
        TRACE.lock().unwrap().push(Trace {
            input: input.clone(),
            small,
            output: output.clone(),
            ready_merges: READY.load(Ordering::Relaxed),
            producers,
        });
    }
    Some(output)
}

pub fn query_stats() -> Value {
    json!({"g4_pbs_calls":CALLS.load(Ordering::Relaxed),
        "g4_ks_calls":CALLS.load(Ordering::Relaxed),"maximum_ready_merges":MAX_READY.load(Ordering::Relaxed),
        "thread_budget":THREAD_BUDGET,"traced":TRACE_ENABLED.load(Ordering::Relaxed)})
}

pub(super) fn record_consumer(
    left: &[Lwe],
    right: &[Lwe],
    combined: &Lwe,
    control: &Lwe,
    output: &[Lwe],
    lanes: impl Iterator<Item = usize>,
) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) || PRODUCERS.load(Ordering::Relaxed) == 0 {
        return;
    }
    CONSUMERS.lock().unwrap().push(ConsumerTrace {
        left: left.to_vec(),
        right: right.to_vec(),
        combined: combined.clone(),
        control: control.clone(),
        output: output.to_vec(),
        lanes: lanes.collect(),
    });
}

/// Observe the actual retained A44 KS/mean object and actual PFKS/BR/extracted outputs.
/// This is a client diagnostic after the complete endpoint; it cannot alter its result.
pub fn observe_completed_consumers(
    big_glwe: &GlweSecretKeyOwned<u64>,
    a44_small: &LweSecretKeyOwned<u64>,
) -> Vec<Value> {
    assert_eq!(a44_small.lwe_dimension().0, 859);
    let big = big_glwe.as_lwe_secret_key();
    let traces = std::mem::take(&mut *CONSUMERS.lock().unwrap());
    traces.into_iter().map(|trace| {
        let combined_phase = decrypt_lwe_ciphertext(&big,&trace.combined).0;
        let choose_right = (combined_phase as i64)>0;
        let switched: Vec<usize> = trace.control.as_ref().iter().map(|&w|pbs_modulus_switch(w,PolynomialSize(2048))).collect();
        let dot: i128 = switched[..859].iter().zip(a44_small.as_ref()).map(|(&a,&s)|a as i128*s as i128).sum();
        let address = (switched[859] as i128-dot).rem_euclid(4096) as usize;
        let window = service_selected::window_function();
        let coefficient = window.as_ref()[address%2048];
        let window_value = if address<2048 { coefficient } else { coefficient.wrapping_neg() };
        let reference = if choose_right { &trace.right } else { &trace.left };
        let lanes:Vec<Value> = trace.lanes.iter().map(|&lane| {
            let reference_phase=decrypt_lwe_ciphertext(&big,&reference[lane]).0;
            let expected_digit=reference_phase.wrapping_add(SCORE_DELTA/2)/SCORE_DELTA;
            let output_phase=decrypt_lwe_ciphertext(&big,&trace.output[lane]).0;
            let error=output_phase.wrapping_sub(expected_digit.wrapping_mul(SCORE_DELTA)) as i64;
            json!({"lane":lane,"expected_digit_from_observed_selected_input":expected_digit,
                "output_phase":output_phase,"error_torus":error,
                "output_sha256":observer::hash_words(trace.output[lane].as_ref()),
                "pass":expected_digit<=15 && error.unsigned_abs()<SCORE_DELTA/2})
        }).collect();
        let pass=window_value==u64::from(choose_right) && lanes.iter().all(|v|v["pass"]==true);
        json!({"record":"actual_pfks_consumer_observation","combined_sha256":observer::hash_words(trace.combined.as_ref()),
            "combined_phase":combined_phase,"choose_right_from_observed_control":choose_right,
            "retained_a44_mean_corrected_control_sha256":observer::hash_words(trace.control.as_ref()),
            "actual_standard_modulus_switched_address":address,"window_value_at_actual_address":window_value,
            "pfks_base_log":22,"pfks_levels":1,"lane_offsets":"positions*41 within each group; actual sample extraction plus original left addback",
            "lanes":lanes,"pass":pass})
    }).collect()
}

struct GroupedAddress {
    address: usize,
    selected_degrees: Vec<usize>,
    body_residue: i64,
    grouped_residue_sum: i128,
    phase_identity: bool,
}

/// Group4 rounds the selected subset sum once, rather than each mask coefficient.
fn grouped_address(input: &Lwe, secret: &[u64]) -> GroupedAddress {
    assert_eq!(input.get_mask().as_ref().len(), secret.len());
    assert_eq!(secret.len() % 4, 0);
    assert!(secret.iter().all(|&value| value <= 1));
    let unit = 1u64 << 52;
    let mut selected_degrees = Vec::with_capacity(secret.len() / 4);
    let mut grouped_residue_sum = 0i128;
    let mut mask_phase = 0u64;
    for (mask, bits) in input
        .get_mask()
        .as_ref()
        .chunks_exact(4)
        .zip(secret.chunks_exact(4))
    {
        let selected_sum = mask
            .iter()
            .zip(bits)
            .fold(0u64, |sum, (&a, &s)| sum.wrapping_add(a.wrapping_mul(s)));
        let selected_degree = pbs_modulus_switch(selected_sum, PolynomialSize(2048));
        selected_degrees.push(selected_degree);
        grouped_residue_sum +=
            selected_sum.wrapping_sub((selected_degree as u64).wrapping_mul(unit)) as i64 as i128;
        mask_phase = mask_phase.wrapping_add(selected_sum);
    }
    let body = *input.get_body().data;
    let body_degree = pbs_modulus_switch(body, PolynomialSize(2048));
    let body_residue = body.wrapping_sub((body_degree as u64).wrapping_mul(unit)) as i64;
    let degree_sum: i128 = selected_degrees.iter().map(|&degree| degree as i128).sum();
    let address = (body_degree as i128 - degree_sum).rem_euclid(4096) as usize;
    let reconstructed = (address as u64)
        .wrapping_mul(unit)
        .wrapping_add(body_residue as u64)
        .wrapping_sub(grouped_residue_sum as u64);
    GroupedAddress {
        address,
        selected_degrees,
        body_residue,
        grouped_residue_sum,
        phase_identity: reconstructed == body.wrapping_sub(mask_phase),
    }
}

/// Only call AFTER keys.evaluate has returned. Observed values never feed the evaluator.
pub fn observe_completed_query(
    big_glwe: &GlweSecretKeyOwned<u64>,
    small_secret: &LweSecretKeyOwned<u64>,
) -> Vec<Value> {
    let big = big_glwe.as_lwe_secret_key();
    let traces = std::mem::take(&mut *TRACE.lock().unwrap());
    traces.into_iter().map(|trace| {
        let input_phase = decrypt_lwe_ciphertext(&big, &trace.input).0;
        let small_phase = decrypt_lwe_ciphertext(small_secret, &trace.small).0;
        let output_phase = decrypt_lwe_ciphertext(&big, &trace.output).0;
        let residue = input_phase.wrapping_add(SCORE_DELTA/2) / SCORE_DELTA;
        let input_digit = if residue >= 16 { residue as i64 - 32 } else { residue as i64 };
        let expected_output = input_digit.signum();
        let output_error = output_phase.wrapping_sub((expected_output as u64).wrapping_mul(SCORE_DELTA)) as i64;
        let grouped = grouped_address(&trace.small, small_secret.as_ref());
        let actual_address = grouped.address;
        let actual_lut = comparator::value(false, actual_address);
        let input_error = input_phase.wrapping_sub((input_digit as u64).wrapping_mul(SCORE_DELTA)) as i64;
        let small_error = small_phase.wrapping_sub((input_digit as u64).wrapping_mul(SCORE_DELTA)) as i64;
        let pass = grouped.phase_identity && (-15..=15).contains(&input_digit) && actual_lut==expected_output
            && output_error.unsigned_abs()<SCORE_DELTA/2 && small_error.unsigned_abs()<SCORE_DELTA/2;
        let nontrivial_masks=[&trace.input,&trace.small,&trace.output]
            .map(|ct|ct.get_mask().as_ref().iter().any(|&word|word!=0));
        json!({"record":"g4_bridge_observation","input_sha256":observer::hash_words(trace.input.as_ref()),
            "small_sha256":observer::hash_words(trace.small.as_ref()),"output_sha256":observer::hash_words(trace.output.as_ref()),
            "input_phase":input_phase,"small_phase":small_phase,"output_phase":output_phase,
            "observed_input_digit_difference":input_digit,"expected_ternary_from_observed_input":expected_output,
            "input_error_torus":input_error,"small_error_torus":small_error,"output_error_torus":output_error,
            "ks_increment_torus":small_phase.wrapping_sub(input_phase) as i64,
            "actual_grouped_modulus_switched_address":actual_address,"actual_lut":actual_lut,
            "selected_group_degrees":grouped.selected_degrees,"grouped_phase_identity_pass":grouped.phase_identity,
            "body_residue_torus":grouped.body_residue,"grouped_residue_sum_decimal":grouped.grouped_residue_sum.to_string(),
            "ready_merges":trace.ready_merges,"producers_per_call":trace.producers,
            "nontrivial_masks":nontrivial_masks,
            "observation_scope":"After complete endpoint returned; input digit inferred from diagnostic decryption; complete endpoint separately checked against independent public-scene oracle.",
            "pass":pass})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_glwe_and_scale_match_without_changing_input_profile() {
        let a44 = V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
        assert_eq!(a44.lwe_dimension.0, 859);
        assert_eq!(G4.lwe_dimension.0, 904);
        assert_eq!(a44.glwe_dimension, G4.glwe_dimension);
        assert_eq!(a44.polynomial_size, G4.polynomial_size);
        assert_eq!(a44.glwe_noise_distribution, G4.glwe_noise_distribution);
        assert_eq!(G4.ks_base_log.0 * G4.ks_level.0, 16);
        assert_eq!(SCORE_DELTA, 1u64 << 59);
        for left in 0i64..16 {
            for right in 0i64..16 {
                let degree = ((left - right) * 128).rem_euclid(4096) as usize;
                assert_eq!(comparator::value(false, degree), (left - right).signum());
            }
        }
    }

    #[test]
    fn grouped_address_matches_library_for_random_wrap_and_rounding_boundaries() {
        let unit = 1u64 << 52;
        let mut random = 0x83d29d1b2ab6507du64;
        let mut next = || {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        };
        let boundaries = [
            0,
            1,
            u64::MAX,
            unit / 2 - 1,
            unit / 2,
            unit / 2 + 1,
            3 * unit / 8,
            u64::MAX - unit / 2,
            u64::MAX - unit / 2 + 1,
            unit - 1,
            unit,
            unit + 1,
        ];
        for case in 0..1024 {
            let mask: [u64; 8] = std::array::from_fn(|lane| {
                if case < boundaries.len() {
                    boundaries[(case + lane) % boundaries.len()]
                } else {
                    next()
                }
            });
            let body = if case < boundaries.len() {
                boundaries[case]
            } else {
                next()
            };
            for pattern in 0..256usize {
                let bits: [u64; 8] =
                    std::array::from_fn(|lane| ((pattern >> (7 - lane)) & 1) as u64);
                let mut words = mask.to_vec();
                words.push(body);
                let input = Lwe::from_container(words, CiphertextModulus::new_native());
                let observed = grouped_address(&input, &bits);
                let library_degrees: Vec<usize> = mask
                    .chunks_exact(4)
                    .zip(bits.chunks_exact(4))
                    .map(|(mask, bits)| {
                        let index = bits
                            .iter()
                            .fold(0usize, |index, &bit| (index << 1) | bit as usize);
                        if index == 0 {
                            0
                        } else {
                            tfhe::core_crypto::algorithms::modulus_switch_multi_bit(
                                CiphertextModulusLog(12),
                                LweBskGroupingFactor(4),
                                mask,
                            )
                            .nth(index - 1)
                            .unwrap()
                        }
                    })
                    .collect();
                assert_eq!(observed.selected_degrees, library_degrees);
                let library_address = (pbs_modulus_switch(body, PolynomialSize(2048)) as i128
                    - library_degrees
                        .iter()
                        .map(|&degree| degree as i128)
                        .sum::<i128>())
                .rem_euclid(4096) as usize;
                assert_eq!(observed.address, library_address);
                assert!(observed.phase_identity);
            }
        }
        let input = Lwe::from_container(
            vec![3 * unit / 8, 3 * unit / 8, 0, 0, 0],
            CiphertextModulus::new_native(),
        );
        assert_eq!(grouped_address(&input, &[1, 1, 0, 0]).address, 4095);
    }
}

// Public evaluation-key access for this separate primitive gate only.
impl BridgeKeys {
    pub(crate) fn primitive_keys(&self) -> (&LweKeyswitchKeyOwned<u64>, &FourierLweMultiBitBootstrapKeyOwned) {
        (&self.ksk, &self.bsk)
    }
}

// Experimental whole-query dynamic selector borrows the installed same-key bridge.
pub(super) fn installed_primitive_keys() -> &'static BridgeKeys {
    KEYS.get().expect("g4 bridge installed before dynamic selection")
}
