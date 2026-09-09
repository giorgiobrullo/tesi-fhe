//! Scratch route for an open-set encrypted argmin without a noisy selection tournament.
//!
//! The compact GLWE probe and plaintext gallery produce all wide LWE scores exactly as in the
//! current service.  Every pair of scores is then compared independently with an extended
//! periodic-fold comparator.  A row-wise encrypted AND yields exactly one accepted winner (or no
//! winner when the nearest score is above the threshold), and the server returns one compact
//! encrypted code: `0 = reject`, `i + 1 = accepted nearest identity i`.
//!
//! This is intentionally a quadratic reliability baseline.  Unlike the circuit-bootstrap
//! tournament, no selected/noisy score is fed into a later comparison.  The source is separate
//! from `varco_demo.rs` and `argmin_torneo.rs`.
//!
//! Example:
//! `cargo run --release --bin argmin_pairwise_periodic -- --n 128 --probe 0 --probe 64`

use std::time::Instant;

use rayon::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const DIM: usize = 512;
const LOG_DELTA: u32 = 50;
const SCORE_RADIUS: i64 = (1i64 << (63 - LOG_DELTA)) - 1;
const PERIODS: [u64; 3] = [32, 512, 8192];
const LOG_BIT: u32 = 60;
const LOG_CODE: u32 = 55;
const AND_BLOCK: usize = 8;

struct Scene {
    gallery: Vec<Vec<i64>>,
    squared_norms: Vec<i64>,
    probes: Vec<Vec<i64>>,
    labels: Vec<i64>,
    threshold: i64,
}

fn load_scene(path: &str) -> Scene {
    let text = std::fs::read_to_string(path).expect("missing scene");
    let mut lines = text.lines();
    let header: Vec<i64> = lines
        .next()
        .expect("missing scene header")
        .split_whitespace()
        .map(|value| value.parse().expect("invalid header integer"))
        .collect();
    let (dim, gallery_len, probe_len, threshold) = (
        header[0] as usize,
        header[1] as usize,
        header[2] as usize,
        header[3],
    );
    assert_eq!(dim, DIM, "this scratch route expects 512-D embeddings");
    let gallery: Vec<Vec<i64>> = (0..gallery_len)
        .map(|_| {
            lines
                .next()
                .expect("missing gallery row")
                .split_whitespace()
                .map(|value| value.parse().expect("invalid gallery integer"))
                .collect()
        })
        .collect();
    let mut probes = Vec::with_capacity(probe_len);
    let mut labels = Vec::with_capacity(probe_len);
    for _ in 0..probe_len {
        let row: Vec<i64> = lines
            .next()
            .expect("missing probe row")
            .split_whitespace()
            .map(|value| value.parse().expect("invalid probe integer"))
            .collect();
        labels.push(row[0]);
        probes.push(row[1..].to_vec());
    }
    let squared_norms = gallery
        .iter()
        .map(|row| row.iter().map(|value| value * value).sum())
        .collect();
    Scene {
        gallery,
        squared_norms,
        probes,
        labels,
        threshold,
    }
}

fn clear_fold_doubled(difference: i64) -> i64 {
    let mut value = 2 * difference - 1;
    for period in PERIODS {
        let period = period as i64;
        let residue = value.rem_euclid(2 * period);
        value += if residue < period {
            period / 2
        } else {
            -(period / 2)
        };
    }
    value
}

fn pair_bound(scene: &Scene, n: usize, q: i64) -> i64 {
    (0..n)
        .into_par_iter()
        .map(|i| {
            ((i + 1)..n)
                .map(|j| {
                    let l1_difference: i64 = scene.gallery[i]
                        .iter()
                        .zip(&scene.gallery[j])
                        .map(|(left, right)| (left - right).abs())
                        .sum();
                    (scene.squared_norms[i] - scene.squared_norms[j]).abs() + 2 * q * l1_difference
                })
                .max()
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
}

fn threshold_bound(scene: &Scene, n: usize, q: i64) -> i64 {
    (0..n)
        .map(|i| {
            let l1: i64 = scene.gallery[i].iter().map(|value| value.abs()).sum();
            2 * q * l1 + scene.squared_norms[i] + scene.threshold.abs()
        })
        .max()
        .unwrap_or(0)
}

fn pbs(
    input: &LweCiphertextOwned<u64>,
    accumulator: &GlweCiphertextOwned<u64>,
    ksk: &LweKeyswitchKeyOwned<u64>,
    fbsk: &FourierLweBootstrapKeyOwned,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
) -> LweCiphertextOwned<u64> {
    let mut switched = LweCiphertext::new(0u64, small_size, modulus);
    keyswitch_lwe_ciphertext(ksk, input, &mut switched);
    let mut output = LweCiphertext::new(0u64, big_size, modulus);
    programmable_bootstrap_lwe_ciphertext(&switched, &mut output, accumulator, fbsk);
    output
}

struct PeriodicComparator<'a> {
    delta: u64,
    fold_accumulators: Vec<GlweCiphertextOwned<u64>>,
    sign_accumulator: GlweCiphertextOwned<u64>,
    ksk: &'a LweKeyswitchKeyOwned<u64>,
    fbsk: &'a FourierLweBootstrapKeyOwned,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
}

impl PeriodicComparator<'_> {
    /// Input is `difference * Delta`; output is a bit at `2^LOG_BIT` for `difference <= 0`.
    fn less_or_equal_zero(&self, mut state: LweCiphertextOwned<u64>) -> LweCiphertextOwned<u64> {
        lwe_ciphertext_plaintext_sub_assign(&mut state, Plaintext(self.delta >> 1));
        for (period, accumulator) in PERIODS.iter().zip(&self.fold_accumulators) {
            let shift = u64::BITS - LOG_DELTA - period.ilog2();
            let mut periodic_phase = state.clone();
            lwe_ciphertext_cleartext_mul_assign(&mut periodic_phase, Cleartext(1u64 << shift));
            let correction = pbs(
                &periodic_phase,
                accumulator,
                self.ksk,
                self.fbsk,
                self.small_size,
                self.big_size,
                self.modulus,
            );
            lwe_ciphertext_add_assign(&mut state, &correction);
        }
        let mut bit = pbs(
            &state,
            &self.sign_accumulator,
            self.ksk,
            self.fbsk,
            self.small_size,
            self.big_size,
            self.modulus,
        );
        lwe_ciphertext_plaintext_add_assign(&mut bit, Plaintext(1u64 << (LOG_BIT - 1)));
        bit
    }
}

struct AndReducer<'a> {
    sign_accumulator: &'a GlweCiphertextOwned<u64>,
    ksk: &'a LweKeyswitchKeyOwned<u64>,
    fbsk: &'a FourierLweBootstrapKeyOwned,
    small_size: LweSize,
    big_size: LweSize,
    modulus: CiphertextModulus<u64>,
    poly: PolynomialSize,
    glwe_size: GlweSize,
}

impl AndReducer<'_> {
    fn all_one_bit(&self, bits: &[LweCiphertextOwned<u64>]) -> LweCiphertextOwned<u64> {
        assert!(!bits.is_empty() && bits.len() <= AND_BLOCK);
        // (len - count - 1/2) * 2^LOG_BIT is negative exactly when every bit is one.
        let centered = ((bits.len() as u64) << LOG_BIT) - (1u64 << (LOG_BIT - 1));
        let mut state = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            self.big_size,
            Plaintext(centered),
            self.modulus,
        );
        for bit in bits {
            lwe_ciphertext_sub_assign(&mut state, bit);
        }
        let mut output = pbs(
            &state,
            self.sign_accumulator,
            self.ksk,
            self.fbsk,
            self.small_size,
            self.big_size,
            self.modulus,
        );
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(1u64 << (LOG_BIT - 1)));
        output
    }

    /// Returns `(accepted identity code, PBS count)` where code is zero or `identity + 1`.
    fn all_one_to_code(
        &self,
        mut bits: Vec<LweCiphertextOwned<u64>>,
        identity: usize,
    ) -> (LweCiphertextOwned<u64>, usize) {
        assert!(!bits.is_empty());
        let mut count = 0usize;
        while bits.len() > AND_BLOCK {
            bits = bits
                .chunks(AND_BLOCK)
                .map(|chunk| {
                    count += 1;
                    self.all_one_bit(chunk)
                })
                .collect();
        }

        let centered = ((bits.len() as u64) << LOG_BIT) - (1u64 << (LOG_BIT - 1));
        let mut state = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            self.big_size,
            Plaintext(centered),
            self.modulus,
        );
        for bit in &bits {
            lwe_ciphertext_sub_assign(&mut state, bit);
        }
        let code = (identity + 1) as u64;
        let half_code = code << (LOG_CODE - 1);
        let code_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            self.glwe_size,
            &PlaintextList::new(half_code.wrapping_neg(), PlaintextCount(self.poly.0)),
            self.modulus,
        );
        count += 1;
        let mut output = pbs(
            &state,
            &code_accumulator,
            self.ksk,
            self.fbsk,
            self.small_size,
            self.big_size,
            self.modulus,
        );
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(half_code));
        (output, count)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scene_path = args
        .iter()
        .position(|value| value == "--scene")
        .map(|index| args[index + 1].clone())
        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/results/scena_reale_q3.txt").into());
    let n: usize = args
        .iter()
        .position(|value| value == "--n")
        .map(|index| args[index + 1].parse().expect("invalid N"))
        .unwrap_or(64);
    let q: i64 = args
        .iter()
        .position(|value| value == "--q")
        .map(|index| args[index + 1].parse().expect("invalid q"))
        .unwrap_or(3);
    let mut probe_indices: Vec<usize> = args
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == "--probe")
        .map(|(index, _)| args[index + 1].parse().expect("invalid probe index"))
        .collect();
    if probe_indices.is_empty() {
        probe_indices.push(0);
    }

    let scene = load_scene(&scene_path);
    assert!((2..=128).contains(&n));
    assert!(n <= scene.gallery.len());
    assert!(probe_indices
        .iter()
        .all(|index| *index < scene.probes.len()));
    let observed_q = scene
        .probes
        .iter()
        .flat_map(|probe| probe.iter())
        .map(|value| value.abs())
        .max()
        .unwrap_or(0);
    assert!(observed_q <= q, "scene exceeds the declared probe range");

    let bound_pairs = pair_bound(&scene, n, q);
    let bound_threshold = threshold_bound(&scene, n, q);
    assert!(
        bound_pairs.max(bound_threshold) <= SCORE_RADIUS,
        "score domain does not fit Delta=2^{LOG_DELTA}: pair={bound_pairs}, threshold={bound_threshold}, radius={SCORE_RADIUS}"
    );
    let folded: Vec<i64> = (-SCORE_RADIUS..=SCORE_RADIUS)
        .map(clear_fold_doubled)
        .collect();
    assert!((-SCORE_RADIUS..=SCORE_RADIUS)
        .zip(&folded)
        .all(|(difference, value)| (*value < 0) == (difference <= 0)));
    let folded_min = folded.iter().map(|value| value.abs()).min().unwrap();
    let folded_max = folded.iter().map(|value| value.abs()).max().unwrap();
    assert!(folded_max < 2 * (SCORE_RADIUS + 1));

    println!(
        "pairwise periodic argmin: N={n} q={q} T={} pair_bound={bound_pairs} threshold_bound={bound_threshold} Delta=2^{LOG_DELTA} radius={SCORE_RADIUS}",
        scene.threshold
    );
    println!(
        "folds={PERIODS:?} + sign, clear exhaustive {} points, final_abs={folded_min}..{folded_max}, threads={}",
        folded.len(),
        rayon::current_num_threads()
    );

    let key_start = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret, _, params) = client_key.into_raw_parts();
    let big_secret = glwe_secret.as_lwe_secret_key();
    let ksk = &server_key.key_switching_key;
    let fbsk = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("classic bootstrap key required"),
    };
    let modulus = CiphertextModulus::<u64>::new_native();
    let poly = glwe_secret.polynomial_size();
    let glwe_size = glwe_secret.glwe_dimension().to_glwe_size();
    let big_size = glwe_secret
        .glwe_dimension()
        .to_equivalent_lwe_dimension(poly)
        .to_lwe_size();
    let small_size = ksk.output_key_lwe_dimension().to_lwe_size();
    println!("keygen_s={:.3}", key_start.elapsed().as_secs_f64());

    let delta = 1u64 << LOG_DELTA;
    let fold_accumulators: Vec<_> = PERIODS
        .iter()
        .map(|period| {
            allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &PlaintextList::new((period / 4) * delta, PlaintextCount(poly.0)),
                modulus,
            )
        })
        .collect();
    let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (1u64 << (LOG_BIT - 1)).wrapping_neg(),
            PlaintextCount(poly.0),
        ),
        modulus,
    );
    let comparator = PeriodicComparator {
        delta,
        fold_accumulators,
        sign_accumulator,
        ksk,
        fbsk,
        small_size,
        big_size,
        modulus,
    };
    let reducer = AndReducer {
        sign_accumulator: &comparator.sign_accumulator,
        ksk,
        fbsk,
        small_size,
        big_size,
        modulus,
        poly,
        glwe_size,
    };

    let pairs: Vec<(usize, usize)> = (0..n)
        .flat_map(|left| ((left + 1)..n).map(move |right| (left, right)))
        .collect();
    let pair_index = |left: usize, right: usize| -> usize {
        left * n - left * (left + 1) / 2 + (right - left - 1)
    };
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let mut all_correct = true;
    for probe_index in probe_indices {
        let probe = &scene.probes[probe_index];
        let clear_scores: Vec<i64> = (0..n)
            .map(|identity| {
                scene.squared_norms[identity]
                    - 2 * scene.gallery[identity]
                        .iter()
                        .zip(probe)
                        .map(|(gallery_value, probe_value)| gallery_value * probe_value)
                        .sum::<i64>()
            })
            .collect();
        let clear_best = (0..n)
            .min_by_key(|identity| (clear_scores[*identity], *identity))
            .unwrap();
        let clear_code = if clear_scores[clear_best] <= scene.threshold {
            clear_best + 1
        } else {
            0
        };

        let encryption_start = Instant::now();
        let mut coefficients = vec![0u64; poly.0];
        for (index, value) in probe.iter().enumerate() {
            coefficients[index] = (*value as u64).wrapping_mul(delta);
        }
        let mut encrypted_probe = GlweCiphertext::new(0u64, glwe_size, poly, modulus);
        encrypt_glwe_ciphertext(
            &glwe_secret,
            &mut encrypted_probe,
            &PlaintextList::from_container(coefficients),
            params.glwe_noise_distribution(),
            &mut encryption_generator,
        );
        let encryption_seconds = encryption_start.elapsed().as_secs_f64();

        let score_start = Instant::now();
        let scores: Vec<LweCiphertextOwned<u64>> = (0..n)
            .into_par_iter()
            .map(|identity| {
                let mut polynomial = vec![0u64; poly.0];
                for index in 0..DIM {
                    polynomial[DIM - 1 - index] = (-2 * scene.gallery[identity][index]) as u64;
                }
                let polynomial = Polynomial::from_container(polynomial);
                let mut product = GlweCiphertext::new(0u64, glwe_size, poly, modulus);
                for (mut output, input) in product
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(encrypted_probe.as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
                }
                product.get_mut_body().as_mut()[DIM - 1] = product.get_body().as_ref()[DIM - 1]
                    .wrapping_add((scene.squared_norms[identity] as u64).wrapping_mul(delta));
                let mut score = LweCiphertext::new(0u64, big_size, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &product,
                    &mut score,
                    MonomialDegree(DIM - 1),
                );
                score
            })
            .collect();
        let score_seconds = score_start.elapsed().as_secs_f64();

        let comparison_start = Instant::now();
        let comparisons: Vec<LweCiphertextOwned<u64>> = pairs
            .par_iter()
            .map(|(left, right)| {
                let mut difference = scores[*left].clone();
                lwe_ciphertext_sub_assign(&mut difference, &scores[*right]);
                comparator.less_or_equal_zero(difference)
            })
            .collect();
        let comparison_seconds = comparison_start.elapsed().as_secs_f64();

        let mut comparison_correct = 0usize;
        for ((left, right), encrypted) in pairs.iter().zip(&comparisons) {
            let phase = decrypt_lwe_ciphertext(&big_secret, encrypted).0;
            let observed = (phase.wrapping_add(1u64 << (LOG_BIT - 1)) >> LOG_BIT) & 1;
            let expected = u64::from(clear_scores[*left] <= clear_scores[*right]);
            comparison_correct += usize::from(observed == expected);
        }

        let threshold_start = Instant::now();
        let threshold_bits: Vec<LweCiphertextOwned<u64>> = scores
            .par_iter()
            .map(|score| {
                let mut difference = score.clone();
                lwe_ciphertext_plaintext_sub_assign(
                    &mut difference,
                    Plaintext((scene.threshold as u64).wrapping_mul(delta)),
                );
                comparator.less_or_equal_zero(difference)
            })
            .collect();
        let threshold_seconds = threshold_start.elapsed().as_secs_f64();

        let threshold_correct = threshold_bits
            .iter()
            .zip(&clear_scores)
            .filter(|(encrypted, score)| {
                let phase = decrypt_lwe_ciphertext(&big_secret, encrypted).0;
                let observed = (phase.wrapping_add(1u64 << (LOG_BIT - 1)) >> LOG_BIT) & 1;
                observed == u64::from(**score <= scene.threshold)
            })
            .count();

        let reduction_start = Instant::now();
        let row_codes: Vec<(LweCiphertextOwned<u64>, usize)> = (0..n)
            .into_par_iter()
            .map(|identity| {
                let mut row = Vec::with_capacity(n);
                for other in 0..n {
                    if other == identity {
                        continue;
                    }
                    if identity < other {
                        row.push(comparisons[pair_index(identity, other)].clone());
                    } else {
                        let mut inverted = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                            big_size,
                            Plaintext(1u64 << LOG_BIT),
                            modulus,
                        );
                        lwe_ciphertext_sub_assign(
                            &mut inverted,
                            &comparisons[pair_index(other, identity)],
                        );
                        row.push(inverted);
                    }
                }
                row.push(threshold_bits[identity].clone());
                reducer.all_one_to_code(row, identity)
            })
            .collect();
        let reduction_pbs: usize = row_codes.iter().map(|(_, count)| count).sum();
        let mut encrypted_code =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
        for (row_code, _) in &row_codes {
            lwe_ciphertext_add_assign(&mut encrypted_code, row_code);
        }
        let reduction_seconds = reduction_start.elapsed().as_secs_f64();

        let decoded_rows: Vec<usize> = row_codes
            .iter()
            .map(|(row_code, _)| {
                let phase = decrypt_lwe_ciphertext(&big_secret, row_code).0;
                (phase.wrapping_add(1u64 << (LOG_CODE - 1)) >> LOG_CODE) as usize
            })
            .collect();
        let nonzero_rows: Vec<(usize, usize)> = decoded_rows
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, code)| *code != 0)
            .collect();

        let phase = decrypt_lwe_ciphertext(&big_secret, &encrypted_code).0;
        let decoded_code = (phase.wrapping_add(1u64 << (LOG_CODE - 1)) >> LOG_CODE) as usize;
        let code_error = phase.wrapping_sub((clear_code as u64) << LOG_CODE) as i64 as f64
            / (1u64 << LOG_CODE) as f64;
        let correct = decoded_code == clear_code;
        all_correct &= correct;
        let total_seconds = encryption_seconds
            + score_seconds
            + comparison_seconds
            + threshold_seconds
            + reduction_seconds;
        let total_pbs = PERIODS.len().saturating_add(1) * (pairs.len() + n) + reduction_pbs;
        println!(
            "probe={probe_index} label={} clear_best={clear_best} clear_min={} clear_code={clear_code} encrypted_code={decoded_code} correct={correct}",
            scene.labels[probe_index], clear_scores[clear_best]
        );
        println!(
            "diagnostics pair_bits={comparison_correct}/{} threshold_bits={threshold_correct}/{n} nonzero_rows={nonzero_rows:?}",
            pairs.len()
        );
        println!(
            "timing_s encrypt={encryption_seconds:.6} score={score_seconds:.6} pairs={comparison_seconds:.6} thresholds={threshold_seconds:.6} reduce={reduction_seconds:.6} total={total_seconds:.6} pbs={total_pbs} code_error={code_error:.6}"
        );
    }
    assert!(
        all_correct,
        "at least one encrypted nearest-identity result was wrong"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_periodic_fold_is_exact_on_the_full_score_domain() {
        let folded: Vec<i64> = (-SCORE_RADIUS..=SCORE_RADIUS)
            .map(clear_fold_doubled)
            .collect();
        assert!((-SCORE_RADIUS..=SCORE_RADIUS)
            .zip(&folded)
            .all(|(difference, value)| (*value < 0) == (difference <= 0)));
        assert_eq!(folded.iter().map(|value| value.abs()).min(), Some(4369));
        assert_eq!(folded.iter().map(|value| value.abs()).max(), Some(12015));
    }

    #[test]
    fn pair_index_matches_lexicographic_pair_order() {
        for n in [2usize, 8, 64, 128] {
            let pairs: Vec<_> = (0..n)
                .flat_map(|left| ((left + 1)..n).map(move |right| (left, right)))
                .collect();
            for (expected, &(left, right)) in pairs.iter().enumerate() {
                let actual = left * n - left * (left + 1) / 2 + (right - left - 1);
                assert_eq!(actual, expected);
            }
        }
    }
}
