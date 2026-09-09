//! Standalone audit harness for the periodic-fold threshold comparator in `varco_demo`.
//!
//! The circuit uses the production KSK/BSK only: two sign-preserving periodic corrections followed
//! by the final sign PBS, for three PBS per template. The exhaustive clear test proves the predicate
//! over the declared domain; encrypted trials remain empirical evidence, not a formal p-fail proof.
//!
//! Nothing expensive runs without `--run`. Example:
//! `cargo run --release --bin exact_comparator_scratch -- --run --trials 25 --gallery`.

use std::time::Instant;

use rayon::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const DIM: usize = 512;
const LOG_DELTA: u32 = 51;
const LOG_DO: u32 = 60;
const PERIODS: [u64; 2] = [32, 512];

fn folded_clear_doubled(score_minus_threshold: i64) -> i64 {
    let mut value = 2 * score_minus_threshold - 1;
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

fn blind_rotation_phase<Cont, KeyCont>(
    ct: &LweCiphertext<Cont>,
    key: &LweSecretKey<KeyCont>,
    polynomial_size: PolynomialSize,
) -> usize
where
    Cont: Container<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    let rotation_modulus = 2 * polynomial_size.0;
    let body = pbs_modulus_switch(*ct.get_body().data, polynomial_size) % rotation_modulus;
    let mask_dot = ct.get_mask().as_ref().iter().zip(key.as_ref()).fold(
        0usize,
        |sum, (coefficient, secret)| {
            (sum + pbs_modulus_switch(*coefficient, polynomial_size) * (*secret as usize))
                % rotation_modulus
        },
    );
    (body + rotation_modulus - mask_dot) % rotation_modulus
}

fn signed_modular_difference(actual: usize, expected: usize, modulus: usize) -> i64 {
    let forward = (actual + modulus - expected) % modulus;
    if forward > modulus / 2 {
        forward as i64 - modulus as i64
    } else {
        forward as i64
    }
}

fn decode_big<Cont: Container<Element = u64>>(
    sk: &LweSecretKey<Cont>,
    ct: &LweCiphertextOwned<u64>,
) -> u64 {
    (decrypt_lwe_ciphertext(sk, ct)
        .0
        .wrapping_add(1u64 << (LOG_DO - 1))
        >> LOG_DO)
        & 1
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|x| x == "--run") {
        eprintln!(
            "usage: exact_comparator_scratch --run [--trials N] \
             [--bound-near] [--gallery] [--domain-sweep]"
        );
        return;
    }
    let trials: usize = args
        .iter()
        .position(|x| x == "--trials")
        .map(|i| args[i + 1].parse().unwrap())
        .unwrap_or(10);
    assert!(trials > 0, "--trials deve essere positivo");
    let adversarial = args.iter().any(|x| x == "--bound-near");
    let gallery_mode = args.iter().any(|x| x == "--gallery");
    let domain_sweep = args.iter().any(|x| x == "--domain-sweep");
    let modulus = CiphertextModulus::<u64>::new_native();
    let delta = 1u64 << LOG_DELTA;
    let ck = ClientKey::new(PARAMS);
    let sk = ServerKey::new(&ck);
    let (glwe_sk, small_sk, params) = ck.into_raw_parts();
    let big_sk = glwe_sk.as_lwe_secret_key();
    let ksk = &sk.key_switching_key;
    let fbsk = match &sk.bootstrapping_key {
        ShortintBootstrappingKey::Classic(k) => k,
        _ => panic!("classic only"),
    };
    let poly = glwe_sk.polynomial_size();
    let big = glwe_sk
        .glwe_dimension()
        .to_equivalent_lwe_dimension(poly)
        .to_lwe_size();
    let small = ksk.output_key_lwe_dimension().to_lwe_size();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        fbsk.glwe_size(),
        &PlaintextList::new(
            (1u64 << (LOG_DO - 1)).wrapping_neg(),
            PlaintextCount(poly.0),
        ),
        modulus,
    );
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut gen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!(
        "N={} n_regular={} Delta=2^{} periods={:?} pbs_per_threshold={} trials={} nominal_log2_p_fail={}",
        poly.0,
        small.to_lwe_dimension().0,
        LOG_DELTA,
        PERIODS,
        PERIODS.len() + 1,
        trials,
        PARAMS.log2_p_fail,
    );

    let fold_accumulators: Vec<_> = PERIODS
        .iter()
        .map(|period| {
            allocate_and_trivially_encrypt_new_glwe_ciphertext(
                fbsk.glwe_size(),
                &PlaintextList::new((period / 4) * delta, PlaintextCount(poly.0)),
                modulus,
            )
        })
        .collect();

    let exact_compare = |mut state: LweCiphertextOwned<u64>, difference: i64| {
        let rotation_modulus = 2 * poly.0;
        let mut clear_doubled = 2 * difference - 1;
        let mut phase_error_max = 0i64;
        for (period, fold_acc) in PERIODS.iter().zip(&fold_accumulators) {
            let multiplier = 1u64 << (u64::BITS - LOG_DELTA - period.ilog2());
            let mut periodic_phase = state.clone();
            lwe_ciphertext_cleartext_mul_assign(&mut periodic_phase, Cleartext(multiplier));
            let mut switched = LweCiphertext::new(0u64, small, modulus);
            keyswitch_lwe_ciphertext(ksk, &periodic_phase, &mut switched);
            let expected_phase = (clear_doubled as u64)
                .wrapping_mul(delta >> 1)
                .wrapping_mul(multiplier);
            let expected_rotation = pbs_modulus_switch(expected_phase, poly) % rotation_modulus;
            let phase_error = signed_modular_difference(
                blind_rotation_phase(&switched, &small_sk, poly),
                expected_rotation,
                rotation_modulus,
            );
            phase_error_max = phase_error_max.max(phase_error.abs());

            let mut correction = LweCiphertext::new(0u64, big, modulus);
            programmable_bootstrap_lwe_ciphertext(&switched, &mut correction, fold_acc, fbsk);
            lwe_ciphertext_add_assign(&mut state, &correction);

            let period = *period as i64;
            let residue = clear_doubled.rem_euclid(2 * period);
            clear_doubled += if residue < period {
                period / 2
            } else {
                -(period / 2)
            };
        }
        debug_assert_eq!(clear_doubled, folded_clear_doubled(difference));

        let mut residual_ks = LweCiphertext::new(0u64, small, modulus);
        keyswitch_lwe_ciphertext(ksk, &state, &mut residual_ks);
        let expected_phase = (clear_doubled as u64).wrapping_mul(delta >> 1);
        let expected_rotation = pbs_modulus_switch(expected_phase, poly) % rotation_modulus;
        let phase_error = signed_modular_difference(
            blind_rotation_phase(&residual_ks, &small_sk, poly),
            expected_rotation,
            rotation_modulus,
        );
        phase_error_max = phase_error_max.max(phase_error.abs());
        let mut exact = LweCiphertext::new(0u64, big, modulus);
        programmable_bootstrap_lwe_ciphertext(&residual_ks, &mut exact, &acc, fbsk);
        lwe_ciphertext_plaintext_add_assign(&mut exact, Plaintext(1u64 << (LOG_DO - 1)));
        (exact, phase_error_max)
    };

    if domain_sweep {
        let mut points = vec![-4095, -4094, -2, -1, 0, 1, 2, 4094, 4095];
        // Ciphertext checks around representative discontinuities of both periodic folds. The
        // clear unit test below remains the exhaustive proof over every integer in the domain.
        for (half_period, multiples) in [(16i64, -16i64..=16), (256, -8..=8)] {
            for multiple in multiples {
                let boundary = multiple * half_period;
                points.extend([boundary - 1, boundary, boundary + 1]);
            }
        }
        points.retain(|difference| (-4095..=4095).contains(difference));
        points.sort_unstable();
        points.dedup();

        let mut correct = 0usize;
        let mut total = 0usize;
        let mut max_phase_error = 0i64;
        for difference in &points {
            for _ in 0..trials {
                let mut coefficients = vec![0u64; poly.0];
                coefficients[0] = (*difference as u64)
                    .wrapping_mul(delta)
                    .wrapping_sub(delta >> 1);
                let mut encrypted = GlweCiphertext::new(
                    0u64,
                    glwe_sk.glwe_dimension().to_glwe_size(),
                    poly,
                    modulus,
                );
                encrypt_glwe_ciphertext(
                    &glwe_sk,
                    &mut encrypted,
                    &PlaintextList::from_container(coefficients),
                    params.glwe_noise_distribution(),
                    &mut gen,
                );
                let mut exact_x = LweCiphertext::new(0u64, big, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &encrypted,
                    &mut exact_x,
                    MonomialDegree(0),
                );
                let (result, phase_error) = exact_compare(exact_x, *difference);
                let observed = decode_big(&big_sk, &result) == 1;
                correct += usize::from(observed == (*difference <= 0));
                total += 1;
                max_phase_error = max_phase_error.max(phase_error.abs());
            }
        }
        println!(
            "domain_sweep points={} trials_per_point={} correct={}/{} phase_error_rot_max={}",
            points.len(),
            trials,
            correct,
            total,
            max_phase_error
        );
        return;
    }

    let scores: Vec<usize> = if adversarial {
        vec![3, 5]
    } else {
        (2usize..=7).collect()
    };
    for score in scores {
        let (gal, probe) = if adversarial {
            let mut gal = vec![0i64; DIM];
            gal[..150].fill(3);
            gal[150] = 1;
            let mut probe = vec![0i64; DIM];
            probe[..74].fill(3);
            probe[74] = 2;
            probe[150] = if score == 3 { 2 } else { 1 };
            (gal, probe)
        } else {
            let mut gal = vec![0i64; DIM];
            gal[..score].fill(1);
            (gal, vec![0i64; DIM])
        };
        let bsq: i64 = gal.iter().map(|x| x * x).sum();
        let clear_score = bsq - 2 * gal.iter().zip(&probe).map(|(g, q)| g * q).sum::<i64>();
        assert_eq!(clear_score, score as i64);
        let mut old_ok = 0usize;
        let mut exact_ok = 0usize;
        let mut exact_total = 0.0;
        let mut phase_error_max = 0i64;
        let difference = clear_score - 4;
        for trial in 0..trials {
            let mut coeff = vec![0u64; poly.0];
            for j in 0..DIM {
                coeff[j] = (probe[j] as u64).wrapping_mul(delta);
            }
            let mut glwe =
                GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &PlaintextList::from_container(coeff),
                params.glwe_noise_distribution(),
                &mut gen,
            );
            let mut p = vec![0u64; poly.0];
            for j in 0..DIM {
                p[DIM - 1 - j] = (-2 * gal[j]) as u64;
            }
            let p = Polynomial::from_container(p);
            let mut prod =
                GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
            for (mut o, c) in prod
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(glwe.as_polynomial_list().iter())
            {
                polynomial_wrapping_add_mul_assign(&mut o, &c, &p);
            }
            let mut x = LweCiphertext::new(0u64, big, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&prod, &mut x, MonomialDegree(DIM - 1));

            // Historical comparator: (score - T - 0.5) * Delta.
            let mut old_x = x.clone();
            let old_cost = ((bsq - 4) as u64)
                .wrapping_mul(delta)
                .wrapping_sub(delta >> 1);
            lwe_ciphertext_plaintext_add_assign(&mut old_x, Plaintext(old_cost));
            let mut old_ks = LweCiphertext::new(0u64, small, modulus);
            keyswitch_lwe_ciphertext(ksk, &old_x, &mut old_ks);
            let mut old = LweCiphertext::new(0u64, big, modulus);
            programmable_bootstrap_lwe_ciphertext(&old_ks, &mut old, &acc, fbsk);
            lwe_ciphertext_plaintext_add_assign(&mut old, Plaintext(1u64 << (LOG_DO - 1)));
            old_ok += usize::from(decode_big(&big_sk, &old) == u64::from(score <= 4));

            // Periodic-fold comparator: retain the same half-centered input, then widen its
            // decision margin with P=32 and P=512 before the final sign PBS.
            let mut exact_x = x;
            lwe_ciphertext_plaintext_add_assign(&mut exact_x, Plaintext(old_cost));
            let t0 = Instant::now();
            let (exact, phase_error) = exact_compare(exact_x.clone(), difference);
            exact_total += t0.elapsed().as_secs_f64();
            exact_ok += usize::from(decode_big(&big_sk, &exact) == u64::from(score <= 4));
            phase_error_max = phase_error_max.max(phase_error.abs());

            if gallery_mode && trial == 0 {
                let gallery_t0 = Instant::now();
                let gallery_bits: Vec<u64> = (0..127usize)
                    .into_par_iter()
                    .map(|_| {
                        let (bit, _) = exact_compare(exact_x.clone(), difference);
                        decode_big(&big_sk, &bit)
                    })
                    .collect();
                let gallery_ok = gallery_bits.iter().all(|bit| *bit == u64::from(score <= 4));
                println!(
                    "gallery score={} n=127 correct={} ones={} exact_ms={:.2} pbs_threshold={}",
                    score,
                    gallery_ok,
                    gallery_bits.iter().sum::<u64>(),
                    gallery_t0.elapsed().as_secs_f64() * 1000.0,
                    127 * (PERIODS.len() + 1)
                );
            }
        }
        println!(
            "score={} expected={} legacy={}/{} exact={}/{} exact_ms_mean={:.2} phase_error_rot_max={}",
            score,
            score <= 4,
            old_ok,
            trials,
            exact_ok,
            trials,
            1000.0 * exact_total / trials as f64,
            phase_error_max,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_fold_separates_the_full_inclusive_domain_without_wrap() {
        let mut minimum = i64::MAX;
        let mut maximum = 0i64;
        for difference in -4095..=4095 {
            let folded = folded_clear_doubled(difference);
            assert_eq!(folded < 0, difference <= 0, "d={difference}");
            minimum = minimum.min(folded.abs());
            maximum = maximum.max(folded.abs());
        }
        assert_eq!(minimum, 273);
        assert_eq!(maximum, 7919);
        assert!(maximum < 8192);
    }
}
