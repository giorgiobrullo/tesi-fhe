//! Verifica isolata dell'estrazione diretta dei bit di un punteggio quantizzato.
//!
//! Per un punteggio intero `x` codificato con `Delta = 2^50`, il bit `k` di `x` e' il segno
//! periodico di `(x + 1/2) * 2^(63 - 50 - k)`.  Il mezzo passo sposta tutti gli interi lontano
//! dalle discontinuita' del PBS.  Con bin di ampiezza otto, i bit del numero di bin sono quindi
//! i bit 3..12 del punteggio traslato nel dominio pubblico.

use dyn_stack::{GlobalPodBuffer, PodStack};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::time::Instant;
use tfhe::core_crypto::algorithms::lwe_wopbs::{
    extract_bits_from_lwe_ciphertext_mem_optimized,
    extract_bits_from_lwe_ciphertext_mem_optimized_requirement,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const LOG_SCORE_DELTA: u32 = 50;
const LOG_BOOL_DELTA: u32 = 60;
const LOW_BIT: u32 = 3;
const HIGH_BIT: u32 = 12;
const DOMAIN_SIZE: usize = 8192;
const SCORE_BITS: usize = 13;
const BUCKET_BITS: usize = SCORE_BITS - LOW_BIT as usize;

type Lwe = LweCiphertextOwned<u64>;

fn test_points(exhaustive: bool) -> Vec<usize> {
    if exhaustive {
        return (0..DOMAIN_SIZE).collect();
    }

    let mut points = BTreeSet::from([0, 1, 2, DOMAIN_SIZE - 2, DOMAIN_SIZE - 1]);
    for bit in LOW_BIT..=HIGH_BIT {
        let half_period = 1usize << bit;
        let period = half_period * 2;
        for boundary in (0..DOMAIN_SIZE).step_by(half_period) {
            for offset in [-2isize, -1, 0, 1, 2] {
                let point = boundary as isize + offset;
                if (0..DOMAIN_SIZE as isize).contains(&point) {
                    points.insert(point as usize);
                }
            }
        }
        for boundary in (period..DOMAIN_SIZE).step_by(period) {
            points.insert(boundary - 1);
            points.insert(boundary);
        }
    }
    points.into_iter().collect()
}

fn official_test_points() -> Vec<usize> {
    let mut points = BTreeSet::from([
        0,
        1,
        2,
        3,
        DOMAIN_SIZE - 4,
        DOMAIN_SIZE - 3,
        DOMAIN_SIZE - 2,
        DOMAIN_SIZE - 1,
    ]);
    for bit in 0..SCORE_BITS {
        let boundary = 1usize << bit;
        for multiple in [1usize, 2, 3] {
            let center = boundary * multiple;
            for offset in [-1isize, 0, 1] {
                let point = center as isize + offset;
                if (0..DOMAIN_SIZE as isize).contains(&point) {
                    points.insert(point as usize);
                }
            }
        }
    }
    points.into_iter().collect()
}

fn extract_official_bits(
    input: &Lwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    delta_log: usize,
    bit_count: usize,
) -> LweCiphertextListOwned<u64> {
    let fft = Fft::new(fourier_bootstrap_key.polynomial_size());
    let fft = fft.as_view();
    let requirement = extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
        input.lwe_size().to_lwe_dimension(),
        key_switching_key.output_key_lwe_dimension(),
        fourier_bootstrap_key.glwe_size(),
        fourier_bootstrap_key.polynomial_size(),
        fft,
    )
    .unwrap();
    let mut memory = GlobalPodBuffer::new(requirement);
    let mut output = LweCiphertextListOwned::new(
        0u64,
        key_switching_key.output_lwe_size(),
        LweCiphertextCount(bit_count),
        input.ciphertext_modulus(),
    );
    extract_bits_from_lwe_ciphertext_mem_optimized(
        input,
        &mut output,
        fourier_bootstrap_key,
        key_switching_key,
        DeltaLog(delta_log),
        ExtractedBitsCount(bit_count),
        fft,
        PodStack::new(&mut memory),
    );
    output
}

fn main() {
    let exhaustive = std::env::args().any(|argument| argument == "--exhaustive");
    let official = std::env::args().any(|argument| argument == "--official");
    let bucket_official = std::env::args().any(|argument| argument == "--bucket-official");
    let points = if official || bucket_official {
        official_test_points()
    } else {
        test_points(exhaustive)
    };
    let score_delta = 1u64 << LOG_SCORE_DELTA;
    let bool_delta = 1u64 << LOG_BOOL_DELTA;
    let modulus = CiphertextModulus::<u64>::new_native();

    let key_started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let key_switching_key = &server_key.key_switching_key;
    let fourier_bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("attesa bootstrapping key classica"),
    };
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = glwe_secret_key
        .glwe_dimension()
        .to_equivalent_lwe_dimension(polynomial_size)
        .to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();

    let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (bool_delta >> 1).wrapping_neg(),
            PlaintextCount(polynomial_size.0),
        ),
        modulus,
    );
    let recode_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (bool_delta >> 1).wrapping_neg(),
            PlaintextCount(polynomial_size.0),
        ),
        modulus,
    );
    let apply_pbs = |input: &Lwe| -> Lwe {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut output,
            &sign_accumulator,
            fourier_bootstrap_key,
        );
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(bool_delta >> 1));
        output
    };
    let decode = |ciphertext: &Lwe| -> bool {
        ((decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
            .0
            .wrapping_add(bool_delta >> 1)
            >> LOG_BOOL_DELTA)
            & 1)
            == 1
    };

    let recode_extracted = |input: LweCiphertextView<'_, u64>| -> Lwe {
        let mut shifted = LweCiphertextOwned::from_container(input.as_ref().to_vec(), modulus);
        lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(1u64 << 61));
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &shifted,
            &mut output,
            &recode_accumulator,
            fourier_bootstrap_key,
        );
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(bool_delta >> 1));
        output
    };

    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let input_delta = if official || bucket_official {
        1u64 << (64 - SCORE_BITS)
    } else {
        score_delta
    };
    let encrypted: Vec<_> = points
        .iter()
        .map(|point| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &big_secret_key,
                Plaintext((*point as u64).wrapping_mul(input_delta)),
                client_params.glwe_noise_distribution(),
                modulus,
                &mut generator,
            )
        })
        .collect();

    let extraction_started = Instant::now();
    let rows: Vec<_> = if official || bucket_official {
        encrypted
            .par_iter()
            .zip(&points)
            .map(|(ciphertext, point)| {
                let extraction_input = ciphertext.clone();
                let (delta_log, bit_count) = if bucket_official {
                    // Asking for ten bits at Delta=2^54 discards the three low score bits.
                    (54, BUCKET_BITS)
                } else {
                    (64 - SCORE_BITS, SCORE_BITS)
                };
                let extracted = extract_official_bits(
                    &extraction_input,
                    fourier_bootstrap_key,
                    key_switching_key,
                    delta_log,
                    bit_count,
                );
                let mut mismatches = Vec::new();
                for (position, bit) in extracted.iter().take(BUCKET_BITS).enumerate() {
                    let actual = decode(&recode_extracted(bit));
                    let expected_bit = if bucket_official {
                        BUCKET_BITS - 1 - position
                    } else {
                        SCORE_BITS - 1 - position
                    };
                    let expected_value = if bucket_official { *point / 8 } else { *point };
                    let expected = ((expected_value >> expected_bit) & 1) == 1;
                    if actual != expected {
                        mismatches.push(expected_bit as u32);
                    }
                }
                (*point, mismatches)
            })
            .collect()
    } else {
        encrypted
            .par_iter()
            .zip(&points)
            .map(|(ciphertext, point)| {
                let mut mismatches = Vec::new();
                for bit in LOW_BIT..=HIGH_BIT {
                    let shift = 63 - LOG_SCORE_DELTA - bit;
                    let mut phase = ciphertext.clone();
                    lwe_ciphertext_plaintext_add_assign(&mut phase, Plaintext(score_delta >> 1));
                    lwe_ciphertext_cleartext_mul_assign(&mut phase, Cleartext(1u64 << shift));
                    let actual = decode(&apply_pbs(&phase));
                    let expected = ((*point >> bit) & 1) == 1;
                    if actual != expected {
                        mismatches.push(bit);
                    }
                }
                (*point, mismatches)
            })
            .collect()
    };
    let extraction_s = extraction_started.elapsed().as_secs_f64();
    let failures: Vec<_> = rows
        .into_iter()
        .filter(|(_, mismatches)| !mismatches.is_empty())
        .collect();

    println!(
        "CONFIG,mode={},params=V0_11_MESSAGE_2_CARRY_2_TUNIFORM_2M64,log2_p_fail={},domain=0..{},bits={}..{},points={},pbs={},key_s={:.6},extract_s={:.6}",
        if bucket_official {
            "official_bucket_extract_recode"
        } else if official {
            "official_extract_recode"
        } else {
            "direct_periodic"
        },
        PARAMS.log2_p_fail,
        DOMAIN_SIZE - 1,
        LOW_BIT,
        HIGH_BIT,
        points.len(),
        points.len()
            * if bucket_official {
                BUCKET_BITS * 2
            } else if official {
                SCORE_BITS + BUCKET_BITS
            } else {
                usize::try_from(HIGH_BIT - LOW_BIT + 1).unwrap()
            },
        key_started.elapsed().as_secs_f64() - extraction_s,
        extraction_s,
    );
    for (point, bits) in failures.iter().take(20) {
        println!("FAIL,x={point},bits={bits:?}");
    }
    println!(
        "SUMMARY,correct={},failures={},tested_bits={}",
        failures.is_empty(),
        failures.len(),
        points.len()
            * if official || bucket_official {
                BUCKET_BITS
            } else {
                usize::try_from(HIGH_BIT - LOW_BIT + 1).unwrap()
            },
    );
    assert!(failures.is_empty(), "estrazione periodica non esatta");
}
