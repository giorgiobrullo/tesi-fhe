//! Scratch measurement for the exact tfhe-rs LWE bit-extraction primitive.
//!
//! A compact GLWE probe is scored against the plaintext gallery, producing the same large-LWE
//! scores used by the gate prototype.  The scores are shifted into `[0, 8192)`, encoded with
//! `Delta = 2^51`, and decomposed into 13 encrypted bits by
//! `extract_bits_from_lwe_ciphertext_mem_optimized`.  Key generation and score evaluation are
//! reported separately from the extraction timing.
//!
//! The harness also records two bridge experiments.  Directly treating q/2 bits as shortint
//! blocks is an explicit negative control, as is the unreliable one-PBS recoder.  The supported
//! route uses tfhe-rs' circuit bootstrap plus vertical packing to produce canonical radix blocks;
//! `--cbs-vp N` tests the high eight bits and `--cbs-vp-full N` the exact 13-bit score.

use dyn_stack::{GlobalPodBuffer, PodStack};
use rayon::prelude::*;
use std::time::Instant;
use tfhe::core_crypto::algorithms::lwe_wopbs::{
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized,
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement,
    extract_bits_from_lwe_ciphertext_mem_optimized,
    extract_bits_from_lwe_ciphertext_mem_optimized_requirement,
};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::integer::{gen_keys_radix, IntegerCiphertext, RadixCiphertext};
use tfhe::shortint::ciphertext::{Degree, NoiseLevel};
use tfhe::shortint::parameters::LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{Ciphertext, PBSOrder};

const DIM: usize = 512;
const SCORE_BITS: usize = 13;
const SCORE_OFFSET: i64 = 4096;
const LOG_DELTA: usize = 64 - SCORE_BITS;
const CBS_BITS: usize = 8;

struct Scene {
    gallery: Vec<Vec<i64>>,
    squared_norms: Vec<i64>,
    probes: Vec<Vec<i64>>,
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
    assert_eq!(dim, DIM);
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
    for _ in 0..probe_len {
        let row: Vec<i64> = lines
            .next()
            .expect("missing probe row")
            .split_whitespace()
            .map(|value| value.parse().expect("invalid probe integer"))
            .collect();
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
        threshold,
    }
}

fn extract_bits(
    input: &LweCiphertextOwned<u64>,
    fbsk: &FourierLweBootstrapKeyOwned,
    ksk: &LweKeyswitchKeyOwned<u64>,
) -> LweCiphertextListOwned<u64> {
    let fft = Fft::new(fbsk.polynomial_size());
    let fft = fft.as_view();
    let requirement = extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
        input.lwe_size().to_lwe_dimension(),
        ksk.output_key_lwe_dimension(),
        fbsk.glwe_size(),
        fbsk.polynomial_size(),
        fft,
    )
    .unwrap();
    let mut memory = GlobalPodBuffer::new(requirement);
    let mut output = LweCiphertextListOwned::new(
        0u64,
        ksk.output_lwe_size(),
        LweCiphertextCount(SCORE_BITS),
        input.ciphertext_modulus(),
    );
    extract_bits_from_lwe_ciphertext_mem_optimized(
        input,
        &mut output,
        fbsk,
        ksk,
        DeltaLog(LOG_DELTA),
        ExtractedBitsCount(SCORE_BITS),
        fft,
        PodStack::new(&mut memory),
    );
    output
}

/// Re-encode an extracted boolean from `{0, q/2}` to a canonical shortint bit at
/// `{0, 2^61}`.  Adding q/8 moves the two inputs to q/8 and -3q/8; a constant anti-periodic
/// accumulator maps the points, which are away from its discontinuity, to +/-2^60.  A clear
/// +2^60 shift
/// gives the desired encoding.  The final key switch returns to the small LWE key used by the
/// PBS-KS radix bridge.
fn reencode_bit(
    bit: LweCiphertextView<'_, u64>,
    accumulator: &GlweCiphertextOwned<u64>,
    fbsk: &FourierLweBootstrapKeyOwned,
    ksk: &LweKeyswitchKeyOwned<u64>,
    large_size: LweSize,
    modulus: CiphertextModulus<u64>,
) -> LweCiphertextOwned<u64> {
    let mut shifted = LweCiphertextOwned::from_container(bit.as_ref().to_vec(), modulus);
    lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(1u64 << 61));
    let mut large = LweCiphertextOwned::new(0u64, large_size, modulus);
    programmable_bootstrap_lwe_ciphertext(&shifted, &mut large, accumulator, fbsk);
    lwe_ciphertext_plaintext_add_assign(&mut large, Plaintext(1u64 << 60));
    let mut small = LweCiphertextOwned::new(0u64, ksk.output_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, &large, &mut small);
    small
}

fn cbs_vertical_pack_bits(
    extracted: &LweCiphertextListOwned<u64>,
    lut: &PolynomialListOwned<u64>,
    fbsk: &FourierLweBootstrapKeyOwned,
    pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
    input_bits: usize,
    output_blocks: usize,
) -> LweCiphertextListOwned<u64> {
    assert!(extracted.lwe_ciphertext_count().0 >= input_bits);
    let modulus = extracted.ciphertext_modulus();
    let mut high_bits = LweCiphertextListOwned::new(
        0u64,
        extracted.lwe_size(),
        LweCiphertextCount(input_bits),
        modulus,
    );
    for (mut output, input) in high_bits.iter_mut().zip(extracted.iter().take(input_bits)) {
        output.as_mut().copy_from_slice(input.as_ref());
    }
    let mut output = LweCiphertextListOwned::new(
        0u64,
        fbsk.output_lwe_dimension().to_lwe_size(),
        LweCiphertextCount(output_blocks),
        modulus,
    );
    let fft = Fft::new(fbsk.polynomial_size());
    let fft = fft.as_view();
    let requirement =
        circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<
            u64,
        >(
            high_bits.lwe_ciphertext_count(),
            output.lwe_ciphertext_count(),
            high_bits.lwe_size(),
            lut.polynomial_count(),
            fbsk.output_lwe_dimension().to_lwe_size(),
            fbsk.glwe_size(),
            pfpksk.output_polynomial_size(),
            PARAMS.cbs_level,
            fft,
        )
        .unwrap();
    let mut memory = GlobalPodBuffer::new(requirement);
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
        &high_bits,
        &mut output,
        lut,
        fbsk,
        pfpksk,
        PARAMS.cbs_base_log,
        PARAMS.cbs_level,
        fft,
        PodStack::new(&mut memory),
    );
    output
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
    let probe_index: usize = args
        .iter()
        .position(|value| value == "--probe")
        .map(|index| args[index + 1].parse().expect("invalid probe index"))
        .unwrap_or(3);
    let cbs_count: usize = args
        .iter()
        .position(|value| value == "--cbs-vp")
        .map(|index| args[index + 1].parse().expect("invalid CBS count"))
        .unwrap_or(0);
    let cbs_full_count: usize = args
        .iter()
        .position(|value| value == "--cbs-vp-full")
        .map(|index| args[index + 1].parse().expect("invalid full CBS count"))
        .unwrap_or(0);
    let scene = load_scene(&scene_path);
    assert!(n <= scene.gallery.len());
    assert!(probe_index < scene.probes.len());

    let key_start = Instant::now();
    // A high zero block leaves room for carry propagation experiments.
    let (client_key, server_key) = gen_keys_radix(PARAMS, SCORE_BITS + 1);
    let key_seconds = key_start.elapsed().as_secs_f64();
    let shortint_client: &tfhe::shortint::ClientKey = client_key.as_ref().as_ref();
    let (glwe_secret, small_secret, parameters) = shortint_client.clone().into_raw_parts();
    let large_secret = glwe_secret.as_lwe_secret_key();
    let shortint_server: &tfhe::shortint::ServerKey = server_key.as_ref();
    let fbsk = match &shortint_server.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("classic bootstrap key required"),
    };
    let ksk = &shortint_server.key_switching_key;
    let modulus = CiphertextModulus::<u64>::new_native();
    let polynomial_size = glwe_secret.polynomial_size();
    let glwe_size = glwe_secret.glwe_dimension().to_glwe_size();
    let large_size = large_secret.lwe_dimension().to_lwe_size();
    let delta = 1u64 << LOG_DELTA;

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
    let shifted_scores: Vec<u64> = clear_scores
        .iter()
        .map(|score| {
            let shifted = score + SCORE_OFFSET;
            assert!(
                (0..(1 << SCORE_BITS)).contains(&shifted),
                "score {score} does not fit the shifted {SCORE_BITS}-bit domain"
            );
            shifted as u64
        })
        .collect();

    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let cbs_setup_start = Instant::now();
    let cbs_pfpksk = (cbs_count > 0 || cbs_full_count > 0).then(|| {
        par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &large_secret,
            &glwe_secret,
            PARAMS.pfks_base_log,
            PARAMS.pfks_level,
            PARAMS.pfks_noise_distribution,
            modulus,
            &mut encryption_generator,
        )
    });
    let cbs_setup_seconds = cbs_setup_start.elapsed().as_secs_f64();
    let encryption_start = Instant::now();
    let mut coefficients = vec![0u64; polynomial_size.0];
    for (index, value) in probe.iter().enumerate() {
        coefficients[index] = (*value as u64).wrapping_mul(delta);
    }
    let mut encrypted_probe = GlweCiphertextOwned::new(0u64, glwe_size, polynomial_size, modulus);
    encrypt_glwe_ciphertext(
        &glwe_secret,
        &mut encrypted_probe,
        &PlaintextList::from_container(coefficients),
        parameters.glwe_noise_distribution(),
        &mut encryption_generator,
    );
    let encryption_seconds = encryption_start.elapsed().as_secs_f64();

    let score_start = Instant::now();
    let scores: Vec<LweCiphertextOwned<u64>> = (0..n)
        .into_par_iter()
        .map(|identity| {
            let mut polynomial = vec![0u64; polynomial_size.0];
            for index in 0..DIM {
                polynomial[DIM - 1 - index] = (-2 * scene.gallery[identity][index]) as u64;
            }
            let polynomial = Polynomial::from_container(polynomial);
            let mut product = GlweCiphertextOwned::new(0u64, glwe_size, polynomial_size, modulus);
            for (mut output, input) in product
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(encrypted_probe.as_polynomial_list().iter())
            {
                polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
            }
            let constant = scene.squared_norms[identity] + SCORE_OFFSET;
            product.get_mut_body().as_mut()[DIM - 1] = product.get_body().as_ref()[DIM - 1]
                .wrapping_add((constant as u64).wrapping_mul(delta));
            let mut score = LweCiphertextOwned::new(0u64, large_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&product, &mut score, MonomialDegree(DIM - 1));
            score
        })
        .collect();
    let score_seconds = score_start.elapsed().as_secs_f64();

    let one_start = Instant::now();
    let first_bits = extract_bits(&scores[0], fbsk, ksk);
    let one_seconds = one_start.elapsed().as_secs_f64();
    let all_start = Instant::now();
    let all_bits: Vec<LweCiphertextListOwned<u64>> = scores
        .par_iter()
        .map(|score| extract_bits(score, fbsk, ksk))
        .collect();
    let all_seconds = all_start.elapsed().as_secs_f64();

    let reencode_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (1u64 << 60).wrapping_neg(),
            PlaintextCount(polynomial_size.0),
        ),
        modulus,
    );
    let reencode_start = Instant::now();
    let canonical_bits: Vec<Vec<LweCiphertextOwned<u64>>> = all_bits
        .par_iter()
        .map(|score_bits| {
            score_bits
                .iter()
                .map(|bit| reencode_bit(bit, &reencode_accumulator, fbsk, ksk, large_size, modulus))
                .collect()
        })
        .collect();
    let reencode_seconds = reencode_start.elapsed().as_secs_f64();

    let bit_decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));
    let decode_bits = |bits: &LweCiphertextListOwned<u64>| -> u64 {
        bits.iter().fold(0u64, |value, encrypted_bit| {
            let phase = decrypt_lwe_ciphertext(&small_secret, &encrypted_bit).0;
            let bit = bit_decomposer.closest_representable(phase) >> 63;
            (value << 1) | bit
        })
    };
    let decoded: Vec<u64> = all_bits.iter().map(decode_bits).collect();
    let correct = decoded
        .iter()
        .zip(&shifted_scores)
        .filter(|(observed, expected)| observed == expected)
        .count();

    let canonical_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(3), DecompositionLevelCount(1));
    let canonical_correct = canonical_bits
        .iter()
        .zip(&shifted_scores)
        .filter(|(bits, expected)| {
            let observed = bits
                .iter()
                .rev()
                .enumerate()
                .fold(0u64, |value, (index, bit)| {
                    let phase = decrypt_lwe_ciphertext(&small_secret, bit).0;
                    let digit = canonical_decomposer.closest_representable(phase) >> 61;
                    value | ((digit & 1) << index)
                });
            observed == **expected
        })
        .count();
    let canonical_mismatches: Vec<(usize, u64, u64)> = canonical_bits
        .iter()
        .zip(&shifted_scores)
        .enumerate()
        .filter_map(|(identity, (bits, expected))| {
            let observed = bits
                .iter()
                .rev()
                .enumerate()
                .fold(0u64, |value, (index, bit)| {
                    let phase = decrypt_lwe_ciphertext(&small_secret, bit).0;
                    let digit = canonical_decomposer.closest_representable(phase) >> 61;
                    value | ((digit & 1) << index)
                });
            (observed != *expected).then_some((identity, *expected, observed))
        })
        .collect();
    let canonical_bit_errors: Vec<usize> = (0..SCORE_BITS)
        .map(|position| {
            canonical_bits
                .iter()
                .zip(&shifted_scores)
                .filter(|(bits, expected)| {
                    let phase = decrypt_lwe_ciphertext(&small_secret, &bits[position]).0;
                    let observed = (canonical_decomposer.closest_representable(phase) >> 61) & 1;
                    let expected_bit = (**expected >> (SCORE_BITS - 1 - position)) & 1;
                    observed != expected_bit
                })
                .count()
        })
        .collect();
    let extracted_max_error_log2: Vec<f64> = (0..SCORE_BITS)
        .map(|position| {
            let maximum = all_bits
                .iter()
                .zip(&shifted_scores)
                .map(|(bits, expected)| {
                    let phase = decrypt_lwe_ciphertext(&small_secret, &bits.get(position)).0;
                    let expected_phase = ((expected >> (SCORE_BITS - 1 - position)) & 1) << 63;
                    phase
                        .wrapping_sub(expected_phase)
                        .cast_signed()
                        .unsigned_abs()
                })
                .max()
                .unwrap_or(0);
            (maximum as f64).log2()
        })
        .collect();

    // Test the tempting zero-copy radix bridge explicitly.  The extractor returns q/2 for bit 1;
    // under message=2, carry=2, tfhe-rs' shortint delta is 2^61, so this is raw block value 4,
    // not a canonical radix bit.  We expose the observed decryption before trying propagation.
    let mut wrapped_blocks: Vec<Ciphertext> = first_bits
        .iter()
        .rev()
        .map(|bit| {
            Ciphertext::new(
                LweCiphertextOwned::from_container(bit.as_ref().to_vec(), modulus),
                Degree::new(4),
                NoiseLevel::NOMINAL,
                shortint_server.message_modulus,
                shortint_server.carry_modulus,
                PBSOrder::BootstrapKeyswitch,
            )
        })
        .collect();
    let mut bridge_shortint_server = shortint_server.clone();
    bridge_shortint_server.pbs_order = PBSOrder::BootstrapKeyswitch;
    let bridge_server =
        tfhe::integer::ServerKey::new_radix_server_key_from_shortint(bridge_shortint_server);
    let high_zeros: RadixCiphertext = bridge_server.create_trivial_radix(0u64, 2);
    wrapped_blocks.extend(high_zeros.blocks().iter().cloned());
    let wrapped: RadixCiphertext = RadixCiphertext::from(wrapped_blocks);
    let wrapped_block_values: Vec<u64> = wrapped
        .blocks()
        .iter()
        .map(|block| shortint_client.decrypt_message_and_carry(block))
        .collect();

    let canonical_radix: Vec<RadixCiphertext> = canonical_bits
        .iter()
        .map(|bits| {
            let mut blocks: Vec<Ciphertext> = bits
                .iter()
                .rev()
                .map(|bit| {
                    Ciphertext::new(
                        bit.clone(),
                        Degree::new(1),
                        NoiseLevel::NOMINAL,
                        shortint_server.message_modulus,
                        shortint_server.carry_modulus,
                        PBSOrder::BootstrapKeyswitch,
                    )
                })
                .collect();
            let high: RadixCiphertext = bridge_server.create_trivial_radix(0u64, 1);
            blocks.extend(high.blocks().iter().cloned());
            RadixCiphertext::from(blocks)
        })
        .collect();
    let canonical_radix_correct = canonical_radix
        .iter()
        .zip(&shifted_scores)
        .filter(|(encrypted, expected)| client_key.decrypt::<u64>(encrypted) == **expected)
        .count();
    let threshold: RadixCiphertext =
        bridge_server.create_trivial_radix((scene.threshold + SCORE_OFFSET) as u64, SCORE_BITS + 1);
    let compare_start = Instant::now();
    let first_under_threshold = bridge_server.le_parallelized(&canonical_radix[0], &threshold);
    let compare_seconds = compare_start.elapsed().as_secs_f64();
    let first_under_threshold_clear = client_key.decrypt_bool(&first_under_threshold);

    let cbs_measurement = (cbs_count > 0).then(|| {
        let pfpksk = cbs_pfpksk.as_ref().unwrap();
        let count = cbs_count.min(n);
        assert!(count > 0);
        let mut lut_values = vec![0u64; CBS_BITS * polynomial_size.0];
        for block in 0..CBS_BITS {
            for value in 0..(1usize << CBS_BITS) {
                let bit = (value >> block) & 1;
                lut_values[block * polynomial_size.0 + value] = (bit as u64) << 61;
            }
        }
        let lut = PolynomialListOwned::from_container(lut_values, polynomial_size);
        let one_start = Instant::now();
        let one = cbs_vertical_pack_bits(&all_bits[0], &lut, fbsk, pfpksk, CBS_BITS, CBS_BITS);
        let one_seconds = one_start.elapsed().as_secs_f64();
        let all_start = Instant::now();
        let packed: Vec<_> = all_bits[..count]
            .par_iter()
            .map(|bits| cbs_vertical_pack_bits(bits, &lut, fbsk, pfpksk, CBS_BITS, CBS_BITS))
            .collect();
        let all_seconds = all_start.elapsed().as_secs_f64();
        let to_radix = |blocks: &LweCiphertextListOwned<u64>| -> RadixCiphertext {
            RadixCiphertext::from(
                blocks
                    .iter()
                    .map(|block| {
                        Ciphertext::new(
                            LweCiphertextOwned::from_container(block.as_ref().to_vec(), modulus),
                            Degree::new(1),
                            NoiseLevel::NOMINAL,
                            shortint_server.message_modulus,
                            shortint_server.carry_modulus,
                            PBSOrder::KeyswitchBootstrap,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let first_observed: u64 = client_key.decrypt(&to_radix(&one));
        let expected: Vec<u64> = shifted_scores[..count]
            .iter()
            .map(|score| score >> (SCORE_BITS - CBS_BITS))
            .collect();
        let observed: Vec<u64> = packed
            .iter()
            .map(|blocks| client_key.decrypt(&to_radix(blocks)))
            .collect();
        let correct = observed
            .iter()
            .zip(&expected)
            .filter(|(left, right)| left == right)
            .count();
        (
            count,
            one_seconds,
            all_seconds,
            first_observed,
            expected[0],
            correct,
            observed,
            expected,
        )
    });
    let cbs_full_measurement = (cbs_full_count > 0).then(|| {
        let pfpksk = cbs_pfpksk.as_ref().unwrap();
        let count = cbs_full_count.min(n);
        assert!(count > 0);
        let domain = 1usize << SCORE_BITS;
        let polynomials_per_output = domain.div_ceil(polynomial_size.0);
        let mut lut_values = vec![0u64; SCORE_BITS * polynomials_per_output * polynomial_size.0];
        for block in 0..SCORE_BITS {
            let output_offset = block * polynomials_per_output * polynomial_size.0;
            for value in 0..domain {
                let bit = (value >> block) & 1;
                lut_values[output_offset + value] = (bit as u64) << 61;
            }
        }
        let lut = PolynomialListOwned::from_container(lut_values, polynomial_size);
        let one_start = Instant::now();
        let one = cbs_vertical_pack_bits(&all_bits[0], &lut, fbsk, pfpksk, SCORE_BITS, SCORE_BITS);
        let one_seconds = one_start.elapsed().as_secs_f64();
        let all_start = Instant::now();
        let packed: Vec<_> = all_bits[..count]
            .par_iter()
            .map(|bits| cbs_vertical_pack_bits(bits, &lut, fbsk, pfpksk, SCORE_BITS, SCORE_BITS))
            .collect();
        let all_seconds = all_start.elapsed().as_secs_f64();
        let to_radix = |blocks: &LweCiphertextListOwned<u64>| -> RadixCiphertext {
            RadixCiphertext::from(
                blocks
                    .iter()
                    .map(|block| {
                        Ciphertext::new(
                            LweCiphertextOwned::from_container(block.as_ref().to_vec(), modulus),
                            Degree::new(1),
                            NoiseLevel::NOMINAL,
                            shortint_server.message_modulus,
                            shortint_server.carry_modulus,
                            PBSOrder::KeyswitchBootstrap,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let first_observed: u64 = client_key.decrypt(&to_radix(&one));
        let observed: Vec<u64> = packed
            .iter()
            .map(|blocks| client_key.decrypt(&to_radix(blocks)))
            .collect();
        let expected = shifted_scores[..count].to_vec();
        let correct = observed
            .iter()
            .zip(&expected)
            .filter(|(left, right)| left == right)
            .count();
        (
            count,
            one_seconds,
            all_seconds,
            first_observed,
            expected[0],
            correct,
            observed,
            expected,
            polynomials_per_output,
        )
    });
    let propagation_result = if args.iter().any(|argument| argument == "--try-propagate") {
        let mut propagated = wrapped.clone();
        let start = Instant::now();
        bridge_server.full_propagate_parallelized(&mut propagated);
        let seconds = start.elapsed().as_secs_f64();
        let decrypted: u64 = client_key.decrypt(&propagated);
        Some((seconds, decrypted))
    } else {
        None
    };

    let clear_best = clear_scores
        .iter()
        .enumerate()
        .min_by_key(|(identity, score)| (**score, *identity))
        .unwrap();
    println!(
        "score bit extraction: N={n} probe={probe_index} T={} bits={SCORE_BITS} offset={SCORE_OFFSET} Delta=2^{LOG_DELTA} threads={}",
        scene.threshold,
        rayon::current_num_threads()
    );
    println!(
        "setup_s keygen={key_seconds:.6} encrypt={encryption_seconds:.6} score={score_seconds:.6} (excluded from extraction)"
    );
    if cbs_count > 0 || cbs_full_count > 0 {
        println!("cbs_setup_s pfpksk={cbs_setup_seconds:.6} (excluded)");
    }
    println!(
        "extract_s one_score={one_seconds:.6} all_scores_parallel={all_seconds:.6} per_score_parallel_avg={:.6} pbs={} correctness={correct}/{n}",
        all_seconds / n as f64,
        SCORE_BITS * n
    );
    println!(
        "canonical_bridge_s all_bits_parallel={reencode_seconds:.6} per_score_parallel_avg={:.6} pbs={} bit_vectors={canonical_correct}/{n} radix_values={canonical_radix_correct}/{n} one_radix_le={compare_seconds:.6}s result={} expected={}",
        reencode_seconds / n as f64,
        SCORE_BITS * n,
        first_under_threshold_clear,
        clear_scores[0] <= scene.threshold
    );
    println!(
        "canonical_mismatches={:?}",
        &canonical_mismatches[..canonical_mismatches.len().min(12)]
    );
    println!(
        "canonical_bit_errors_msb_to_lsb={canonical_bit_errors:?} extracted_max_abs_error_log2_msb_to_lsb={extracted_max_error_log2:?}"
    );
    if let Some((count, one_s, all_s, first, first_expected, correct, observed, expected)) =
        cbs_measurement
    {
        println!(
            "cbs_vp_8bit_s count={count} one_score={one_s:.6} all_parallel={all_s:.6} projected_n64_from_batch={:.6} outputs={} correctness={correct}/{count} first={first} first_expected={first_expected}",
            all_s * 64.0 / count as f64,
            CBS_BITS
        );
        println!("cbs_vp_observed={observed:?} expected={expected:?}");
    }
    if let Some((
        count,
        one_s,
        all_s,
        first,
        first_expected,
        correct,
        observed,
        expected,
        polynomials_per_output,
    )) = cbs_full_measurement
    {
        println!(
            "cbs_vp_full13_s count={count} one_score={one_s:.6} all_parallel={all_s:.6} projected_n64_from_batch={:.6} outputs={} lut_polys_per_output={polynomials_per_output} correctness={correct}/{count} first={first} first_expected={first_expected}",
            all_s * 64.0 / count as f64,
            SCORE_BITS
        );
        println!("cbs_vp_full_observed={observed:?} expected={expected:?}");
    }
    println!(
        "clear_best={} clear_min={} shifted={} first_shifted={} first_decoded={} first_redecoded={} raw_wrapped_blocks={wrapped_block_values:?}",
        clear_best.0,
        clear_best.1,
        clear_best.1 + SCORE_OFFSET,
        shifted_scores[0],
        decode_bits(&first_bits),
        decoded[0]
    );
    println!(
        "zero_copy_bridge raw_q_over_2_as_shortint={wrapped_block_values:?} propagation={propagation_result:?} expected_if_factor4={} (direct metadata is outside valid degree <= 3)",
        shifted_scores[0] * 4
    );
    assert_eq!(correct, n, "at least one extracted score was wrong");
}
