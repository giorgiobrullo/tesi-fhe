//! Micro-harness FHE per il classificatore sparso A33.
//!
//! Gli otto stati `h=0..7` arrivano a distanza `q/8`. Un accumulatore a otto box usa gli
//! slot pari per il codice signed `r` e gli slot dispari per un indicatore signed. Una sola blind
//! rotation produce entrambi con sample extraction a distanza di un box. Due indicatori, con pesi
//! 1 e 3 incorporati negli accumulatori (non moltiplicati dopo la cifratura), vengono poi
//! canonicalizzati da un solo PBS di gruppo.

use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const BOOL_DELTA_LOG: u32 = 59;
const H_DELTA_LOG: u32 = 61;
const CLASSIFIER_BOXES: usize = 8;
const GROUP_BOXES: usize = 16;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

fn decode_symbol(secret_key: &LweSecretKeyView<'_, u64>, ciphertext: &Lwe) -> u64 {
    let phase = decrypt_lwe_ciphertext(secret_key, ciphertext).0;
    phase.wrapping_add(1u64 << (BOOL_DELTA_LOG - 1)) >> BOOL_DELTA_LOG
}

fn expected_r(h: u64) -> u64 {
    [2, 3, 4, 4, 30, 29, 28, 28][h as usize]
}

fn expected_signed_flag(h: u64, weight: u64) -> u64 {
    match h {
        0 => weight,
        4 => 32 - weight,
        _ => 0,
    }
}

fn classifier_accumulator(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
    weight: u64,
) -> Glwe {
    let delta = 1u64 << BOOL_DELTA_LOG;
    generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        CLASSIFIER_BOXES,
        modulus,
        delta,
        move |slot| match slot {
            // Gli slot pari sono osservati dall'estrazione in grado zero per h=0..3.
            0 => 2,
            2 => 3,
            4 | 6 => 4,
            // Gli slot dispari sono osservati dalla seconda estrazione. Il semigiro alto
            // produce automaticamente il negativo, quindi h=4 emette -weight.
            1 => weight,
            3 | 5 | 7 => 0,
            _ => unreachable!("generate_programmable_bootstrap_glwe_lut valuta 0..7"),
        },
    )
}

fn group_accumulator(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    modulus: CiphertextModulus<u64>,
) -> Glwe {
    let delta = 1u64 << BOOL_DELTA_LOG;
    // Dopo l'offset pubblico +4, i cinque stati con almeno un indicatore positivo sono
    // {2,5,6,7,8}; gli stati senza positivi sono {0,1,3,4}. Sono tutti nel semigiro base.
    generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        GROUP_BOXES,
        modulus,
        delta,
        |slot| u64::from(matches!(slot, 2 | 5 | 6 | 7 | 8)),
    )
}

fn main() {
    let started = Instant::now();
    let client_key = ClientKey::new(PARAMS);
    let server_key = ServerKey::new(&client_key);
    let (glwe_secret_key, _small_secret_key, client_params) = client_key.into_raw_parts();
    let big_secret_key = glwe_secret_key.as_lwe_secret_key();
    let key_seconds = started.elapsed().as_secs_f64();

    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => panic!("il micro-harness richiede una bootstrap key classica"),
    };
    let key_switching_key = &server_key.key_switching_key;
    let polynomial_size = bootstrap_key.polynomial_size();
    let glwe_size = bootstrap_key.glwe_size();
    let big_size = bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let modulus = CiphertextModulus::<u64>::new_native();
    let extraction_stride = polynomial_size.0 / CLASSIFIER_BOXES;
    assert_eq!(extraction_stride, 256);

    let classifiers = [
        classifier_accumulator(polynomial_size, glwe_size, modulus, 1),
        classifier_accumulator(polynomial_size, glwe_size, modulus, 3),
    ];
    let group_lut = group_accumulator(polynomial_size, glwe_size, modulus);

    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let mut encrypt_h = |h: u64| {
        let mut plaintext = vec![0u64; polynomial_size.0];
        plaintext[0] = h << H_DELTA_LOG;
        let mut encrypted = GlweCiphertext::new(
            0u64,
            glwe_secret_key.glwe_dimension().to_glwe_size(),
            polynomial_size,
            modulus,
        );
        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut encrypted,
            &PlaintextList::from_container(plaintext),
            client_params.glwe_noise_distribution(),
            &mut generator,
        );
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&encrypted, &mut output, MonomialDegree(0));
        output
    };

    let classify = |input: &Lwe, accumulator: &Glwe| {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = accumulator.clone();
        blind_rotate_assign(&switched, &mut rotated, bootstrap_key);

        let mut r = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut r, MonomialDegree(0));
        let mut flag = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &rotated,
            &mut flag,
            MonomialDegree(extraction_stride),
        );
        (r, flag)
    };

    let validation_started = Instant::now();
    let mut outputs: [Vec<(Lwe, Lwe)>; 2] = std::array::from_fn(|_| Vec::with_capacity(8));
    let mut classifier_mismatches = 0usize;
    for h in 0..8u64 {
        for (position, accumulator) in classifiers.iter().enumerate() {
            let encrypted = encrypt_h(h);
            let (r, flag) = classify(&encrypted, accumulator);
            let weight = [1, 3][position];
            let actual_r = decode_symbol(&big_secret_key, &r) & 31;
            let actual_flag = decode_symbol(&big_secret_key, &flag) & 31;
            let expected_r = expected_r(h);
            let expected_flag = expected_signed_flag(h, weight);
            classifier_mismatches +=
                usize::from(actual_r != expected_r || actual_flag != expected_flag);
            println!(
                "CLASSIFIER,h={h},position={position},weight={weight},r={actual_r},expected_r={expected_r},flag={actual_flag},expected_flag={expected_flag}"
            );
            outputs[position].push((r, flag));
        }
    }

    let apply_group_gate = |left: &Lwe, right: &Lwe| {
        let mut packed = left.clone();
        lwe_ciphertext_add_assign(&mut packed, right);
        lwe_ciphertext_plaintext_add_assign(&mut packed, Plaintext(4u64 << BOOL_DELTA_LOG));
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, &packed, &mut switched);
        let mut result = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut result, &group_lut, bootstrap_key);
        result
    };

    let mut group_mismatches = 0usize;
    for left_h in 0..8usize {
        for right_h in 0..8usize {
            let result = apply_group_gate(&outputs[0][left_h].1, &outputs[1][right_h].1);
            let actual = decode_symbol(&big_secret_key, &result) & 31;
            let expected = u64::from(left_h == 0 || right_h == 0);
            group_mismatches += usize::from(actual != expected);
            println!("GROUP,left_h={left_h},right_h={right_h},flag={actual},expected={expected}");
        }
    }

    let validation_seconds = validation_started.elapsed().as_secs_f64();
    let total_mismatches = classifier_mismatches + group_mismatches;
    println!(
        "SUMMARY,classifier=16/16,groups=64/64,classifier_mismatches={classifier_mismatches},group_mismatches={group_mismatches},total_mismatches={total_mismatches},blind_rotations=80,key_s={key_seconds:.6},validation_s={validation_seconds:.6},secret_material_persisted=false"
    );
    assert_eq!(total_mismatches, 0, "il classificatore sparso A33 diverge");
}
