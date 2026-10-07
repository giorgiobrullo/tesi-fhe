//! A158 P0: actual first low KS and returned Standard MS; zero BR. Client-local only.
mod observe;
use observe::*;
use std::fs;
use std::path::PathBuf;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey};
use tfhe::shortint::{ClientKey, ServerKey};

const SOURCE_ID: &str = include_str!("../SOURCE_DIGEST.txt");
const FINGERPRINT: &str = "ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61";
const ACK: &str = "A160_EXCLUSIVE_PREFIX_AUTHORIZED";

fn run(directory: PathBuf, run_id: String) {
    private_directory(&directory);
    assert!(safe_id(&run_id));
    assert_eq!(std::env::var("A160_RUN_ACK").as_deref(), Ok(ACK));
    assert_eq!(
        std::env::var("A160_SOURCE_SHA256").as_deref(),
        Ok(SOURCE_ID.trim())
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("1"));
    let binary_hash = hash(&fs::read(std::env::current_exe().unwrap()).unwrap());
    assert_eq!(
        std::env::var("A160_BINARY_SHA256").as_deref(),
        Ok(binary_hash.as_str())
    );
    assert_eq!(
        hash(include_bytes!("../PARAMETER_CANONICAL.txt")),
        FINGERPRINT
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global()
        .unwrap();
    save(
        &directory,
        "started.json",
        object(&[
            ("schema", text("a160.prefix.started.v1")),
            ("run_id", text(&run_id)),
            ("source_sha256", text(SOURCE_ID.trim())),
            ("binary_sha256", text(&binary_hash)),
            ("pid", std::process::id().to_string()),
            ("timed_benchmark", "false".into()),
            ("secret_material_persisted", "false".into()),
        ]),
    );

    // Same normal setup as the frozen Standard harness. This creates a BSK, unused by P0.
    let client = ClientKey::new(PARAMS);
    let server = ServerKey::new(&client);
    assert_eq!(server.message_modulus.0, 2);
    assert_eq!(server.carry_modulus.0, 8);
    assert_eq!(server.max_noise_level.get(), 15);
    assert_eq!(server.max_degree.get(), 15);
    assert!(server.ciphertext_modulus.is_native_modulus());
    let standard = match &server.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => panic!("requires Standard atomic pattern"),
    };
    assert_eq!(standard.pbs_order, PBSOrder::KeyswitchBootstrap);
    let (bsk, configuration) = match &standard.bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => (bsk, modulus_switch_noise_reduction_key),
        _ => panic!("requires Classic BSK"),
    };
    assert!(matches!(
        configuration,
        ModulusSwitchConfiguration::Standard
    ));
    assert_eq!(bsk.input_lwe_dimension().0, 859);
    assert_eq!(bsk.output_lwe_dimension().0, 2048);
    assert_eq!(bsk.glwe_size().0, 2);
    assert_eq!(bsk.polynomial_size().0, 2048);
    assert_eq!(bsk.decomposition_base_log().0, 23);
    assert_eq!(bsk.decomposition_level_count().0, 1);
    let ksk = &standard.key_switching_key;
    assert_eq!(ksk.input_key_lwe_dimension().0, 2048);
    assert_eq!(ksk.output_key_lwe_dimension().0, 859);
    assert_eq!(ksk.decomposition_base_log().0, 3);
    assert_eq!(ksk.decomposition_level_count().0, 5);
    assert!(ksk.ciphertext_modulus().is_native_modulus());
    assert_eq!(ksk.as_ref().len(), 2048 * 5 * 860);
    let (glwe, small, parameters) = match client.atomic_pattern {
        AtomicPatternClientKey::Standard(key) => {
            let (glwe, small, parameters, wopbs) = key.into_raw_parts();
            assert!(wopbs.is_none());
            (glwe, small, parameters)
        }
        _ => panic!("requires Standard client"),
    };
    assert_eq!(parameters, PARAMS.into());
    assert_eq!(glwe.glwe_dimension().0, 1);
    assert_eq!(glwe.polynomial_size().0, 2048);
    assert_eq!(small.lwe_dimension().0, 859);
    let big = glwe.as_lwe_secret_key();
    assert!(big.as_ref().iter().chain(small.as_ref()).all(|&s| s <= 1));
    let ksk_hash = words_hash(ksk.as_ref());
    let mut keyset_bytes = b"A158-KEYSET-V1\0".to_vec();
    keyset_bytes.extend(hex_bytes(FINGERPRINT));
    keyset_bytes.extend(hex_bytes(&ksk_hash));
    keyset_bytes.extend(run_id.as_bytes());
    let bindings = object(&[
        ("run_id", text(&run_id)),
        ("tfhe_version", text("1.7.0")),
        ("configuration", text("Standard")),
        ("parameter_fingerprint", text(FINGERPRINT)),
        ("source_sha256", text(SOURCE_ID.trim())),
        ("binary_sha256", text(&binary_hash)),
        ("ksk_words_sha256", text(&ksk_hash)),
        ("keyset_id", text(&hash(&keyset_bytes))),
    ]);
    // Separate key record exists before the query and phase observations.
    save(&directory, "key-binding.json", bindings.clone());

    let mut probe = vec![0i64; 512];
    for (i, value) in [(0, 1), (1, -2), (255, 2), (511, -1)] {
        probe[i] = value;
    }
    let mut template = vec![0i64; 512];
    for (i, value) in [(0, 1), (1, -1), (255, 1), (511, 1)] {
        template[i] = value;
    }
    let norm: i64 = template.iter().map(|x| x * x).sum();
    let dot: i64 = template.iter().zip(&probe).map(|(t, q)| t * q).sum();
    assert_eq!((norm, dot, norm - 2 * dot), (4, 4, -4));
    let mut plaintext = vec![0u64; 2048];
    for (i, &q) in probe.iter().enumerate() {
        plaintext[i] = (q as u64).wrapping_mul(1u64 << 52);
        plaintext[1024 + i] = (q as u64).wrapping_mul(1u64 << 60);
    }
    let modulus = CiphertextModulus::new_native();
    let mut seeder_box = new_seeder();
    let seeder = seeder_box.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut packed = GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
    encrypt_glwe_ciphertext(
        &glwe,
        &mut packed,
        &PlaintextList::from_container(plaintext.clone()),
        parameters.glwe_noise_distribution(),
        &mut generator,
    );
    assert!(packed.get_mask().as_ref().iter().any(|&x| x != 0));
    let mut decrypted = PlaintextList::new(0u64, PlaintextCount(2048));
    decrypt_glwe_ciphertext(&glwe, &packed, &mut decrypted);
    let mut low_noise = 0i128;
    let mut noise_terms = Vec::new();
    for (i, &t) in template.iter().enumerate().filter(|(_, t)| **t != 0) {
        let epsilon = signed(decrypted.as_ref()[1024 + i].wrapping_sub(plaintext[1024 + i]));
        low_noise -= 2 * i128::from(t) * epsilon;
        noise_terms.push(object(&[
            ("coefficient_index", (1024 + i).to_string()),
            ("epsilon_lift", epsilon.to_string()),
        ]));
    }
    let mut polynomial = vec![0u64; 2048];
    for coordinate in 0..512 {
        polynomial[511 - coordinate] = (-2 * template[coordinate]) as u64;
    }
    let polynomial = Polynomial::from_container(polynomial);
    let mut product = GlweCiphertext::new(0u64, GlweSize(2), PolynomialSize(2048), modulus);
    for (mut output, input) in product
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(packed.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
    }
    let mut low = LweCiphertext::new(0u64, LweSize(2049), modulus);
    extract_lwe_sample_from_glwe_ciphertext(&product, &mut low, MonomialDegree(1535));
    lwe_ciphertext_plaintext_add_assign(
        &mut low,
        Plaintext(((norm + 1033) as u64).wrapping_mul(1u64 << 60)),
    );
    let mut input = low.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut input, Cleartext(8));

    // Independent component observation precedes KS: no post-KS ciphertext exists here.
    let components = measure_before_ks(ksk, &input, big.as_ref(), &small);
    save(
        &directory,
        "before-ks.json",
        object(&[
            ("bindings", bindings.clone()),
            ("packed_query", ciphertext(packed.as_ref())),
            ("product", ciphertext(product.as_ref())),
            ("score_low", ciphertext(low.as_ref())),
            ("ks_input", ciphertext(input.as_ref())),
            ("initial_noise_terms_client", array(&noise_terms)),
            ("input_noise_lift", (8 * low_noise).to_string()),
            ("large_remainder_lift", components.remainder.to_string()),
            (
                "row_noise_signed_sum_direct_lift",
                components.row_noise.to_string(),
            ),
            ("used_rows", array(&components.rows)),
            ("subgroup_g", components.g.to_string()),
            ("ks_calls_so_far", "0".into()),
            ("post_ks_exists", "false".into()),
        ]),
    );

    let mut post = LweCiphertext::new(0u64, LweSize(860), modulus);
    keyswitch_lwe_ciphertext(ksk, &input, &mut post);
    let mut centered = post.clone();
    lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 62));
    let log_modulus = bsk.polynomial_size().to_blind_rotation_input_modulus_log();
    assert_eq!(log_modulus.0, 12);
    let switched = configuration.lwe_ciphertext_modulus_switch::<usize, _>(&centered, log_modulus);
    let (returned, correction, returned_log) = switched.as_view().into_raw_parts();
    let degrees: Vec<u64> = switched.mask().map(|x| x as u64).collect();
    let body_degree = switched.body() as u64;
    let low_phase = decrypt_lwe_ciphertext(&big, &low).0;
    let input_phase = decrypt_lwe_ciphertext(&big, &input).0;
    let post_phase = decrypt_lwe_ciphertext(&small, &post).0;
    let a = dot_mod(post.get_mask().as_ref(), small.as_ref());
    let d: i128 = degrees
        .iter()
        .zip(small.as_ref())
        .map(|(&d, &s)| i128::from(d) * i128::from(s))
        .sum();
    let z: i128 = post
        .get_mask()
        .as_ref()
        .iter()
        .zip(&degrees)
        .zip(small.as_ref())
        .map(|((&a, &d), &s)| signed(a.wrapping_sub(d.wrapping_mul(U))) * i128::from(s))
        .sum();
    let e_input = 8 * low_noise;
    let inferred = post_phase
        .wrapping_sub(input_phase)
        .wrapping_sub(components.remainder as u64);
    let address = (i128::from(body_degree) - d).rem_euclid(4096);
    let lift = (e_input + components.remainder + components.row_noise + z + i128::from(U / 2))
        .div_euclid(i128::from(U));
    let native_ok = post_phase.wrapping_add(1u64 << 62) >> 63 == 1;
    let lut_ok = address >= 2048;
    let record = object(&[
        ("schema", text("a158.first_low_ks_trace.v1")),
        ("kind", text("client_observed")),
        ("bindings", bindings),
        ("fixture", include_str!("../FIXTURE.json").trim().into()),
        (
            "counts",
            "{\"ordinary_ks\":1,\"configured_ms\":1,\"blind_rotations\":0}".into(),
        ),
        ("full_n4_evaluation", "false".into()),
        ("blind_rotation_consumed", "false".into()),
        ("key_sensitive_client_local_only", "true".into()),
        ("client_key_membership_attested", "false".into()),
        (
            "ciphertexts",
            object(&[
                ("score_low", ciphertext(low.as_ref())),
                ("ks_input", ciphertext(input.as_ref())),
                ("post_ks", ciphertext(post.as_ref())),
                ("centered_input", ciphertext(centered.as_ref())),
                ("returned_lazy_base", ciphertext(returned.as_ref())),
            ]),
        ),
        ("returned_body_correction_words", correction.to_string()),
        ("returned_log_modulus", returned_log.0.to_string()),
        (
            "actual_mask_degrees",
            array(&degrees.iter().map(u64::to_string).collect::<Vec<_>>()),
        ),
        ("actual_body_degree", body_degree.to_string()),
        ("subgroup_g", components.g.to_string()),
        ("initial_noise_terms_client", array(&noise_terms)),
        (
            "client",
            object(&[
                ("low_phase_words", low_phase.to_string()),
                (
                    "large_input_mask_dot_words",
                    dot_mod(input.get_mask().as_ref(), big.as_ref()).to_string(),
                ),
                ("input_phase_words", input_phase.to_string()),
                ("input_probe_weighted_noise_low_lift", low_noise.to_string()),
                (
                    "input_probe_weighted_noise_shifted_lift",
                    e_input.to_string(),
                ),
                ("large_remainder_lift", components.remainder.to_string()),
                (
                    "row_noise_signed_sum_direct_lift",
                    components.row_noise.to_string(),
                ),
                ("row_noise_signed_sum_inferred_words", inferred.to_string()),
                ("small_mask_dot_words", a.to_string()),
                ("post_phase_words", post_phase.to_string()),
                ("small_weighted_ms_degrees", d.to_string()),
                ("small_weighted_ms_residues_lift", z.to_string()),
                (
                    "centered_phase_words",
                    post_phase.wrapping_add(1u64 << 62).to_string(),
                ),
                ("direct_address", address.to_string()),
                ("displacement_lift", lift.to_string()),
            ]),
        ),
        ("native_first_bit_decode_pass", native_ok.to_string()),
        ("conditional_lut_address_pass", lut_ok.to_string()),
    ]);
    // Preserve full evidence before assertions, including an unexpected phase or address.
    save(&directory, "trace.json", record);
    assert_eq!(
        low_phase,
        (1029u64.wrapping_mul(1u64 << 60)).wrapping_add(low_noise as u64)
    );
    assert_eq!(input_phase, (1u64 << 63).wrapping_add(e_input as u64));
    assert_eq!(inferred, components.row_noise as u64);
    assert_eq!(returned.as_ref(), centered.as_ref());
    assert_eq!(correction, 0);
    assert_eq!(returned_log, log_modulus);
    assert_eq!(address, (3072 + lift).rem_euclid(4096));
    assert!(
        native_ok && lut_ok,
        "selected P0 prefix gate failed; preserve this run"
    );
    save(
        &directory,
        "completed.json",
        object(&[
            ("status", text("P0_NATIVE_AND_CONDITIONAL_ADDRESS_PASS")),
            ("ordinary_ks", "1".into()),
            ("configured_ms", "1".into()),
            ("blind_rotations", "0".into()),
            ("actual_sampler_p_fail", "null".into()),
            ("independent_replay_pending", "true".into()),
        ]),
    );
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("A160 P0 plan only: one template, 1 KS, 1 actual Standard MS, 0 BR; no keygen.");
        return;
    }
    assert_eq!(args.len(), 3, "use the private launcher");
    assert_eq!(args[0], "--run-authorized");
    run(PathBuf::from(&args[1]), args[2].clone());
}
