//! Real noisy FHE regression with fresh, in-memory keys and three serialized queries.
//! Run this ignored test alone in a fresh process with `--test-threads=1`: composite controls
//! are process-wide. It checks selected-path semantics and counters, not latency or a failure bound.
use crate::{composite, service};
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;

#[test]
#[ignore = "fresh noisy FHE keys and three selected-path queries; run alone, not as a benchmark"]
fn fresh_key_public_parallel_preserves_exact_ids_without_benchmarking() {
    setup_custom_fft_plan(Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    ));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build()
        .expect("fixed query pool");
    pool.install(|| {
        let client =
            tfhe::shortint::ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let ordinary = tfhe::shortint::ServerKey::new(&client);
        let bundle = service::generate_bundle(&client, ordinary).expect("fresh Head bundle");
        let evaluation =
            service::EvaluationKeys::from_bundle(bundle).expect("valid evaluation keys");
        let (glwe_secret, _, parameters, _) = match client.atomic_pattern {
            AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
            _ => panic!("selected A44 client must use Standard keys"),
        };
        let big_secret = glwe_secret.as_lwe_secret_key();

        // Probe q[0]=1 in the same full51/low60 packed representation as the selected client.
        let mut coefficients = vec![0u64; glwe_secret.polynomial_size().0];
        coefficients[0] = 1u64 << 51;
        coefficients[1024] = 1u64 << 60;
        let mut packed = GlweCiphertext::new(
            0u64,
            glwe_secret.glwe_dimension().to_glwe_size(),
            glwe_secret.polynomial_size(),
            CiphertextModulus::new_native(),
        );
        let mut seeder = new_seeder();
        let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder.as_mut(),
        );
        encrypt_glwe_ciphertext(
            &glwe_secret,
            &mut packed,
            &PlaintextList::from_container(coefficients),
            parameters.glwe_noise_distribution(),
            &mut generator,
        );

        let mut template = [0i64; 512];
        template[0] = 1;
        // Both scores are -1. The first row must win ties even when the second accepts.
        for (thresholds, expected) in [([-1, -1], 1u64), ([-2, -2], 0), ([-2, 100], 0)] {
            let templates = thresholds.map(|threshold| service::TemplateView {
                template: &template,
                norm2: 1,
                threshold,
            });
            let plan = service::plan(&templates).expect("admitted gallery");
            composite::begin_query(composite::Mode::PublicParallel, false);
            let (low, middle, high, counts) = evaluation
                .evaluate_public_thresholds(&packed, &templates, plan.execution_domain, true)
                .expect("selected circuit and actual operation ledger agree");
            assert!(counts.br > 0 && counts.pfks > 0);
            let digits = [low, middle, high].map(|ciphertext| {
                let phase = decrypt_lwe_ciphertext(&big_secret, &ciphertext).0;
                let digit = phase.wrapping_add(1u64 << 58) >> 59;
                assert!(digit < 15, "noncanonical base15 output: {digit}");
                digit
            });
            let code = digits[0] + 15 * digits[1] + 225 * digits[2];
            assert_eq!(code, expected, "thresholds {thresholds:?}");
        }
    });
}
