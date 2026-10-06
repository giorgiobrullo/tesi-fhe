//! Calls only TFHE's analytical noise-model APIs: no keys/ciphertexts/FHE are generated.
use serde_json::json;
use tfhe::core_crypto::commons::noise_formulas::noise_simulation::traits::*;
use tfhe::core_crypto::commons::noise_formulas::noise_simulation::*;
use tfhe::core_crypto::commons::noise_formulas::secure_noise::{
    minimal_glwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_gaussian,
};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as A44;

fn ks(variance: f64, sigma: f64) -> NoiseSimulationLwe {
    let modulus = NoiseSimulationModulus::from_ciphertext_modulus(A44.ciphertext_modulus);
    let key = NoiseSimulationLweKeyswitchKey::new(
        LweDimension(2048),
        A44.lwe_dimension,
        A44.ks_base_log,
        A44.ks_level,
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(sigma)),
        modulus,
    );
    let input = NoiseSimulationLwe::new(LweDimension(2048), Variance(variance), modulus);
    let mut output = key.allocate_lwe_keyswitch_result(&mut ());
    key.lwe_keyswitch(&input, &mut output, &mut ());
    output
}

fn pbs(input_variance: f64, accumulator_variance: f64, sigma: f64) -> NoiseSimulationLwe {
    let modulus = NoiseSimulationModulus::from_ciphertext_modulus(A44.ciphertext_modulus);
    let key = NoiseSimulationLweFourierBsk::new(
        A44.lwe_dimension,
        A44.glwe_dimension.to_glwe_size(),
        A44.polynomial_size,
        A44.pbs_base_log,
        A44.pbs_level,
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(sigma)),
        modulus,
    );
    let input = NoiseSimulationLwe::new(A44.lwe_dimension, Variance(input_variance), modulus);
    let accumulator = NoiseSimulationGlwe::new(
        A44.glwe_dimension,
        A44.polynomial_size,
        Variance(accumulator_variance),
        modulus,
    );
    let mut output = accumulator.allocate_lwe_bootstrap_result(&mut ());
    key.lwe_classic_fft_pbs(&input, &mut output, &accumulator, &mut ());
    output
}

fn main() {
    assert_eq!(A44.lwe_dimension.0, 859);
    assert_eq!(A44.polynomial_size.0, 2048);
    assert_eq!((A44.ks_base_log.0, A44.ks_level.0), (3, 5));
    assert_eq!((A44.pbs_base_log.0, A44.pbs_level.0), (23, 1));
    let modulus = NoiseSimulationModulus::from_ciphertext_modulus(A44.ciphertext_modulus);
    let q = modulus.as_f64();
    let unit = NoiseSimulationLwe::new(LweDimension(2048), Variance(1.0), modulus);
    // These deliberately misuse the explicitly uncorrelated operation on aliases.
    // Their outputs characterize the API; they are NOT adopted as actual variances.
    let wrong_alias_sub = unit.lwe_uncorrelated_sub(&unit, &mut ());
    let wrong_alias_sum = unit.lwe_uncorrelated_add(&unit, &mut ());
    let scaled = unit.scalar_mul(6u64, &mut ());
    assert_eq!(wrong_alias_sub.variance().0, 2.0);
    assert_eq!(wrong_alias_sum.variance().0, 2.0);
    assert_eq!(scaled.variance().0, 36.0);

    let small_sigma = 2.3088161607134664e-6;
    let glwe_sigma = 2.845267479601915e-15;
    let ks0 = ks(0.0, small_sigma);
    let ks_changed_sigma = ks(0.0, 2.0 * small_sigma);
    assert_eq!(ks0.variance(), ks_changed_sigma.variance());
    let mut ms = ks0.allocate_standard_mod_switch_result(&mut ());
    ks0.standard_mod_switch(CiphertextModulusLog(12), &mut ms, &mut ());
    assert_eq!(ms.modulus(), ks0.modulus());
    let pbs0 = pbs(ms.variance().0, 0.0, glwe_sigma);
    let pbs_changed_sigma = pbs(ms.variance().0, 0.0, 2.0 * glwe_sigma);
    let pbs_huge_input = pbs(1.0, 0.0, glwe_sigma);
    assert_eq!(pbs0.variance(), pbs_changed_sigma.variance());
    assert_eq!(pbs0.variance(), pbs_huge_input.variance());
    let accumulator_test = 1.0e-10;
    let pbs_noisy_accumulator = pbs(ms.variance().0, accumulator_test, glwe_sigma);
    assert_eq!(
        pbs_noisy_accumulator.variance().0,
        pbs0.variance().0 + accumulator_test
    );

    println!(
        "{}",
        json!({
            "schema":"a141.library-model.v1", "status":"LIBRARY_MODEL_API_CROSSCHECK_ONLY",
            "tfhe_version":"1.7.0", "fhe_executed":false, "keys_generated":false,
            "source_binding":serde_json::from_str::<serde_json::Value>(include_str!("../SOURCE_BINDING.json")).expect("pinned binding JSON"),
            "a44_geometry":{"big_lwe":2048,"small_lwe":859,"polynomial_size":2048,
                "ks_base_log":3,"ks_levels":5,"pbs_base_log":23,"pbs_levels":1},
            "variance_unit":"normalized original torus; multiply by q^2 for torus-word variance",
            "q":q, "address_modulus":4096,
            "api_misuse_negative_controls":{"uncorrelated_alias_sub":wrong_alias_sub.variance().0,
                "correct_alias_sub":0,"uncorrelated_alias_sum":wrong_alias_sum.variance().0,
                "correct_alias_sum":4,"scalar_six":scaled.variance().0},
            "ks_additive_variance":ks0.variance().0,
            "ks_changed_supplied_sigma_variance":ks_changed_sigma.variance().0,
            "ms_total_variance":ms.variance().0,
            "ms_additive_variance":ms.variance().0-ks0.variance().0,
            "ms_keeps_original_modulus":ms.modulus()==modulus,
            "pbs_marginal_model_variance":pbs0.variance().0,
            "pbs_changed_supplied_sigma_variance":pbs_changed_sigma.variance().0,
            "pbs_huge_input_variance_result":pbs_huge_input.variance().0,
            "pbs_accumulator_variance_added":pbs_noisy_accumulator.variance().0,
            "minimal_small_key_calibration_variance":minimal_lwe_variance_for_132_bits_security_gaussian(A44.lwe_dimension,q).0,
            "minimal_glwe_key_calibration_variance":minimal_glwe_variance_for_132_bits_security_gaussian(A44.glwe_dimension,A44.polynomial_size,q).0,
            "supplied_small_sigma_squared":small_sigma*small_sigma,
            "supplied_glwe_sigma_squared":glwe_sigma*glwe_sigma,
            "label_132_bits":"security/noise calibration; not a failure exponent",
            "unsupported":["actual input bias/tail and coefficientwise address","custom LUT body and degrees0/768",
                "shared BR/KSK covariance","multi-call key reuse","runtime attestation"],
            "a133_noise_bound_status":"OPEN", "p_fail_claimed":false
        })
    );
}
