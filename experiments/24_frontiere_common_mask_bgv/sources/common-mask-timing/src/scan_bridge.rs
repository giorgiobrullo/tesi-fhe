//! Exact frozen A66 backend and A53 gate, exposed for A190's ordinary egress flags.
use baseline_20260905_tfhe17::a53_scan::fhe::{
    materialize_a53_scan, A53FheBackend, BackendParameterContract, FutureFheError, FutureFheGate,
    A66_EXPERIMENT_ACK, A66_OBSERVED_SOURCE_GUARDS, A66_PFAIL_ACK,
};
use baseline_20260905_tfhe17::a53_scan::{
    PrimitiveCounts as A53PrimitiveCounts, A44_MAX_NOISE_LEVEL as A53_REQUIRED_MAX_NOISE_LEVEL,
};
use baseline_20260905_tfhe17::{
    validate_a44_parameter_binding, PrivateArgminError, A44_PARAMETER_BINDING,
    A44_PARAMETER_CANONICAL, A44_PARAMETER_FINGERPRINT_SHA256, A44_PARAMS_ID,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey};
use tfhe::shortint::ServerKey;
type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
const PBS_MESSAGE_MODULUS: usize = 16;
fn standard_server_key_parts(
    server_key: &ServerKey,
) -> Result<
    (
        &LweKeyswitchKeyOwned<u64>,
        &FourierLweBootstrapKeyOwned,
        &ModulusSwitchConfiguration<u64>,
        PBSOrder,
    ),
    PrivateArgminError,
> {
    let standard_key = match &server_key.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    match &standard_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => Ok((
            &standard_key.key_switching_key,
            bsk,
            modulus_switch_noise_reduction_key,
            standard_key.pbs_order,
        )),
        _ => Err(PrivateArgminError::UnsupportedBootstrappingKey),
    }
}

fn blind_rotate_assign_with_modulus_switch(
    input: &Lwe,
    accumulator: &mut Glwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    modulus_switch_configuration: &ModulusSwitchConfiguration<u64>,
) {
    let log_modulus = fourier_bootstrap_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let modulus_switched =
        modulus_switch_configuration.lwe_ciphertext_modulus_switch::<usize, _>(input, log_modulus);
    blind_rotate_assign(&modulus_switched, accumulator, fourier_bootstrap_key);
}

struct A66A53CoreBackend<'a> {
    server_key: &'a ServerKey,
    modulus: CiphertextModulus<u64>,
    big_size: LweSize,
    small_size: LweSize,
    pbs_count: &'a AtomicU64,
    scan_pbs: AtomicU64,
    scan_extra_output_marginals: AtomicU64,
}

impl A66A53CoreBackend<'_> {
    fn validate_body(&self, torus_body: &[u64]) -> Result<(), PrivateArgminError> {
        let expected = standard_server_key_parts(self.server_key)?
            .1
            .polynomial_size()
            .0;
        if torus_body.len() != expected {
            return Err(PrivateArgminError::A62A53AccumulatorLengthMismatch {
                actual: torus_body.len(),
                expected,
            });
        }
        Ok(())
    }

    fn record_pbs(&self, output_marginals: u64) {
        self.pbs_count.fetch_add(1, Ordering::Relaxed);
        self.scan_pbs.fetch_add(1, Ordering::Relaxed);
        if output_marginals > 1 {
            self.scan_extra_output_marginals
                .fetch_add(output_marginals - 1, Ordering::Relaxed);
        }
    }
}

impl A53FheBackend for A66A53CoreBackend<'_> {
    type Lwe = Lwe;
    type Accumulator = Glwe;
    type Error = PrivateArgminError;

    fn trivial_zero(&self) -> Self::Lwe {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(
            self.big_size,
            Plaintext(0u64),
            self.modulus,
        )
    }

    fn add_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe) {
        lwe_ciphertext_add_assign(target, source);
    }

    fn sub_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe) {
        lwe_ciphertext_sub_assign(target, source);
    }

    fn add_plaintext_assign(&self, target: &mut Self::Lwe, torus_plaintext: u64) {
        lwe_ciphertext_plaintext_add_assign(target, Plaintext(torus_plaintext));
    }

    fn prepare_raw_accumulator(
        &self,
        torus_body: &[u64],
    ) -> Result<Self::Accumulator, Self::Error> {
        self.validate_body(torus_body)?;
        let (_, bootstrap_key, _, _) = standard_server_key_parts(self.server_key)?;
        Ok(allocate_and_trivially_encrypt_new_glwe_ciphertext(
            bootstrap_key.glwe_size(),
            &PlaintextList::from_container(torus_body.to_vec()),
            self.modulus,
        ))
    }

    fn pbs_prepared(
        &self,
        input: &Self::Lwe,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::Lwe, Self::Error> {
        let (key_switching_key, bootstrap_key, _, _) = standard_server_key_parts(self.server_key)?;
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, self.big_size, self.modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut output, accumulator, bootstrap_key);
        self.record_pbs(1);
        Ok(output)
    }

    fn pbs_dual_prepared(
        &self,
        input: &Self::Lwe,
        mut accumulator: Self::Accumulator,
        first_degree: usize,
        second_degree: usize,
    ) -> Result<(Self::Lwe, Self::Lwe), Self::Error> {
        let (key_switching_key, bootstrap_key, modulus_switch_configuration, _) =
            standard_server_key_parts(self.server_key)?;
        let polynomial_size = bootstrap_key.polynomial_size().0;
        for degree in [first_degree, second_degree] {
            if degree >= polynomial_size {
                return Err(PrivateArgminError::A62A53SampleDegreeOutOfRange {
                    degree,
                    polynomial_size,
                });
            }
        }
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        blind_rotate_assign_with_modulus_switch(
            &switched,
            &mut accumulator,
            bootstrap_key,
            modulus_switch_configuration,
        );
        let mut first = LweCiphertext::new(0u64, self.big_size, self.modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut first,
            MonomialDegree(first_degree),
        );
        let mut second = LweCiphertext::new(0u64, self.big_size, self.modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut second,
            MonomialDegree(second_degree),
        );
        self.record_pbs(2);
        Ok((first, second))
    }

    fn counters(&self) -> A53PrimitiveCounts {
        let pbs = self.scan_pbs.load(Ordering::Relaxed);
        let extra_marginals = self.scan_extra_output_marginals.load(Ordering::Relaxed);
        A53PrimitiveCounts {
            blind_rotations: pbs,
            key_switches: pbs,
            output_marginals: pbs + extra_marginals,
        }
    }
}

fn a66_a53_gate() -> FutureFheGate<'static> {
    FutureFheGate {
        backend_parameter: BackendParameterContract {
            params_id: A44_PARAMS_ID,
            canonical: A44_PARAMETER_CANONICAL,
            fingerprint_sha256: A44_PARAMETER_FINGERPRINT_SHA256,
            polynomial_size: 2048,
            pbs_message_modulus: PBS_MESSAGE_MODULUS,
            max_noise_level: A53_REQUIRED_MAX_NOISE_LEVEL,
        },
        observed_sources: A66_OBSERVED_SOURCE_GUARDS,
        experiment_ack: A66_EXPERIMENT_ACK,
        pfail_ack: A66_PFAIL_ACK,
    }
}

fn map_a53_error(error: FutureFheError<PrivateArgminError>) -> PrivateArgminError {
    match error {
        FutureFheError::Gate(_) => PrivateArgminError::A62A53GateRejected,
        FutureFheError::Static(_) => PrivateArgminError::A62A53StaticContractRejected,
        FutureFheError::Backend(error) => error,
        FutureFheError::CounterUnderflow => PrivateArgminError::A62A53CounterUnderflow,
        FutureFheError::CounterMismatch { expected, observed } => {
            PrivateArgminError::A62A53CounterMismatch {
                expected_blind_rotations: expected.blind_rotations,
                actual_blind_rotations: observed.blind_rotations,
                expected_key_switches: expected.key_switches,
                actual_key_switches: observed.key_switches,
                expected_output_marginals: expected.output_marginals,
                actual_output_marginals: observed.output_marginals,
            }
        }
    }
}

pub fn scan(
    server_key: &ServerKey,
    flags: &[Lwe],
) -> Result<(Lwe, Lwe, A53PrimitiveCounts), PrivateArgminError> {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, server_key)?;
    let (ksk, bsk, _, _) = standard_server_key_parts(server_key)?;
    assert_eq!(flags.len(), 16);
    assert!(flags.iter().all(
        |ct| ct.lwe_size() == bsk.output_lwe_dimension().to_lwe_size()
            && ct.ciphertext_modulus() == server_key.ciphertext_modulus
    ));
    let total = AtomicU64::new(0);
    let backend = A66A53CoreBackend {
        server_key,
        modulus: server_key.ciphertext_modulus,
        big_size: bsk.output_lwe_dimension().to_lwe_size(),
        small_size: ksk.output_lwe_size(),
        pbs_count: &total,
        scan_pbs: AtomicU64::new(0),
        scan_extra_output_marginals: AtomicU64::new(0),
    };
    let output = materialize_a53_scan(&a66_a53_gate(), &backend, flags).map_err(map_a53_error)?;
    assert_eq!(output.observed_counts.blind_rotations, 16);
    Ok((output.low_digit, output.high_digit, output.observed_counts))
}
