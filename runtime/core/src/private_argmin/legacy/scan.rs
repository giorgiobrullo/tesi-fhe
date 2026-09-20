//! Adapter and admission gate for the historical A53 encrypted scan.
use super::*;

pub(super) struct A66A53CoreBackend<'a> {
    pub(super) server_key: &'a ServerKey,
    pub(super) modulus: CiphertextModulus<u64>,
    pub(super) big_size: LweSize,
    pub(super) small_size: LweSize,
    pub(super) pbs_count: &'a AtomicU64,
    pub(super) scan_pbs: AtomicU64,
    pub(super) scan_extra_output_marginals: AtomicU64,
}

impl A66A53CoreBackend<'_> {
    fn validate_body(&self, torus_body: &[u64]) -> Result<(), PrivateArgminError> {
        let expected = match &self.server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key.polynomial_size().0,
            _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
        };
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
        let bootstrap_key = match &self.server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key,
            _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
        };
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
        let bootstrap_key = match &self.server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key,
            _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
        };
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(&self.server_key.key_switching_key, input, &mut switched);
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
        let bootstrap_key = match &self.server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(key) => key,
            _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
        };
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
        keyswitch_lwe_ciphertext(&self.server_key.key_switching_key, input, &mut switched);
        blind_rotate_assign(&switched, &mut accumulator, bootstrap_key);
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

pub(super) fn a66_a53_gate() -> FutureFheGate<'static> {
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

pub(super) fn map_a53_error(error: FutureFheError<PrivateArgminError>) -> PrivateArgminError {
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
