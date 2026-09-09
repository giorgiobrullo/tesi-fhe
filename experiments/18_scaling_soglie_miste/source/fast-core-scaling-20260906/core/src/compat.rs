//! Strict API boundary for actual TFHE1.7 Standard keys and standard modulus switching.
//! Owned key containers are moved without conversion; the PFKS circuit remains unchanged.
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::ciphertext::{MaxDegree, MaxNoiseLevel};
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey as NativeBsk};
use tfhe::shortint::{PBSOrder, PBSParameters};

#[derive(Clone)]
pub struct ClientKey(tfhe::shortint::ClientKey);

impl ClientKey {
    pub fn new(parameters: ClassicPBSParameters) -> Self {
        Self(tfhe::shortint::ClientKey::new(parameters))
    }

    pub fn into_raw_parts(self) -> (GlweSecretKeyOwned<u64>, LweSecretKeyOwned<u64>, PBSParameters) {
        let standard = match self.0.atomic_pattern {
            AtomicPatternClientKey::Standard(key) => key,
            _ => panic!("PFKS port requires the actual Standard client key"),
        };
        let (glwe, small, parameters, wopbs) = standard.into_raw_parts();
        assert!(wopbs.is_none(), "no WOPBS parameter substitution");
        (glwe, small, parameters)
    }
}

#[derive(Clone)]
pub enum ShortintBootstrappingKey {
    Classic(FourierLweBootstrapKeyOwned),
}

#[derive(Clone)]
pub struct ServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    pub pbs_order: PBSOrder,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl ServerKey {
    pub fn new(client: &ClientKey) -> Self {
        let native = tfhe::shortint::ServerKey::new(&client.0);
        let standard = match native.atomic_pattern {
            AtomicPatternServerKey::Standard(key) => key,
            _ => panic!("PFKS port requires the actual Standard server key"),
        };
        let bsk = match standard.bootstrapping_key {
            NativeBsk::Classic { bsk, modulus_switch_noise_reduction_key } => {
                assert!(matches!(modulus_switch_noise_reduction_key, ModulusSwitchConfiguration::Standard),
                        "PFKS same-parameter port refuses non-Standard modulus switching");
                bsk
            }
            _ => panic!("PFKS port requires the actual Classic bootstrap key"),
        };
        Self {
            key_switching_key: standard.key_switching_key,
            bootstrapping_key: ShortintBootstrappingKey::Classic(bsk),
            pbs_order: standard.pbs_order,
            message_modulus: native.message_modulus,
            carry_modulus: native.carry_modulus,
            max_degree: native.max_degree,
            max_noise_level: native.max_noise_level,
            ciphertext_modulus: native.ciphertext_modulus,
        }
    }
}

/// Restore the removed convenience API using the actual1.7 standard integer rounding.
pub fn pbs_modulus_switch<Scalar: UnsignedInteger + CastInto<usize>>(
    input: Scalar,
    polynomial_size: PolynomialSize,
) -> usize {
    tfhe::core_crypto::fft_impl::common::modulus_switch(
        input, polynomial_size.to_blind_rotation_input_modulus_log(),
    ).cast_into()
}

/// 1.7 takes an explicitly modulus-switched LWE; the admitted key is Standard only.
pub fn blind_rotate_assign(
    input: &LweCiphertextOwned<u64>,
    accumulator: &mut GlweCiphertextOwned<u64>,
    bsk: &FourierLweBootstrapKeyOwned,
) {
    let switched = ModulusSwitchConfiguration::<u64>::Standard
        .lwe_ciphertext_modulus_switch::<usize, _>(
            input, bsk.polynomial_size().to_blind_rotation_input_modulus_log(),
        );
    tfhe::core_crypto::algorithms::blind_rotate_assign(&switched, accumulator, bsk);
}
