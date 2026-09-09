//! Shared Head key bundle with uniform and winner-specific threshold endpoints.
use super::*;
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::fft_impl::fft64::math::fft::Fft;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::server_key::{
    ModulusSwitchConfiguration, ShortintBootstrappingKey as NativeBsk,
};

#[path = "head_key.rs"]
pub mod head_key;
pub use super::general::{ThresholdMode, UniformExecutionPlan};
pub use super::mixed_plan::{ExecutionMode, ExecutionPlan};
pub use super::private_argmin::{PrivateArgminExecutionPlan, ScoreDomain, TemplateView};
pub use head_key::MAX_HEAD_BUNDLE_BYTES;

// Keep the original three fields first so the missing-Head diagnostic is a real truncation.
#[derive(Serialize, Deserialize)]
pub struct ServerBundle {
    ordinary: tfhe::shortint::ServerKey,
    window: LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    window_function_sha256: String,
    head: FourierLweBootstrapKeyOwned,
}

pub struct EvaluationKeys {
    ordinary: tfhe::shortint::ServerKey,
    adapter: ServerKey,
    window: LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    head: FourierLweBootstrapKeyOwned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub br: u64,
    pub ks: u64,
    pub marginals: u64,
    pub pfks: u64,
    pub initial_samples: u64,
}

// Bundle geometry stays fixed; only the bounded benchmark selector arm changes at runtime.
pub const N127_COUNTS: Counts = super::service_selected::N127_COUNTS;
pub const MAX_GALLERY_SIZE: usize = super::general::MAX_GALLERY_SIZE;
pub const ID_DIGITS: usize = 3;
pub const ID_BASE: u64 = 15;
pub const ID_CONTRACT: &str = "head-pfks-split333-b22-mean-three-id-winner-threshold.v1";

/// Structural work for a size and terminal mode; this does not admit templates or validate noise.
pub fn operation_counts(n: usize, mode: ExecutionMode) -> Option<Counts> {
    let mut counts = super::smallcuts::operation_counts(n, mode, super::smallcuts::mode())?;
    counts.br -= counts.initial_samples * super::shared_normalizers::mode().saved_br_per_score();
    Some(counts)
}

/// Derive the mode from actual templates, retaining the complete parent uniform plan.
pub fn plan(templates: &[TemplateView<'_>]) -> Result<ExecutionPlan, String> {
    super::mixed_plan::plan(templates)
}
pub const WINDOW_PAYLOAD_BYTES: usize = 67_141_632;
pub const ORDINARY_ADAPTER_PAYLOAD_BYTES: usize = 126_746_624;
pub const BUNDLE_CONTAINER_PAYLOAD_BYTES: usize = 306_479_104;
pub const EVALUATION_CONTAINER_PAYLOAD_BYTES: usize =
    BUNDLE_CONTAINER_PAYLOAD_BYTES + ORDINARY_ADAPTER_PAYLOAD_BYTES;

/// Check the complete serialized envelope before writing/uploading or deserializing it.
/// Container payload constants exclude serialization framing and are not RSS measurements.
pub fn validate_serialized_bundle_size(bytes: usize) -> Result<(), String> {
    if bytes == 0 || bytes > MAX_HEAD_BUNDLE_BYTES {
        return Err("serialized Head bundle exceeds the fixed 320MiB boundary or is empty".into());
    }
    Ok(())
}

fn selected_window_function() -> Result<Poly, String> {
    if !matches!(super::service_selected::PFKS_BASE_LOG, 22 | 24) {
        return Err("selected PFKS base must be the bound 22 or 24 finalist".into());
    }
    let function = super::service_selected::window_function();
    if function.polynomial_size().0 != 2048 {
        return Err("selected PFKS function must contain exactly 2048 coefficients".into());
    }
    Ok(function)
}

fn validate_window(
    window: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
) -> Result<(), String> {
    if window.decomposition_base_log().0 != super::service_selected::PFKS_BASE_LOG
        || window.decomposition_level_count().0 != 1
    {
        return Err("PFKS window decomposition differs from the selected circuit".into());
    }
    if !window.ciphertext_modulus().is_native_modulus()
        || window.input_key_lwe_dimension().0 != 2048
        || window.output_glwe_size().0 != 2
        || window.output_polynomial_size().0 != 2048
        || std::mem::size_of_val(window.as_ref()) != WINDOW_PAYLOAD_BYTES
    {
        return Err("PFKS window geometry differs from the fixed native profile".into());
    }
    Ok(())
}

fn validate_selected_function(declared: &str) -> Result<(), String> {
    let expected = observer::hash_words(selected_window_function()?.as_ref());
    if declared != expected {
        return Err("PFKS declared window function differs from the bound circuit".into());
    }
    Ok(())
}

// The same native-key clone used by the paired timing source. No key regeneration.
fn adapter(native: &tfhe::shortint::ServerKey) -> Result<ServerKey, String> {
    let standard = match &native.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => return Err("Standard native server key required".into()),
    };
    let bsk = match &standard.bootstrapping_key {
        NativeBsk::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => {
            if !matches!(
                modulus_switch_noise_reduction_key,
                ModulusSwitchConfiguration::Standard
            ) {
                return Err("Standard modulus switching required".into());
            }
            bsk
        }
        _ => return Err("Classic native bootstrap key required".into()),
    };
    if standard.key_switching_key.as_ref().len() != 8_806_400
        || !standard
            .key_switching_key
            .ciphertext_modulus()
            .is_native_modulus()
        || bsk.as_view().data().len() != 3_518_464
        || bsk
            .as_view()
            .data()
            .iter()
            .any(|value| !value.re.is_finite() || !value.im.is_finite())
    {
        return Err("ordinary key container length, modulus or Fourier values differ from the fixed profile".into());
    }
    let cloned = ServerKey {
        key_switching_key: standard.key_switching_key.clone(),
        bootstrapping_key: ShortintBootstrappingKey::Classic(bsk.clone()),
        pbs_order: standard.pbs_order,
        message_modulus: native.message_modulus,
        carry_modulus: native.carry_modulus,
        max_degree: native.max_degree,
        max_noise_level: native.max_noise_level,
        ciphertext_modulus: native.ciphertext_modulus,
    };
    private_argmin::validate_a44_parameter_binding(private_argmin::A44_PARAMETER_BINDING, &cloned)
        .map_err(|error| format!("ordinary A44 parameter binding: {error:?}"))?;
    let ShortintBootstrappingKey::Classic(cloned_bsk) = &cloned.bootstrapping_key;
    let equal = cloned.key_switching_key.as_ref() == standard.key_switching_key.as_ref()
        && cloned_bsk.as_view().data().len() == bsk.as_view().data().len()
        && cloned_bsk
            .as_view()
            .data()
            .iter()
            .zip(bsk.as_view().data())
            .all(|(a, b)| a.re.to_bits() == b.re.to_bits() && a.im.to_bits() == b.im.to_bits());
    if !equal {
        return Err("ordinary adapter bytes differ".into());
    }
    Ok(cloned)
}

/// Client-only generation; ordinary must come from this same client, as in the original CLI.
/// The bundle contains evaluation keys only. Public geometry does not attest secret membership.
pub fn generate_bundle(
    client: &tfhe::shortint::ClientKey,
    ordinary: tfhe::shortint::ServerKey,
) -> Result<ServerBundle, String> {
    let (glwe, small, params, wopbs) = match client.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return Err("Standard client family required".into()),
    };
    let expected: tfhe::shortint::PBSParameters =
        V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64.into();
    if params != expected
        || wopbs.is_some()
        || glwe.glwe_dimension().0 != 1
        || glwe.polynomial_size().0 != 2048
        || small.lwe_dimension().0 != 859
    {
        return Err("client profile differs from the fixed A44 family".into());
    }
    let function = selected_window_function()?;
    let big = glwe.as_lwe_secret_key();
    let mut window = LwePrivateFunctionalPackingKeyswitchKey::new(
        0u64,
        DecompositionBaseLog(super::service_selected::PFKS_BASE_LOG),
        DecompositionLevelCount(1),
        big.lwe_dimension(),
        GlweSize(2),
        PolynomialSize(2048),
        CiphertextModulus::new_native(),
    );
    let mut boxed = new_seeder();
    let seeder = boxed.as_mut();
    let mut generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &big,
        &glwe,
        &mut window,
        params.glwe_noise_distribution(),
        &mut generator,
        |v| v,
        &function,
    );
    validate_window(&window)?;
    let standard_head = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small,
        &glwe,
        DecompositionBaseLog(15),
        DecompositionLevelCount(2),
        params.glwe_noise_distribution(),
        CiphertextModulus::new_native(),
        &mut generator,
    );
    let mut head = FourierLweBootstrapKey::new(
        standard_head.input_lwe_dimension(),
        standard_head.glwe_size(),
        standard_head.polynomial_size(),
        standard_head.decomposition_base_log(),
        standard_head.decomposition_level_count(),
    );
    head.as_mut_view().par_fill_with_forward_fourier(
        standard_head.as_view(),
        Fft::new(PolynomialSize(2048)).as_view(),
    );
    drop(standard_head);
    head_key::validate_head(&head)?;
    Ok(ServerBundle {
        ordinary,
        window,
        window_function_sha256: observer::hash_words(function.as_ref()),
        head,
    })
}

impl ServerBundle {
    /// One malformed payload from a consumed valid bundle; no key generation or encryption.
    /// The caller retains the original file and binds this payload to its requested diagnostic.
    pub fn diagnostic_payload(mut self, name: &str) -> Result<Vec<u8>, String> {
        validate_window(&self.window)?;
        validate_selected_function(&self.window_function_sha256)?;
        head_key::validate_head(&self.head)?;
        match name {
            "missing_head_key" => {
                return bincode::serialize(&(
                    self.ordinary,
                    self.window,
                    self.window_function_sha256,
                ))
                .map_err(|error| format!("serialize missing-Head diagnostic: {error}"));
            }
            "wrong_head_dimensions" => {
                let mut head = FourierLweBootstrapKey::new(
                    LweDimension(858),
                    GlweSize(2),
                    PolynomialSize(2048),
                    DecompositionBaseLog(15),
                    DecompositionLevelCount(2),
                );
                let word_count = head.as_view().data().len();
                head.as_mut_view()
                    .data()
                    .copy_from_slice(&self.head.as_view().data()[..word_count]);
                self.head = head;
            }
            "wrong_head_decomposition" => {
                self.head = FourierLweBootstrapKey::from_container(
                    self.head.data(),
                    LweDimension(859),
                    GlweSize(2),
                    PolynomialSize(2048),
                    DecompositionBaseLog(14),
                    DecompositionLevelCount(2),
                );
            }
            "nonfinite_head_fourier_word" => {
                self.head.as_mut_view().data()[0].re = f64::NAN;
            }
            "wrong_selected_pfks_base" => {
                let wrong_base = match super::service_selected::PFKS_BASE_LOG {
                    22 => 24,
                    24 => 22,
                    _ => return Err("unbound PFKS diagnostic base".into()),
                };
                self.window = LwePrivateFunctionalPackingKeyswitchKey::from_container(
                    self.window.into_container(),
                    DecompositionBaseLog(wrong_base),
                    DecompositionLevelCount(1),
                    GlweSize(2),
                    PolynomialSize(2048),
                    CiphertextModulus::new_native(),
                );
            }
            "wrong_selected_pfks_function" => {
                let replacement = if self.window_function_sha256.starts_with('0') {
                    "1"
                } else {
                    "0"
                };
                self.window_function_sha256.replace_range(..1, replacement);
            }
            _ => return Err("unknown Head bundle diagnostic".into()),
        }
        bincode::serialize(&self)
            .map_err(|error| format!("serialize Head bundle diagnostic: {error}"))
    }
}

impl EvaluationKeys {
    pub fn from_bundle(bundle: ServerBundle) -> Result<Self, String> {
        validate_window(&bundle.window)?;
        validate_selected_function(&bundle.window_function_sha256)?;
        head_key::validate_head(&bundle.head)?;
        let adapter = adapter(&bundle.ordinary)?;
        let ShortintBootstrappingKey::Classic(bsk) = &adapter.bootstrapping_key;
        let ordinary_bytes = std::mem::size_of_val(adapter.key_switching_key.as_ref())
            + std::mem::size_of_val(bsk.as_view().data());
        let bundle_bytes = ordinary_bytes
            + std::mem::size_of_val(bundle.window.as_ref())
            + std::mem::size_of_val(bundle.head.as_view().data());
        if ordinary_bytes != ORDINARY_ADAPTER_PAYLOAD_BYTES
            || bundle_bytes != BUNDLE_CONTAINER_PAYLOAD_BYTES
        {
            return Err(
                "Head evaluation-key container payload differs from the bound profile".into(),
            );
        }
        Ok(Self {
            ordinary: bundle.ordinary,
            adapter,
            window: bundle.window,
            head: bundle.head,
        })
    }

    pub fn ordinary(&self) -> &tfhe::shortint::ServerKey {
        &self.ordinary
    }

    pub fn evaluate(
        &self,
        packed: &Glwe,
        templates: &[TemplateView<'_>],
        domain: ScoreDomain,
    ) -> Result<(Lwe, Lwe, Lwe, Counts), String> {
        self.evaluate_with_parallel(packed, templates, domain, true, false)
    }

    /// Same arithmetic and indexed order, with serial template, Head and tree scheduling.
    /// This is useful for ciphertext-equality checks outside a timed parallel evaluation.
    pub fn evaluate_serial(
        &self,
        packed: &Glwe,
        templates: &[TemplateView<'_>],
        domain: ScoreDomain,
    ) -> Result<(Lwe, Lwe, Lwe, Counts), String> {
        self.evaluate_with_parallel(packed, templates, domain, false, false)
    }

    /// Experimental public-threshold specialization; no process-wide selector.
    /// Uniform mode runs the original endpoint without a threshold-plan build.
    pub fn evaluate_public_thresholds(
        &self,
        packed: &Glwe,
        templates: &[TemplateView<'_>],
        domain: ScoreDomain,
        parallel: bool,
    ) -> Result<(Lwe, Lwe, Lwe, Counts), String> {
        self.evaluate_with_parallel(packed, templates, domain, parallel, true)
    }

    fn evaluate_with_parallel(
        &self,
        packed: &Glwe,
        templates: &[TemplateView<'_>],
        domain: ScoreDomain,
        parallel: bool,
        specialize_thresholds: bool,
    ) -> Result<(Lwe, Lwe, Lwe, Counts), String> {
        let profile_started = super::smallcuts::begin_profile(templates.len(), parallel);
        request::validate(packed, templates, domain)?;
        let plan = plan(templates)?;
        let threshold_plan =
            if specialize_thresholds && plan.mode == ExecutionMode::MixedWinnerThreshold {
                Some(super::public_thresholds::plan_in_domain(
                    templates,
                    plan.execution_domain,
                )?)
            } else {
                None
            };
        let expected = operation_counts(templates.len(), plan.mode)
            .ok_or("Head execution mode or gallery size is invalid")?;
        let expected = super::public_thresholds::adjust_public_counts(
            expected,
            threshold_plan
                .as_ref()
                .map_or(0, |plan| plan.omitted_threshold_selections),
        );
        let (low, middle, high, counts) = match plan.mode {
            ExecutionMode::Uniform(_) => super::service_selected::evaluate(
                &self.adapter,
                &self.head,
                &self.window,
                packed,
                templates,
                domain,
                parallel,
            )?,
            ExecutionMode::MixedWinnerThreshold => super::mixed::evaluate_with_public_thresholds(
                &self.adapter,
                &self.head,
                &self.window,
                packed,
                templates,
                domain,
                parallel,
                threshold_plan.as_ref(),
            )?,
        };
        if counts != expected {
            return Err("Head actual operation ledger differs from the selected circuit".into());
        }
        super::smallcuts::finish_profile(profile_started, &counts);
        Ok((low, middle, high, counts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_window_geometry_is_checked_before_use() {
        let selected = super::super::service_selected::PFKS_BASE_LOG;
        let other = if selected == 22 { 24 } else { 22 };
        for (base, levels, dimension, expected) in [
            (selected, 1, 2048, true),
            (other, 1, 2048, false),
            (12, 2, 2048, false),
            (selected, 1, 1024, false),
        ] {
            let window = LwePrivateFunctionalPackingKeyswitchKey::new(
                0u64,
                DecompositionBaseLog(base),
                DecompositionLevelCount(levels),
                LweDimension(dimension),
                GlweSize(2),
                PolynomialSize(2048),
                CiphertextModulus::new_native(),
            );
            assert_eq!(validate_window(&window).is_ok(), expected);
        }
    }

    #[test]
    fn complete_serialized_envelope_obeys_the_public_size_boundary() {
        for bytes in [0, MAX_HEAD_BUNDLE_BYTES + 1, usize::MAX] {
            assert!(validate_serialized_bundle_size(bytes).is_err());
        }
        for bytes in [1, BUNDLE_CONTAINER_PAYLOAD_BYTES, MAX_HEAD_BUNDLE_BYTES] {
            assert!(validate_serialized_bundle_size(bytes).is_ok());
        }
    }
}

/// Public request admission runs before the selected endpoint's first FHE operation.
pub mod request {
    include!("request_guard.rs");
}
