//! Reusable Standard/A44 nibble endpoint. Only the parallel evaluator is timed.
use crate::{
    integration_scan_flags, integration_score_prefix, plan_private_argmin_execution, TemplateView,
};
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey};
use tfhe::shortint::ServerKey;
pub type Lwe = LweCiphertextOwned<u64>;
pub type Glwe = GlweCiphertextOwned<u64>;
include!("a34_tables.rs");

fn scale(input: &Lwe, factor: u64) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_cleartext_mul_assign(&mut out, Cleartext(factor));
    out
}
fn add(input: &Lwe, other: &Lwe) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_add_assign(&mut out, other);
    out
}
fn sub(input: &Lwe, other: &Lwe) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_sub_assign(&mut out, other);
    out
}
fn offset(input: &Lwe, value: u64) -> Lwe {
    let mut out = input.clone();
    lwe_ciphertext_plaintext_add_assign(&mut out, Plaintext(value));
    out
}
fn digest(input: &Lwe) -> String {
    let mut hash = Sha256::new();
    for x in input.as_ref() {
        hash.update(x.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}
fn switch_word(x: u64) -> u64 {
    x.wrapping_add(1 << 51) >> 52
}

pub struct Event {
    pub name: String,
    pub input: Lwe,
    pub switched: Lwe,
    pub output: Lwe,
    pub body: Vec<u64>,
}
struct Backend<'a> {
    server: &'a ServerKey,
    events: Vec<Event>,
    capture_trace: bool,
    calls: usize,
}
impl<'a> Backend<'a> {
    fn key_parts(&self) -> (&LweKeyswitchKeyOwned<u64>, &FourierLweBootstrapKeyOwned) {
        match &self.server.atomic_pattern {
            AtomicPatternServerKey::Standard(key) => match &key.bootstrapping_key {
                ShortintBootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                } => {
                    assert!(matches!(
                        modulus_switch_noise_reduction_key,
                        ModulusSwitchConfiguration::Standard
                    ));
                    (&key.key_switching_key, bsk)
                }
                _ => panic!("fixed classic Standard profile required"),
            },
            _ => panic!("fixed Standard atomic pattern required"),
        }
    }
    fn bsk(&self) -> &FourierLweBootstrapKeyOwned {
        self.key_parts().1
    }
    fn body_pbs(&mut self, input: &Lwe, body: Vec<u64>, name: String) -> Lwe {
        let bsk = self.bsk();
        let modulus = CiphertextModulus::new_native();
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            bsk.glwe_size(),
            &PlaintextList::from_container(body.clone()),
            modulus,
        );
        let mut switched = LweCiphertext::new(0, self.key_parts().0.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(self.key_parts().0, input, &mut switched);
        let mut out = LweCiphertext::new(0, input.lwe_size(), modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut out, &accumulator, bsk);
        self.calls += 1;
        if self.capture_trace {
            self.events.push(Event {
                name,
                input: input.clone(),
                switched,
                output: out.clone(),
                body,
            });
        }
        out
    }
    fn table(&mut self, input: &Lwe, values: Vec<u64>, name: String) -> Lwe {
        let n = self.bsk().polynomial_size().0;
        assert!(values.len().is_power_of_two() && n % values.len() == 0);
        let box_size = n / values.len();
        // Literal public stock helper, allowing already-scaled wrapping words.
        let mut body: Vec<u64> = values.iter().flat_map(|x| vec![*x; box_size]).collect();
        for x in &mut body[..box_size / 2] {
            *x = x.wrapping_neg();
        }
        body.rotate_left(box_size / 2);
        self.body_pbs(input, body, name)
    }
    fn msb(&mut self, centered: &Lwe, output_log: u32, name: String) -> Lwe {
        let alpha = 1u64 << (output_log - 1);
        let raw = self.body_pbs(centered, vec![alpha.wrapping_neg(); 2048], name);
        offset(&raw, alpha)
    }
    fn initial(&mut self, tops: &[Lwe], flag_log: u32) -> Vec<Lwe> {
        assert!([59, 63].contains(&flag_log));
        let codes: Vec<_> = tops
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    x,
                    (0..16)
                        .map(|v| a34_top_classifier_slot_lut(v) << 59)
                        .collect(),
                    format!("a34.classify/{i}"),
                )
            })
            .collect();
        let mut layer: Vec<_> = codes
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(x, 4 << 59),
                    (0..16)
                        .map(|v| a34_canonical_category_lut(v) << 59)
                        .collect(),
                    format!("a34.canonical/{i}"),
                )
            })
            .collect();
        let mut depth = 0;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    if pair.len() == 1 {
                        pair[0].clone()
                    } else {
                        self.table(
                            &add(&pair[0], &pair[1]),
                            (0..16).map(|v| a34_pair_category_lut(v) << 59).collect(),
                            format!("a34.reduce/{depth}/{i}"),
                        )
                    }
                })
                .collect();
            depth += 1;
        }
        codes
            .iter()
            .enumerate()
            .map(|(i, x)| {
                self.table(
                    &offset(&add(x, &layer[0]), 4 << 59),
                    (0..16)
                        .map(|v| a34_top_candidate_lut(v) << flag_log)
                        .collect(),
                    format!("a34.candidate/{i}"),
                )
            })
            .collect()
    }
}
pub struct Evaluation {
    pub low: Vec<Lwe>,
    pub middle: Vec<Lwe>,
    pub top: Vec<Lwe>,
    pub flags: Vec<Lwe>,
    pub events: Vec<Event>,
    pub calls: usize,
}

#[path = "parallel.rs"]
mod parallel;
#[path = "precision.rs"]
pub mod precision;

pub struct IntegratedOutput {
    pub low_digit: Lwe,
    pub high_digit: Lwe,
    pub br: usize,
    pub ks: usize,
    pub pbs_samples: usize,
}
/// Retained state belongs only to a correctness caller, never to the service output.
pub struct DiagnosticOutput {
    pub endpoint: IntegratedOutput,
    pub state: precision::Output,
    pub full: Vec<Lwe>,
    pub packed_low: Vec<Lwe>,
}
fn checked_domain(templates: &[TemplateView<'_>]) -> Result<crate::ScoreDomain, String> {
    if ![4usize, 16, 127, 128].contains(&templates.len()) {
        return Err("supported gallery sizes are 4, 16, 127, 128".into());
    }
    let plan = plan_private_argmin_execution(templates).map_err(|e| format!("{e:?}"))?;
    if !plan.aligned_fast_path {
        return Err("uniform aligned threshold required".into());
    }
    Ok(plan.execution_domain)
}
/// Full actual encrypted packed-query -> two encrypted base15 ID digits.
/// No key generation, plaintext oracle, trace, timer or thread-pool construction.
/// The caller's Rayon pool determines scheduling. Unsupported/alignment inputs refuse before crypto.
pub fn parallel_nibble_id(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
) -> Result<IntegratedOutput, String> {
    let domain = checked_domain(templates)?;
    let (full, packed_low) = integration_score_prefix(server, packed, templates, domain)
        .map_err(|e| format!("{e:?}"))?;
    let state = parallel::evaluate(&full, &packed_low, server, false);
    // Move the only consumed vectors out; diagnostic intermediates are dropped before scan.
    let precision::Output {
        evaluation:
            Evaluation {
                flags,
                calls,
                events,
                ..
            },
        ..
    } = state;
    assert!(events.is_empty());
    let (low_digit, high_digit, expected, observed) =
        integration_scan_flags(server, &flags).map_err(|e| format!("{e:?}"))?;
    assert_eq!(expected, observed);
    Ok(IntegratedOutput {
        low_digit,
        high_digit,
        br: calls + observed.blind_rotations as usize,
        ks: calls + observed.key_switches as usize,
        pbs_samples: calls + observed.output_marginals as usize,
    })
}
pub fn parallel_diagnostic(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
) -> Result<DiagnosticOutput, String> {
    let domain = checked_domain(templates)?;
    let (full, packed_low) = integration_score_prefix(server, packed, templates, domain)
        .map_err(|e| format!("{e:?}"))?;
    let state = parallel::evaluate(&full, &packed_low, server, false);
    assert!(state.evaluation.events.is_empty());
    let (low_digit, high_digit, expected, observed) =
        integration_scan_flags(server, &state.evaluation.flags).map_err(|e| format!("{e:?}"))?;
    assert_eq!(expected, observed);
    let endpoint = IntegratedOutput {
        low_digit,
        high_digit,
        br: state.evaluation.calls + observed.blind_rotations as usize,
        ks: state.evaluation.calls + observed.key_switches as usize,
        pbs_samples: state.evaluation.calls + observed.output_marginals as usize,
    };
    Ok(DiagnosticOutput {
        endpoint,
        state,
        full,
        packed_low,
    })
}
/// Same retained prefix, exact original R2 serial graph; correctness only.
pub fn serial_reference(
    full: &[Lwe],
    packed_low: &[Lwe],
    server: &ServerKey,
    wrong_scale: bool,
    trace: bool,
) -> precision::Output {
    precision::evaluate_with_trace(full, packed_low, server, wrong_scale, trace)
}

// Append-only complete controls on the shared Delta51/60 prototype wire.
pub fn prototype_parallel_nibble_id(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
) -> Result<IntegratedOutput, String> {
    let domain = checked_domain(templates)?;
    let (full, packed_low) = crate::prototype_score_prefix(server, packed, templates, domain)
        .map_err(|e| format!("{e:?}"))?;
    let state = parallel::evaluate(&full, &packed_low, server, false);
    // Move the only consumed vectors out; diagnostic intermediates are dropped before scan.
    let precision::Output {
        evaluation:
            Evaluation {
                flags,
                calls,
                events,
                ..
            },
        ..
    } = state;
    assert!(events.is_empty());
    let (low_digit, high_digit, expected, observed) =
        integration_scan_flags(server, &flags).map_err(|e| format!("{e:?}"))?;
    assert_eq!(expected, observed);
    Ok(IntegratedOutput {
        low_digit,
        high_digit,
        br: calls + observed.blind_rotations as usize,
        ks: calls + observed.key_switches as usize,
        pbs_samples: calls + observed.output_marginals as usize,
    })
}
pub fn prototype_parallel_diagnostic(
    server: &ServerKey,
    packed: &Glwe,
    templates: &[TemplateView<'_>],
) -> Result<DiagnosticOutput, String> {
    let domain = checked_domain(templates)?;
    let (full, packed_low) = crate::prototype_score_prefix(server, packed, templates, domain)
        .map_err(|e| format!("{e:?}"))?;
    let state = parallel::evaluate(&full, &packed_low, server, false);
    assert!(state.evaluation.events.is_empty());
    let (low_digit, high_digit, expected, observed) =
        integration_scan_flags(server, &state.evaluation.flags).map_err(|e| format!("{e:?}"))?;
    assert_eq!(expected, observed);
    let endpoint = IntegratedOutput {
        low_digit,
        high_digit,
        br: state.evaluation.calls + observed.blind_rotations as usize,
        ks: state.evaluation.calls + observed.key_switches as usize,
        pbs_samples: state.evaluation.calls + observed.output_marginals as usize,
    };
    Ok(DiagnosticOutput {
        endpoint,
        state,
        full,
        packed_low,
    })
}
