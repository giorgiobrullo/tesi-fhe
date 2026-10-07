#![recursion_limit = "256"]
//! Isolated A145: packed score -> two nibble adapters -> actual A34 -> A135 masks.
//! No secret key or plaintext score enters the server evaluator. Outputs/traces are local
//! diagnostics, not a service response. This file has not been typechecked or run as FHE.
use serde_json::json;
use sha2::{Digest, Sha256};
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;
include!("a34_tables.rs");
mod coefficient_observer;

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

struct Event {
    name: String,
    input: Lwe,
    switched: Lwe,
    output: Lwe,
    body: Vec<u64>,
}
struct Backend<'a> {
    server: &'a ServerKey,
    events: Vec<Event>,
}
impl<'a> Backend<'a> {
    fn bsk(&self) -> &FourierLweBootstrapKeyOwned {
        match &self.server.bootstrapping_key {
            ShortintBootstrappingKey::Classic(bsk) => bsk,
            _ => panic!("A145 requires the classic A44 key"),
        }
    }
    fn body_pbs(&mut self, input: &Lwe, body: Vec<u64>, name: String) -> Lwe {
        let bsk = self.bsk();
        let modulus = CiphertextModulus::new_native();
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            bsk.glwe_size(),
            &PlaintextList::from_container(body.clone()),
            modulus,
        );
        let mut switched =
            LweCiphertext::new(0, self.server.key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(&self.server.key_switching_key, input, &mut switched);
        let mut out = LweCiphertext::new(0, input.lwe_size(), modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut out, &accumulator, bsk);
        self.events.push(Event {
            name,
            input: input.clone(),
            switched,
            output: out.clone(),
            body,
        });
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
    fn nibble(&mut self, input: &Lwe, independent: bool, prefix: &str) -> Lwe {
        // Input d*Delta60 on full torus. Half-digit center avoids the sign edge.
        let centered = offset(input, 1 << 59);
        let msb_small = self.msb(&centered, 54, format!("{prefix}.msb54"));
        let fold = if independent {
            self.msb(&centered, 63, format!("{prefix}.msb63_independent_scale"))
        } else {
            scale(&msb_small, 512)
        };
        let remainder = sub(input, &fold);
        let low = self.table(
            &remainder,
            (0..8).map(|r| r << 51).collect(),
            format!("{prefix}.low3"),
        );
        add(&low, &msb_small)
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
    fn round(
        &mut self,
        active: &[Lwe],
        digits: &[Lwe],
        name: &str,
        active_log: u32,
        valid_log: u32,
        output_log: u32,
    ) -> Vec<Lwe> {
        assert!([active_log, valid_log, output_log]
            .iter()
            .all(|x| [59, 63].contains(x)));
        let valid_half = 1u64 << (valid_log - 1);
        let output_half = 1u64 << (output_log - 1);
        assert_eq!(active.len(), digits.len());
        assert!((1..=128).contains(&active.len()));
        let before = self.events.len();
        let masked: Vec<_> = active
            .iter()
            .zip(digits)
            .enumerate()
            .map(|(i, (a, d))| {
                let input = add(&scale(d, 256), &scale(a, 1u64 << (63 - active_log)));
                let signed = self.table(
                    &input,
                    (0..16).map(|v| (16 - v) << 51).collect(),
                    format!("{name}.mask/{i}"),
                );
                offset(&add(&signed, d), 16 << 51)
            })
            .collect();
        let mut layer = masked.clone();
        let mut log = 52u32;
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| {
                    if pair.len() == 1 {
                        scale(&pair[0], 2)
                    } else {
                        let input = scale(&sub(&pair[0], &pair[1]), 1 << (59 - log));
                        let abs = self.table(
                            &input,
                            (0u64..16)
                                .map(|v| v.wrapping_sub(8).wrapping_shl(log))
                                .collect(),
                            format!("{name}.minimum/{log}/{i}"),
                        );
                        offset(
                            &sub(&add(&pair[0], &pair[1]), &abs),
                            (8u64 << log).wrapping_neg(),
                        )
                    }
                })
                .collect();
            log += 1;
        }
        let minimum = scale(&layer[0], 1 << (59 - log));
        let signed_valid = self.table(&minimum, vec![valid_half; 16], format!("{name}.valid"));
        let valid = offset(&signed_valid, valid_half);
        let outputs = masked
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let input = add(
                    &sub(&scale(q, 128), &minimum),
                    &scale(&valid, 1u64 << (63 - valid_log)),
                );
                let values = (0..16)
                    .map(|v| {
                        if v == 0 {
                            output_half.wrapping_neg()
                        } else {
                            output_half
                        }
                    })
                    .collect();
                let signed = self.table(&input, values, format!("{name}.update/{i}"));
                offset(&signed, output_half)
            })
            .collect();
        assert_eq!(self.events.len() - before, 3 * active.len());
        outputs
    }
}

#[derive(Clone, Copy)]
struct Arm {
    name: &'static str,
    independent: bool,
    padding: bool,
    wrong_final: bool,
    wrong_scale: bool,
}
const ARMS: [Arm; 6] = [
    Arm {
        name: "canonical_shared",
        independent: false,
        padding: false,
        wrong_final: false,
        wrong_scale: false,
    },
    Arm {
        name: "canonical_separate",
        independent: true,
        padding: false,
        wrong_final: false,
        wrong_scale: false,
    },
    Arm {
        name: "padding_shared",
        independent: false,
        padding: true,
        wrong_final: false,
        wrong_scale: false,
    },
    Arm {
        name: "padding_separate",
        independent: true,
        padding: true,
        wrong_final: false,
        wrong_scale: false,
    },
    Arm {
        name: "negative_final_delta63",
        independent: false,
        padding: true,
        wrong_final: true,
        wrong_scale: false,
    },
    Arm {
        name: "negative_digit_scale",
        independent: false,
        padding: true,
        wrong_final: false,
        wrong_scale: true,
    },
];

struct Evaluation {
    low: Vec<Lwe>,
    middle: Vec<Lwe>,
    top: Vec<Lwe>,
    flags: Vec<Lwe>,
    events: Vec<Event>,
}
fn evaluate(full: &[Lwe], packed_low: &[Lwe], server: &ServerKey, arm: Arm) -> Evaluation {
    let independent = arm.independent;
    let wrong_scale = arm.wrong_scale;
    let flag_log = if arm.padding { 63 } else { 59 };
    let final_log = if arm.wrong_final { 63 } else { 59 };
    let mut backend = Backend {
        server,
        events: Vec::new(),
    };
    let mut low = Vec::new();
    let mut middle = Vec::new();
    let mut top = Vec::new();
    for (i, (f, l)) in full.iter().zip(packed_low).enumerate() {
        let d0 = backend.nibble(l, independent, &format!("ingress/{i}/low"));
        let residual = sub(f, &scale(&d0, 2));
        let d1 = backend.nibble(
            &scale(&residual, 16),
            independent,
            &format!("ingress/{i}/middle"),
        );
        top.push(sub(&residual, &scale(&d1, 32)));
        low.push(d0);
        middle.push(d1);
    }
    let active = backend.initial(&top, flag_log);
    let middle_for_consumer: Vec<_> = middle
        .iter()
        .map(|x| scale(x, if wrong_scale { 2 } else { 1 }))
        .collect();
    let low_for_consumer: Vec<_> = low
        .iter()
        .map(|x| scale(x, if wrong_scale { 2 } else { 1 }))
        .collect();
    let active = backend.round(
        &active,
        &middle_for_consumer,
        "middle_round",
        flag_log,
        flag_log,
        flag_log,
    );
    let flags = backend.round(
        &active,
        &low_for_consumer,
        "low_round",
        flag_log,
        flag_log,
        final_log,
    );
    assert_eq!(
        backend.events.len(),
        (if independent { 16 } else { 14 }) * full.len() - 1
    );
    Evaluation {
        low,
        middle,
        top,
        flags,
        events: backend.events,
    }
}

mod precision;
include!("gate.rs");
