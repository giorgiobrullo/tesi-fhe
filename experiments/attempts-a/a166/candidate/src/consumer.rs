//! One consumer of the already returned Standard MS object. Client-local witnesses.
use crate::observe::*;
use sha2::{Digest, Sha256};
use std::path::Path;
use tfhe::core_crypto::prelude::*;

const ALPHA: u64 = 1u64 << 59;

#[derive(Default)]
pub struct Counts {
    pub ks: u64,
    pub ms: u64,
    pub br: u64,
}

impl Counts {
    fn record(&self) -> String {
        object(&[
            ("ordinary_ks", self.ks.to_string()),
            ("configured_ms", self.ms.to_string()),
            ("blind_rotations", self.br.to_string()),
        ])
    }
}

pub fn key_binding(bsk: &FourierLweBootstrapKeyOwned, p0: &str, p0_keyset: &str) -> String {
    // Hash existing public Fourier data; never serialize either client secret.
    // The ordering is the stored complex array, re then im, binary64 little endian.
    let mut h = Sha256::new();
    for value in bsk.as_view().data() {
        h.update(value.re.to_bits().to_le_bytes());
        h.update(value.im.to_bits().to_le_bytes());
    }
    let bsk_hash = format!("{:x}", h.finalize());
    let mut id = b"A166-KEYSET-V1\0".to_vec();
    id.extend(hex_bytes(p0_keyset));
    id.extend(hex_bytes(&bsk_hash));
    object(&[
        ("schema", text("a166.p1-key-binding.v1")),
        ("p0_bindings", p0.into()),
        ("fourier_bsk_re_im_f64le_sha256", text(&bsk_hash)),
        ("p1_keyset_id", text(&hash(&id))),
        ("secret_key_membership_attested", "false".into()),
    ])
}

fn switched_record(switched: &impl ModulusSwitchedLweCiphertext<usize>) -> String {
    object(&[
        ("log_modulus", switched.log_modulus().0.to_string()),
        ("body_degree", switched.body().to_string()),
        (
            "mask_degrees",
            array(&switched.mask().map(|x| x.to_string()).collect::<Vec<_>>()),
        ),
    ])
}

pub fn consume_p1<SecretCont: Container<Element = u64>>(
    directory: &Path,
    switched: &impl ModulusSwitchedLweCiphertext<usize>,
    bsk: &FourierLweBootstrapKeyOwned,
    big: &LweSecretKey<SecretCont>,
    p1_binding: &str,
    p0_trace: &str,
    p0_completed: &str,
    actual_address: usize,
    counts: &mut Counts,
) {
    assert_eq!((counts.ks, counts.ms, counts.br), (1, 1, 0));
    assert_eq!(switched.lwe_dimension(), bsk.input_lwe_dimension());
    assert_eq!(switched.log_modulus().0, 12);
    assert_eq!(big.lwe_dimension(), bsk.output_lwe_dimension());
    assert!(actual_address < 4096);
    let modulus = CiphertextModulus::new_native();
    let body = vec![0u64.wrapping_sub(ALPHA); 2048];
    let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        bsk.glwe_size(),
        &PlaintextList::from_container(body.clone()),
        modulus,
    );
    let before = switched_record(switched);
    let mut rotated = accumulator.clone();
    // This is the sole actual BR. `switched` is the same retained object from main;
    // this module contains no key switch or modulus-switch constructor.
    blind_rotate_assign(switched, &mut rotated, bsk);
    counts.br += 1;
    let after = switched_record(switched);
    let mut raw = LweCiphertext::new(0u64, LweSize(2049), modulus);
    extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut raw, MonomialDegree(0));
    let mut output = raw.clone();
    lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(ALPHA));

    // All client observations happen after this single server BR and extraction.
    let raw_phase = decrypt_lwe_ciphertext(big, &raw).0;
    let output_phase = decrypt_lwe_ciphertext(big, &output).0;
    let raw_dot = dot_mod(raw.get_mask().as_ref(), big.as_ref());
    let output_dot = dot_mod(output.get_mask().as_ref(), big.as_ref());
    // X^-address applied to the constant negative body gives -alpha on [0,N),
    // +alpha on [N,2N). This source LUT value uses the actual coefficientwise MS.
    let ideal_raw = if actual_address < 2048 {
        0u64.wrapping_sub(ALPHA)
    } else {
        ALPHA
    };
    let ideal_output = ideal_raw.wrapping_add(ALPHA);
    let raw_error = signed(raw_phase.wrapping_sub(ideal_raw));
    let output_error = signed(output_phase.wrapping_sub(1u64 << 60));
    let decoded = output_phase.wrapping_add(ALPHA) >> 60;
    let sample_ok = raw.get_body().data == &rotated.get_body().as_ref()[0]
        && raw.get_mask().as_ref().iter().enumerate().all(|(i, &x)| {
            x == if i == 0 {
                rotated.get_mask().as_ref()[0]
            } else {
                0u64.wrapping_sub(rotated.get_mask().as_ref()[2048 - i])
            }
        });
    let predicates = [
        ("p0_prefix_pass", actual_address >= 2048),
        ("retained_ms_input_unchanged", before == after),
        ("degree0_extraction_matches_rotated", sample_ok),
        (
            "output_only_public_add",
            output.get_mask().as_ref() == raw.get_mask().as_ref()
                && *output.get_body().data == raw.get_body().data.wrapping_add(ALPHA),
        ),
        (
            "raw_error_inside_actual_lut_decode_cell",
            -i128::from(ALPHA) <= raw_error && raw_error < i128::from(ALPHA),
        ),
        (
            "raw_to_output_phase_addition",
            output_phase == raw_phase.wrapping_add(ALPHA),
        ),
        ("output_decodes_fixture_bit", decoded == 1),
    ];
    let pass = predicates.iter().all(|(_, value)| *value);
    save(
        directory,
        "p1-trace.json",
        object(&[
            ("schema", text("a166.first_low_p1_trace.v1")),
            ("kind", text("client_observed")),
            ("bindings", p1_binding.into()),
            (
                "p0_snapshot",
                object(&[
                    ("schema", text("a166.frozen-p0-snapshot.v1")),
                    ("trace", p0_trace.into()),
                    ("completed", p0_completed.into()),
                ]),
            ),
            ("counts", counts.record()),
            (
                "counter_scope",
                text("producer post-call increments; not library-internal instrumentation"),
            ),
            (
                "consumed_input_origin",
                text("same retained Standard lazy-MS object; no second KS/MS"),
            ),
            ("switched_before", before),
            ("switched_after", after),
            ("accumulator_body_u64le_sha256", text(&words_hash(&body))),
            ("input_accumulator", ciphertext(accumulator.as_ref())),
            ("rotated_accumulator", ciphertext(rotated.as_ref())),
            ("raw_sample", ciphertext(raw.as_ref())),
            ("output", ciphertext(output.as_ref())),
            ("extraction_degree", "0".into()),
            ("public_output_add_words", ALPHA.to_string()),
            ("expected_fixture_bit", "1".into()),
            ("output_delta_words", (1u64 << 60).to_string()),
            ("actual_address", actual_address.to_string()),
            ("ideal_raw_at_actual_address_words", ideal_raw.to_string()),
            (
                "ideal_output_at_actual_address_words",
                ideal_output.to_string(),
            ),
            (
                "client",
                object(&[
                    ("raw_mask_dot_words", raw_dot.to_string()),
                    ("output_mask_dot_words", output_dot.to_string()),
                    ("raw_phase_words", raw_phase.to_string()),
                    ("output_phase_words", output_phase.to_string()),
                    ("raw_error_centered_lift", raw_error.to_string()),
                    (
                        "output_error_vs_fixture_centered_lift",
                        output_error.to_string(),
                    ),
                    ("decoded_delta60", decoded.to_string()),
                ]),
            ),
            (
                "predicates",
                object(
                    &predicates
                        .iter()
                        .map(|(key, value)| (*key, value.to_string()))
                        .collect::<Vec<_>>(),
                ),
            ),
            ("p1_selected_consumer_gate_pass", pass.to_string()),
            ("client_key_membership_attested", "false".into()),
            ("full_n4_evaluation", "false".into()),
            ("actual_sampler_p_fail", "null".into()),
            ("fixed_key_p_fail", "null".into()),
            ("pipeline_p_fail", "null".into()),
        ]),
    );
    assert_eq!((counts.ks, counts.ms, counts.br), (1, 1, 1));
    assert!(
        pass,
        "P1 consumer failed; preserve the new run and its P0 snapshot"
    );
    save(
        directory,
        "completed.json",
        object(&[
            ("status", text("P1_SINGLE_RETAINED_MS_CONSUMER_PASS")),
            ("ordinary_ks", counts.ks.to_string()),
            ("configured_ms", counts.ms.to_string()),
            ("blind_rotations", counts.br.to_string()),
            ("p0_prefix_pass", "true".into()),
            ("p1_selected_consumer_gate_pass", "true".into()),
            ("actual_sampler_p_fail", "null".into()),
            ("fixed_key_p_fail", "null".into()),
            ("pipeline_p_fail", "null".into()),
            ("independent_replay_pending", "true".into()),
        ]),
    );
}
