use super::*;

// All count-sensitive fixtures share process-global prototype flags. Initialize
// them exactly once before any fixture reads the selected composite ledger.
static TEST_RUNTIME: std::sync::Once = std::sync::Once::new();

pub(super) fn initialize_runtime() {
    TEST_RUNTIME.call_once(runtime::initialize);
    assert_eq!(pfks_core::shared_normalizers::mode(), pfks_core::shared_normalizers::Mode::Both);
    assert_eq!(pfks_core::smallcuts::mode(), pfks_core::smallcuts::Mode::Both);
    assert_eq!(pfks_core::public_digits::mode(), pfks_core::public_digits::Mode::Repack);
}

pub(super) fn rejected_wire_versions() -> Vec<u64> {
    assert_eq!(WIRE_VERSION, 9);
    (0..WIRE_VERSION).chain([WIRE_VERSION + 1, u64::MAX]).collect()
}

fn gallery(n: usize) -> Galleria {
    Galleria {
        dim: PROBE_DIM,
        t_default: 4,
        iscritti: (0..n)
            .map(|i| Entry::new(format!("public_{i}"), vec![0; PROBE_DIM], 4).unwrap())
            .collect(),
        chiave: None,
        chiave_sha256: None,
            g4_sha256: None,
        epoch: 123,
        revision: 7,
    }
}

#[test]
fn ciphertext_word_framing_rejects_truncation_and_extra_header_claims() {
    for bytes in [
        vec![],
        vec![0; 7],
        vec![0; 9],
        u64::MAX.to_le_bytes().to_vec(),
    ] {
        assert!(bytes_to_u64(&bytes).is_err());
    }
    let bytes = u64_to_bytes(&[11, 22], &[&[33, 44], &[55]]);
    let (header, body) = bytes_to_u64(&bytes).unwrap();
    assert_eq!(header, vec![11, 22]);
    assert_eq!(body, vec![33, 44, 55]);
    for length in 0..8 {
        assert!(bytes_to_u64(&bytes[..length]).is_err());
    }
}

#[test]
fn http_body_limits_are_route_specific_and_bounded() {
    assert_eq!(body_limit("POST", "/chiave"), Some(335_544_320));
    assert_eq!(body_limit("POST", "/varco"), Some(65_536));
    assert_eq!(body_limit("POST", "/iscrivi"), Some(8_192));
    assert_eq!(body_limit("POST", "/reset"), Some(0));
    assert_eq!(body_limit("GET", "/stato"), Some(0));
    assert_eq!(body_limit("POST", "/stato"), None);
    assert_eq!(body_limit("POST", "/sconosciuto"), None);
}

#[test]
fn hashes_and_json_strings_have_the_required_stable_encoding() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(json_quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
}

#[test]
fn key_envelopes_reject_old_versions_wrong_bindings_and_bad_lengths() {
    let payload = b"opaque-bincode";
    for magic in [SERVER_KEY_MAGIC, CLIENT_KEY_MAGIC] {
        let envelope = encode_bound_key(magic, payload);
        assert_eq!(decode_bound_key(&envelope, magic).unwrap(), payload);
        for length in 0..envelope.len() {
            assert!(
                decode_bound_key(&envelope[..length], magic).is_err(),
                "truncation {length}"
            );
        }
        let other = if magic == SERVER_KEY_MAGIC {
            CLIENT_KEY_MAGIC
        } else {
            SERVER_KEY_MAGIC
        };
        assert!(decode_bound_key(&envelope, other).is_err());
        for version in rejected_wire_versions() {
            let mut wrong = envelope.clone();
            wrong[8..16].copy_from_slice(&version.to_le_bytes());
            assert!(decode_bound_key(&wrong, magic).is_err());
        }
        for word in 2..7 {
            let mut wrong = envelope.clone();
            wrong[word * 8..(word + 1) * 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(decode_bound_key(&wrong, magic).is_err());
        }
        let mut offset = KEY_ENVELOPE_FIXED_BYTES;
        for text in [
            A44_PARAMS_ID,
            A44_PARAMETER_FINGERPRINT_SHA256,
            VARIANT_ID,
            CIRCUIT_SHA256,
        ] {
            let mut wrong = envelope.clone();
            wrong[offset] ^= 1;
            assert!(decode_bound_key(&wrong, magic).is_err());
            offset += text.len();
        }
        let mut extra = envelope.clone();
        extra.push(0);
        assert!(decode_bound_key(&extra, magic).is_err());
    }
    assert!(decode_bound_key(payload, SERVER_KEY_MAGIC).is_err());
    // A correct envelope alone never turns a malformed bincode payload into an accepted key.
    assert!(deserialize_bound_server_key(&encode_bound_key(SERVER_KEY_MAGIC, &[])).is_err());
    assert!(deserialize_bound_server_key(&encode_bound_key(SERVER_KEY_MAGIC, payload)).is_err());
}

#[test]
fn output_header_binds_wire_mode_geometry_and_gallery_version() {
    let g = gallery(225);
    let header = output_header(&g, OUTPUT_LWE_WORDS);
    assert_eq!(
        &header[..OUTPUT_FIXED_HEADER_WORDS],
        &[OUTPUT_MAGIC, 9, 5, 123, 7, 225, 2049, 59, 3, 15, 2,]
    );
    assert_eq!(
        decode_output_header(&header).unwrap(),
        OutputHeader {
            profile: QueryProfile::Head51,
            epoch: 123,
            revision: 7,
            gallery_size: 225,
            lwe_size: 2049,
        }
    );
    for (word, values) in [
        (0, vec![0, u64::from_le_bytes(*b"VRCOUTP2")]),
        (1, rejected_wire_versions()),
        (2, vec![0, 2, 4, 6, u64::MAX]),
        (5, vec![0, 3375, u64::MAX]),
        (6, vec![0, 2048, 2050, u64::MAX]),
        (7, vec![0, 51, 52, 56, 60, u64::MAX]),
        (8, vec![0, 1, 2, 4, u64::MAX]),
        (9, vec![0, 14, 16, u64::MAX]),
        (10, vec![0, 1, 3, u64::MAX]),
    ] {
        for value in values {
            let mut wrong = header.clone();
            wrong[word] = value;
            assert!(
                decode_output_header(&wrong).is_err(),
                "word {word} value {value}"
            );
        }
    }
    for length in 0..header.len() {
        assert!(decode_output_header(&header[..length]).is_err());
    }
    let mut extra = header.clone();
    extra.push(0);
    assert!(decode_output_header(&extra).is_err());
    for word in OUTPUT_FIXED_HEADER_WORDS..header.len() {
        let mut wrong = header.clone();
        wrong[word] ^= 1;
        assert!(decode_output_header(&wrong).is_err());
    }
    let mut changed_revision = header.clone();
    changed_revision[4] += 1;
    assert_eq!(decode_output_header(&changed_revision).unwrap().revision, 8);
    // The decoder carries actual epoch/revision; the client checks its prior snapshot.
}

#[test]
fn three_actual_trivial_roots_are_serialized_without_recomposition() {
    let g = gallery(225);
    let modulus = CiphertextModulus::new_native();
    let roots: Vec<_> = [0u64, 0, 1]
        .into_iter()
        .enumerate()
        .map(|(lane, digit)| {
            let mut ct = LweCiphertext::new(0, LweSize(OUTPUT_LWE_WORDS), modulus);
            ct.as_mut()[lane] = lane as u64 + 17;
            *ct.as_mut().last_mut().unwrap() = digit << LOG_DIGIT_DELTA;
            ct
        })
        .collect();
    let bytes = serialize_exact_output(&g, &roots[0], &roots[1], &roots[2]).unwrap();
    let (header_words, words) = bytes_to_u64(&bytes).unwrap();
    let header = decode_output_header(&header_words).unwrap();
    let lanes = output_digit_words(&header, &words).unwrap();
    assert_eq!(words.len(), 6147);
    assert_eq!(words.len() * 8, 49_176);
    for lane in 0..3 {
        assert_eq!(lanes[lane], roots[lane].as_ref());
    }
    for length in [0, 2049, 4098, 6146] {
        assert!(output_digit_words(&header, &words[..length]).is_err());
    }
    let mut extra = words.clone();
    extra.push(0);
    assert!(output_digit_words(&header, &extra).is_err());
    let short = LweCiphertext::new(0, LweSize(2048), modulus);
    assert!(serialize_exact_output(&g, &short, &roots[1], &roots[2]).is_err());
    assert!(serialize_exact_output(&g, &roots[0], &short, &roots[2]).is_err());
    assert!(serialize_exact_output(&g, &roots[0], &roots[1], &short).is_err());
    assert!(serialize_exact_output(&gallery(0), &roots[0], &roots[1], &roots[2]).is_err());
}

#[test]
fn all_three_digit_id_values_and_torus_rounding_are_checked() {
    let delta = 1u64 << LOG_DIGIT_DELTA;
    let half = delta >> 1;
    for digit in 0..15 {
        assert_eq!(decode_plain_digit(digit * delta).unwrap(), digit as usize);
    }
    assert_eq!(decode_plain_digit(half - 1).unwrap(), 0);
    assert_eq!(decode_plain_digit(half).unwrap(), 1);
    assert_eq!(decode_plain_digit(0u64.wrapping_sub(half)).unwrap(), 0);
    assert_eq!(decode_plain_digit(u64::MAX).unwrap(), 0);
    assert!(decode_plain_digit(0u64.wrapping_sub(half + 1)).is_err());
    for digit in 15..32 {
        assert!(decode_plain_digit(digit * delta).is_err());
    }
    for code in 0..=3374 {
        let low = code % 15;
        let middle = (code / 15) % 15;
        let high = code / 225;
        assert_eq!(reconstruct_code(low, middle, high, 3374).unwrap(), code);
        if code > 0 {
            assert_eq!(reconstruct_code(low, middle, high, code).unwrap(), code);
            if code > 1 {
                assert!(reconstruct_code(low, middle, high, code - 1).is_err());
            }
        }
    }
    assert_eq!(reconstruct_code(14, 14, 0, 224).unwrap(), 224);
    assert_eq!(reconstruct_code(0, 0, 1, 225).unwrap(), 225);
    assert_eq!(reconstruct_code(14, 14, 14, 3374).unwrap(), 3374);
    for [low, middle, high] in [[15, 0, 0], [0, 15, 0], [0, 0, 15], [usize::MAX, 0, 0]] {
        assert!(reconstruct_code(low, middle, high, 3374).is_err());
    }
    for n in [0, 3375, usize::MAX] {
        assert!(reconstruct_code(0, 0, 0, n).is_err());
    }
}
