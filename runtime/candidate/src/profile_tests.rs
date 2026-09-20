use crate::profile::QueryProfile;
use crate::protocol::*;
use crate::wire::*;

#[test]
fn actual_encoder_uses_native51_and_retains_the_low60_channel() {
    let mut query = vec![0; PROBE_DIM];
    query[0] = -3;
    query[1] = -1;
    query[2] = 1;
    query[PROBE_DIM - 1] = 2;
    let profile = QueryProfile::Head51;
    let words = encode_probe_coefficients(&query, POLYNOMIAL_SIZE, profile).unwrap();
    for (j, value) in query.iter().copied().enumerate() {
        assert_eq!(words[j], (value as u64).wrapping_mul(1u64 << 51));
        assert_eq!(
            words[LOW_MOD16_OFFSET + j],
            (value.rem_euclid(16) as u64) << 60
        );
    }
    assert!(words[PROBE_DIM..LOW_MOD16_OFFSET]
        .iter()
        .all(|&word| word == 0));
    assert!(words[LOW_MOD16_OFFSET + PROBE_DIM..]
        .iter()
        .all(|&word| word == 0));
    let header = probe_header(POLYNOMIAL_SIZE, GLWE_DIMENSION, profile);
    assert_eq!(header[6..9], [51, 60, 2]);
    assert_eq!(decode_probe_header(&header).unwrap().profile, profile);
}

#[test]
fn actual_encoder_rejects_bad_plaintext_before_encryption() {
    let profile = QueryProfile::Head51;
    for length in [0, 511, 513] {
        assert!(encode_probe_coefficients(&vec![0; length], 2048, profile).is_err());
    }
    for value in [i64::MIN, -4, 4, i64::MAX] {
        let mut query = vec![0; PROBE_DIM];
        query[0] = value;
        assert!(encode_probe_coefficients(&query, 2048, profile).is_err());
    }
    let mut boundary = vec![0; PROBE_DIM];
    boundary[..113].fill(3); // 1017
    boundary[113] = 2; // 1021
    boundary[114..117].fill(1); // 1024
    assert!(encode_probe_coefficients(&boundary, 2048, profile).is_ok());
    boundary[117] = 1; // 1025
    assert!(encode_probe_coefficients(&boundary, 2048, profile)
        .unwrap_err()
        .contains("norma quadratica"));
    let mut quantized_unit_example = vec![0; PROBE_DIM];
    quantized_unit_example[..264].fill(2); // 1056; L2 before quantization did not guarantee this bound.
    assert!(encode_probe_coefficients(&quantized_unit_example, 2048, profile).is_err());
    assert!(encode_probe_coefficients(&vec![0; PROBE_DIM], 1024, profile).is_err());
}

#[test]
fn probe_codec_rejects_old_profiles_versions_scales_and_geometry() {
    let header = probe_header(2048, 1, QueryProfile::Head51);
    assert_eq!(
        decode_probe_header(&header).unwrap(),
        ProbeHeader {
            profile: QueryProfile::Head51,
            polynomial_size: 2048,
            glwe_dimension: 1,
            embedding_dim: 512,
        }
    );
    for (word, values) in [
        (0, vec![0, u64::from_le_bytes(*b"VRCOPRB2")]),
        (1, crate::tests::rejected_wire_versions()),
        (2, vec![0, 2, u64::MAX]),
        (3, vec![0, 1024, 4096, u64::MAX]),
        (4, vec![0, 2, u64::MAX]),
        (5, vec![0, 511, 513, u64::MAX]),
        (6, vec![0, 50, 52, 53, 60, u64::MAX]),
        (7, vec![0, 51, 52, 59, 61, u64::MAX]),
        (8, vec![0, 1, 3, 7, u64::MAX]),
    ] {
        for value in values {
            let mut wrong = header.clone();
            wrong[word] = value;
            assert!(
                decode_probe_header(&wrong).is_err(),
                "word {word} value {value}"
            );
        }
    }
    for length in 0..header.len() {
        assert!(decode_probe_header(&header[..length]).is_err());
    }
    let mut extra = header.clone();
    extra.push(0);
    assert!(decode_probe_header(&extra).is_err());
    for word in PROBE_FIXED_HEADER_WORDS..header.len() {
        let mut wrong = header.clone();
        wrong[word] ^= 1;
        assert!(decode_probe_header(&wrong).is_err());
    }
    for n in [1, 126, 127, 128, 224, 225, 1024, 3374] {
        assert!(decode_probe_header(&header)
            .unwrap()
            .profile
            .validate_gallery(n)
            .is_ok());
    }
}
