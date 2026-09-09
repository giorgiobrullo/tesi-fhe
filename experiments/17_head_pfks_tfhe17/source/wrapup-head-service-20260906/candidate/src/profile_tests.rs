use super::*;

#[test]
fn actual_codec_supports_both_signed_input_profiles() {
    let mut query = vec![0; PROBE_DIM];
    query[0] = -3;
    query[1] = -1;
    query[2] = 1;
    query[PROBE_DIM - 1] = 2;
    for profile in [QueryProfile::Legacy52, QueryProfile::Head51] {
        let words = encode_probe_coefficients(&query, 2048, profile).unwrap();
        let delta = 1u64 << profile.score_delta_log();
        for (j, value) in query.iter().copied().enumerate() {
            assert_eq!(words[j], (value as u64).wrapping_mul(delta));
            assert_eq!(words[LOW_MOD16_OFFSET + j], (value.rem_euclid(16) as u64) << 60);
        }
        for j in PROBE_DIM..LOW_MOD16_OFFSET { assert_eq!(words[j], 0); }
        for j in LOW_MOD16_OFFSET + PROBE_DIM..2048 { assert_eq!(words[j], 0); }
        let header = probe_header(2048, 1, profile);
        assert_eq!(header[6], profile.score_delta_log() as u64);
        assert_eq!(header[7], 60);
        assert_eq!(header[8], profile.wire());
        assert_eq!(decode_probe_header(&header).unwrap().profile, profile);
        for wrong_full in [0, 50, 51, 52, 53, 60, u64::MAX] {
            if wrong_full == profile.score_delta_log() as u64 { continue; }
            let mut wrong = header.clone(); wrong[6] = wrong_full;
            assert!(decode_probe_header(&wrong).is_err());
        }
        for wrong_low in [0, 51, 52, 59, 61, u64::MAX] {
            let mut wrong = header.clone(); wrong[7] = wrong_low;
            assert!(decode_probe_header(&wrong).is_err());
        }
        let mut wrong = header.clone(); wrong[1] = 6;
        assert!(decode_probe_header(&wrong).is_err());
        for id in [0, 3, 7, u64::MAX] {
            let mut wrong = header.clone(); wrong[8] = id;
            assert!(decode_probe_header(&wrong).is_err());
        }
    }
}

#[test]
fn correct_profile_must_match_both_public_neighbors() {
    for n in [126, 127, 128] {
        for profile in [QueryProfile::Legacy52, QueryProfile::Head51] {
            let decoded = decode_probe_header(&probe_header(2048, 1, profile)).unwrap();
            assert_eq!(decoded.profile.validate_gallery(n).is_ok(), (n == 127) == (profile == QueryProfile::Head51));
        }
    }
}

#[test]
fn output_profile_cannot_be_swapped_for_other_valid_enum() {
    for n in [4, 127, 128] {
        let profile = QueryProfile::for_gallery(n).unwrap();
        let mut header = vec![OUTPUT_MAGIC, WIRE_VERSION, OUTPUT_MODE_EXACT_ID_TWO_LWE,
                              123, 7, n as u64, 2049, 59, 2, 15, profile.wire()];
        append_a126_binding(&mut header);
        assert_eq!(decode_output_header(&header).unwrap().profile, profile);
        header[10] = if profile == QueryProfile::Head51 {1} else {2};
        assert!(decode_output_header(&header).is_err());
    }
}
