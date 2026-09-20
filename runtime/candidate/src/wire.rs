//! Ciphertext framing, circuit binding and trusted-client integer encodings.
use crate::gallery::Galleria;
use crate::profile::QueryProfile;
use crate::protocol::*;
use sha2::{Digest, Sha256};
use tfhe::core_crypto::prelude::*;

pub(crate) fn scrivi_u64(path: &str, header: &[u64], dati: &[&[u64]]) {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(header.len() as u64).to_le_bytes());
    for h in header {
        buf.extend_from_slice(&h.to_le_bytes());
    }
    for d in dati {
        for x in *d {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    std::fs::write(path, buf).unwrap();
}

pub(crate) fn bytes_to_u64(b: &[u8]) -> Result<(Vec<u64>, Vec<u64>), String> {
    if b.len() < 8 || !b.len().is_multiple_of(8) {
        return Err("formato cifrato troncato: la lunghezza non e' un multiplo di 8".to_string());
    }
    let w: Vec<u64> = b
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("chunks_exact produce blocchi da 8")))
        .collect();
    let nh = w[0] as usize;
    if nh > w.len() - 1 {
        return Err(format!("header cifrato troncato: dichiarate {nh} parole"));
    }
    Ok((w[1..1 + nh].to_vec(), w[1 + nh..].to_vec()))
}

pub(crate) fn u64_to_bytes(header: &[u64], dati: &[&[u64]]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(header.len() as u64).to_le_bytes());
    for h in header {
        buf.extend_from_slice(&h.to_le_bytes());
    }
    for d in dati {
        for x in *d {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    buf
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("scrivere in una String non puo' fallire");
    }
    encoded
}

pub(crate) fn text_words(value: &str) -> Vec<u64> {
    value
        .as_bytes()
        .chunks(8)
        .map(|chunk| {
            let mut padded = [0u8; 8];
            padded[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(padded)
        })
        .collect()
}

pub(crate) fn append_circuit_binding(header: &mut Vec<u64>) {
    header.push(A44_PARAMS_ID.len() as u64);
    header.push(A44_PARAMETER_FINGERPRINT_SHA256.len() as u64);
    header.push(VARIANT_ID.len() as u64);
    header.push(CIRCUIT_SHA256.len() as u64);
    header.extend(text_words(A44_PARAMS_ID));
    header.extend(text_words(A44_PARAMETER_FINGERPRINT_SHA256));
    header.extend(text_words(VARIANT_ID));
    header.extend(text_words(CIRCUIT_SHA256));
}

pub(crate) fn expected_bound_header_words(fixed_words: usize) -> usize {
    fixed_words
        + BINDING_LENGTH_WORDS
        + A44_PARAMS_ID.len().div_ceil(8)
        + A44_PARAMETER_FINGERPRINT_SHA256.len().div_ceil(8)
        + VARIANT_ID.len().div_ceil(8)
        + CIRCUIT_SHA256.len().div_ceil(8)
}

pub(crate) fn validate_circuit_wire_binding(
    header: &[u64],
    fixed_words: usize,
) -> Result<(), String> {
    let expected_words = expected_bound_header_words(fixed_words);
    if header.len() != expected_words {
        return Err(format!(
            "header fast mixed: {} parole, attese {expected_words}; altri wire non supportati",
            header.len()
        ));
    }
    let mut expected = vec![0u64; fixed_words];
    append_circuit_binding(&mut expected);
    if header[fixed_words..] != expected[fixed_words..] {
        return Err("binding parametri/variante/circuito fast mixed errato".to_string());
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbeHeader {
    pub(crate) profile: QueryProfile,
    pub(crate) polynomial_size: usize,
    pub(crate) glwe_dimension: usize,
    pub(crate) embedding_dim: usize,
}

pub(crate) fn decode_probe_header(header: &[u64]) -> Result<ProbeHeader, String> {
    validate_circuit_wire_binding(header, PROBE_FIXED_HEADER_WORDS)?;
    if header[0] != PROBE_MAGIC {
        return Err("magic del probe sconosciuto".to_string());
    }
    if header[1] != WIRE_VERSION {
        return Err(format!("versione del probe non supportata: {}", header[1]));
    }
    if header[2] != PROBE_LAYOUT_DUAL_SAME_GLWE {
        return Err(format!("layout del probe non supportato: {}", header[2]));
    }
    let profile = QueryProfile::from_wire(header[8])?;
    profile.validate_scales(header[6], header[7])?;
    let decoded = ProbeHeader {
        profile,
        polynomial_size: usize::try_from(header[3])
            .map_err(|_| "polynomial_size del probe non rappresentabile".to_string())?,
        glwe_dimension: usize::try_from(header[4])
            .map_err(|_| "glwe_dimension del probe non rappresentabile".to_string())?,
        embedding_dim: usize::try_from(header[5])
            .map_err(|_| "dimensione dell'embedding non rappresentabile".to_string())?,
    };
    if decoded.polynomial_size != POLYNOMIAL_SIZE
        || decoded.glwe_dimension != GLWE_DIMENSION
        || decoded.embedding_dim != PROBE_DIM
    {
        return Err("geometria del probe diversa dal profilo nativo 2048/1/512".into());
    }
    Ok(decoded)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputHeader {
    pub(crate) profile: QueryProfile,
    pub(crate) epoch: u64,
    pub(crate) revision: u64,
    pub(crate) gallery_size: usize,
    pub(crate) lwe_size: usize,
}

pub(crate) fn decode_output_header(header: &[u64]) -> Result<OutputHeader, String> {
    validate_circuit_wire_binding(header, OUTPUT_FIXED_HEADER_WORDS)?;
    if header[0] != OUTPUT_MAGIC {
        return Err("magic dell'esito sconosciuto".to_string());
    }
    if header[1] != WIRE_VERSION {
        return Err(format!("versione dell'esito non supportata: {}", header[1]));
    }
    if header[2] != OUTPUT_MODE_EXACT_ID_THREE_LWE {
        return Err(format!(
            "modalita' dell'esito non supportata: {}",
            header[2]
        ));
    }
    if header[7] != u64::from(LOG_DIGIT_DELTA) {
        return Err(format!(
            "scala delle cifre non supportata: Delta=2^{}",
            header[7]
        ));
    }
    if header[8] != OUTPUT_LWES as u64 {
        return Err(format!(
            "numero di LWE dell'esito non supportato: {}, attesi {OUTPUT_LWES}",
            header[8]
        ));
    }
    if header[9] != OUTPUT_DIGIT_BASE as u64 {
        return Err(format!(
            "base delle cifre non supportata: {}, attesa {OUTPUT_DIGIT_BASE}",
            header[9]
        ));
    }
    let gallery_size = usize::try_from(header[5])
        .map_err(|_| "dimensione della galleria non rappresentabile".to_string())?;
    if gallery_size == 0 || gallery_size > MAX_GALLERY {
        return Err(format!(
            "dimensione della galleria fuori contratto: {gallery_size}"
        ));
    }
    let lwe_size = usize::try_from(header[6])
        .map_err(|_| "lwe_size dell'esito non rappresentabile".to_string())?;
    if lwe_size != OUTPUT_LWE_WORDS {
        return Err(format!("output LWE size must be {OUTPUT_LWE_WORDS}"));
    }
    let profile = QueryProfile::from_wire(header[10])?;
    profile.validate_gallery(gallery_size)?;
    Ok(OutputHeader {
        profile,
        epoch: header[3],
        revision: header[4],
        gallery_size,
        lwe_size,
    })
}

pub(crate) fn probe_header(
    polynomial_size: usize,
    glwe_dimension: usize,
    profile: QueryProfile,
) -> Vec<u64> {
    let mut header = vec![
        PROBE_MAGIC,
        WIRE_VERSION,
        PROBE_LAYOUT_DUAL_SAME_GLWE,
        polynomial_size as u64,
        glwe_dimension as u64,
        PROBE_DIM as u64,
        u64::from(profile.score_delta_log()),
        u64::from(LOG_LOW_MOD16_DELTA),
        profile.wire(),
    ];
    append_circuit_binding(&mut header);
    header
}

pub(crate) fn output_header(g: &Galleria, lwe_size: usize) -> Vec<u64> {
    let mut header = vec![
        OUTPUT_MAGIC,
        WIRE_VERSION,
        OUTPUT_MODE_EXACT_ID_THREE_LWE,
        g.epoch,
        g.revision,
        g.iscritti.len() as u64,
        lwe_size as u64,
        u64::from(LOG_DIGIT_DELTA),
        OUTPUT_LWES as u64,
        OUTPUT_DIGIT_BASE as u64,
        QueryProfile::for_gallery(g.iscritti.len())
            .expect("nonempty admitted gallery")
            .wire(),
    ];
    append_circuit_binding(&mut header);
    header
}

pub(crate) fn serialize_exact_output(
    g: &Galleria,
    low: &LweCiphertextOwned<u64>,
    middle: &LweCiphertextOwned<u64>,
    high: &LweCiphertextOwned<u64>,
) -> Result<Vec<u8>, String> {
    for digit in [low, middle, high] {
        if digit.lwe_size().0 != OUTPUT_LWE_WORDS || !digit.ciphertext_modulus().is_native_modulus()
        {
            return Err("le tre cifre devono avere geometria LWE nativa 2049".into());
        }
    }
    QueryProfile::Head51.validate_gallery(g.iscritti.len())?;
    Ok(u64_to_bytes(
        &output_header(g, OUTPUT_LWE_WORDS),
        &[low.as_ref(), middle.as_ref(), high.as_ref()],
    ))
}

/// Validate the full ciphertext body before exposing any of its three roots to decryption.
pub(crate) fn output_digit_words<'a>(
    header: &OutputHeader,
    words: &'a [u64],
) -> Result<[&'a [u64]; 3], String> {
    let expected = OUTPUT_LWES
        .checked_mul(header.lwe_size)
        .ok_or("lunghezza del corpo dell'esito non rappresentabile")?;
    if words.len() != expected {
        return Err(format!(
            "corpo dell'esito di {} parole, attese {expected} per tre LWE",
            words.len()
        ));
    }
    let (low, remaining) = words.split_at(header.lwe_size);
    let (middle, high) = remaining.split_at(header.lwe_size);
    Ok([low, middle, high])
}

pub(crate) fn decode_plain_digit(plaintext: u64) -> Result<usize, String> {
    let rounded = (u128::from(plaintext) + (1u128 << (LOG_DIGIT_DELTA - 1))) >> LOG_DIGIT_DELTA;
    // Il rumore negativo attorno al codice 0 appare vicino a 2^64 sul toro.
    let digit = if rounded == (1u128 << (64 - LOG_DIGIT_DELTA)) {
        0
    } else {
        usize::try_from(rounded).map_err(|_| "cifra decifrata non rappresentabile".to_string())?
    };
    if digit >= OUTPUT_DIGIT_BASE {
        return Err(format!("cifra p16 fuori intervallo: {digit}"));
    }
    Ok(digit)
}

pub(crate) fn reconstruct_code(
    low: usize,
    middle: usize,
    high: usize,
    gallery_size: usize,
) -> Result<usize, String> {
    QueryProfile::Head51.validate_gallery(gallery_size)?;
    if [low, middle, high]
        .iter()
        .any(|&digit| digit >= OUTPUT_DIGIT_BASE)
    {
        return Err(format!(
            "cifre base15 fuori intervallo: low={low}, middle={middle}, high={high}"
        ));
    }
    let code = high
        .checked_mul(OUTPUT_DIGIT_BASE)
        .and_then(|value| value.checked_add(middle))
        .and_then(|value| value.checked_mul(OUTPUT_DIGIT_BASE))
        .and_then(|value| value.checked_add(low))
        .ok_or_else(|| "codice ricostruito non rappresentabile".to_string())?;
    if code > gallery_size {
        return Err(format!(
            "codice ricostruito fuori intervallo: {code}, massimo {gallery_size}"
        ));
    }
    Ok(code)
}
pub(crate) fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn encode_probe_coefficients(
    probe: &[i64],
    polynomial_size: usize,
    profile: QueryProfile,
) -> Result<Vec<u64>, String> {
    if probe.len() != PROBE_DIM {
        return Err(format!(
            "il client demo richiede esattamente {PROBE_DIM} coefficienti"
        ));
    }
    if probe
        .iter()
        .any(|x| i128::from(*x).abs() > i128::from(Q_MAX))
    {
        return Err(format!(
            "probe fuori dal dominio dichiarato [-{Q_MAX}, {Q_MAX}]"
        ));
    }
    let norm2 = probe
        .iter()
        .try_fold(0i64, |sum, &x| sum.checked_add(x.checked_mul(x)?));
    let norm2 =
        norm2.ok_or_else(|| "norma quadratica del probe non rappresentabile".to_string())?;
    if norm2 > PROBE_NORM2_MAX {
        return Err(format!(
            "norma quadratica del probe {norm2} oltre il massimo {PROBE_NORM2_MAX}"
        ));
    }
    if LOW_MOD16_OFFSET + PROBE_DIM > polynomial_size {
        return Err(format!(
            "il layout duale richiede almeno {} coefficienti nel GLWE",
            LOW_MOD16_OFFSET + PROBE_DIM
        ));
    }
    let mut coefficients = vec![0u64; polynomial_size];
    for (j, &value) in probe.iter().enumerate() {
        coefficients[j] = (value as u64).wrapping_mul(1u64 << profile.score_delta_log());
        coefficients[LOW_MOD16_OFFSET + j] =
            (value.rem_euclid(16) as u64).wrapping_mul(1u64 << LOG_LOW_MOD16_DELTA);
    }
    Ok(coefficients)
}
