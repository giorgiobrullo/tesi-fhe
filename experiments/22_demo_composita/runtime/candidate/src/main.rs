//! Local exact 0/ID service using the frozen general uniform/mixed Head fast core.
//!
//! Enrollment sends templates and their thresholds in plaintext, as in the camera demo.
//! Queries use one directly encrypted native full51/low60 GLWE. Responses contain
//! three separate base-15 identity digits at delta 2^59. The trusted client validates
//! the query and interprets the output against the same gallery/key snapshot.
#![recursion_limit = "256"]

mod dispatch;
mod metadata;
mod profile;
mod protocol;
mod runtime;
mod supplement;
mod rebind;

use bincode::Options;
use pfks_core::service::{
    self, EvaluationKeys, ExecutionPlan, ScoreDomain, ServerBundle, TemplateView,
};
use profile::QueryProfile;
use protocol::*;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const FFT_PLAN_POLICY: &str = "user-provided-dif4-polynomial2048-base1024-v1";

fn install_fixed_fft_plan() -> String {
    assert_eq!(PARAMS.polynomial_size.0, 2048);
    let plan = Plan::new(
        1024,
        Method::UserProvided {
            base_algo: FftAlgo::Dif4,
            base_n: 1024,
        },
    );
    let description = format!("{plan:?}");
    setup_custom_fft_plan(plan);
    description
}

// ---------------------------------------------------------------- utilita' di formato
fn scrivi_u64(path: &str, header: &[u64], dati: &[&[u64]]) {
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

fn bytes_to_u64(b: &[u8]) -> Result<(Vec<u64>, Vec<u64>), String> {
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

fn u64_to_bytes(header: &[u64], dati: &[&[u64]]) -> Vec<u8> {
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

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("scrivere in una String non puo' fallire");
    }
    encoded
}

fn text_words(value: &str) -> Vec<u64> {
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

fn append_circuit_binding(header: &mut Vec<u64>) {
    header.push(A44_PARAMS_ID.len() as u64);
    header.push(A44_PARAMETER_FINGERPRINT_SHA256.len() as u64);
    header.push(VARIANT_ID.len() as u64);
    header.push(CIRCUIT_SHA256.len() as u64);
    header.extend(text_words(A44_PARAMS_ID));
    header.extend(text_words(A44_PARAMETER_FINGERPRINT_SHA256));
    header.extend(text_words(VARIANT_ID));
    header.extend(text_words(CIRCUIT_SHA256));
}

fn expected_bound_header_words(fixed_words: usize) -> usize {
    fixed_words
        + BINDING_LENGTH_WORDS
        + A44_PARAMS_ID.len().div_ceil(8)
        + A44_PARAMETER_FINGERPRINT_SHA256.len().div_ceil(8)
        + VARIANT_ID.len().div_ceil(8)
        + CIRCUIT_SHA256.len().div_ceil(8)
}

fn validate_circuit_wire_binding(header: &[u64], fixed_words: usize) -> Result<(), String> {
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

fn encode_bound_key(magic: u64, payload: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(
        KEY_ENVELOPE_FIXED_BYTES
            + A44_PARAMS_ID.len()
            + A44_PARAMETER_FINGERPRINT_SHA256.len()
            + VARIANT_ID.len()
            + CIRCUIT_SHA256.len()
            + payload.len(),
    );
    for word in [
        magic,
        WIRE_VERSION,
        A44_PARAMS_ID.len() as u64,
        A44_PARAMETER_FINGERPRINT_SHA256.len() as u64,
        VARIANT_ID.len() as u64,
        CIRCUIT_SHA256.len() as u64,
        payload.len() as u64,
    ] {
        envelope.extend_from_slice(&word.to_le_bytes());
    }
    envelope.extend_from_slice(A44_PARAMS_ID.as_bytes());
    envelope.extend_from_slice(A44_PARAMETER_FINGERPRINT_SHA256.as_bytes());
    envelope.extend_from_slice(VARIANT_ID.as_bytes());
    envelope.extend_from_slice(CIRCUIT_SHA256.as_bytes());
    envelope.extend_from_slice(payload);
    envelope
}

fn decode_bound_key<'a>(data: &'a [u8], expected_magic: u64) -> Result<&'a [u8], String> {
    if data.len() < KEY_ENVELOPE_FIXED_BYTES {
        return Err(
            "chiave senza envelope fast mixed v8; formati precedenti non supportati".to_string(),
        );
    }
    let words: Vec<u64> = data[..KEY_ENVELOPE_FIXED_BYTES]
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("chunk da 8 byte")))
        .collect();
    if words[0] != expected_magic {
        return Err("magic della chiave fast mixed non valido".to_string());
    }
    if words[1] != WIRE_VERSION {
        return Err(format!(
            "versione dell'envelope chiave non supportata: {}",
            words[1]
        ));
    }
    let params_len = usize::try_from(words[2])
        .map_err(|_| "lunghezza params_id non rappresentabile".to_string())?;
    let fingerprint_len = usize::try_from(words[3])
        .map_err(|_| "lunghezza fingerprint non rappresentabile".to_string())?;
    let variant_len = usize::try_from(words[4])
        .map_err(|_| "lunghezza variant_id non rappresentabile".to_string())?;
    let circuit_len = usize::try_from(words[5])
        .map_err(|_| "lunghezza circuit hash non rappresentabile".to_string())?;
    let payload_len = usize::try_from(words[6])
        .map_err(|_| "lunghezza chiave non rappresentabile".to_string())?;
    let params_end = KEY_ENVELOPE_FIXED_BYTES
        .checked_add(params_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let fingerprint_end = params_end
        .checked_add(fingerprint_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let variant_end = fingerprint_end
        .checked_add(variant_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let circuit_end = variant_end
        .checked_add(circuit_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    let payload_end = circuit_end
        .checked_add(payload_len)
        .ok_or_else(|| "envelope chiave troppo grande".to_string())?;
    if payload_end != data.len() {
        return Err("lunghezza dell'envelope chiave incoerente".to_string());
    }
    if &data[KEY_ENVELOPE_FIXED_BYTES..params_end] != A44_PARAMS_ID.as_bytes()
        || &data[params_end..fingerprint_end] != A44_PARAMETER_FINGERPRINT_SHA256.as_bytes()
        || &data[fingerprint_end..variant_end] != VARIANT_ID.as_bytes()
        || &data[variant_end..circuit_end] != CIRCUIT_SHA256.as_bytes()
    {
        return Err("binding parametri/variante/circuito della chiave errato".to_string());
    }
    Ok(&data[circuit_end..payload_end])
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        // Anche una directory preesistente viene riportata al permesso richiesto.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8], unix_mode: u32) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "il file chiave deve avere una directory padre",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "nome del file chiave non valido",
            )
        })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    #[cfg(not(unix))]
    let _ = unix_mode;

    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

// ---------------------------------------------------------------- stato del server
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    template: Vec<i64>,
    norm2: i64,
    l1: i64,
    threshold: i64,
}

struct Galleria {
    dim: usize,
    t_default: i64,
    iscritti: Vec<Entry>,
    chiave: Option<EvaluationKeys>,
    chiave_sha256: Option<String>,
    g4_sha256: Option<String>,
    epoch: u64,
    revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GalleryExecutionMetadata {
    plan: ExecutionPlan,
    counts: service::Counts,
}

impl Entry {
    fn new(name: String, template: Vec<i64>, threshold: i64) -> Result<Self, String> {
        let (l1, norm2) = template
            .iter()
            .try_fold((0i64, 0i64), |(l1, norm2), &x| {
                let abs = x.checked_abs()?;
                Some((l1.checked_add(abs)?, norm2.checked_add(x.checked_mul(x)?)?))
            })
            .ok_or_else(|| "norme del template non rappresentabili".to_string())?;
        Ok(Self {
            name,
            template,
            norm2,
            l1,
            threshold,
        })
    }

    fn score_domain(&self) -> Result<ScoreDomain, String> {
        // Il client fidato verifica ||q||^2 <= PROBE_NORM2_MAX prima della cifratura.
        // Cauchy-Schwarz da' |<g,q>| <= sqrt(||g||^2 ||q||^2); il ceil intero mantiene
        // il bound conservativo senza dipendere da arrotondamenti floating point.
        let product = self
            .norm2
            .checked_mul(PROBE_NORM2_MAX)
            .ok_or_else(|| "dominio del punteggio non rappresentabile".to_string())?;
        let dot_bound = ceil_sqrt_nonnegative(product)?;
        let span = 2i64
            .checked_mul(dot_bound)
            .ok_or_else(|| "dominio del punteggio non rappresentabile".to_string())?;
        Ok(ScoreDomain {
            lower: self
                .norm2
                .checked_sub(span)
                .ok_or_else(|| "limite inferiore del punteggio non rappresentabile".to_string())?,
            upper: self
                .norm2
                .checked_add(span)
                .ok_or_else(|| "limite superiore del punteggio non rappresentabile".to_string())?,
        })
    }
}

fn ceil_sqrt_nonnegative(value: i64) -> Result<i64, String> {
    if value < 0 {
        return Err("radicando negativo nel bound del punteggio".to_string());
    }
    if value <= 1 {
        return Ok(value);
    }
    let mut low = 1i64;
    let mut high = value;
    while low < high {
        let middle = low + (high - low) / 2;
        if i128::from(middle) * i128::from(middle) >= i128::from(value) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low)
}

fn gallery_domain(entries: &[Entry]) -> Result<Option<ScoreDomain>, String> {
    let mut domains = entries.iter().map(Entry::score_domain);
    let Some(first) = domains.next() else {
        return Ok(None);
    };
    let first = first?;
    domains.try_fold(Some(first), |domain, next| {
        let domain = domain.expect("il dominio iniziale esiste");
        let next = next?;
        Ok(Some(ScoreDomain {
            lower: domain.lower.min(next.lower),
            upper: domain.upper.max(next.upper),
        }))
    })
}

fn template_views(entries: &[Entry]) -> Vec<TemplateView<'_>> {
    entries
        .iter()
        .map(|entry| TemplateView {
            template: &entry.template,
            norm2: entry.norm2,
            threshold: entry.threshold,
        })
        .collect()
}

fn gallery_execution_metadata(
    entries: &[Entry],
) -> Result<Option<GalleryExecutionMetadata>, String> {
    if entries.is_empty() {
        return Ok(None);
    }
    let templates = template_views(entries);
    let plan = service::plan(&templates)
        .map_err(|error| format!("galleria non valida per l'argmin esatto: {error}"))?;
    let counts = pfks_core::public_digits::operation_counts(&templates)?;
    Ok(Some(GalleryExecutionMetadata { plan, counts }))
}

fn domain_width(domain: ScoreDomain) -> Result<i64, String> {
    domain
        .upper
        .checked_sub(domain.lower)
        .and_then(|x| x.checked_add(1))
        .ok_or_else(|| "larghezza del dominio non rappresentabile".to_string())
}

fn process_epoch() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ u64::from(std::process::id()).rotate_left(32)
}

fn next_revision(revision: u64) -> Result<u64, String> {
    revision
        .checked_add(1)
        .ok_or_else(|| "contatore di revisione esaurito".to_string())
}

fn upsert_entry(
    gallery: &mut Galleria,
    name: String,
    template: Vec<i64>,
    threshold: i64,
) -> Result<(usize, GalleryExecutionMetadata), String> {
    if name.is_empty() {
        return Err("nome dell'iscritto vuoto".to_string());
    }
    if template.len() != gallery.dim {
        return Err(format!(
            "attesi {} valori, ricevuti {}",
            gallery.dim,
            template.len()
        ));
    }
    if template
        .iter()
        .any(|x| i128::from(*x).abs() > i128::from(Q_MAX))
    {
        return Err(format!(
            "template fuori dal dominio dichiarato: valori ammessi [-{Q_MAX}, {Q_MAX}]"
        ));
    }

    let entry = Entry::new(name.clone(), template, threshold)?;
    let existing = gallery.iscritti.iter().position(|x| x.name == name);
    if gallery.iscritti.len() >= MAX_GALLERY && existing.is_none() {
        return Err(format!("galleria piena: massimo {MAX_GALLERY} iscritti"));
    }

    // La sostituzione viene prima simulata su una copia: se amplia troppo il dominio, lo stato
    // precedente e la sua revisione restano intatti.
    let mut proposed = gallery.iscritti.clone();
    let index = if let Some(index) = existing {
        proposed[index] = entry;
        index
    } else {
        proposed.push(entry);
        proposed.len() - 1
    };
    let domain = gallery_domain(&proposed)?.expect("la proposta contiene almeno un iscritto");
    let width = domain_width(domain)?;
    if width > SCORE_DOMAIN_MAX_WIDTH {
        return Err(format!(
            "dominio globale dei punteggi [{}, {}] largo {width}: massimo {SCORE_DOMAIN_MAX_WIDTH}",
            domain.lower, domain.upper
        ));
    }
    let metadata =
        gallery_execution_metadata(&proposed)?.expect("la proposta contiene almeno un iscritto");
    if metadata.plan.cauchy_domain != domain {
        return Err("dominio Cauchy incoerente tra servizio e core argmin".to_string());
    }
    let revision = next_revision(gallery.revision)?;
    gallery.iscritti = proposed;
    gallery.revision = revision;
    Ok((index, metadata))
}

fn reset_gallery(gallery: &mut Galleria) -> Result<(), String> {
    let revision = next_revision(gallery.revision)?;
    gallery.iscritti.clear();
    gallery.revision = revision;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProbeHeader {
    profile: QueryProfile,
    polynomial_size: usize,
    glwe_dimension: usize,
    embedding_dim: usize,
}

fn decode_probe_header(header: &[u64]) -> Result<ProbeHeader, String> {
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
struct OutputHeader {
    profile: QueryProfile,
    epoch: u64,
    revision: u64,
    gallery_size: usize,
    lwe_size: usize,
}

fn decode_output_header(header: &[u64]) -> Result<OutputHeader, String> {
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

fn probe_header(polynomial_size: usize, glwe_dimension: usize, profile: QueryProfile) -> Vec<u64> {
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

fn output_header(g: &Galleria, lwe_size: usize) -> Vec<u64> {
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

fn serialize_exact_output(
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
fn output_digit_words<'a>(
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

fn decode_plain_digit(plaintext: u64) -> Result<usize, String> {
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

fn reconstruct_code(
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

fn client_key_compatibile_con_params(chiave: &ClientKey) -> bool {
    let (glwe_secret_key, small_secret_key, params, wopbs) = match chiave.clone().atomic_pattern {
        AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
        _ => return false,
    };
    let expected: tfhe::shortint::PBSParameters = PARAMS.into();
    params == expected
        && wopbs.is_none()
        && glwe_secret_key.glwe_dimension() == PARAMS.glwe_dimension
        && glwe_secret_key.polynomial_size() == PARAMS.polynomial_size
        && small_secret_key.lwe_dimension() == PARAMS.lwe_dimension
}

fn deserialize_bound_server_key(data: &[u8]) -> Result<EvaluationKeys, String> {
    pfks_core::service::validate_serialized_bundle_size(data.len())?;
    let payload = decode_bound_key(data, SERVER_KEY_MAGIC)?;
    // Native serde containers can panic on malformed geometry. Reject at upload boundary.
    std::panic::catch_unwind(|| {
        let bundle: ServerBundle = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_SERVER_KEY_BODY_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|error| format!("payload bincode del bundle non valido: {error}"))?;
        EvaluationKeys::from_bundle(bundle)
    })
    .map_err(|_| "geometria interna del bundle non valida".to_string())?
}

fn json_quote(s: &str) -> String {
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

fn encode_probe_coefficients(
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

fn main() {
    // Install the qualified numerical policy before any key generation or loading.
    let fft_plan = install_fixed_fft_plan();
    let threads = std::env::var("RAYON_NUM_THREADS")
        .map(|value| {
            value
                .parse::<usize>()
                .expect("RAYON_NUM_THREADS must be an integer")
        })
        .unwrap_or(16);
    assert_eq!(threads, 16, "this service is qualified for exactly 16 Rayon threads");
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .expect("initialize the service thread pool");
    eprintln!("runtime: threads={threads} fft_policy={FFT_PLAN_POLICY} fft_plan={fft_plan}");
    runtime::initialize();
    let a: Vec<String> = std::env::args().collect();
    let modulus = CiphertextModulus::<u64>::new_native();
    match a.get(1).map(String::as_str) {
        Some("export-phase-key") => {
            assert_eq!(a.len(), 4, "export-phase-key requires a fresh experiment key directory and new private output");
            let destination = Path::new(&a[3]);
            assert!(!destination.exists(), "phase key export never overwrites an existing artifact");
            let bound = std::fs::read(Path::new(&a[2]).join("client.key")).expect("local fresh client key");
            assert!(bound.len() <= 1024 * 1024, "bounded client key");
            let payload = decode_bound_key(&bound, CLIENT_KEY_MAGIC).expect("current client binding");
            let client: ClientKey = bincode::DefaultOptions::new().with_fixint_encoding().with_limit(1024 * 1024)
                .reject_trailing_bytes().deserialize(payload).expect("exact client key");
            assert!(client_key_compatibile_con_params(&client));
            let (secret, _) = client.encryption_key_and_noise();
            assert_eq!(secret.lwe_dimension().0, 2048);
            assert!(secret.as_ref().iter().all(|word| *word <= 1));
            let bytes: Vec<u8> = secret.as_ref().iter().flat_map(|word| word.to_le_bytes()).collect();
            atomic_write(destination, &bytes, 0o600).expect("private diagnostic key output");
            println!("{}", serde_json::json!({"schema":"local-phase-key-export.v1","words":2048,
                "sha256":sha256_hex(&bytes),"scope":"fresh experiment only; never upload this private file"}));
        }
        Some("rebind-v8") => {
            assert_eq!(a.len(), 4, "rebind-v8 requires an old key directory and a new destination");
            println!("{}", rebind::keys(Path::new(&a[2]), Path::new(&a[3])).expect("strict v8 key rebind"));
        }
        Some("rebind-probe-v8") => {
            assert_eq!(a.len(), 4, "rebind-probe-v8 requires an old probe and a new destination");
            println!("{}", rebind::probe(Path::new(&a[2]), Path::new(&a[3])).expect("strict v8 probe rebind"));
        }
        Some("plan-json") => {
            assert_eq!(a.len(), 3, "plan-json requires a public template fixture");
            println!("{}", rebind::plan(Path::new(&a[2])).expect("admitted public template plan"));
        }
        Some("counts-base") => {
            assert!(
                (4..=5).contains(&a.len()),
                "counts-base is an incomplete structural baseline; use plan-json for actual template counts"
            );
            let n: usize = a[2].parse().expect("integer gallery size");
            let mode = dispatch::mode_from_cli(&a[3], a.get(4).map(String::as_str))
                .expect("explicit structural mode");
            let counts = service::operation_counts(n, mode).expect("valid gallery size and mode");
            let mut receipt = metadata::counts_json(counts);
            let fields = receipt.as_object_mut().expect("count object");
            fields.insert("scope".into(), serde_json::json!("baseline before public threshold/digit savings; use plan-json for an actual template ledger"));
            fields.insert("n".into(), serde_json::json!(n));
            fields.insert(
                "execution_mode".into(),
                serde_json::json!(dispatch::mode_name(mode)),
            );
            fields.insert(
                "sentinel_score".into(),
                serde_json::json!(dispatch::sentinel_score(mode)),
            );
            fields.insert(
                "endpoint".into(),
                serde_json::json!(dispatch::endpoint_name(mode)),
            );
            fields.insert("structural_only".into(), serde_json::json!(true));
            println!("{receipt}");
        }
        Some("mutate-bundle") => {
            assert_eq!(
                a.len(),
                5,
                "mutate-bundle requires source, destination, mutation"
            );
            let bound = std::fs::read(&a[2]).expect("public evaluation bundle");
            let payload =
                decode_bound_key(&bound, SERVER_KEY_MAGIC).expect("current bundle envelope");
            let bundle: ServerBundle =
                bincode::deserialize(payload).expect("valid diagnostic source bundle");
            drop(bound);
            let changed = bundle
                .diagnostic_payload(&a[4])
                .expect("fixed public bundle diagnostic");
            let envelope = encode_bound_key(SERVER_KEY_MAGIC, &changed);
            assert!(envelope.len() <= MAX_SERVER_KEY_BODY_BYTES);
            atomic_write(Path::new(&a[3]), &envelope, 0o600)
                .expect("private diagnostic destination");
            println!(
                "{{\"mutation\":{},\"bytes\":{},\"sha256\":{}}}",
                json_quote(&a[4]),
                envelope.len(),
                json_quote(&sha256_hex(&envelope))
            );
        }
        // ------------------------------------------------ client: chiavi
        Some("keygen") => {
            assert_eq!(a.len(), 3, "keygen requires one new private key directory");
            let dir = Path::new(&a[2]);
            for name in ["client.key", "server.key", "g4.key"] {
                assert!(!dir.join(name).exists(), "keygen never overwrites an existing key artifact");
            }
            ensure_private_directory(dir).unwrap();
            let t0 = Instant::now();
            let ck = ClientKey::new(PARAMS);
            let sk = ServerKey::new(&ck);
            let client_path = dir.join("client.key");
            let server_path = dir.join("server.key");
            let client_payload = bincode::serialize(&ck).unwrap();
            let bundle = pfks_core::service::generate_bundle(&ck, sk).unwrap();
            let server_payload = bincode::serialize(&bundle).unwrap();
            drop(bundle);
            let roundtrip: ServerBundle =
                bincode::deserialize(&server_payload).expect("actual bundle roundtrip decode");
            let roundtrip_bytes =
                bincode::serialize(&roundtrip).expect("actual bundle roundtrip encode");
            assert_eq!(
                server_payload, roundtrip_bytes,
                "actual serialized bundle roundtrip changed bytes"
            );
            drop(roundtrip_bytes);
            let checked = EvaluationKeys::from_bundle(roundtrip)
                .expect("actual selected bundle validation before writing");
            drop(checked);
            let server_envelope = encode_bound_key(SERVER_KEY_MAGIC, &server_payload);
            assert!(
                server_envelope.len() <= MAX_SERVER_KEY_BODY_BYTES,
                "serialized server bundle exceeds the fixed HTTP upload limit"
            );
            atomic_write(
                &client_path,
                &encode_bound_key(CLIENT_KEY_MAGIC, &client_payload),
                0o600,
            )
            .unwrap();
            atomic_write(&server_path, &server_envelope, 0o600).unwrap();
            let supplemental = supplement::generate(&ck, &server_envelope, &dir.join("g4.key"))
                .expect("optional G4 sidecar generation");
            atomic_write(&dir.join("supplement-setup.json"), supplemental.to_string().as_bytes(), 0o600).unwrap();
            println!(
                "{{\"bundle_roundtrip_equal\":true,\"bundle_validation_pass\":true,\"server_payload_b\":{},\"server_envelope_sha256\":{},\"keygen_s\":{:.2},\"client_key_b\":{},\"server_key_b\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
                server_payload.len(), json_quote(&sha256_hex(&server_envelope)),
                t0.elapsed().as_secs_f64(),
                std::fs::metadata(client_path).unwrap().len(),
                std::fs::metadata(server_path).unwrap().len(),
                json_quote(A44_PARAMS_ID),
                json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                json_quote(VARIANT_ID),
                json_quote(CIRCUIT_SHA256),
            );
        }
        // ------------------------------------------------ client: cifra il probe (un GLWE)
        Some("encrypt") => {
            assert_eq!(a.len(), 6, "encrypt requires one explicit head51 profile");
            let profile = QueryProfile::from_cli(&a[5]).expect("named query profile");
            let (dir, probe_path, out) = (&a[2], &a[3], &a[4]);
            let key_bytes = std::fs::read(format!("{dir}/client.key")).unwrap();
            let key_payload = decode_bound_key(&key_bytes, CLIENT_KEY_MAGIC)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            let ck: ClientKey = bincode::deserialize(key_payload)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            assert!(
                client_key_compatibile_con_params(&ck),
                "chiave client incompatibile con il profilo A44 fast mixed"
            );
            let (glwe_sk, _, params, _) = match ck.atomic_pattern {
                AtomicPatternClientKey::Standard(key) => key.into_raw_parts(),
                _ => panic!("richiesta client key Standard TFHE 1.7"),
            };
            let poly = glwe_sk.polynomial_size();
            let probe: Vec<i64> = std::fs::read_to_string(probe_path)
                .unwrap()
                .split_whitespace()
                .map(|x| x.parse().unwrap())
                .collect();
            let t0 = Instant::now();
            let coeff = encode_probe_coefficients(&probe, poly.0, profile)
                .unwrap_or_else(|e| panic!("probe non valido: {e}"));
            let mut boxed = new_seeder();
            let seeder = boxed.as_mut();
            let mut gen =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let mut glwe =
                GlweCiphertext::new(0u64, glwe_sk.glwe_dimension().to_glwe_size(), poly, modulus);
            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &PlaintextList::from_container(coeff),
                params.glwe_noise_distribution(),
                &mut gen,
            );
            let header = probe_header(poly.0, glwe_sk.glwe_dimension().0, profile);
            scrivi_u64(out, &header, &[glwe.as_ref()]);
            println!(
                "{{\"query_profile\":{},\"query_profile_id\":{},\"score_delta_log\":{},\"encrypt_ms\":{:.2},\"probe_ct_b\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
                json_quote(profile.name()), profile.wire(), profile.score_delta_log(),
                t0.elapsed().as_secs_f64() * 1000.0,
                std::fs::metadata(out).unwrap().len(),
                json_quote(A44_PARAMS_ID),
                json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                json_quote(VARIANT_ID),
                json_quote(CIRCUIT_SHA256),
            );
        }
        // ------------------------------------------------ client: decifra l'esito
        Some("decrypt") => {
            let (dir, ct_path) = (&a[2], &a[3]);
            let key_bytes = std::fs::read(format!("{dir}/client.key")).unwrap();
            let key_payload = decode_bound_key(&key_bytes, CLIENT_KEY_MAGIC)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            let ck: ClientKey = bincode::deserialize(key_payload)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            assert!(
                client_key_compatibile_con_params(&ck),
                "chiave client incompatibile con il profilo A44 fast mixed"
            );
            let (enc_key, _) = ck.encryption_key_and_noise();
            let (hdr, dati) = bytes_to_u64(&std::fs::read(ct_path).unwrap())
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            let header = decode_output_header(&hdr)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            let [low_words, middle_words, high_words] = output_digit_words(&header, &dati)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            let expected_lwe_size = enc_key.lwe_dimension().to_lwe_size().0;
            assert_eq!(
                header.lwe_size, expected_lwe_size,
                "esito cifrato non valido: lwe_size incompatibile con la chiave client"
            );
            let low_ct = LweCiphertext::from_container(low_words, modulus);
            let middle_ct = LweCiphertext::from_container(middle_words, modulus);
            let high_ct = LweCiphertext::from_container(high_words, modulus);
            let low = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &low_ct).0)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: low: {e}"));
            let middle = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &middle_ct).0)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: middle: {e}"));
            let high = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &high_ct).0)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: high: {e}"));
            let code = reconstruct_code(low, middle, high, header.gallery_size)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            println!(
                "{}",
                serde_json::json!({
                    "query_profile": header.profile.name(),
                    "query_profile_id": header.profile.wire(),
                    "autorizzato": code != 0,
                    "indice": code.checked_sub(1),
                    "codice": code,
                    "low": low,
                    "middle": middle,
                    "high": high,
                    "iscritti": header.gallery_size,
                    "galleria_epoch": header.epoch,
                    "galleria_revision": header.revision,
                    "params_id": A44_PARAMS_ID,
                    "params_fingerprint_sha256": A44_PARAMETER_FINGERPRINT_SHA256,
                    "variant_id": VARIANT_ID,
                    "circuit_sha256": CIRCUIT_SHA256,
                })
            );
        }
        // ------------------------------------------------ server: il servizio
        Some("serve") => {
            let porta: u16 = a[2].parse().unwrap();
            let dim: usize = a.get(3).map(|s| s.parse().unwrap()).unwrap_or(512);
            let t: i64 = a.get(4).map(|s| s.parse().unwrap()).unwrap_or(0);
            assert_eq!(dim, PROBE_DIM, "varco_demo supporta dim={PROBE_DIM}");
            let stato = Mutex::new(Galleria {
                dim,
                t_default: t,
                iscritti: Vec::new(),
                chiave: None,
                chiave_sha256: None,
            g4_sha256: None,
                epoch: process_epoch(),
                revision: 0,
            });
            let l = TcpListener::bind(("127.0.0.1", porta)).unwrap();
            println!("varco fast uniform/mixed in ascolto su 127.0.0.1:{porta} | dim={dim} T={t} | Delta_score=2^51, Delta_low=2^{LOG_LOW_MOD16_DELTA}, Delta_digit=2^{LOG_DIGIT_DELTA}, base={OUTPUT_DIGIT_BASE} | params_id={A44_PARAMS_ID} fingerprint={A44_PARAMETER_FINGERPRINT_SHA256} variant={VARIANT_ID} circuit={CIRCUIT_SHA256}");
            println!(
                "il server NON ha la chiave segreta: riceve byte cifrati e ne restituisce altri."
            );
            for s in l.incoming().flatten() {
                gestisci(s, &stato, modulus);
            }
        }
        _ => eprintln!(
            "uso: varco_demo_fast_mixed keygen <dir> | encrypt <dir> <probe.txt> <out> head51 | \
                        decrypt <dir> <esito.ct> | serve <porta> <dim> <T_default>"
        ),
    }
}

// ---------------------------------------------------------------- HTTP minimale (solo std)
fn body_limit(metodo: &str, path: &str) -> Option<usize> {
    match (metodo, path) {
        ("POST", "/chiave") => Some(MAX_SERVER_KEY_BODY_BYTES),
        ("POST", "/g4-key") => Some(MAX_G4_KEY_BODY_BYTES),
        ("POST", "/iscrivi") => Some(MAX_ENROLLMENT_BODY_BYTES),
        ("POST", "/varco") => Some(MAX_PROBE_BODY_BYTES),
        ("POST", "/reset") | ("GET", "/stato") => Some(0),
        _ => None,
    }
}

fn gestisci(mut s: TcpStream, stato: &Mutex<Galleria>, modulus: CiphertextModulus<u64>) {
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut riga = String::new();
    if r.read_line(&mut riga).is_err() || riga.is_empty() {
        return;
    }
    let parti: Vec<&str> = riga.split_whitespace().collect();
    if parti.len() < 2 {
        return;
    }
    let (metodo, path) = (parti[0].to_string(), parti[1].to_string());
    let mut len = None;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        let hl = h.to_ascii_lowercase();
        if let Some(v) = hl.strip_prefix("content-length:") {
            if len.is_some() {
                return risposta(
                    &mut s,
                    400,
                    "application/json",
                    String::new(),
                    b"{\"errore\":\"header Content-Length duplicato\"}".to_vec(),
                );
            }
            len = match v.trim().parse::<usize>() {
                Ok(value) => Some(value),
                Err(_) => {
                    return risposta(
                        &mut s,
                        400,
                        "application/json",
                        String::new(),
                        b"{\"errore\":\"header Content-Length non valido\"}".to_vec(),
                    );
                }
            };
        }
    }
    let Some(max_body) = body_limit(&metodo, &path) else {
        return risposta(
            &mut s,
            404,
            "application/json",
            String::new(),
            b"{\"errore\":\"non trovato\"}".to_vec(),
        );
    };
    let len = len.unwrap_or(0);
    if len > max_body {
        return risposta(
            &mut s,
            413,
            "application/json",
            String::new(),
            format!(
                "{{\"errore\":\"corpo troppo grande per {metodo} {path}: {len} byte, massimo {max_body}\"}}"
            )
            .into_bytes(),
        );
    }
    let mut corpo = vec![0u8; len];
    if len > 0 && r.read_exact(&mut corpo).is_err() {
        return;
    }

    let (codice, tipo, extra, body): (u16, &str, String, Vec<u8>) = match (
        metodo.as_str(),
        path.as_str(),
    ) {
        ("POST", "/chiave") => {
            let fingerprint = sha256_hex(&corpo);
            let mut g = stato.lock().unwrap();
            match g.chiave_sha256.as_deref() {
                Some(existing) if existing == fingerprint => (
                    200,
                    "application/json",
                    String::new(),
                    format!(
                        "{{\"ok\":true,\"idempotente\":true,\"chiave_sha256\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
                        json_quote(&fingerprint),
                        json_quote(A44_PARAMS_ID),
                        json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                        json_quote(VARIANT_ID),
                        json_quote(CIRCUIT_SHA256),
                    )
                    .into_bytes(),
                ),
                Some(_) => (
                    409,
                    "application/json",
                    String::new(),
                    b"{\"errore\":\"una chiave di valutazione diversa e' gia' installata; riavviare il server per cambiarla\"}".to_vec(),
                ),
                None => match deserialize_bound_server_key(&corpo) {
                    Ok(k) => {
                        g.chiave = Some(k);
                        g.chiave_sha256 = Some(fingerprint.clone());
                        (
                            200,
                            "application/json",
                            String::new(),
                            format!(
                                "{{\"ok\":true,\"idempotente\":false,\"chiave_sha256\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
                                json_quote(&fingerprint),
                                json_quote(A44_PARAMS_ID),
                                json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                                json_quote(VARIANT_ID),
                                json_quote(CIRCUIT_SHA256),
                            )
                            .into_bytes(),
                        )
                    }
                    Err(e) => (
                        400,
                        "application/json",
                        String::new(),
                        format!("{{\"errore\":{}}}", json_quote(&format!("chiave non valida: {e}")))
                            .into_bytes(),
                    ),
                },
            }
        }
        ("POST", "/g4-key") => {
            let mut g = stato.lock().unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| supplement::upload(&mut g, &corpo)))
                .unwrap_or_else(|_| Err("invalid G4 key geometry or installation state".into()));
            match result {
                Ok(value) => (200, "application/json", String::new(), value.to_string().into_bytes()),
                Err(error) => (400, "application/json", String::new(), serde_json::json!({"errore":error}).to_string().into_bytes()),
            }
        }
        ("POST", "/iscrivi") => {
            let testo = String::from_utf8_lossy(&corpo);
            let mut righe = testo.splitn(2, '\n');
            let intestazione = righe.next().unwrap_or("?").trim();
            let v: Vec<i64> = match righe
                .next()
                .unwrap_or("")
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<_, _>>()
            {
                Ok(v) => v,
                Err(_) => {
                    return risposta(
                        &mut s,
                        400,
                        "application/json",
                        String::new(),
                        format!(
                            "{{\"errore\":{}}}",
                            json_quote(
                                "template non valido: ogni coefficiente deve essere un intero"
                            )
                        )
                        .into_bytes(),
                    );
                }
            };
            let mut g = stato.lock().unwrap();
            let mut campi = intestazione.splitn(2, '\t');
            let nome = campi.next().unwrap_or("?").trim().to_string();
            let t = match campi.next() {
                Some(x) => match x.trim().parse::<i64>() {
                    Ok(t) => t,
                    Err(_) => {
                        return risposta(
                            &mut s,
                            400,
                            "application/json",
                            String::new(),
                            format!(
                                "{{\"errore\":{}}}",
                                json_quote("soglia di enrollment non valida")
                            )
                            .into_bytes(),
                        );
                    }
                },
                None => g.t_default,
            };
            match upsert_entry(&mut g, nome, v, t) {
                Ok((index, metadata)) => (
                    200,
                    "application/json",
                    String::new(),
                    metadata::enrollment_json(&g, index, t, metadata)
                        .to_string()
                        .into_bytes(),
                ),
                Err(e) => (
                    400,
                    "application/json",
                    String::new(),
                    format!("{{\"errore\":{}}}", json_quote(&e)).into_bytes(),
                ),
            }
        }
        ("POST", "/varco") => {
            let g = stato.lock().unwrap();
            if g.chiave.is_none() {
                (
                    400,
                    "application/json",
                    String::new(),
                    b"{\"errore\":\"chiave di valutazione mancante\"}".to_vec(),
                )
            } else if runtime::mode().uses_g4() && g.g4_sha256.is_none() {
                (400, "application/json", String::new(), b"{\"errore\":\"chiave G4 mancante\"}".to_vec())
            } else if g.iscritti.is_empty() {
                (
                    400,
                    "application/json",
                    String::new(),
                    b"{\"errore\":\"galleria vuota\"}".to_vec(),
                )
            } else {
                let t0 = Instant::now();
                match varco(&g, &corpo, modulus) {
                    Ok((out, counts)) => {
                        let n_pbs = counts.br;
                        let n_pfks = counts.pfks;
                        let n_ks = counts.ks;
                        let n_marginals = counts.marginals;
                        let n_initial = counts.initial_samples;
                        let query_profile = QueryProfile::for_gallery(g.iscritti.len())
                            .expect("admitted gallery")
                            .name();
                        let ms = t0.elapsed().as_secs_f64() * 1000.0;
                        (
                            200,
                            "application/octet-stream",
                            format!(
                                "X-Tempo-Ms: {ms:.1}\r\nX-Pbs: {n_pbs}\r\nX-Pfks: {n_pfks}\r\nX-Ks: {n_ks}\r\nX-Marginals: {n_marginals}\r\nX-Initial-Samples: {n_initial}\r\n\
                                 X-Varco-Contract: {HTTP_CONTRACT}\r\n\
                                 X-Varco-Params-Id: {A44_PARAMS_ID}\r\n\
                                 X-Varco-Params-Fingerprint: {A44_PARAMETER_FINGERPRINT_SHA256}\r\n\
                                 X-Varco-Variant-Id: {VARIANT_ID}\r\n\
                                 X-Varco-Circuit-Sha256: {CIRCUIT_SHA256}\r\nX-Varco-Query-Profile: {query_profile}\r\n"
                            ),
                            out,
                        )
                    }
                    Err(e) => (
                        400,
                        "application/json",
                        String::new(),
                        format!("{{\"errore\":{}}}", json_quote(&e)).into_bytes(),
                    ),
                }
            }
        }
        ("GET", "/stato") => {
            let g = stato.lock().unwrap();
            match metadata::status_json(&g) {
                Ok(status) => (
                    200,
                    "application/json",
                    String::new(),
                    status.to_string().into_bytes(),
                ),
                Err(error) => (
                    500,
                    "application/json",
                    String::new(),
                    serde_json::json!({"errore": error})
                        .to_string()
                        .into_bytes(),
                ),
            }
        }
        ("POST", "/reset") => {
            let mut g = stato.lock().unwrap();
            match reset_gallery(&mut g) {
                Ok(()) => (
                    200,
                    "application/json",
                    String::new(),
                    format!(
                        "{{\"ok\":true,\"galleria_epoch\":{},\"galleria_revision\":{}}}",
                        g.epoch, g.revision
                    )
                    .into_bytes(),
                ),
                Err(e) => (
                    500,
                    "application/json",
                    String::new(),
                    format!("{{\"errore\":{}}}", json_quote(&e)).into_bytes(),
                ),
            }
        }
        _ => (
            404,
            "application/json",
            String::new(),
            b"{\"errore\":\"non trovato\"}".to_vec(),
        ),
    };

    risposta(&mut s, codice, tipo, extra, body);
}

fn risposta(s: &mut TcpStream, codice: u16, tipo: &str, extra: String, body: Vec<u8>) {
    let motivo = match codice {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Response",
    };
    let testa = format!(
        "HTTP/1.1 {codice} {motivo}\r\nContent-Type: {tipo}\r\nContent-Length: {}\r\n\
                         Access-Control-Allow-Origin: *\r\n{extra}\r\n",
        body.len()
    );
    let _ = s.write_all(testa.as_bytes());
    let _ = s.write_all(&body);
    let _ = s.flush();
}

// ---------------------------------------------------------------- core argmin esatto
// Native full51 input, actual template-derived uniform/mixed plan, three separate output roots.
fn varco(
    g: &Galleria,
    probe_ct: &[u8],
    modulus: CiphertextModulus<u64>,
) -> Result<(Vec<u8>, dispatch::Counts), String> {
    let ssk = g.chiave.as_ref().ok_or("chiave di valutazione mancante")?;
    let standard = match &ssk.ordinary().atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => return Err("richiesta server key Standard TFHE 1.7".to_string()),
    };
    let fbsk = match &standard.bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => bsk,
        _ => return Err("attesa bootstrapping key classica".to_string()),
    };
    let (hdr, dati) = bytes_to_u64(probe_ct)?;
    let header = decode_probe_header(&hdr)?;
    header.profile.validate_gallery(g.iscritti.len())?;
    let poly = fbsk.polynomial_size();
    let k = fbsk.glwe_size().to_glwe_dimension();
    if header.polynomial_size != poly.0 || header.glwe_dimension != k.0 {
        return Err("geometria del probe incompatibile con la chiave di valutazione".to_string());
    }
    if header.embedding_dim != g.dim {
        return Err(format!(
            "dimensione del probe {} diversa da quella del server {}",
            header.embedding_dim, g.dim
        ));
    }
    if LOW_MOD16_OFFSET + g.dim > poly.0 {
        return Err("layout duale incompatibile con la polynomial_size".to_string());
    }
    let expected_words =
        fbsk.glwe_size().0.checked_mul(poly.0).ok_or_else(|| {
            "geometria della chiave di valutazione non rappresentabile".to_string()
        })?;
    if dati.len() != expected_words {
        return Err(format!(
            "corpo del probe di lunghezza errata: {} parole, attese {expected_words}",
            dati.len()
        ));
    }

    let templates = template_views(&g.iscritti);
    let packed_probe = GlweCiphertext::from_container(dati, poly, modulus);
    let (low, middle, high, counts) =
        dispatch::evaluate(ssk, &packed_probe, &templates, header.profile)?;
    Ok((serialize_exact_output(g, &low, &middle, &high)?, counts))
}

#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod threshold_tests;
