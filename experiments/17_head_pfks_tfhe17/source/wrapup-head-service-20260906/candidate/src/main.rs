// Il varco come SERVIZIO: i due ruoli separati. Nella singola verifica, dopo setup ed enrollment,
// probe ed esito attraversano il confine cifrati; galleria e metadati di controllo sono in chiaro.
//
// Il wire format A126 e' quello dell'identificazione open-set esatta: il client cifra nello stesso
// GLWE sia i coefficienti interi a Delta=2^51 (N127) o 2^52 (altri N) sia i loro residui modulo 16 a Delta=2^60. Il server
// restituisce due LWE p16 non combinati. Il client decifra `low` e `high`, poi ricostruisce
// `code = low + 15*high`: 0=rifiuto oppure indice+1=identita' accettata.
//
//   client (terminale fidato)   keygen, encrypt, decrypt: ha la chiave segreta, non la manda mai
//   server (macchina remota)    serve: ha la galleria IN CHIARO e la chiave di valutazione,
//                               calcola sul cifrato, non puo' decifrare nulla
//
// Sottocomandi:
//   varco_demo keygen  <dir>                    -> <dir>/client.key (segreta), <dir>/server.key (valutazione)
//   varco_demo encrypt <dir> <probe.txt> <out> <head51|legacy52>  -> probe cifrato: UN GLWE, doppio layout
//   varco_demo decrypt <dir> <esito.ct>         -> decisione + indice verificati fail-closed
//   varco_demo serve   <porta> <dim> <T_default>
//
// Il server espone un HTTP minimale (solo std::net, nessuna dipendenza):
//   POST /chiave    corpo = server.key                      (una volta, all'avvio del client)
//   POST /iscrivi   corpo = "nome[\\tT]\nv1 v2 ... vdim"     (template IN CHIARO: e' la galleria del server)
//   POST /varco     corpo = probe cifrato                   -> esito cifrato (+ header di misura/stato)
//   GET  /stato     -> JSON con iscritti, chiave presente, parametri
//   POST /reset     svuota la galleria
mod dispatch;
mod profile;
use profile::QueryProfile;
use bincode::Options;
use pfks_core::service::{EvaluationKeys, ServerBundle};
use pipeline_tfhe_rs::MAX_DOMAIN_WIDTH as SCORE_DOMAIN_MAX_WIDTH;
use pipeline_tfhe_rs::{
    plan_private_argmin_execution,
    validate_a44_parameter_binding, PrivateArgminExecutionPlan, ScoreDomain,
    TemplateView, A44_PARAMETER_BINDING, A44_PARAMETER_FINGERPRINT_SHA256, A44_PARAMS_ID,
    BOOL_DELTA_LOG as LOG_DIGIT_DELTA, FULL_DELTA_LOG as LOG_SCORE_DELTA,
    LOW_MOD16_DELTA_LOG as LOG_LOW_MOD16_DELTA, LOW_MOD16_POLYNOMIAL_OFFSET as LOW_MOD16_OFFSET,
    MAX_GALLERY_SIZE as MAX_GALLERY, PROBE_DIM, PROBE_NORM2_MAX,
};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64 as PARAMS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::{ClientKey, ServerKey};

const Q_MAX: i64 = 3;

const HTTP_CONTRACT: &str = "exact-open-set-id-v7-head-mean127-b22-uniform-a126-tfhe17-base15-two-lwe";
const VARIANT_ID: &str = "head-mean127-b22-uniform-a126-tfhe17-base15-two-p16-v1";
const CIRCUIT_SHA256: &str = "70ad93af0aa30a52e466c880da8c1a9c3b66e59d3326a565299ff19ace7de536";
const WIRE_VERSION: u64 = 7;
const PROBE_MAGIC: u64 = u64::from_le_bytes(*b"VRCOPR17");
const OUTPUT_MAGIC: u64 = u64::from_le_bytes(*b"VRCOUT17");
const CLIENT_KEY_MAGIC: u64 = u64::from_le_bytes(*b"VRCCK17!");
const SERVER_KEY_MAGIC: u64 = u64::from_le_bytes(*b"VRCHD17!");
const PROBE_LAYOUT_DUAL_SAME_GLWE: u64 = 1;
const OUTPUT_MODE_EXACT_ID_TWO_LWE: u64 = 4;
const OUTPUT_LWES: usize = 2;
const OUTPUT_DIGIT_BASE: usize = 15;
const PROBE_FIXED_HEADER_WORDS: usize = 9;
const OUTPUT_FIXED_HEADER_WORDS: usize = 11;
const BINDING_LENGTH_WORDS: usize = 4;
const KEY_ENVELOPE_FIXED_BYTES: usize = 7 * 8;

// Limiti applicati al Content-Length prima di allocare il body. La evaluation key corrente e'
// circa 307 MB inclusi PFKS e Head; 320 MiB e' verificato sui byte serializzati dal client.
const MAX_SERVER_KEY_BODY_BYTES: usize = 320 * 1024 * 1024;
const MAX_PROBE_BODY_BYTES: usize = 64 * 1024;
const MAX_ENROLLMENT_BODY_BYTES: usize = 8 * 1024;

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

fn append_a126_binding(header: &mut Vec<u64>) {
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

fn validate_a126_wire_binding(header: &[u64], fixed_words: usize) -> Result<(), String> {
    let expected_words = expected_bound_header_words(fixed_words);
    if header.len() != expected_words {
        return Err(format!(
            "header A126: {} parole, attese {expected_words}; wire A44/v2 non supportati",
            header.len()
        ));
    }
    let mut expected = vec![0u64; fixed_words];
    append_a126_binding(&mut expected);
    if header[fixed_words..] != expected[fixed_words..] {
        return Err("binding parametri/variante/circuito A126 errato".to_string());
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
        return Err("chiave senza envelope A126; formati A44/A38/A41 non supportati".to_string());
    }
    let words: Vec<u64> = data[..KEY_ENVELOPE_FIXED_BYTES]
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("chunk da 8 byte")))
        .collect();
    if words[0] != expected_magic {
        return Err("magic della chiave non A126; formati A44/A38/A41 non supportati".to_string());
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
#[allow(dead_code)] // `template` viene consumato dal core argmin, collegato separatamente.
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
    epoch: u64,
    revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgminPath {
    A126Base15TwoLwe,
    A29General,
}

impl ArgminPath {
    fn from_plan(plan: PrivateArgminExecutionPlan) -> Self {
        if plan.aligned_fast_path {
            Self::A126Base15TwoLwe
        } else {
            Self::A29General
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::A126Base15TwoLwe => "uniform_aligned_base15_domain",
            Self::A29General => "a29_general",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GalleryExecutionMetadata {
    enrollment_domain: ScoreDomain,
    execution_domain: ScoreDomain,
    path: ArgminPath,
    endpoint_fhe: &'static str,
    endpoint_domain_supported: bool,
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
    let plan = plan_private_argmin_execution(&templates)
        .map_err(|error| format!("galleria non valida per l'argmin esatto: {error}"))?;
    Ok(Some(GalleryExecutionMetadata {
        enrollment_domain: plan.cauchy_domain,
        execution_domain: plan.execution_domain,
        path: ArgminPath::from_plan(plan),
        endpoint_fhe: dispatch::endpoint_name(entries.len()),
        endpoint_domain_supported: plan.aligned_fast_path,
    }))
}

fn domain_json(domain: ScoreDomain) -> String {
    format!(
        "{{\"l\":{},\"u\":{},\"larghezza\":{}}}",
        domain.lower,
        domain.upper,
        domain_width(domain).expect("dominio validato e rappresentabile")
    )
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
    if metadata.enrollment_domain != domain {
        return Err("dominio Cauchy incoerente tra servizio e core argmin".to_string());
    }
    if metadata.path != ArgminPath::A126Base15TwoLwe {
        return Err(
            "A126 base-15 richiede soglia uniforme e dominio allineabile; fallback A29 disabilitato"
                .to_string(),
        );
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
    validate_a126_wire_binding(header, PROBE_FIXED_HEADER_WORDS)?;
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
    Ok(ProbeHeader {
        profile,
        polynomial_size: usize::try_from(header[3])
            .map_err(|_| "polynomial_size del probe non rappresentabile".to_string())?,
        glwe_dimension: usize::try_from(header[4])
            .map_err(|_| "glwe_dimension del probe non rappresentabile".to_string())?,
        embedding_dim: usize::try_from(header[5])
            .map_err(|_| "dimensione dell'embedding non rappresentabile".to_string())?,
    })
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
    validate_a126_wire_binding(header, OUTPUT_FIXED_HEADER_WORDS)?;
    if header[0] != OUTPUT_MAGIC {
        return Err("magic dell'esito sconosciuto".to_string());
    }
    if header[1] != WIRE_VERSION {
        return Err(format!("versione dell'esito non supportata: {}", header[1]));
    }
    if header[2] != OUTPUT_MODE_EXACT_ID_TWO_LWE {
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
    if lwe_size != 2049 {
        return Err("output LWE size must be2049".into());
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
    append_a126_binding(&mut header);
    header
}

fn output_header(g: &Galleria, lwe_size: usize) -> Vec<u64> {
    let mut header = vec![
        OUTPUT_MAGIC,
        WIRE_VERSION,
        OUTPUT_MODE_EXACT_ID_TWO_LWE,
        g.epoch,
        g.revision,
        g.iscritti.len() as u64,
        lwe_size as u64,
        u64::from(LOG_DIGIT_DELTA),
        OUTPUT_LWES as u64,
        OUTPUT_DIGIT_BASE as u64,
        QueryProfile::for_gallery(g.iscritti.len()).expect("nonempty admitted gallery").wire(),
    ];
    append_a126_binding(&mut header);
    header
}

fn serialize_exact_output(
    g: &Galleria,
    low: &LweCiphertextOwned<u64>,
    high: &LweCiphertextOwned<u64>,
) -> Result<Vec<u8>, String> {
    if low.lwe_size() != high.lwe_size() || low.lwe_size().0 != 2049 {
        return Err("le due cifre A126 hanno geometrie LWE diverse".to_string());
    }
    Ok(u64_to_bytes(
        &output_header(g, low.lwe_size().0),
        &[low.as_ref(), high.as_ref()],
    ))
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

fn reconstruct_code(low: usize, high: usize, gallery_size: usize) -> Result<usize, String> {
    if low >= OUTPUT_DIGIT_BASE || high >= OUTPUT_DIGIT_BASE {
        return Err(format!(
            "cifre p16 fuori intervallo: low={low}, high={high}"
        ));
    }
    let code = high
        .checked_mul(OUTPUT_DIGIT_BASE)
        .and_then(|value| value.checked_add(low))
        .ok_or_else(|| "codice ricostruito non rappresentabile".to_string())?;
    if code > gallery_size {
        return Err(format!(
            "codice ricostruito fuori intervallo: {code}, massimo {gallery_size}"
        ));
    }
    Ok(code)
}

/// Questo controllo verifica solo che la chiave abbia geometria e decomposizioni di `PARAMS`.
/// Non autentica il binding con la client key e non rende il `log2_p_fail` nominale una garanzia
/// per il circuito low-level composto o per la decodifica finale.
fn chiave_compatibile_con_params(chiave: &ServerKey) -> bool {
    validate_a44_parameter_binding(A44_PARAMETER_BINDING, chiave).is_ok()
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
    }).map_err(|_| "geometria interna del bundle non valida".to_string())?
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

fn encode_probe_coefficients(probe: &[i64], polynomial_size: usize, profile: QueryProfile) -> Result<Vec<u64>, String> {
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
    let a: Vec<String> = std::env::args().collect();
    let modulus = CiphertextModulus::<u64>::new_native();
    match a.get(1).map(String::as_str) {
        Some("counts") => {
            let n: usize = a[2].parse().unwrap();
            let c = dispatch::counts(n).expect("gallery range 1..128");
            println!(
                "{{\"n\":{},\"br\":{},\"ks\":{},\"marginals\":{},\"pfks\":{},\"initial_samples\":{},\"endpoint\":{}}}",
                n, c.br, c.ks, c.marginals, c.pfks, c.initial_samples, json_quote(dispatch::endpoint_name(n))
            );
        }
        Some("mutate-bundle") => {
            assert_eq!(a.len(), 5, "mutate-bundle requires source, destination, mutation");
            let bound = std::fs::read(&a[2]).expect("public evaluation bundle");
            let payload = decode_bound_key(&bound, SERVER_KEY_MAGIC).expect("current bundle envelope");
            let bundle: ServerBundle = bincode::deserialize(payload).expect("valid diagnostic source bundle");
            drop(bound);
            let changed = bundle.diagnostic_payload(&a[4]).expect("fixed public bundle diagnostic");
            let envelope = encode_bound_key(SERVER_KEY_MAGIC, &changed);
            assert!(envelope.len() <= MAX_SERVER_KEY_BODY_BYTES);
            atomic_write(Path::new(&a[3]), &envelope, 0o600).expect("private diagnostic destination");
            println!("{{\"mutation\":{},\"bytes\":{},\"sha256\":{}}}", json_quote(&a[4]), envelope.len(), json_quote(&sha256_hex(&envelope)));
        }
        // ------------------------------------------------ client: chiavi
        Some("keygen") => {
            let dir = Path::new(&a[2]);
            ensure_private_directory(dir).unwrap();
            let t0 = Instant::now();
            let ck = ClientKey::new(PARAMS);
            let sk = ServerKey::new(&ck);
            let client_path = dir.join("client.key");
            let server_path = dir.join("server.key");
            let client_payload = bincode::serialize(&ck).unwrap();
            if a.get(3).map(String::as_str) == Some("--legacy-diagnostic") {
                let ordinary_payload = bincode::serialize(&sk).unwrap();
                let variant = "nibble127-r3-a126-a66-a53-tfhe17-base15-two-p16-v1";
                let circuit = "d6d4bc3080fdf181bf7abaa861f03b309709c41658386ad9d9fa52b4c51234b9";
                let mut legacy = Vec::new();
                for word in [u64::from_le_bytes(*b"VRCSK17!"), 5,
                    A44_PARAMS_ID.len() as u64, A44_PARAMETER_FINGERPRINT_SHA256.len() as u64,
                    variant.len() as u64, circuit.len() as u64, ordinary_payload.len() as u64] {
                    legacy.extend_from_slice(&word.to_le_bytes());
                }
                for text in [A44_PARAMS_ID, A44_PARAMETER_FINGERPRINT_SHA256, variant, circuit] {
                    legacy.extend_from_slice(text.as_bytes());
                }
                legacy.extend_from_slice(&ordinary_payload);
                atomic_write(&dir.join("legacy-server.key"), &legacy, 0o600).unwrap();
            }
            let bundle = pfks_core::service::generate_bundle(&ck, sk).unwrap();
            let server_payload = bincode::serialize(&bundle).unwrap();
            drop(bundle);
            let roundtrip: ServerBundle = bincode::deserialize(&server_payload).expect("actual bundle roundtrip decode");
            let roundtrip_bytes = bincode::serialize(&roundtrip).expect("actual bundle roundtrip encode");
            assert_eq!(server_payload, roundtrip_bytes, "actual serialized bundle roundtrip changed bytes");
            drop(roundtrip_bytes);
            let checked = EvaluationKeys::from_bundle(roundtrip).expect("actual selected bundle validation before writing");
            drop(checked);
            let server_envelope = encode_bound_key(SERVER_KEY_MAGIC, &server_payload);
            assert!(server_envelope.len() <= MAX_SERVER_KEY_BODY_BYTES,
                    "serialized server bundle exceeds the fixed HTTP upload limit");
            atomic_write(
                &client_path,
                &encode_bound_key(CLIENT_KEY_MAGIC, &client_payload),
                0o600,
            )
            .unwrap();
            atomic_write(
                &server_path,
                &server_envelope,
                0o600,
            )
            .unwrap();
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
            assert_eq!(a.len(), 6, "encrypt requires one explicit head51 or legacy52 profile");
            let profile = QueryProfile::from_cli(&a[5]).expect("named query profile");
            let (dir, probe_path, out) = (&a[2], &a[3], &a[4]);
            let key_bytes = std::fs::read(format!("{dir}/client.key")).unwrap();
            let key_payload = decode_bound_key(&key_bytes, CLIENT_KEY_MAGIC)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            let ck: ClientKey = bincode::deserialize(key_payload)
                .unwrap_or_else(|e| panic!("chiave client non valida: {e}"));
            assert!(
                client_key_compatibile_con_params(&ck),
                "chiave client con geometria A38/A41 incompatibile con A126/A44"
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
                "chiave client con geometria A38/A41 incompatibile con A126/A44"
            );
            let (enc_key, _) = ck.encryption_key_and_noise();
            let (hdr, dati) = bytes_to_u64(&std::fs::read(ct_path).unwrap())
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            let header = decode_output_header(&hdr)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            assert_eq!(
                dati.len(),
                OUTPUT_LWES * header.lwe_size,
                "esito cifrato non valido: corpo di {} parole, attese {} per due LWE",
                dati.len(),
                OUTPUT_LWES * header.lwe_size
            );
            let expected_lwe_size = enc_key.lwe_dimension().to_lwe_size().0;
            assert_eq!(
                header.lwe_size, expected_lwe_size,
                "esito cifrato non valido: lwe_size incompatibile con la chiave client"
            );
            let (low_words, high_words) = dati.split_at(header.lwe_size);
            let low_ct = LweCiphertext::from_container(low_words, modulus);
            let high_ct = LweCiphertext::from_container(high_words, modulus);
            let low = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &low_ct).0)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: low: {e}"));
            let high = decode_plain_digit(decrypt_lwe_ciphertext(&enc_key, &high_ct).0)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: high: {e}"));
            let code = reconstruct_code(low, high, header.gallery_size)
                .unwrap_or_else(|e| panic!("esito cifrato non valido: {e}"));
            let index = if code == 0 {
                "null".to_string()
            } else {
                (code - 1).to_string()
            };
            println!(
                "{{\"query_profile\":{},\"query_profile_id\":{},\"autorizzato\":{},\"indice\":{},\"codice\":{},\"low\":{},\"high\":{},\"iscritti\":{},\"galleria_epoch\":{},\"galleria_revision\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{}}}",
                json_quote(header.profile.name()), header.profile.wire(),
                code != 0,
                index,
                code,
                low,
                high,
                header.gallery_size,
                header.epoch,
                header.revision,
                json_quote(A44_PARAMS_ID),
                json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                json_quote(VARIANT_ID),
                json_quote(CIRCUIT_SHA256),
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
                epoch: process_epoch(),
                revision: 0,
            });
            let l = TcpListener::bind(("127.0.0.1", porta)).unwrap();
            println!("varco PFKS127/A126 in ascolto su :{porta} | dim={dim} T={t} | Delta_score=2^51 (N127)/2^52 (other N), Delta_low=2^{LOG_LOW_MOD16_DELTA}, Delta_digit=2^{LOG_DIGIT_DELTA}, base={OUTPUT_DIGIT_BASE} | params_id={A44_PARAMS_ID} fingerprint={A44_PARAMETER_FINGERPRINT_SHA256} variant={VARIANT_ID} circuit={CIRCUIT_SHA256}");
            println!(
                "il server NON ha la chiave segreta: riceve byte cifrati e ne restituisce altri."
            );
            for s in l.incoming().flatten() {
                gestisci(s, &stato, modulus);
            }
        }
        _ => eprintln!(
            "uso: varco_demo keygen <dir> | encrypt <dir> <probe.txt> <out> <head51|legacy52> | \
                        decrypt <dir> <esito.ct> | serve <porta> <dim> <T_default>"
        ),
    }
}

// ---------------------------------------------------------------- HTTP minimale (solo std)
fn body_limit(metodo: &str, path: &str) -> Option<usize> {
    match (metodo, path) {
        ("POST", "/chiave") => Some(MAX_SERVER_KEY_BODY_BYTES),
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
                    format!(
                        "{{\"ok\":true,\"indice\":{index},\"iscritti\":{},\"soglia\":{t},\"galleria_epoch\":{},\"galleria_revision\":{},\"dominio\":{},\"dominio_esecuzione\":{},\"percorso_argmin\":{},\"endpoint_fhe\":{},\"endpoint_domain_supported\":{}}}",
                        g.iscritti.len(),
                        g.epoch,
                        g.revision,
                        domain_json(metadata.enrollment_domain),
                        domain_json(metadata.execution_domain),
                        json_quote(metadata.path.as_str()),
                        json_quote(metadata.endpoint_fhe),
                        metadata.endpoint_domain_supported,
                    )
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
                        let query_profile = QueryProfile::for_gallery(g.iscritti.len()).expect("admitted gallery").name();
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
            let profile = QueryProfile::for_gallery(g.iscritti.len()).ok();
            let profile_name = profile.map(|p| json_quote(p.name())).unwrap_or_else(|| "null".into());
            let profile_id = profile.map(|p| p.wire()).unwrap_or(0);
            let score_delta_log = profile.map(|p| p.score_delta_log()).unwrap_or(0);
            let nomi: Vec<String> = g.iscritti.iter().map(|x| json_quote(&x.name)).collect();
            let soglie: Vec<String> = g.iscritti.iter().map(|x| x.threshold.to_string()).collect();
            let (dominio, dominio_esecuzione, percorso_argmin, endpoint_fhe, endpoint_domain_supported) =
                match gallery_execution_metadata(&g.iscritti) {
                    Ok(Some(metadata)) => (
                        domain_json(metadata.enrollment_domain),
                        domain_json(metadata.execution_domain),
                        json_quote(metadata.path.as_str()),
                        json_quote(metadata.endpoint_fhe),
                        metadata.endpoint_domain_supported,
                    ),
                    Ok(None) => ("null".to_string(), "null".to_string(), "null".to_string(), "null".to_string(), false),
                    Err(e) => (
                        format!("{{\"errore\":{}}}", json_quote(&e)),
                        "null".to_string(),
                        "null".to_string(),
                        "null".to_string(),
                        false,
                    ),
                };
            let chiave_sha256 = g
                .chiave_sha256
                .as_deref()
                .map(json_quote)
                .unwrap_or_else(|| "null".to_string());
            (200, "application/json", String::new(),
             format!("{{\"iscritti\":{},\"nomi\":[{}],\"soglie\":[{}],\"chiave\":{},\"chiave_sha256\":{},\"dim\":{},\"soglia_default\":{},\"epoch\":{},\"revision\":{},\"dominio\":{},\"dominio_esecuzione\":{},\"percorso_argmin\":{},\"endpoint_fhe\":{},\"endpoint_domain_supported\":{},\"contratto_esatto\":{{\"http_contract\":{},\"wire_version\":{},\"probe_magic\":{},\"probe_layout\":{},\"query_profile\":{},\"query_profile_id\":{},\"score_delta_log\":{},\"low_mod16_offset\":{},\"low_mod16_delta_log\":{},\"output_magic\":{},\"output_mode\":{},\"digit_delta_log\":{},\"output_lwes\":{},\"digit_base\":{},\"params_id\":{},\"params_fingerprint_sha256\":{},\"variant_id\":{},\"circuit_sha256\":{},\"n127_threshold_policy\":\"uniform_aligned_original_planner\",\"n127_execution_lower_offset\":1023,\"n127_domain_max_width\":4096,\"n127_cauchy_coverage_required\":true,\"pfks_window_payload_bytes\":67141632,\"head_fourier_payload_bytes\":112590848,\"server_key_body_limit_bytes\":335544320,\"max_noise_level\":15,\"small_lwe_dimension\":859,\"client_key_magic\":{},\"server_key_magic\":{},\"codice\":\"0=rifiuto; i+1=identita_accettata\",\"ricostruzione_client\":\"low+15*high\",\"un_solo_lwe\":false}}}}",
                     g.iscritti.len(), nomi.join(","), soglie.join(","), g.chiave.is_some(), chiave_sha256, g.dim,
                     g.t_default, g.epoch, g.revision, dominio, dominio_esecuzione,
                     percorso_argmin, endpoint_fhe, endpoint_domain_supported, json_quote(HTTP_CONTRACT), WIRE_VERSION, PROBE_MAGIC,
                     PROBE_LAYOUT_DUAL_SAME_GLWE, profile_name, profile_id, score_delta_log, LOW_MOD16_OFFSET,
                     LOG_LOW_MOD16_DELTA, OUTPUT_MAGIC, OUTPUT_MODE_EXACT_ID_TWO_LWE,
                     LOG_DIGIT_DELTA, OUTPUT_LWES, OUTPUT_DIGIT_BASE,
                     json_quote(A44_PARAMS_ID), json_quote(A44_PARAMETER_FINGERPRINT_SHA256),
                     json_quote(VARIANT_ID), json_quote(CIRCUIT_SHA256), CLIENT_KEY_MAGIC,
                     SERVER_KEY_MAGIC).into_bytes())
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
//
// Il vecchio algoritmo `any_match` e il wire A38 a un LWE non vengono adattati implicitamente:
// entrambi potrebbero produrre un'identita' falsa o decodificata con la scala sbagliata. Questa
// funzione accetta soltanto il probe A126 bound, invoca l'endpoint A126 del core e serializza le due
// radici p16 base-15 separate, senza ricomposizione lineare sul server.
fn varco(
    g: &Galleria,
    probe_ct: &[u8],
    modulus: CiphertextModulus<u64>,
) -> Result<(Vec<u8>, dispatch::Counts), String> {
    let ssk = g.chiave.as_ref().unwrap();
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
    let plan = plan_private_argmin_execution(&templates)
        .map_err(|error| format!("galleria non valida per l'argmin esatto: {error}"))?;
    if !plan.aligned_fast_path {
        return Err(
            "galleria incompatibile con A126 base-15: richiesto percorso uniforme allineato"
                .to_string(),
        );
    }
    let packed_probe = GlweCiphertext::from_container(dati, poly, modulus);
    let (low, high, counts) = dispatch::evaluate(ssk, &packed_probe, &templates, plan.execution_domain, header.profile)?;
    Ok((serialize_exact_output(g, &low, &high)?, counts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_gallery(dim: usize) -> Galleria {
        Galleria {
            dim,
            t_default: 7,
            iscritti: Vec::new(),
            chiave: None,
            chiave_sha256: None,
            epoch: 123,
            revision: 0,
        }
    }

    #[test]
    fn rejects_truncated_ciphertext_format() {
        assert!(bytes_to_u64(&[0u8; 7]).is_err());
        assert!(bytes_to_u64(&[0u8; 9]).is_err());
    }

    #[test]
    fn http_body_limits_are_route_specific_and_bounded() {
        assert_eq!(body_limit("POST", "/chiave"), Some(320 * 1024 * 1024));
        assert_eq!(body_limit("POST", "/varco"), Some(64 * 1024));
        assert_eq!(body_limit("POST", "/iscrivi"), Some(8 * 1024));
        assert_eq!(body_limit("POST", "/reset"), Some(0));
        assert_eq!(body_limit("GET", "/stato"), Some(0));
        assert_eq!(body_limit("POST", "/stato"), None);
        assert_eq!(body_limit("POST", "/sconosciuto"), None);
    }

    #[test]
    fn sha256_fingerprint_is_lowercase_and_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn entry_and_global_score_domains_use_the_checked_probe_norm_bound() {
        let a = Entry::new("a".to_string(), vec![1, 0], 5).unwrap();
        let b = Entry::new("b".to_string(), vec![0, 2], 9).unwrap();
        assert_eq!(a.norm2, 1);
        assert_eq!(a.l1, 1);
        assert_eq!(
            a.score_domain().unwrap(),
            ScoreDomain {
                lower: -63,
                upper: 65
            }
        );
        assert_eq!(
            b.score_domain().unwrap(),
            ScoreDomain {
                lower: -124,
                upper: 132
            }
        );
        let domain = gallery_domain(&[a, b]).unwrap().unwrap();
        assert_eq!(
            domain,
            ScoreDomain {
                lower: -124,
                upper: 132
            }
        );
        assert_eq!(domain_width(domain).unwrap(), 257);
        assert_eq!(ceil_sqrt_nonnegative(0).unwrap(), 0);
        assert_eq!(ceil_sqrt_nonnegative(1).unwrap(), 1);
        assert_eq!(ceil_sqrt_nonnegative(2).unwrap(), 2);
        assert_eq!(ceil_sqrt_nonnegative(1024).unwrap(), 32);
        assert_eq!(ceil_sqrt_nonnegative(1025).unwrap(), 33);
    }

    #[test]
    fn execution_metadata_keeps_enrollment_tight_and_reports_the_selected_path() {
        assert_eq!(gallery_execution_metadata(&[]).unwrap(), None);

        let mut template = vec![0i64; PROBE_DIM];
        template[..74].fill(3);
        template[74] = 2;
        template[75] = 1;
        let entry = Entry::new("alice".to_string(), template.clone(), 4).unwrap();
        let metadata = gallery_execution_metadata(&[entry]).unwrap().unwrap();
        assert_eq!(
            metadata,
            GalleryExecutionMetadata {
                enrollment_domain: ScoreDomain {
                    lower: -987,
                    upper: 2329,
                },
                execution_domain: ScoreDomain {
                    lower: -1019,
                    upper: 2329,
                },
                path: ArgminPath::A126Base15TwoLwe,
                endpoint_fhe: "a126",
                endpoint_domain_supported: true,
            }
        );
        assert_eq!(
            domain_json(metadata.enrollment_domain),
            "{\"l\":-987,\"u\":2329,\"larghezza\":3317}"
        );
        assert_eq!(
            domain_json(metadata.execution_domain),
            "{\"l\":-1019,\"u\":2329,\"larghezza\":3349}"
        );
        assert_eq!(metadata.path.as_str(), "uniform_aligned_base15_domain");

        let mixed = [
            Entry::new("alice".to_string(), template.clone(), 4).unwrap(),
            Entry::new("bob".to_string(), template, 5).unwrap(),
        ];
        let metadata = gallery_execution_metadata(&mixed).unwrap().unwrap();
        assert_eq!(metadata.execution_domain, metadata.enrollment_domain);
        assert_eq!(metadata.path, ArgminPath::A29General);
        assert_eq!(metadata.path.as_str(), "a29_general");
    }

    #[test]
    fn rejected_replacement_is_atomic_and_successes_increment_revision() {
        let mut gallery = empty_gallery(PROBE_DIM);
        let (index, metadata) =
            upsert_entry(&mut gallery, "alice".to_string(), vec![0; PROBE_DIM], 4).unwrap();
        assert_eq!(index, 0);
        assert_eq!(
            metadata.enrollment_domain,
            ScoreDomain { lower: 0, upper: 0 }
        );
        assert_eq!(
            metadata.execution_domain,
            ScoreDomain {
                lower: -1019,
                upper: 0,
            }
        );
        assert_eq!(metadata.path, ArgminPath::A126Base15TwoLwe);
        assert_eq!(gallery.revision, 1);

        let error =
            upsert_entry(&mut gallery, "alice".to_string(), vec![Q_MAX; PROBE_DIM], 4).unwrap_err();
        assert!(error.contains("dominio globale"));
        assert_eq!(gallery.revision, 1);
        assert_eq!(gallery.iscritti[0].norm2, 0);

        let mut replacement = vec![0; PROBE_DIM];
        replacement[0] = 1;
        upsert_entry(&mut gallery, "alice".to_string(), replacement, 5).unwrap();
        assert_eq!(gallery.revision, 2);
        assert_eq!(gallery.iscritti[0].threshold, 5);

        reset_gallery(&mut gallery).unwrap();
        assert!(gallery.iscritti.is_empty());
        assert_eq!(gallery.revision, 3);
        reset_gallery(&mut gallery).unwrap();
        assert_eq!(gallery.revision, 4);
    }

    #[test]
    fn gallery_names_are_valid_json_strings() {
        assert_eq!(json_quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn dual_probe_layout_uses_one_plaintext_with_both_fixed_scales() {
        let mut probe = vec![0; PROBE_DIM];
        probe[0] = -3;
        probe[PROBE_DIM - 1] = 2;
        let coefficients = encode_probe_coefficients(&probe, 2048, QueryProfile::Legacy52).unwrap();
        assert_eq!(coefficients.len(), 2048);
        assert_eq!(
            coefficients[0],
            (-3i64 as u64).wrapping_mul(1u64 << LOG_SCORE_DELTA)
        );
        assert_eq!(coefficients[PROBE_DIM - 1], 2u64 << LOG_SCORE_DELTA);
        assert_eq!(coefficients[LOW_MOD16_OFFSET], 13u64 << LOG_LOW_MOD16_DELTA);
        assert_eq!(
            coefficients[LOW_MOD16_OFFSET + PROBE_DIM - 1],
            2u64 << LOG_LOW_MOD16_DELTA
        );
        assert!(coefficients[PROBE_DIM..LOW_MOD16_OFFSET]
            .iter()
            .all(|&x| x == 0));
    }

    #[test]
    fn probe_norm2_limit_is_enforced_before_encryption() {
        let mut boundary = vec![0; PROBE_DIM];
        boundary[..113].fill(3); // 1017
        boundary[113] = 2; // 1021
        assert!(encode_probe_coefficients(&boundary, 2048, QueryProfile::Legacy52).is_ok());
        boundary[114] = 2; // 1025
        let error = encode_probe_coefficients(&boundary, 2048, QueryProfile::Legacy52).unwrap_err();
        assert!(error.contains("norma quadratica"));
    }

    #[test]
    fn headers_are_versioned_strict_and_in_the_declared_order() {
        let probe = probe_header(2048, 2, QueryProfile::Legacy52);
        assert_eq!(
            decode_probe_header(&probe).unwrap(),
            ProbeHeader {
                profile: QueryProfile::Legacy52,
                polynomial_size: 2048,
                glwe_dimension: 2,
                embedding_dim: PROBE_DIM,
            }
        );
        let mut bad_probe = probe.clone();
        bad_probe[1] += 1;
        assert!(decode_probe_header(&bad_probe).is_err());
        let mut wire_v2_probe = probe.clone();
        wire_v2_probe[1] = 2;
        assert!(decode_probe_header(&wire_v2_probe).is_err());
        let mut a65_v3_probe = probe.clone();
        a65_v3_probe[0] = u64::from_le_bytes(*b"VRCOPR44");
        a65_v3_probe[1] = 3;
        assert!(decode_probe_header(&a65_v3_probe).is_err());
        let legacy_probe = &probe[..PROBE_FIXED_HEADER_WORDS];
        assert!(decode_probe_header(legacy_probe).is_err());
        let mut wrong_fingerprint = probe.clone();
        *wrong_fingerprint.last_mut().unwrap() ^= 1;
        assert!(decode_probe_header(&wrong_fingerprint).is_err());

        let mut gallery = empty_gallery(PROBE_DIM);
        upsert_entry(&mut gallery, "alice".to_string(), vec![0; PROBE_DIM], 4).unwrap();
        let output = output_header(&gallery, 2049);
        assert_eq!(
            &output[..OUTPUT_FIXED_HEADER_WORDS],
            &[
                OUTPUT_MAGIC,
                WIRE_VERSION,
                OUTPUT_MODE_EXACT_ID_TWO_LWE,
                123,
                1,
                1,
                2049,
                u64::from(LOG_DIGIT_DELTA),
                OUTPUT_LWES as u64,
                OUTPUT_DIGIT_BASE as u64,
                QueryProfile::Legacy52.wire(),
            ]
        );
        assert_eq!(
            decode_output_header(&output).unwrap(),
            OutputHeader {
                profile: QueryProfile::Legacy52,
                epoch: 123,
                revision: 1,
                gallery_size: 1,
                lwe_size: 2049,
            }
        );
        let mut wire_v2 = output.clone();
        wire_v2[1] = 2;
        assert!(decode_output_header(&wire_v2).is_err());

        let mut a44_base16_v3 = output.clone();
        a44_base16_v3[0] = u64::from_le_bytes(*b"VRCOUT44");
        a44_base16_v3[1] = 3;
        a44_base16_v3[2] = 3;
        a44_base16_v3[9] = 16;
        assert!(decode_output_header(&a44_base16_v3).is_err());

        let mut base16_under_v4 = output.clone();
        base16_under_v4[9] = 16;
        assert!(decode_output_header(&base16_under_v4).is_err());

        let variant_word = OUTPUT_FIXED_HEADER_WORDS
            + BINDING_LENGTH_WORDS
            + A44_PARAMS_ID.len().div_ceil(8)
            + A44_PARAMETER_FINGERPRINT_SHA256.len().div_ceil(8);
        let mut wrong_variant = output.clone();
        wrong_variant[variant_word] ^= 1;
        assert!(decode_output_header(&wrong_variant).is_err());

        let circuit_word = variant_word + VARIANT_ID.len().div_ceil(8);
        let mut wrong_circuit = output.clone();
        wrong_circuit[circuit_word] ^= 1;
        assert!(decode_output_header(&wrong_circuit).is_err());

        let mut one_lwe = output;
        one_lwe[8] = 1;
        assert!(decode_output_header(&one_lwe).is_err());
    }

    #[test]
    fn two_digit_decode_and_reconstruction_are_fail_closed() {
        let delta = 1u64 << LOG_DIGIT_DELTA;
        let half = delta >> 1;

        for digit in 0..15 {
            assert_eq!(decode_plain_digit(digit * delta).unwrap(), digit as usize);
        }
        assert_eq!(decode_plain_digit(0).unwrap(), 0);
        assert_eq!(decode_plain_digit(half - 1).unwrap(), 0);
        assert_eq!(decode_plain_digit(half).unwrap(), 1);
        assert_eq!(decode_plain_digit(0u64.wrapping_sub(half)).unwrap(), 0);
        assert_eq!(decode_plain_digit(u64::MAX).unwrap(), 0);
        assert!(decode_plain_digit(0u64.wrapping_sub(half + 1)).is_err());
        assert!(decode_plain_digit(15 * delta).is_err());
        assert!(decode_plain_digit(16 * delta).is_err());

        for gallery_size in 1..=128 {
            for code in 0..=gallery_size {
                let low = code % OUTPUT_DIGIT_BASE;
                let high = code / OUTPUT_DIGIT_BASE;
                assert_eq!(reconstruct_code(low, high, gallery_size).unwrap(), code);
            }
        }
        assert_eq!(reconstruct_code(0, 0, 128).unwrap(), 0);
        assert_eq!(reconstruct_code(7, 8, 128).unwrap(), 127);
        assert_eq!(reconstruct_code(8, 8, 128).unwrap(), 128);
        assert!(reconstruct_code(9, 8, 128).is_err());
        assert!(reconstruct_code(15, 0, 128).is_err());
        assert!(reconstruct_code(0, 15, 128).is_err());
    }

    #[test]
    fn key_envelope_rejects_legacy_and_wrong_binding() {
        let payload = b"opaque-bincode";
        let envelope = encode_bound_key(SERVER_KEY_MAGIC, payload);
        assert_eq!(
            decode_bound_key(&envelope, SERVER_KEY_MAGIC).unwrap(),
            payload
        );
        assert!(decode_bound_key(payload, SERVER_KEY_MAGIC).is_err());
        assert!(decode_bound_key(&envelope, CLIENT_KEY_MAGIC).is_err());
        let mut wrong_fingerprint = envelope.clone();
        wrong_fingerprint[KEY_ENVELOPE_FIXED_BYTES + A44_PARAMS_ID.len()] ^= 1;
        assert!(decode_bound_key(&wrong_fingerprint, SERVER_KEY_MAGIC).is_err());

        let variant_offset =
            KEY_ENVELOPE_FIXED_BYTES + A44_PARAMS_ID.len() + A44_PARAMETER_FINGERPRINT_SHA256.len();
        let mut wrong_variant = envelope.clone();
        wrong_variant[variant_offset] ^= 1;
        assert!(decode_bound_key(&wrong_variant, SERVER_KEY_MAGIC).is_err());

        let circuit_offset = variant_offset + VARIANT_ID.len();
        let mut wrong_circuit = envelope.clone();
        wrong_circuit[circuit_offset] ^= 1;
        assert!(decode_bound_key(&wrong_circuit, SERVER_KEY_MAGIC).is_err());

        let mut a65_v3_envelope = envelope;
        a65_v3_envelope[..8].copy_from_slice(&u64::from_le_bytes(*b"VRCSK44!").to_le_bytes());
        a65_v3_envelope[8..16].copy_from_slice(&3u64.to_le_bytes());
        assert!(decode_bound_key(&a65_v3_envelope, SERVER_KEY_MAGIC).is_err());
    }
}

#[cfg(test)]
mod general_threshold_tests { include!("threshold_tests.rs"); }

#[cfg(test)]
mod profile_tests { include!("profile_tests.rs"); }
