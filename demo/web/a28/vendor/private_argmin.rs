//! Argmin TFHE esatto e privato per il varco 1:N.
//!
//! Il core non possiede chiavi segrete e non decifra valori intermedi. Calcola i punteggi da un
//! probe GLWE impacchettato, seleziona cifratamente il primo minimo, seleziona la soglia associata
//! soltanto a quel vincitore e restituisce un unico LWE: zero per il rifiuto, `indice+1` per il
//! match. La distanza non fa parte dell'output.

use rayon::prelude::*;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::ServerKey;

pub const PROBE_DIM: usize = 512;
pub const PROBE_NORM2_MAX: i64 = 1024;
pub const MAX_GALLERY_SIZE: usize = 128;
pub const MAX_DOMAIN_WIDTH: i64 = 4096;
pub const FULL_DELTA_LOG: u32 = 52;
pub const LOW_MOD16_DELTA_LOG: u32 = 60;
pub const BOOL_DELTA_LOG: u32 = 59;
pub const CODE_DELTA_LOG: u32 = 56;
pub const LOW_MOD16_POLYNOMIAL_OFFSET: usize = 1024;

const HIGH_SCORE_BIT: u32 = 11;
const SCORE_BITS: u32 = HIGH_SCORE_BIT + 1;
const SPLIT_LOW_BITS: u32 = 3;
const LOW_EXTRACTED_BITS: u32 = 4;
const HIGH_EXTRACTED_BITS: u32 = SCORE_BITS - LOW_EXTRACTED_BITS;
const HIGH_DELTA_LOG: u32 = FULL_DELTA_LOG + LOW_EXTRACTED_BITS;
const PBS_MESSAGE_MODULUS: usize = 16;
// Ogni ingresso e' un Booleano appena rinfrescato. Quattro contributi restano sotto il
// `max_noise_level=5` del parameter set; il precedente fan-in 8 non aveva questo margine.
const OR_BLOCK: usize = 4;
const FIRST_ONE_GROUP: usize = 3;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScoreDomain {
    pub lower: i64,
    pub upper: i64,
}

impl ScoreDomain {
    pub fn checked_width(self) -> Option<i64> {
        self.upper.checked_sub(self.lower)?.checked_add(1)
    }

    pub fn contains(self, score: i64) -> bool {
        (self.lower..=self.upper).contains(&score)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TemplateView<'a> {
    pub template: &'a [i64],
    pub norm2: i64,
    pub threshold: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct StageMetrics {
    pub seconds: f64,
    pub pbs_count: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PrivateArgminMetrics {
    /// Costruzione delle LUT e degli accumulatori specifici della chiave e di N.
    pub setup: StageMetrics,
    pub score: StageMetrics,
    pub extract: StageMetrics,
    pub select: StageMetrics,
    pub scan: StageMetrics,
    pub threshold: StageMetrics,
    pub output: StageMetrics,
    pub total_seconds: f64,
    pub total_pbs_count: u64,
}

#[derive(Clone, Debug)]
pub struct PrivateArgminOutput {
    pub code: Lwe,
    pub metrics: PrivateArgminMetrics,
}

/// Checkpoint cifrati usati soltanto dal replay locale con la chiave client.
///
/// Il servizio non chiama questa API e continua a ricevere soltanto [`PrivateArgminOutput`]. La
/// struttura non contiene plaintext o chiavi segrete: consente a un harness separato, eseguito dal
/// proprietario della chiave, di individuare il primo stadio divergente senza aggiungere leakage al
/// protocollo HTTP.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct PrivateArgminTrace {
    pub bit_positions_msb_first: Vec<u32>,
    pub bit_weights_msb_first: Vec<u64>,
    pub score_full: Vec<Lwe>,
    pub score_low_mod16: Vec<Lwe>,
    pub high_residuals: Vec<Lwe>,
    pub full_small_bits_lsb_first: Vec<Vec<Lwe>>,
    pub full_corrections_lsb_first: Vec<Vec<Lwe>>,
    pub low_small_bits_lsb_first: Vec<Vec<Lwe>>,
    pub low_corrections_lsb_first: Vec<Vec<Lwe>>,
    pub bridged_bits_by_level: Vec<Vec<Lwe>>,
    pub zero_candidates_by_level: Vec<Vec<Lwe>>,
    pub any_zero_by_level: Vec<Lwe>,
    pub candidates_by_level: Vec<Vec<Lwe>>,
    pub group_prefixes: Vec<Lwe>,
    pub winners: Vec<Lwe>,
    pub selected_threshold_bits_msb_first: Vec<Lwe>,
    pub selected_below: Option<Lwe>,
    pub comparison_state_by_level: Vec<Lwe>,
    pub accept_tag: Option<Lwe>,
    pub coded_digits_lsb_first: Vec<Lwe>,
    pub code_groups: Vec<Lwe>,
    pub final_code: Option<Lwe>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearPrivateArgminResult {
    pub winner_index: usize,
    pub matched: bool,
    pub code: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateArgminError {
    EmptyGallery,
    GalleryTooLarge {
        actual: usize,
        maximum: usize,
    },
    ScoreLengthMismatch {
        scores: usize,
        templates: usize,
    },
    InvalidDomain {
        lower: i64,
        upper: i64,
    },
    DomainTooWide {
        width: i64,
        maximum: i64,
    },
    InvalidTemplateDimension {
        index: usize,
        actual: usize,
    },
    InvalidTemplateCoordinate {
        index: usize,
        coordinate: usize,
        value: i64,
    },
    TemplateNormOverflow {
        index: usize,
    },
    IncorrectTemplateNorm {
        index: usize,
        declared: i64,
        actual: i64,
    },
    DomainDoesNotCoverTemplate {
        index: usize,
        required_lower: i64,
        required_upper: i64,
    },
    InvalidProbeShape,
    InvalidProbeModulus,
    UnsupportedBootstrappingKey,
}

impl Display for PrivateArgminError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyGallery => write!(formatter, "la galleria e' vuota"),
            Self::GalleryTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "galleria N={actual}, massimo supportato N={maximum}"
                )
            }
            Self::ScoreLengthMismatch { scores, templates } => write!(
                formatter,
                "numero punteggi {scores}, numero template {templates}"
            ),
            Self::InvalidDomain { lower, upper } => {
                write!(formatter, "dominio non valido [{lower},{upper}]")
            }
            Self::DomainTooWide { width, maximum } => {
                write!(formatter, "dominio largo {width}, massimo {maximum}")
            }
            Self::InvalidTemplateDimension { index, actual } => write!(
                formatter,
                "template {index} di dimensione {actual}, attesa {PROBE_DIM}"
            ),
            Self::InvalidTemplateCoordinate {
                index,
                coordinate,
                value,
            } => write!(
                formatter,
                "template {index}, coordinata {coordinate}: valore {value}, atteso [-3,3]"
            ),
            Self::TemplateNormOverflow { index } => {
                write!(
                    formatter,
                    "overflow calcolando la norma del template {index}"
                )
            }
            Self::IncorrectTemplateNorm {
                index,
                declared,
                actual,
            } => write!(
                formatter,
                "norma template {index}: dichiarata {declared}, effettiva {actual}"
            ),
            Self::DomainDoesNotCoverTemplate {
                index,
                required_lower,
                required_upper,
            } => write!(
                formatter,
                "dominio non copre template {index}: richiesto [{required_lower},{required_upper}]"
            ),
            Self::InvalidProbeShape => write!(formatter, "layout GLWE del probe non valido"),
            Self::InvalidProbeModulus => {
                write!(
                    formatter,
                    "modulo del probe non nativo o incompatibile con la chiave"
                )
            }
            Self::UnsupportedBootstrappingKey => {
                write!(formatter, "attesa chiave di bootstrap classica")
            }
        }
    }
}

impl std::error::Error for PrivateArgminError {}

fn ceil_sqrt(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut lower = 1u64;
    let mut upper = value.min(1u64 << 32);
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let quotient_ceiling = value / middle + u64::from(!value.is_multiple_of(middle));
        if middle >= quotient_ceiling {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    lower
}

fn template_score_bounds(norm2: i64) -> Option<(i64, i64)> {
    let product = u64::try_from(norm2)
        .ok()?
        .checked_mul(PROBE_NORM2_MAX as u64)?;
    let radius = i64::try_from(ceil_sqrt(product)).ok()?.checked_mul(2)?;
    Some((norm2.checked_sub(radius)?, norm2.checked_add(radius)?))
}

pub fn cauchy_score_domain(
    templates: &[TemplateView<'_>],
) -> Result<ScoreDomain, PrivateArgminError> {
    validate_gallery_size(templates.len())?;
    let mut lower = i64::MAX;
    let mut upper = i64::MIN;
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
        let (entry_lower, entry_upper) = template_score_bounds(entry.norm2)
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
        lower = lower.min(entry_lower);
        upper = upper.max(entry_upper);
    }
    let domain = ScoreDomain { lower, upper };
    validate_domain(domain)?;
    Ok(domain)
}

pub fn clear_private_argmin(
    scores: &[i64],
    templates: &[TemplateView<'_>],
) -> Result<ClearPrivateArgminResult, PrivateArgminError> {
    validate_gallery_size(templates.len())?;
    if scores.len() != templates.len() {
        return Err(PrivateArgminError::ScoreLengthMismatch {
            scores: scores.len(),
            templates: templates.len(),
        });
    }
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
    }
    let winner_index = scores
        .iter()
        .enumerate()
        .min_by_key(|(index, score)| (**score, *index))
        .map(|(index, _)| index)
        .expect("galleria validata non vuota");
    let matched = scores[winner_index] <= templates[winner_index].threshold;
    Ok(ClearPrivateArgminResult {
        winner_index,
        matched,
        code: if matched { winner_index as u64 + 1 } else { 0 },
    })
}

fn or_reduction_pbs(mut items: usize) -> u64 {
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(OR_BLOCK);
        count += items as u64;
    }
    count
}

fn radix4_exclusive_prefix_pbs(items: usize) -> u64 {
    if items <= 2 {
        return 0;
    }
    if items <= OR_BLOCK {
        return (items - 2) as u64;
    }
    let mut totals = 0u64;
    let mut expansion = 0u64;
    let mut groups = 0usize;
    for start in (0..items).step_by(OR_BLOCK) {
        let len = (items - start).min(OR_BLOCK);
        groups += 1;
        totals += u64::from(len > 1);
        expansion += if start == 0 {
            len.saturating_sub(2) as u64
        } else {
            (len - 1) as u64
        };
    }
    totals + expansion + radix4_exclusive_prefix_pbs(groups)
}

fn first_one_scan_pbs(items: usize) -> u64 {
    let groups = items.div_ceil(FIRST_ONE_GROUP);
    let group_totals = (0..items)
        .step_by(FIRST_ONE_GROUP)
        .filter(|&start| (items - start).min(FIRST_ONE_GROUP) > 1)
        .count() as u64;
    group_totals + radix4_exclusive_prefix_pbs(groups) + items as u64
}

fn output_bit_positions(gallery_size: usize) -> Vec<u32> {
    (0..usize::BITS)
        .filter(|&bit_position| {
            (0..gallery_size).any(|index| output_code_has_bit(index, bit_position))
        })
        .collect()
}

fn output_code_has_bit(index: usize, bit_position: u32) -> bool {
    (((index + 1) >> bit_position) & 1) == 1
}

fn output_code_pbs(gallery_size: usize) -> u64 {
    let positions = output_bit_positions(gallery_size);
    let bit_pbs: u64 = positions
        .iter()
        .copied()
        .map(|bit_position| {
            (0..gallery_size)
                .filter(|&index| output_code_has_bit(index, bit_position))
                .count()
        })
        .map(|items| or_reduction_pbs(items).max(1))
        .sum();
    // Tre digit freschi 1/2/4 e il tag di accettazione 8 entrano in una sola LUT di gruppo.
    bit_pbs + positions.len().div_ceil(3) as u64
}

pub fn expected_pbs_count(gallery_size: usize) -> Option<u64> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    Some(
        37 * n
            + 25 * or_reduction_pbs(gallery_size)
            + first_one_scan_pbs(gallery_size)
            + output_code_pbs(gallery_size)
            + 13,
    )
}

fn winner_mask_pbs(mask: &[bool]) -> u64 {
    let enabled = mask.iter().filter(|&&value| value).count();
    if enabled == 0 || enabled == mask.len() {
        0
    } else {
        or_reduction_pbs(enabled)
    }
}

/// Conteggio esatto quando le soglie pubbliche consentono di evitare gli slot disabilitati.
///
/// [`expected_pbs_count`] resta il limite indipendente dai valori; questa funzione sottrae le
/// tredici riduzioni dense e aggiunge soltanto quelle richieste dai bit realmente non costanti
/// delle soglie per-template.
pub fn expected_pbs_count_for_thresholds(
    gallery_size: usize,
    thresholds: &[i64],
    domain: ScoreDomain,
) -> Option<u64> {
    if thresholds.len() != gallery_size || validate_domain(domain).is_err() {
        return None;
    }
    let maximum = expected_pbs_count(gallery_size)?;
    let metadata: Vec<(u64, bool)> = thresholds
        .iter()
        .map(|&threshold| {
            let below = threshold < domain.lower;
            let clamped = threshold.clamp(domain.lower, domain.upper);
            ((clamped - domain.lower) as u64, below)
        })
        .collect();
    let mut masks: Vec<Vec<bool>> = (0..SCORE_BITS)
        .rev()
        .map(|bit_position| {
            metadata
                .iter()
                .map(|(threshold, _)| ((threshold >> bit_position) & 1) == 1)
                .collect()
        })
        .collect();
    masks.push(metadata.iter().map(|(_, below)| *below).collect());
    let dense = 13 * or_reduction_pbs(gallery_size);
    let sparse: u64 = masks.iter().map(|mask| winner_mask_pbs(mask)).sum();
    Some(maximum - dense + sparse)
}

fn validate_gallery_size(size: usize) -> Result<(), PrivateArgminError> {
    if size == 0 {
        return Err(PrivateArgminError::EmptyGallery);
    }
    if size > MAX_GALLERY_SIZE {
        return Err(PrivateArgminError::GalleryTooLarge {
            actual: size,
            maximum: MAX_GALLERY_SIZE,
        });
    }
    Ok(())
}

fn validate_template(index: usize, entry: &TemplateView<'_>) -> Result<(), PrivateArgminError> {
    if entry.template.len() != PROBE_DIM {
        return Err(PrivateArgminError::InvalidTemplateDimension {
            index,
            actual: entry.template.len(),
        });
    }
    let mut actual = 0i64;
    for (coordinate, value) in entry.template.iter().copied().enumerate() {
        if !(-3..=3).contains(&value) {
            return Err(PrivateArgminError::InvalidTemplateCoordinate {
                index,
                coordinate,
                value,
            });
        }
        actual = actual
            .checked_add(
                value
                    .checked_mul(value)
                    .ok_or(PrivateArgminError::TemplateNormOverflow { index })?,
            )
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
    }
    if actual != entry.norm2 {
        return Err(PrivateArgminError::IncorrectTemplateNorm {
            index,
            declared: entry.norm2,
            actual,
        });
    }
    Ok(())
}

fn validate_domain(domain: ScoreDomain) -> Result<(), PrivateArgminError> {
    if domain.lower > domain.upper {
        return Err(PrivateArgminError::InvalidDomain {
            lower: domain.lower,
            upper: domain.upper,
        });
    }
    let width = domain
        .checked_width()
        .ok_or(PrivateArgminError::InvalidDomain {
            lower: domain.lower,
            upper: domain.upper,
        })?;
    if width > MAX_DOMAIN_WIDTH {
        return Err(PrivateArgminError::DomainTooWide {
            width,
            maximum: MAX_DOMAIN_WIDTH,
        });
    }
    Ok(())
}

fn validate_inputs(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(), PrivateArgminError> {
    validate_gallery_size(templates.len())?;
    validate_domain(domain)?;
    for (index, entry) in templates.iter().enumerate() {
        validate_template(index, entry)?;
        let (required_lower, required_upper) = template_score_bounds(entry.norm2)
            .ok_or(PrivateArgminError::TemplateNormOverflow { index })?;
        if domain.lower > required_lower || domain.upper < required_upper {
            return Err(PrivateArgminError::DomainDoesNotCoverTemplate {
                index,
                required_lower,
                required_upper,
            });
        }
    }
    let bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    if !packed_probe.ciphertext_modulus().is_native_modulus()
        || packed_probe.ciphertext_modulus() != server_key.ciphertext_modulus
        || packed_probe.ciphertext_modulus() != server_key.key_switching_key.ciphertext_modulus()
    {
        return Err(PrivateArgminError::InvalidProbeModulus);
    }
    let polynomial_size = bootstrap_key.polynomial_size();
    let packed_support_end = LOW_MOD16_POLYNOMIAL_OFFSET + 2 * PROBE_DIM - 2;
    if packed_probe.polynomial_size() != polynomial_size
        || packed_probe.glwe_size() != bootstrap_key.glwe_size()
        || packed_support_end >= polynomial_size.0
    {
        return Err(PrivateArgminError::InvalidProbeShape);
    }
    Ok(())
}

fn zero_candidate_lut(code: u64, candidate_weight: u64, bit_weight: u64) -> u64 {
    let mut output = None;
    for candidate in [false, true] {
        for bit in [false, true] {
            if u64::from(candidate) * candidate_weight + u64::from(bit) * bit_weight == code {
                let value = u64::from(candidate && !bit);
                assert!(output.is_none() || output == Some(value), "layout ambiguo");
                output = Some(value);
            }
        }
    }
    output.unwrap_or(0)
}

fn update_candidate_from_zero_lut(code: u64) -> u64 {
    // L'ingresso e' `candidate + zero_candidate - any_zero` modulo 16. Sui soli stati
    // raggiungibili vale uno esattamente quando il candidato sopravvive al livello corrente.
    u64::from(code == 1)
}

fn encoded_zero_candidate_lut(code: u64) -> u64 {
    // Nei livelli dispari il candidato attivo e' 15, gli inattivi sono 0/1. Sommando il bit
    // pesato 1/2/4/8, il codice 15 resta raggiungibile soltanto per (attivo, bit=0). L'attivo e'
    // pero' il valore torus *negativo* -1, non il messaggio positivo 15: la rotazione
    // negaciclica nega la casella 15. La LUT base deve quindi contenere -1 per ottenere +1.
    if code == 15 {
        u64::MAX
    } else {
        0
    }
}

fn weighted_or_lut(code: u64, weight: u64) -> u64 {
    if (1..=OR_BLOCK as u64).contains(&code) {
        weight
    } else {
        0
    }
}

fn output_group_lut(code: u64, bit_offset: u32, group_len: usize) -> u64 {
    assert!((1..=3).contains(&group_len));
    if code >= 8 {
        let payload_mask = (1u64 << group_len) - 1;
        ((code - 8) & payload_mask) << bit_offset
    } else {
        0
    }
}

fn boolean_and_lut(code: u64) -> u64 {
    u64::from(code == 2)
}

const COMPARISON_LESS: u64 = 0;
const COMPARISON_EQUAL: u64 = 2;
const COMPARISON_GREATER: u64 = 4;

fn comparison_state_lut(code: u64) -> u64 {
    let mut output = None;
    for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
        for any_zero in [false, true] {
            for threshold_bit in [false, true] {
                let input = state
                    .wrapping_sub(u64::from(any_zero))
                    .wrapping_sub(u64::from(threshold_bit))
                    & (PBS_MESSAGE_MODULUS as u64 - 1);
                if input == code {
                    let minimum_bit = !any_zero;
                    let next = if state != COMPARISON_EQUAL {
                        state
                    } else {
                        match (minimum_bit, threshold_bit) {
                            (false, true) => COMPARISON_LESS,
                            (true, false) => COMPARISON_GREATER,
                            _ => COMPARISON_EQUAL,
                        }
                    };
                    assert!(output.is_none() || output == Some(next), "layout ambiguo");
                    output = Some(next);
                }
            }
        }
    }
    output.unwrap_or(COMPARISON_GREATER)
}

fn comparison_accept_tag_lut(code: u64) -> u64 {
    let mut output = None;
    for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
        for below in [false, true] {
            if state + u64::from(below) == code {
                let value = 8 * u64::from(state != COMPARISON_GREATER && !below);
                assert!(output.is_none() || output == Some(value), "layout ambiguo");
                output = Some(value);
            }
        }
    }
    output.unwrap_or(0)
}

fn bit_source_delta(bit_index: u32) -> u32 {
    if bit_index < SPLIT_LOW_BITS {
        LOW_MOD16_DELTA_LOG
    } else {
        FULL_DELTA_LOG
    }
}

fn recodes_bit(bit_index: u32) -> bool {
    // Le correzioni dei bit 3..=7 nascono a scale via via piu' basse e, per raggiungere
    // Delta_bool, richiederebbero moltiplicatori 32, 16, 8, 4 e 2. Il codice logico resterebbe
    // piccolo, ma verrebbe amplificato anche il rumore prima del PBS successivo. Ricaviamo quindi
    // questi bit direttamente dagli LWE piccoli dell'estrazione e li rinfreschiamo a Booleani.
    // Il bit alto non possiede una correction ciphertext e segue gia' lo stesso percorso.
    bit_index == HIGH_SCORE_BIT || (3..=7).contains(&bit_index)
}

fn extracted_bit_weight(bit_index: u32) -> u64 {
    if recodes_bit(bit_index) {
        return 1;
    }
    let correction_log = bit_source_delta(bit_index) + bit_index;
    if correction_log <= BOOL_DELTA_LOG + 1 {
        2
    } else {
        1u64 << (correction_log - BOOL_DELTA_LOG)
    }
}

fn zero_layout(bit_weight: u64) -> (u64, u64) {
    match bit_weight {
        1 => (1, 2),
        _ => (1, bit_weight),
    }
}

#[derive(Clone)]
struct CapturedExtractedBits {
    small_lsb_first: Vec<Lwe>,
    corrections_lsb_first: Vec<Lwe>,
}

#[derive(Clone)]
struct WeightedBit {
    ciphertext: Lwe,
}

fn correction_from_small_bit(
    small_bit: &Lwe,
    accumulator: &Glwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    output_lwe_size: LweSize,
    alpha: u64,
    pbs_count: &AtomicU64,
) -> Lwe {
    let modulus = small_bit.ciphertext_modulus();
    let mut centered = small_bit.clone();
    lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 62));
    let mut correction = LweCiphertext::new(0u64, output_lwe_size, modulus);
    programmable_bootstrap_lwe_ciphertext(
        &centered,
        &mut correction,
        accumulator,
        fourier_bootstrap_key,
    );
    pbs_count.fetch_add(1, Ordering::Relaxed);
    lwe_ciphertext_plaintext_add_assign(&mut correction, Plaintext(alpha));
    correction
}

/// Variante strumentata dell'algoritmo `extract_bits` di tfhe-rs 0.11.3.
///
/// La sequenza residuo -> shift -> KS -> PBS di correzione e' adattata dall'implementazione
/// Copyright (c) 2024 ZAMA, distribuita con licenza BSD-3-Clause-Clear. I termini completi sono
/// conservati in `LICENSE.tfhe-rs-BSD-3-Clause-Clear`. Questa variante conserva la correzione LWE
/// grande prima che sia sottratta dal residuo.
fn extract_bits_with_corrections(
    input: &Lwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    correction_accumulators: &[Glwe],
    delta_log: u32,
    bit_count: u32,
    pbs_count: &AtomicU64,
) -> CapturedExtractedBits {
    assert_eq!(correction_accumulators.len(), bit_count as usize - 1);
    assert!(delta_log + bit_count <= 64);
    let modulus = input.ciphertext_modulus();
    let mut residual = input.clone();
    let mut small_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut corrections_lsb_first = Vec::with_capacity(bit_count as usize - 1);

    for bit_index in 0..bit_count {
        let shift = 64 - delta_log - bit_index - 1;
        let mut shifted = residual.clone();
        for coefficient in shifted.as_mut() {
            *coefficient <<= shift;
        }
        let mut small = LweCiphertext::new(0u64, key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(key_switching_key, &shifted, &mut small);
        small_lsb_first.push(small.clone());
        if bit_index == bit_count - 1 {
            break;
        }

        let alpha = 1u64 << (delta_log + bit_index - 1);
        let correction = correction_from_small_bit(
            &small,
            &correction_accumulators[bit_index as usize],
            fourier_bootstrap_key,
            input.lwe_size(),
            alpha,
            pbs_count,
        );
        lwe_ciphertext_sub_assign(&mut residual, &correction);
        corrections_lsb_first.push(correction);
    }

    CapturedExtractedBits {
        small_lsb_first,
        corrections_lsb_first,
    }
}

fn compact_or<F>(mut bits: Vec<Lwe>, or_gate: &F) -> Lwe
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    while bits.len() > 1 {
        bits = bits.par_chunks(OR_BLOCK).map(or_gate).collect();
    }
    bits.pop().expect("OR non vuoto")
}

fn radix4_exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!flags.is_empty());
    if flags.len() <= OR_BLOCK {
        return (0..flags.len())
            .map(|index| match index {
                0 => zero.clone(),
                1 => flags[0].clone(),
                _ => or_gate(&flags[..index]),
            })
            .collect();
    }
    let block_totals: Vec<Lwe> = flags
        .par_chunks(OR_BLOCK)
        .map(|block| {
            if block.len() == 1 {
                block[0].clone()
            } else {
                or_gate(block)
            }
        })
        .collect();
    let block_prefixes = radix4_exclusive_prefix_or(&block_totals, zero, or_gate);
    (0..flags.len())
        .into_par_iter()
        .map(|index| {
            let block = index / OR_BLOCK;
            let offset = index % OR_BLOCK;
            if offset == 0 {
                return block_prefixes[block].clone();
            }
            let start = block * OR_BLOCK;
            let mut inputs = Vec::with_capacity(offset + usize::from(block > 0));
            if block > 0 {
                inputs.push(block_prefixes[block].clone());
            }
            inputs.extend(flags[start..start + offset].iter().cloned());
            if inputs.len() == 1 {
                inputs.pop().unwrap()
            } else {
                or_gate(&inputs)
            }
        })
        .collect()
}

fn stage_metrics(started: Instant, pbs_before: u64, pbs_count: &AtomicU64) -> StageMetrics {
    StageMetrics {
        seconds: started.elapsed().as_secs_f64(),
        pbs_count: pbs_count.load(Ordering::Relaxed) - pbs_before,
    }
}

/// Calcola l'identificazione privata esatta e la soglia associata soltanto al vincitore.
///
/// `packed_probe` contiene il probe a `Delta=2^52` nei coefficienti 0..511 e lo stesso probe
/// modulo16 a `Delta=2^60` nei coefficienti 1024..1535. Il server possiede la galleria in chiaro
/// e una chiave di valutazione, ma non la chiave segreta. L'unico ciphertext restituito codifica
/// `0=rifiuto` oppure `indice+1=match`.
///
/// Il client deve aver validato prima della cifratura coordinate in `[-3,3]` e norma quadrata
/// non superiore a [`PROBE_NORM2_MAX`]. Il dominio fornito prova la correttezza sotto quel vincolo;
/// il server non puo' ricontrollare in chiaro una proprieta' del probe cifrato.
pub fn private_argmin(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PrivateArgminOutput, PrivateArgminError> {
    private_argmin_impl(server_key, packed_probe, templates, domain, None)
}

/// Esegue lo stesso core di [`private_argmin`] conservando checkpoint cifrati per un replay locale.
///
/// Questa funzione non decifra nulla e non e' collegata al servizio o al formato wire.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_with_trace(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((output, trace))
}

fn private_argmin_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    mut trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let total_started = Instant::now();
    let pbs_count = AtomicU64::new(0);
    let n = templates.len();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let key_switching_key = &server_key.key_switching_key;
    let fourier_bootstrap_key = match &server_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let bit_positions: Vec<u32> = (0..=HIGH_SCORE_BIT).rev().collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_positions_msb_first = bit_positions.clone();
    }
    let setup_started = Instant::now();
    let setup_pbs = pbs_count.load(Ordering::Relaxed);

    let make_correction_accumulators = |delta_log: u32, correction_count: u32| {
        (0..correction_count)
            .map(|bit_index| {
                let alpha = 1u64 << (delta_log + bit_index - 1);
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    glwe_size,
                    &PlaintextList::new(alpha.wrapping_neg(), PlaintextCount(polynomial_size.0)),
                    modulus,
                )
            })
            .collect::<Vec<_>>()
    };
    let low_correction_accumulators =
        make_correction_accumulators(LOW_MOD16_DELTA_LOG, LOW_EXTRACTED_BITS - 1);
    let low_to_full_correction_accumulators =
        make_correction_accumulators(FULL_DELTA_LOG, LOW_EXTRACTED_BITS);
    let high_correction_accumulators =
        make_correction_accumulators(HIGH_DELTA_LOG, HIGH_EXTRACTED_BITS - 1);
    let sign_accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::new(
            (bool_delta >> 1).wrapping_neg(),
            PlaintextCount(polynomial_size.0),
        ),
        modulus,
    );

    let bit_weights: Vec<u64> = bit_positions
        .iter()
        .map(|bit_index| extracted_bit_weight(*bit_index))
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_weights_msb_first = bit_weights.clone();
    }
    let update_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        update_candidate_from_zero_lut,
    );
    let encoded_zero_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        encoded_zero_candidate_lut,
    );
    let single_zero_accumulators: Vec<Glwe> = bit_weights
        .iter()
        .map(|weight| {
            let (candidate_weight, bit_weight) = zero_layout(*weight);
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                bool_delta,
                move |value| zero_candidate_lut(value, candidate_weight, bit_weight),
            )
        })
        .collect();
    let boolean_and_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        boolean_and_lut,
    );
    let comparison_state_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        comparison_state_lut,
    );
    let comparison_accept_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        comparison_accept_tag_lut,
    );
    let output_bit_positions = output_bit_positions(n);
    let weighted_or_accumulators: Vec<Glwe> = [1u64, 2, 4]
        .into_iter()
        .map(|weight| {
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                bool_delta,
                move |value| weighted_or_lut(value, weight),
            )
        })
        .collect();
    let output_group_accumulators: Vec<Glwe> = output_bit_positions
        .chunks(3)
        .map(|positions| {
            debug_assert!(positions.windows(2).all(|pair| pair[1] == pair[0] + 1));
            let bit_offset = positions[0];
            let group_len = positions.len();
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                code_delta,
                move |value| output_group_lut(value, bit_offset, group_len),
            )
        })
        .collect();
    let setup_metrics = stage_metrics(setup_started, setup_pbs, &pbs_count);

    let apply_pbs = |input: &Lwe, accumulator: &Glwe| -> Lwe {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &switched,
            &mut output,
            accumulator,
            fourier_bootstrap_key,
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        output
    };
    let recode_extracted_bit = |bit: &Lwe| -> Lwe {
        let mut shifted = bit.clone();
        lwe_ciphertext_plaintext_add_assign(&mut shifted, Plaintext(1u64 << 61));
        let mut output = LweCiphertext::new(0u64, big_size, modulus);
        programmable_bootstrap_lwe_ciphertext(
            &shifted,
            &mut output,
            &sign_accumulator,
            fourier_bootstrap_key,
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(bool_delta >> 1));
        output
    };
    let bridge_bit = |full: &CapturedExtractedBits,
                      low: &CapturedExtractedBits,
                      bit_index: u32|
     -> WeightedBit {
        let source = if bit_index < SPLIT_LOW_BITS {
            low
        } else {
            full
        };
        let weight = extracted_bit_weight(bit_index);
        if recodes_bit(bit_index) {
            return WeightedBit {
                ciphertext: recode_extracted_bit(&source.small_lsb_first[bit_index as usize]),
            };
        }
        let correction_log = bit_source_delta(bit_index) + bit_index;
        let target_log = BOOL_DELTA_LOG + weight.ilog2();
        let mut ciphertext = source.corrections_lsb_first[bit_index as usize].clone();
        lwe_ciphertext_cleartext_mul_assign(
            &mut ciphertext,
            Cleartext(1u64 << (target_log - correction_log)),
        );
        WeightedBit { ciphertext }
    };
    let or_gate = |bits: &[Lwe]| -> Lwe {
        assert!(!bits.is_empty() && bits.len() <= OR_BLOCK);
        let mut count =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
        for bit in bits {
            lwe_ciphertext_add_assign(&mut count, bit);
        }
        lwe_ciphertext_opposite_assign(&mut count);
        lwe_ciphertext_plaintext_add_assign(&mut count, Plaintext(bool_delta >> 1));
        let mut any = apply_pbs(&count, &sign_accumulator);
        lwe_ciphertext_plaintext_add_assign(&mut any, Plaintext(bool_delta >> 1));
        any
    };
    let or_reduce = |mut bits: Vec<Lwe>| -> Lwe {
        assert!(!bits.is_empty());
        while bits.len() > 1 {
            bits = bits.chunks(OR_BLOCK).map(&or_gate).collect();
        }
        bits.pop().expect("la riduzione OR parte non vuota")
    };
    let apply_sum_gate = |bits: &[&Lwe], accumulator: &Glwe| -> Lwe {
        let mut sum =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
        for bit in bits {
            lwe_ciphertext_add_assign(&mut sum, bit);
        }
        apply_pbs(&sum, accumulator)
    };
    let and_gate = |left: &Lwe, right: &Lwe| -> Lwe {
        apply_sum_gate(&[left, right], &boolean_and_accumulator)
    };

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let score_pairs: Vec<(Lwe, Lwe)> = templates
        .par_iter()
        .map(|entry| {
            let mut polynomial = vec![0u64; polynomial_size.0];
            for coordinate in 0..PROBE_DIM {
                polynomial[PROBE_DIM - 1 - coordinate] = (-2 * entry.template[coordinate]) as u64;
            }
            let polynomial = Polynomial::from_container(polynomial);
            let mut product = GlweCiphertext::new(0u64, glwe_size, polynomial_size, modulus);
            for (mut output, input) in product
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(packed_probe.as_polynomial_list().iter())
            {
                polynomial_wrapping_add_mul_assign(&mut output, &input, &polynomial);
            }
            let extract_score = |degree: usize, delta: u64| {
                let mut score = LweCiphertext::new(0u64, big_size, modulus);
                extract_lwe_sample_from_glwe_ciphertext(
                    &product,
                    &mut score,
                    MonomialDegree(degree),
                );
                lwe_ciphertext_plaintext_add_assign(
                    &mut score,
                    Plaintext(((entry.norm2 - domain.lower) as u64).wrapping_mul(delta)),
                );
                score
            };
            (
                extract_score(PROBE_DIM - 1, full_delta),
                extract_score(LOW_MOD16_POLYNOMIAL_OFFSET + PROBE_DIM - 1, low_delta),
            )
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.score_full = score_pairs.iter().map(|(full, _)| full.clone()).collect();
        trace.score_low_mod16 = score_pairs.iter().map(|(_, low)| low.clone()).collect();
    }
    let score_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let low_bit_count = LOW_EXTRACTED_BITS as usize;
    // La vista modulo 16 fornisce i bit 0..3 con il margine piu' ampio. Li convertiamo tutti
    // alla scala full e li sottraiamo prima di estrarre soltanto i bit globali 4..11.
    let low_extracted: Vec<CapturedExtractedBits> = score_pairs
        .par_iter()
        .map(|(_, low)| {
            extract_bits_with_corrections(
                low,
                fourier_bootstrap_key,
                key_switching_key,
                &low_correction_accumulators,
                LOW_MOD16_DELTA_LOG,
                LOW_EXTRACTED_BITS,
                &pbs_count,
            )
        })
        .collect();
    let low_to_full_corrections_flat: Vec<Lwe> = (0..n * low_bit_count)
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / low_bit_count;
            let bit_index = flat % low_bit_count;
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index as u32 - 1);
            correction_from_small_bit(
                &low_extracted[gallery_index].small_lsb_first[bit_index],
                &low_to_full_correction_accumulators[bit_index],
                fourier_bootstrap_key,
                big_size,
                alpha,
                &pbs_count,
            )
        })
        .collect();
    let high_inputs: Vec<Lwe> = score_pairs
        .par_iter()
        .enumerate()
        .map(|(gallery_index, (full_score, _))| {
            let mut residual = full_score.clone();
            let start = gallery_index * low_bit_count;
            for correction in &low_to_full_corrections_flat[start..start + low_bit_count] {
                lwe_ciphertext_sub_assign(&mut residual, correction);
            }
            residual
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.high_residuals = high_inputs.clone();
    }
    let high_extracted: Vec<CapturedExtractedBits> = high_inputs
        .par_iter()
        .map(|high| {
            extract_bits_with_corrections(
                high,
                fourier_bootstrap_key,
                key_switching_key,
                &high_correction_accumulators,
                HIGH_DELTA_LOG,
                HIGH_EXTRACTED_BITS,
                &pbs_count,
            )
        })
        .collect();
    let full_extracted: Vec<CapturedExtractedBits> = low_extracted
        .iter()
        .zip(high_extracted)
        .enumerate()
        .map(|(gallery_index, (low, high))| {
            let start = gallery_index * low_bit_count;
            // Manteniamo la rappresentazione globale 0..11 usata dal bridge e dal trace: i primi
            // quattro slot provengono dal canale low, gli altri otto dall'estrattore high.
            let mut small_lsb_first = low.small_lsb_first.clone();
            small_lsb_first.extend(high.small_lsb_first);
            let mut corrections_lsb_first =
                low_to_full_corrections_flat[start..start + low_bit_count].to_vec();
            corrections_lsb_first.extend(high.corrections_lsb_first);
            debug_assert_eq!(small_lsb_first.len(), SCORE_BITS as usize);
            debug_assert_eq!(corrections_lsb_first.len(), SCORE_BITS as usize - 1);
            CapturedExtractedBits {
                small_lsb_first,
                corrections_lsb_first,
            }
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.full_small_bits_lsb_first = full_extracted
            .iter()
            .map(|bits| bits.small_lsb_first.clone())
            .collect();
        trace.full_corrections_lsb_first = full_extracted
            .iter()
            .map(|bits| bits.corrections_lsb_first.clone())
            .collect();
        trace.low_small_bits_lsb_first = low_extracted
            .iter()
            .map(|bits| bits.small_lsb_first.clone())
            .collect();
        trace.low_corrections_lsb_first = low_extracted
            .iter()
            .map(|bits| bits.corrections_lsb_first.clone())
            .collect();
    }
    let flat_bits: Vec<WeightedBit> = (0..n * bit_positions.len())
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / bit_positions.len();
            let level = flat % bit_positions.len();
            bridge_bit(
                &full_extracted[gallery_index],
                &low_extracted[gallery_index],
                bit_positions[level],
            )
        })
        .collect();
    let bits_by_level: Vec<Vec<WeightedBit>> = bit_positions
        .iter()
        .enumerate()
        .map(|(level, _)| {
            (0..n)
                .map(|index| flat_bits[index * bit_positions.len() + level].clone())
                .collect()
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.bridged_bits_by_level = bits_by_level
            .iter()
            .map(|bits| bits.iter().map(|bit| bit.ciphertext.clone()).collect())
            .collect();
    }
    let extract_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let mut candidates: Vec<Lwe> = (0..n)
        .map(|_| {
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                big_size,
                Plaintext(bool_delta),
                modulus,
            )
        })
        .collect();
    let mut any_zero_bits = Vec::with_capacity(SCORE_BITS as usize);
    for (level, bits) in bits_by_level.iter().enumerate() {
        let raw_bit_weight = bit_weights[level];
        let zero_candidates: Vec<Lwe> = if level == 0 {
            assert_eq!(raw_bit_weight, 1);
            bits.par_iter()
                .map(|bit| {
                    let mut zero = bit.ciphertext.clone();
                    lwe_ciphertext_opposite_assign(&mut zero);
                    lwe_ciphertext_plaintext_add_assign(&mut zero, Plaintext(bool_delta));
                    zero
                })
                .collect()
        } else if level % 2 == 1 {
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, &bit.ciphertext);
                    apply_pbs(&encoded, &encoded_zero_candidate_accumulator)
                })
                .collect()
        } else if raw_bit_weight == 1 {
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut not_bit = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                        big_size,
                        Plaintext(bool_delta),
                        modulus,
                    );
                    lwe_ciphertext_sub_assign(&mut not_bit, &bit.ciphertext);
                    and_gate(candidate, &not_bit)
                })
                .collect()
        } else {
            assert!(matches!(raw_bit_weight, 2 | 4 | 8));
            candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, &bit.ciphertext);
                    apply_pbs(&encoded, &single_zero_accumulators[level])
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.zero_candidates_by_level.push(zero_candidates.clone());
        }
        let any_zero = compact_or(zero_candidates.clone(), &or_gate);
        any_zero_bits.push(any_zero.clone());
        candidates = if level % 2 == 0 {
            // Da un candidato Booleano c costruiamo linearmente e=-c-z+a. Gli attivi diventano
            // 15, gli inattivi 0/1; il rumore e' <=2 al MSB e <=3 negli altri livelli pari.
            candidates
                .par_iter()
                .zip(&zero_candidates)
                .map(|(candidate, zero_candidate)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, zero_candidate);
                    lwe_ciphertext_opposite_assign(&mut encoded);
                    lwe_ciphertext_add_assign(&mut encoded, &any_zero);
                    encoded
                })
                .collect()
        } else {
            // Dal candidato codificato e ricaviamo `-e+z-a`: il codice uno identifica soltanto
            // gli attivi che sopravvivono. L'ingresso contiene al massimo cinque unita' di
            // rumore, esattamente il limite del parameter set, e l'uscita torna Booleana fresca.
            candidates
                .par_iter()
                .zip(&zero_candidates)
                .map(|(candidate, zero_candidate)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_opposite_assign(&mut encoded);
                    lwe_ciphertext_add_assign(&mut encoded, zero_candidate);
                    lwe_ciphertext_sub_assign(&mut encoded, &any_zero);
                    apply_pbs(&encoded, &update_candidate_accumulator)
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.any_zero_by_level.push(any_zero);
            trace.candidates_by_level.push(candidates.clone());
        }
    }
    let select_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let zero =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
    // Lo scan opera prima su gruppi di tre candidati: un solo OR produce il flag del gruppo,
    // poi un prefisso ricorsivo radix-4 calcola quali gruppi precedenti contengono un minimo.
    // Il gate finale di ogni elemento incorpora quel prefisso e i (massimo due) predecessori
    // locali. Non serve padding e ogni input contiene al massimo quattro Booleani freschi.
    let group_flags: Vec<Lwe> = candidates
        .par_chunks(FIRST_ONE_GROUP)
        .map(|group| {
            if group.len() == 1 {
                group[0].clone()
            } else {
                or_gate(group)
            }
        })
        .collect();
    let group_prefixes = radix4_exclusive_prefix_or(&group_flags, &zero, &or_gate);
    if let Some(trace) = trace.as_deref_mut() {
        trace.group_prefixes = group_prefixes.clone();
    }
    let winners: Vec<Lwe> = (0..n)
        .into_par_iter()
        .map(|index| {
            let group = index / FIRST_ONE_GROUP;
            let group_start = group * FIRST_ONE_GROUP;
            let mut encoded = candidates[index].clone();
            lwe_ciphertext_sub_assign(&mut encoded, &group_prefixes[group]);
            for previous in &candidates[group_start..index] {
                lwe_ciphertext_sub_assign(&mut encoded, previous);
            }
            apply_pbs(&encoded, &update_candidate_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.winners = winners.clone();
    }
    let scan_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let threshold_metadata: Vec<(u64, bool)> = templates
        .iter()
        .map(|entry| {
            let below = entry.threshold < domain.lower;
            let clamped = entry.threshold.clamp(domain.lower, domain.upper);
            ((clamped - domain.lower) as u64, below)
        })
        .collect();
    // Selezionare la soglia con somme lineari accumula il rumore dei winner che cifrano zero.
    // Riduciamo quindi con OR soltanto gli indici il cui bit pubblico e' impostato. Una maschera
    // vuota e' zero pubblico; una maschera piena e' uno pubblico, perche' esiste esattamente un
    // winner. Le soglie uniformi non richiedono cosi' alcun PBS di selezione, mentre il caso
    // per-template generale conserva la stessa semantica con costo dipendente dalle maschere.
    let threshold_masks: Vec<Vec<bool>> = bit_positions
        .iter()
        .map(|bit_position| {
            threshold_metadata
                .iter()
                .map(|(threshold, _)| ((threshold >> bit_position) & 1) == 1)
                .collect()
        })
        .collect();
    let below_mask: Vec<bool> = threshold_metadata.iter().map(|(_, below)| *below).collect();
    let one =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(bool_delta), modulus);
    let select_winner_mask = |mask: &[bool]| -> Lwe {
        assert_eq!(mask.len(), n);
        let selected: Vec<Lwe> = winners[..n]
            .iter()
            .zip(mask)
            .filter(|(_, enabled)| **enabled)
            .map(|(winner, _)| winner.clone())
            .collect();
        match selected.len() {
            0 => zero.clone(),
            count if count == n => one.clone(),
            _ => or_reduce(selected),
        }
    };
    let selected_threshold_bits: Vec<Lwe> = threshold_masks
        .par_iter()
        .map(|mask| select_winner_mask(mask))
        .collect();
    let selected_below = select_winner_mask(&below_mask);
    if let Some(trace) = trace.as_deref_mut() {
        trace.selected_threshold_bits_msb_first = selected_threshold_bits.clone();
        trace.selected_below = Some(selected_below.clone());
    }
    // Stato ternario less/equal/greater codificato come 0/2/4. Sottrarre i due Booleani
    // `any_zero = !minimum_bit` e `threshold_bit` produce codici non ambigui modulo 16; una sola
    // LUT aggiorna quindi il confronto a ogni bit, invece dei quattro gate Booleani precedenti.
    let mut comparison_state = allocate_and_trivially_encrypt_new_lwe_ciphertext(
        big_size,
        Plaintext(COMPARISON_EQUAL * bool_delta),
        modulus,
    );
    for (any_zero, threshold_bit) in any_zero_bits.iter().zip(&selected_threshold_bits) {
        let mut encoded = comparison_state;
        lwe_ciphertext_sub_assign(&mut encoded, any_zero);
        lwe_ciphertext_sub_assign(&mut encoded, threshold_bit);
        comparison_state = apply_pbs(&encoded, &comparison_state_accumulator);
        if let Some(trace) = trace.as_deref_mut() {
            trace
                .comparison_state_by_level
                .push(comparison_state.clone());
        }
    }
    // `threshold >= upper` non richiede una sentinella separata: il valore viene clampato a upper
    // e ogni score valido e' gia' <= upper. Solo `threshold < lower` deve forzare il rifiuto.
    lwe_ciphertext_add_assign(&mut comparison_state, &selected_below);
    let accept_tag = apply_pbs(&comparison_state, &comparison_accept_accumulator);
    if let Some(trace) = trace.as_deref_mut() {
        trace.accept_tag = Some(accept_tag.clone());
    }
    let threshold_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    // L'ultimo OR di ogni maschera emette direttamente un digit locale fresco 1/2/4. Tre digit
    // e il tag fresco 8 dell'accettazione formano un codice non ambiguo 0..15; una sola LUT di
    // gruppo applica insieme soglia e peso assoluto del codice. La somma finale contiene al
    // massimo tre ciphertext freschi per MAX_GALLERY_SIZE=128.
    let coded_digits: Vec<Lwe> = output_bit_positions
        .par_iter()
        .map(|&bit_position| {
            let mut selected: Vec<Lwe> = winners[..n]
                .iter()
                .enumerate()
                .filter(|(index, _)| output_code_has_bit(*index, bit_position))
                .map(|(_, winner)| winner.clone())
                .collect();
            debug_assert!(!selected.is_empty());
            while selected.len() > OR_BLOCK {
                selected = selected.chunks(OR_BLOCK).map(&or_gate).collect();
            }
            let mut count = zero.clone();
            for winner in &selected {
                lwe_ciphertext_add_assign(&mut count, winner);
            }
            apply_pbs(&count, &weighted_or_accumulators[bit_position as usize % 3])
        })
        .collect();
    let code_groups: Vec<Lwe> = coded_digits
        .par_chunks(3)
        .zip(&output_group_accumulators)
        .map(|(digits, accumulator)| {
            let mut encoded = accept_tag.clone();
            for digit in digits {
                lwe_ciphertext_add_assign(&mut encoded, digit);
            }
            apply_pbs(&encoded, accumulator)
        })
        .collect();
    let mut code = zero;
    for value in &code_groups {
        lwe_ciphertext_add_assign(&mut code, value);
    }
    if let Some(trace) = trace {
        trace.coded_digits_lsb_first = coded_digits.clone();
        trace.code_groups = code_groups;
        trace.final_code = Some(code.clone());
    }
    let output_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);
    let total_pbs_count = pbs_count.load(Ordering::Relaxed);
    Ok(PrivateArgminOutput {
        code,
        metrics: PrivateArgminMetrics {
            setup: setup_metrics,
            score: score_metrics,
            extract: extract_metrics,
            select: select_metrics,
            scan: scan_metrics,
            threshold: threshold_metrics,
            output: output_metrics,
            total_seconds: total_started.elapsed().as_secs_f64(),
            total_pbs_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(template: &'a [i64], threshold: i64) -> TemplateView<'a> {
        TemplateView {
            template,
            norm2: template.iter().map(|value| value * value).sum(),
            threshold,
        }
    }

    #[test]
    fn integer_ceil_sqrt_is_exact_without_floating_point() {
        for value in 0u64..=100_000 {
            let root = ceil_sqrt(value);
            assert!(root * root >= value);
            assert!(root == 0 || (root - 1) * (root - 1) < value);
        }
        assert_eq!(ceil_sqrt(u64::MAX), 1u64 << 32);
    }

    #[test]
    fn cauchy_domain_is_checked_and_twelve_bit() {
        let mut first = [0i64; PROBE_DIM];
        first[0] = 1;
        let mut second = [0i64; PROBE_DIM];
        second[0] = 2;
        let templates = [entry(&first, 0), entry(&second, 0)];
        let domain = cauchy_score_domain(&templates).unwrap();
        assert_eq!(
            domain,
            ScoreDomain {
                lower: -124,
                upper: 132
            }
        );
        assert_eq!(domain.checked_width(), Some(257));

        let invalid = ScoreDomain {
            lower: i64::MIN,
            upper: i64::MAX,
        };
        assert!(matches!(
            validate_domain(invalid),
            Err(PrivateArgminError::InvalidDomain { .. })
        ));
    }

    #[test]
    fn public_template_validation_is_panic_free() {
        let mut invalid = [0i64; PROBE_DIM];
        invalid[19] = 4;
        let view = TemplateView {
            template: &invalid,
            norm2: 16,
            threshold: 0,
        };
        assert_eq!(
            cauchy_score_domain(&[view]),
            Err(PrivateArgminError::InvalidTemplateCoordinate {
                index: 0,
                coordinate: 19,
                value: 4,
            })
        );
        let valid = [0i64; PROBE_DIM];
        let mismatch = TemplateView {
            template: &valid,
            norm2: 1,
            threshold: 0,
        };
        assert!(matches!(
            cauchy_score_domain(&[mismatch]),
            Err(PrivateArgminError::IncorrectTemplateNorm { .. })
        ));
    }

    #[test]
    fn tie_and_per_template_threshold_use_only_first_winner() {
        let first = [0i64; PROBE_DIM];
        let second = [0i64; PROBE_DIM];
        let strict_then_permissive = [entry(&first, 9), entry(&second, 100)];

        let nearest_strict = clear_private_argmin(&[10, 11], &strict_then_permissive).unwrap();
        assert_eq!(nearest_strict.winner_index, 0);
        assert!(!nearest_strict.matched);
        assert_eq!(nearest_strict.code, 0);

        let tied = clear_private_argmin(&[10, 10], &strict_then_permissive).unwrap();
        assert_eq!(tied.winner_index, 0);
        assert!(!tied.matched);
        assert_eq!(tied.code, 0);

        let permissive_first = [entry(&first, 10), entry(&second, -100)];
        let accepted = clear_private_argmin(&[10, 10], &permissive_first).unwrap();
        assert_eq!(accepted.winner_index, 0);
        assert!(accepted.matched);
        assert_eq!(accepted.code, 1);
    }

    #[test]
    fn comparison_state_luts_are_exhaustive() {
        for left in 0u64..=1 {
            for right in 0u64..=1 {
                assert_eq!(boolean_and_lut(left + right), left & right);
            }
        }
        for state in [COMPARISON_LESS, COMPARISON_EQUAL, COMPARISON_GREATER] {
            for any_zero in [false, true] {
                for threshold_bit in [false, true] {
                    let code = state
                        .wrapping_sub(u64::from(any_zero))
                        .wrapping_sub(u64::from(threshold_bit))
                        & 15;
                    let minimum_bit = !any_zero;
                    let expected = if state != COMPARISON_EQUAL {
                        state
                    } else {
                        match (minimum_bit, threshold_bit) {
                            (false, true) => COMPARISON_LESS,
                            (true, false) => COMPARISON_GREATER,
                            _ => COMPARISON_EQUAL,
                        }
                    };
                    assert_eq!(comparison_state_lut(code), expected);
                }
            }
            for below in [false, true] {
                assert_eq!(
                    comparison_accept_tag_lut(state + u64::from(below)),
                    8 * u64::from(state != COMPARISON_GREATER && !below)
                );
            }
        }
    }

    #[test]
    fn boolean_threshold_recurrence_matches_all_twelve_bit_comparisons() {
        for minimum in 0u64..MAX_DOMAIN_WIDTH as u64 {
            for threshold in 0u64..MAX_DOMAIN_WIDTH as u64 {
                let mut state = COMPARISON_EQUAL;
                for bit_position in (0..SCORE_BITS).rev() {
                    let any_zero = ((minimum >> bit_position) & 1) == 0;
                    let threshold_bit = ((threshold >> bit_position) & 1) == 1;
                    let code = state
                        .wrapping_sub(u64::from(any_zero))
                        .wrapping_sub(u64::from(threshold_bit))
                        & 15;
                    state = comparison_state_lut(code);
                }
                assert_eq!(
                    comparison_accept_tag_lut(state),
                    8 * u64::from(minimum <= threshold)
                );
                assert_eq!(comparison_accept_tag_lut(state + 1), 0);
            }
        }
    }

    #[test]
    fn bounded_selection_luts_are_exhaustive() {
        for bit_weight in [2, 4, 8] {
            let (candidate_weight, zero_bit_weight) = zero_layout(bit_weight);
            for candidate in 0u64..=1 {
                for bit in 0u64..=1 {
                    let zero_code = candidate * candidate_weight + bit * zero_bit_weight;
                    assert_eq!(
                        zero_candidate_lut(zero_code, candidate_weight, zero_bit_weight),
                        u64::from(candidate == 1 && bit == 0)
                    );
                }
            }
        }
        for candidate in [false, true] {
            for bit in [false, true] {
                let zero_candidate = candidate && !bit;
                for any_zero in [false, true] {
                    if zero_candidate && !any_zero {
                        continue;
                    }
                    let code = u64::from(candidate)
                        .wrapping_add(u64::from(zero_candidate))
                        .wrapping_sub(u64::from(any_zero))
                        & 15;
                    assert_eq!(
                        update_candidate_from_zero_lut(code),
                        u64::from(candidate && (bit != any_zero))
                    );
                }
            }
        }
        for candidate in [false, true] {
            for even_bit in [false, true] {
                let even_zero = candidate && !even_bit;
                for even_any_zero in [false, true] {
                    if even_zero && !even_any_zero {
                        continue;
                    }
                    let encoded = 0u64
                        .wrapping_sub(u64::from(candidate))
                        .wrapping_sub(u64::from(even_zero))
                        .wrapping_add(u64::from(even_any_zero))
                        & 15;
                    let logically_active = candidate && (even_bit != even_any_zero);
                    assert!(
                        (logically_active && encoded == 15)
                            || (!logically_active && matches!(encoded, 0 | 1))
                    );
                    for bit_weight in [1u64, 2, 4, 8] {
                        for odd_bit in [false, true] {
                            let odd_zero = logically_active && !odd_bit;
                            for odd_any_zero in [false, true] {
                                if odd_zero && !odd_any_zero {
                                    continue;
                                }
                                let zero_code = (encoded + bit_weight * u64::from(odd_bit)) & 15;
                                assert_eq!(
                                    encoded_zero_candidate_lut(zero_code),
                                    if odd_zero { u64::MAX } else { 0 }
                                );
                                let normalize_code = 0u64
                                    .wrapping_sub(encoded)
                                    .wrapping_add(u64::from(odd_zero))
                                    .wrapping_sub(u64::from(odd_any_zero))
                                    & 15;
                                assert_eq!(
                                    update_candidate_from_zero_lut(normalize_code),
                                    u64::from(logically_active && (odd_bit != odd_any_zero))
                                );
                            }
                        }
                    }
                }
            }
        }
        for weight in [1, 2, 4] {
            for code in 0..16 {
                assert_eq!(
                    weighted_or_lut(code, weight),
                    if (1..=4).contains(&code) { weight } else { 0 }
                );
            }
        }
        for bit_offset in [0, 3, 6] {
            for group_len in 1..=3 {
                let payload_mask = (1u64 << group_len) - 1;
                for accept in [false, true] {
                    for payload in 0..8 {
                        assert_eq!(
                            output_group_lut(
                                payload + 8 * u64::from(accept),
                                bit_offset,
                                group_len,
                            ),
                            if accept {
                                (payload & payload_mask) << bit_offset
                            } else {
                                0
                            }
                        );
                    }
                }
            }
        }
        for candidate in [false, true] {
            for prefix in [false, true] {
                for previous_count in 0u64..=2 {
                    let code = u64::from(candidate)
                        .wrapping_sub(u64::from(prefix))
                        .wrapping_sub(previous_count)
                        & 15;
                    assert_eq!(
                        update_candidate_from_zero_lut(code),
                        u64::from(candidate && !prefix && previous_count == 0)
                    );
                }
            }
        }
    }

    #[test]
    fn output_bit_masks_reconstruct_every_supported_code() {
        for gallery_size in 1..=MAX_GALLERY_SIZE {
            let bit_positions = output_bit_positions(gallery_size);
            assert_eq!(
                bit_positions.len() as u32,
                usize::BITS - gallery_size.leading_zeros()
            );
            for winner_index in 0..gallery_size {
                let reconstructed: usize = bit_positions
                    .iter()
                    .filter(|&&bit_position| output_code_has_bit(winner_index, bit_position))
                    .map(|&bit_position| 1usize << bit_position)
                    .sum();
                assert_eq!(reconstructed, winner_index + 1);
            }
        }
    }

    #[test]
    fn output_group_luts_fit_the_code_scale_for_every_gallery_size() {
        let code_delta = 1u64 << CODE_DELTA_LOG;
        for gallery_size in 1..=MAX_GALLERY_SIZE {
            for positions in output_bit_positions(gallery_size).chunks(3) {
                let bit_offset = positions[0];
                for code in 0..PBS_MESSAGE_MODULUS as u64 {
                    assert!(output_group_lut(code, bit_offset, positions.len())
                        .checked_mul(code_delta)
                        .is_some());
                }
            }
        }
    }

    #[test]
    fn deterministic_pbs_counts_include_odd_tail_and_n_one() {
        assert_eq!(expected_pbs_count(0), None);
        assert_eq!(expected_pbs_count(1), Some(53));
        assert_eq!(expected_pbs_count(3), Some(156));
        assert_eq!(expected_pbs_count(64), Some(3087));
        assert_eq!(expected_pbs_count(127), Some(6159));
        assert_eq!(expected_pbs_count(128), Some(6199));
        assert_eq!(expected_pbs_count(129), None);

        let domain = ScoreDomain {
            lower: -10,
            upper: 10,
        };
        assert_eq!(
            expected_pbs_count_for_thresholds(3, &[0, 0, 0], domain),
            Some(143)
        );
        assert_eq!(
            expected_pbs_count_for_thresholds(127, &[0; 127], domain),
            Some(5600)
        );
        assert_eq!(expected_pbs_count_for_thresholds(3, &[0, 1], domain), None);
    }
}
