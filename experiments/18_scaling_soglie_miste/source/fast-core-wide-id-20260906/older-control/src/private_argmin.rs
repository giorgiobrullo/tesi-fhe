//! Prototipo isolato A66 latency-ready dell'argmin TFHE esatto e privato per il varco 1:N.
//!
//! La base A62 e' congelata. A66 conserva score, estrazione, A34-top, selezione A50, semantica A53,
//! contatori e due radici terminali base-15 a `Delta=2^59`. Cambia soltanto l'esecuzione interna
//! dell'adapter A53: accumulatori raw preparati una volta, contatori atomici e peer indipendenti
//! affidati a Rayon. Il client continua a ricostruire `low+15*high`; A66 non e' ancora compilato,
//! eseguito FHE o misurato.

use crate::a53_scan::fhe::{
    materialize_a53_scan, A53FheBackend, BackendParameterContract, FutureFheError, FutureFheGate,
    A66_EXPERIMENT_ACK, A66_OBSERVED_SOURCE_GUARDS, A66_PFAIL_ACK,
};
use crate::a53_scan::{
    scan_counts as a53_scan_counts, PrimitiveCounts as A53PrimitiveCounts,
    A44_MAX_NOISE_LEVEL as A53_REQUIRED_MAX_NOISE_LEVEL,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::server_key::{ModulusSwitchConfiguration, ShortintBootstrappingKey};
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

/// Identita' protocollare del solo preset A44. Non e' un identificatore di compatibilita' con
/// A41: chiavi, probe e risposte devono essere rigenerati anche quando la geometria large-LWE
/// coincide.
pub const A44_PARAMS_ID: &str = "tfhe-rs-1.7.0-v0_11-m1c3-classic-ks-pbs-gaussian-2m64";

/// Serializzazione canonica congelata dei campi del preset ufficiale usato da A44.
///
/// Il fingerprint include anche distribuzioni e `log2_p_fail`, che non sono ricostruibili da un
/// [`ServerKey`] gia' generato. In un protocollo serializzato questa stringa deve quindi stare in
/// un envelope autenticato assieme agli artifact; il solo controllo delle dimensioni non basta.
pub const A44_PARAMETER_CANONICAL: &str = "tfhe-rs=1.7.0;symbol=V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;bootstrap=classic_ks_pbs;modulus_switch=standard;lwe_dimension=859;glwe_dimension=1;polynomial_size=2048;lwe_noise=gaussian_stddev_2.3088161607134664e-6;glwe_noise=gaussian_stddev_2.845267479601915e-15;pbs_base_log=23;pbs_level=1;ks_base_log=3;ks_level=5;message_modulus=2;carry_modulus=8;max_noise_level=15;log2_p_fail=-64.088;ciphertext_modulus=native;encryption_key_choice=Big";

pub const A44_PARAMETER_FINGERPRINT_SHA256: &str =
    "ff8b62d46dee3427a6f048490a171f5eb74158ffe9dad1b32c8bd8990dc2ac61";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A44ParameterBinding<'a> {
    pub params_id: &'a str,
    pub fingerprint_sha256: &'a str,
}

pub const A44_PARAMETER_BINDING: A44ParameterBinding<'static> = A44ParameterBinding {
    params_id: A44_PARAMS_ID,
    fingerprint_sha256: A44_PARAMETER_FINGERPRINT_SHA256,
};

const HIGH_SCORE_BIT: u32 = 11;
const SCORE_BITS: u32 = HIGH_SCORE_BIT + 1;
const SPLIT_LOW_BITS: u32 = 3;
const LOW_EXTRACTED_BITS: u32 = 4;
const HIGH_EXTRACTED_BITS: u32 = SCORE_BITS - LOW_EXTRACTED_BITS;
const HIGH_DELTA_LOG: u32 = FULL_DELTA_LOG + LOW_EXTRACTED_BITS;
const PBS_MESSAGE_MODULUS: usize = 16;
const ALIGNED_UNIFORM_THRESHOLD: i64 = 1023;
const ALIGNED_SELECTION_HIGH_BIT: u32 = 7;
const A34_HIGH_CORRECTION_BITS: u32 = 4;
const A34_TOP_CLASSIFIER_MODULUS: usize = 16;
const A34_TOP_CLASSIFIER_CODES: [u64; 16] = [30, 28, 3, 31, 0, 0, 0, 0, 2, 4, 29, 1, 0, 0, 0, 0];
const A38_REDUCTION_RADIX: usize = 5;
const A38_SCAN_GROUP_SIZE: usize = 3;
const A50_REDUCTION_RADIX: usize = 15;
const A50_SOURCE_MULTIPLIERS: [i64; 8] = [-1, -1, -1, -1, -1, 1, -1, -1];
const A38_NIBBLE_RADIX: u64 = 16;
const A38_EXPECTED_SOURCE_WEIGHTS: [u64; 8] = [1, 1, 1, 1, 1, 8, 4, 2];
const A38_SOURCE_MULTIPLIERS: [i64; 8] = [-2, -2, -2, -2, -2, 1, -1, -1];
const A38_CHUNK_END_LEVELS: [usize; 2] = [3, 7];
// Ogni ingresso e' un Booleano appena rinfrescato. Quattro contributi restano sotto il
// `max_noise_level=15` del preset A44. Il grafo resta quello A41: il margine maggiore non viene
// usato per cambiare il fan-in in questa copia.
const OR_BLOCK: usize = 4;
const FIRST_ONE_GROUP: usize = 3;

type Lwe = LweCiphertextOwned<u64>;
type Glwe = GlweCiphertextOwned<u64>;

fn standard_server_key_parts(
    server_key: &ServerKey,
) -> Result<
    (
        &LweKeyswitchKeyOwned<u64>,
        &FourierLweBootstrapKeyOwned,
        &ModulusSwitchConfiguration<u64>,
        PBSOrder,
    ),
    PrivateArgminError,
> {
    let standard_key = match &server_key.atomic_pattern {
        AtomicPatternServerKey::Standard(key) => key,
        _ => return Err(PrivateArgminError::UnsupportedBootstrappingKey),
    };
    match &standard_key.bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => Ok((
            &standard_key.key_switching_key,
            bsk,
            modulus_switch_noise_reduction_key,
            standard_key.pbs_order,
        )),
        _ => Err(PrivateArgminError::UnsupportedBootstrappingKey),
    }
}

fn blind_rotate_assign_with_modulus_switch(
    input: &Lwe,
    accumulator: &mut Glwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    modulus_switch_configuration: &ModulusSwitchConfiguration<u64>,
) {
    let log_modulus = fourier_bootstrap_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let modulus_switched =
        modulus_switch_configuration.lwe_ciphertext_modulus_switch::<usize, _>(input, log_modulus);
    blind_rotate_assign(&modulus_switched, accumulator, fourier_bootstrap_key);
}

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

/// Piano deterministico del dominio usato dall'argmin privato.
///
/// `cauchy_domain` resta il dominio stretto derivato dalla galleria e costituisce il contratto
/// pubblico di enrollment. `execution_domain` puo' estenderlo soltanto verso il basso quando una
/// soglia uniforme consente il percorso A33 allineato; in ogni altro caso coincide col dominio di
/// Cauchy e mantiene il percorso generale A29. In questa copia isolata il ramo allineato esegue
/// l'intera composizione A38; il fallback generale resta A29.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateArgminExecutionPlan {
    pub cauchy_domain: ScoreDomain,
    pub execution_domain: ScoreDomain,
    pub aligned_fast_path: bool,
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

/// Conteggio strutturale del solo percorso A34-top isolato.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A34OperationCounts {
    pub blind_rotations: u64,
    pub key_switches: u64,
    /// Numero conservativo di uscite LWE: una per BR piu' le quattro estrazioni fuse per score.
    pub output_marginals: u64,
}

/// Conteggio strutturale previsto per il percorso combinato A38.
///
/// Questi numeri descrivono il grafo implementato, ma restano una proiezione fino a quando un
/// binario compilato non conferma i contatori runtime sullo stesso circuito.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A38OperationCounts {
    pub blind_rotations: u64,
    pub key_switches: u64,
    pub output_marginals: u64,
}

/// A41 cambia soltanto il formato delle due radici terminali; il grafo PBS/KS coincide con A38.
pub type A41OperationCounts = A38OperationCounts;

/// A44 cambia soltanto i parametri e il binding protocollare; i conteggi coincidono con A41.
pub type A44OperationCounts = A41OperationCounts;

/// A62 conserva score/estrazione/A34-top, innesta A50 nella selezione A36 e A53 nella scan.
pub type A62OperationCounts = A38OperationCounts;

#[derive(Clone, Debug)]
pub struct PrivateArgminOutput {
    pub code: Lwe,
    pub metrics: PrivateArgminMetrics,
}

/// Risposta A41 per il percorso uniforme allineato.
///
/// Entrambe le cifre sono output freschi p16 alla scala [`BOOL_DELTA_LOG`]. Il server non le
/// combina: dopo la decifratura il client ricostruisce `low_nibble + 16 * high_nibble`.
#[derive(Clone, Debug)]
pub struct PrivateArgminTwoLweOutput {
    pub low_nibble: Lwe,
    pub high_nibble: Lwe,
    pub metrics: PrivateArgminMetrics,
}

/// Risposta A44 con binding esplicito del parameter set. I due LWE e le metriche provengono
/// senza modifiche dal grafo A41; il metadata permette al client di rifiutare una risposta
/// etichettata con un preset diverso.
#[derive(Clone, Debug)]
pub struct A44PrivateArgminTwoLweOutput {
    pub low_nibble: Lwe,
    pub high_nibble: Lwe,
    pub metrics: PrivateArgminMetrics,
    pub parameter_binding: A44ParameterBinding<'static>,
}

/// Risposta A62: due radici p16 a `Delta=2^59`; il client ricostruisce in chiaro
/// `low_digit + 15 * high_digit` ottenendo `0` oppure `i+1`.
#[derive(Clone, Debug)]
pub struct A62PrivateArgminOutput {
    pub low_digit: Lwe,
    pub high_digit: Lwe,
    pub metrics: PrivateArgminMetrics,
    pub parameter_binding: A44ParameterBinding<'static>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlignedWireFormat {
    SingleCode,
    TwoP16Digits,
    A53Radix15TwoP16Digits,
}

struct AlignedPrivateArgminOutput {
    low_nibble: Lwe,
    high_nibble: Lwe,
    code: Option<Lwe>,
    metrics: PrivateArgminMetrics,
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
    /// Vero quando e' stato selezionato il percorso uniforme allineato A38 oppure A62.
    pub aligned_fast_path: bool,
    /// Residui `x - sum(b_j 2^j), j=0..=7`, cioe' `h=x>>8` alla scala `2^60`.
    pub aligned_residuals: Vec<Lwe>,
    /// Codici signed `r` del classificatore sparso A33, alla scala Booleana.
    pub sparse_codes: Vec<Lwe>,
    /// Indicatori signed di peso alternato 1/3 estratti dalla stessa rotazione dei codici.
    pub sparse_signed_flags: Vec<Lwe>,
    /// Indicatori Booleani per le coppie adiacenti, incluso l'eventuale tail dispari.
    pub sparse_pair_flags: Vec<Lwe>,
    pub sparse_any_b9_zero: Option<Lwe>,
    pub aligned_b8_zero_candidates: Vec<Lwe>,
    pub aligned_any_b8_zero: Option<Lwe>,
    /// Codice signed C A34-top, con C(h+8)=-C(h) in Z32.
    pub a34_top_codes: Vec<Lwe>,
    /// Categoria canonica E in {1,3,7,0} per h in {0,1,2,altro}.
    pub a34_canonical_categories: Vec<Lwe>,
    /// Livelli prodotti dal riduttore binario del minimo di E; il primo e' l'input.
    pub a34_category_reduction_levels: Vec<Vec<Lwe>>,
    pub a34_global_category: Option<Lwe>,
    pub aligned_initial_candidates: Vec<Lwe>,
    pub full_small_bits_lsb_first: Vec<Vec<Lwe>>,
    pub full_corrections_lsb_first: Vec<Vec<Lwe>>,
    pub low_small_bits_lsb_first: Vec<Vec<Lwe>>,
    pub low_corrections_lsb_first: Vec<Vec<Lwe>>,
    /// Per ogni score, le quattro uscite Booleane prodotte insieme alle correzioni dei bit 3..=6.
    pub fused_boolean_bits_3_to_6: Vec<Vec<Lwe>>,
    /// Per ogni score, la correzione del bit 7 riusata direttamente alla scala Booleana.
    pub reused_bit7: Vec<Lwe>,
    pub bridged_bits_by_level: Vec<Vec<Lwe>>,
    pub zero_candidates_by_level: Vec<Vec<Lwe>>,
    pub any_zero_by_level: Vec<Lwe>,
    pub candidates_by_level: Vec<Vec<Lwe>>,
    /// A126 diagnostic-only encrypted checkpoints. Scale is 2^59 throughout.
    pub a126_fusion_inputs: Vec<Lwe>,
    pub a126_fresh_candidates: Vec<Lwe>,
    pub a126_zero_candidates: Vec<Lwe>,
    pub group_prefixes: Vec<Lwe>,
    pub winners: Vec<Lwe>,
    /// Checkpoint del solo percorso combinato A38.
    pub a38_scan_group_flags: Vec<Lwe>,
    pub a38_scan_local_first: Vec<Lwe>,
    pub a38_scan_low_digits: Vec<Lwe>,
    pub a38_scan_high_digits: Vec<Lwe>,
    pub a38_low_code: Option<Lwe>,
    pub a38_high_code: Option<Lwe>,
    /// Contatori attesi/osservati della scan A53 integrata; presenti soltanto per A62.
    pub a53_expected_counts: Option<A53PrimitiveCounts>,
    pub a53_observed_counts: Option<A53PrimitiveCounts>,
    pub a53_low_digit: Option<Lwe>,
    pub a53_high_digit: Option<Lwe>,
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
    TwoLweRequiresAlignedUniformFastPath,
    A62RequiresAlignedUniformFastPath,
    A62A53GateRejected,
    A62A53StaticContractRejected,
    A62A53CounterUnderflow,
    A62A53CounterMismatch {
        expected_blind_rotations: u64,
        actual_blind_rotations: u64,
        expected_key_switches: u64,
        actual_key_switches: u64,
        expected_output_marginals: u64,
        actual_output_marginals: u64,
    },
    A62A53AccumulatorLengthMismatch {
        actual: usize,
        expected: usize,
    },
    A62A53SampleDegreeOutOfRange {
        degree: usize,
        polynomial_size: usize,
    },
    A44ParameterIdMismatch,
    A44ParameterFingerprintMismatch,
    A44ParameterFingerprintDefinitionMismatch,
    A44ParameterGeometryMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
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
            Self::TwoLweRequiresAlignedUniformFastPath => write!(
                formatter,
                "l'uscita A41 a due LWE richiede il percorso uniforme allineato"
            ),
            Self::A62RequiresAlignedUniformFastPath => write!(
                formatter,
                "A62 richiede il percorso uniforme allineato A44/A38"
            ),
            Self::A62A53GateRejected => write!(
                formatter,
                "gate A53/A44 A62 non valido: rifiuto fail-closed"
            ),
            Self::A62A53StaticContractRejected => write!(
                formatter,
                "geometria o contratto statico A53 non valido: rifiuto fail-closed"
            ),
            Self::A62A53CounterUnderflow => write!(
                formatter,
                "contatori A53 non monotoni: rifiuto fail-closed"
            ),
            Self::A62A53CounterMismatch {
                expected_blind_rotations,
                actual_blind_rotations,
                expected_key_switches,
                actual_key_switches,
                expected_output_marginals,
                actual_output_marginals,
            } => write!(
                formatter,
                "contatori A53 incompatibili: BR {actual_blind_rotations}/{expected_blind_rotations}, KS {actual_key_switches}/{expected_key_switches}, marginali {actual_output_marginals}/{expected_output_marginals}"
            ),
            Self::A62A53AccumulatorLengthMismatch { actual, expected } => write!(
                formatter,
                "corpo accumulatore A53 lungo {actual}, atteso {expected}"
            ),
            Self::A62A53SampleDegreeOutOfRange {
                degree,
                polynomial_size,
            } => write!(
                formatter,
                "grado di estrazione A53 {degree} fuori dal polinomio N={polynomial_size}"
            ),
            Self::A44ParameterIdMismatch => write!(
                formatter,
                "params_id diverso dal preset A44 atteso: rifiuto fail-closed"
            ),
            Self::A44ParameterFingerprintMismatch => write!(
                formatter,
                "fingerprint parametro diverso dal preset A44 atteso: rifiuto fail-closed"
            ),
            Self::A44ParameterFingerprintDefinitionMismatch => write!(
                formatter,
                "fingerprint A44 compilato non corrisponde alla definizione canonica"
            ),
            Self::A44ParameterGeometryMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "geometria A44 incompatibile per {field}: atteso {expected}, trovato {actual}"
            ),
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

/// Valida la galleria e sceglie un dominio di esecuzione compatibile col dispatch stretto
/// allineato.
///
/// Il percorso allineato e' disponibile soltanto per gallerie non vuote con una soglia uniforme
/// `T`. In quel caso prova `lower = T - 1023`, senza mai restringere il dominio di Cauchy: il
/// candidato deve coprirne il limite inferiore e l'intervallo `[lower, cauchy.upper]` deve restare
/// rappresentabile nei dodici bit del core. Overflow, mancata copertura o eccessiva larghezza non
/// sono errori: selezionano deterministicamente il fallback generale sul dominio stretto.
pub fn plan_private_argmin_execution(
    templates: &[TemplateView<'_>],
) -> Result<PrivateArgminExecutionPlan, PrivateArgminError> {
    let cauchy_domain = cauchy_score_domain(templates)?;
    let uniform_threshold = templates
        .first()
        .map(|entry| entry.threshold)
        .filter(|threshold| templates.iter().all(|entry| entry.threshold == *threshold));

    if let Some(lower) =
        uniform_threshold.and_then(|threshold| threshold.checked_sub(ALIGNED_UNIFORM_THRESHOLD))
    {
        let execution_domain = ScoreDomain {
            lower,
            upper: cauchy_domain.upper,
        };
        if lower <= cauchy_domain.lower
            && execution_domain
                .checked_width()
                .is_some_and(|width| (1..=MAX_DOMAIN_WIDTH).contains(&width))
        {
            return Ok(PrivateArgminExecutionPlan {
                cauchy_domain,
                execution_domain,
                aligned_fast_path: true,
            });
        }
    }

    Ok(PrivateArgminExecutionPlan {
        cauchy_domain,
        execution_domain: cauchy_domain,
        aligned_fast_path: false,
    })
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

fn aligned_uniform_fast_path_for_thresholds(thresholds: &[i64], domain: ScoreDomain) -> bool {
    let Some(&threshold) = thresholds.first() else {
        return false;
    };
    thresholds.iter().all(|&candidate| candidate == threshold)
        && threshold.checked_sub(domain.lower) == Some(ALIGNED_UNIFORM_THRESHOLD)
}

fn aligned_a34_top_pbs_count(gallery_size: usize) -> Option<u64> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    Some(
        27 * n
            + 8 * or_reduction_pbs(gallery_size)
            + first_one_scan_pbs(gallery_size)
            + output_code_pbs(gallery_size)
            - 1,
    )
}

pub fn a34_aligned_operation_counts(gallery_size: usize) -> Option<A34OperationCounts> {
    let blind_rotations = aligned_a34_top_pbs_count(gallery_size)?;
    let n = gallery_size as u64;
    Some(A34OperationCounts {
        blind_rotations,
        key_switches: blind_rotations - 3 * n,
        output_marginals: blind_rotations + 4 * n,
    })
}

fn reduction_pbs_with_radix(mut items: usize, radix: usize) -> u64 {
    debug_assert!(radix >= 2);
    let mut count = 0u64;
    while items > 1 {
        items = items.div_ceil(radix);
        count += items as u64;
    }
    count
}

fn reduction_pbs_forwarding_singletons(mut items: usize, radix: usize) -> u64 {
    debug_assert!(radix >= 2);
    let mut count = 0u64;
    while items > 1 {
        let full = items / radix;
        let tail = items % radix;
        count += full as u64 + u64::from(tail >= 2);
        items = full + usize::from(tail > 0);
    }
    count
}

fn exclusive_prefix_pbs_with_radix(items: usize, radix: usize) -> u64 {
    debug_assert!(items > 0);
    debug_assert!(radix >= 2);
    if items <= 2 {
        return 0;
    }
    if items <= radix {
        return (items - 2) as u64;
    }
    let mut totals = 0u64;
    let mut expansion = 0u64;
    let mut groups = 0usize;
    for start in (0..items).step_by(radix) {
        let len = (items - start).min(radix);
        groups += 1;
        totals += u64::from(len > 1);
        expansion += if start == 0 {
            len.saturating_sub(2) as u64
        } else {
            (len - 1) as u64
        };
    }
    totals + expansion + exclusive_prefix_pbs_with_radix(groups, radix)
}

fn a38_low_selection_pbs(gallery_size: usize) -> u64 {
    10 * gallery_size as u64 + 8 * reduction_pbs_with_radix(gallery_size, A38_REDUCTION_RADIX)
}

fn a38_scan_output_counts(gallery_size: usize) -> A38OperationCounts {
    let groups = gallery_size.div_ceil(A38_SCAN_GROUP_SIZE);
    let group_nodes = (0..gallery_size)
        .step_by(A38_SCAN_GROUP_SIZE)
        .filter(|&start| (gallery_size - start).min(A38_SCAN_GROUP_SIZE) > 1)
        .count() as u64;
    let prefix_nodes = exclusive_prefix_pbs_with_radix(groups, A38_REDUCTION_RADIX);
    let digit_nodes = 2 * reduction_pbs_with_radix(groups, A38_REDUCTION_RADIX);
    let blind_rotations = 2 * group_nodes + prefix_nodes + groups as u64 + digit_nodes;
    A38OperationCounts {
        blind_rotations,
        key_switches: blind_rotations,
        output_marginals: blind_rotations + groups as u64,
    }
}

fn aligned_a38_pbs_count(gallery_size: usize) -> Option<u64> {
    let old_total = aligned_a34_top_pbs_count(gallery_size)?;
    let old_low = 12 * gallery_size as u64 + 8 * or_reduction_pbs(gallery_size);
    let old_scan_output = first_one_scan_pbs(gallery_size) + output_code_pbs(gallery_size);
    let new_scan_output = a38_scan_output_counts(gallery_size).blind_rotations;
    Some(
        old_total - old_low - old_scan_output
            + a38_low_selection_pbs(gallery_size)
            + new_scan_output,
    )
}

pub fn a38_aligned_operation_counts(gallery_size: usize) -> Option<A38OperationCounts> {
    let blind_rotations = aligned_a38_pbs_count(gallery_size)?;
    let n = gallery_size as u64;
    let scan = a38_scan_output_counts(gallery_size);
    Some(A38OperationCounts {
        blind_rotations,
        key_switches: blind_rotations - 3 * n,
        // A34-top conserva quattro estrazioni fuse extra per template; il selettore A34 espone
        // inoltre due marginali per rotazione, quindi una marginale extra per gruppo.
        output_marginals: blind_rotations + 4 * n + (scan.output_marginals - scan.blind_rotations),
    })
}

pub fn a41_aligned_operation_counts(gallery_size: usize) -> Option<A41OperationCounts> {
    a38_aligned_operation_counts(gallery_size)
}

pub fn a44_aligned_operation_counts(gallery_size: usize) -> Option<A44OperationCounts> {
    a41_aligned_operation_counts(gallery_size)
}

fn a50_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let baseline = a44_aligned_operation_counts(gallery_size)?;
    let old_nodes = reduction_pbs_with_radix(gallery_size, A38_REDUCTION_RADIX);
    let new_nodes = reduction_pbs_forwarding_singletons(gallery_size, A50_REDUCTION_RADIX);
    let saving = 8 * old_nodes.checked_sub(new_nodes)?;
    Some(A62OperationCounts {
        blind_rotations: baseline.blind_rotations.checked_sub(saving)?,
        key_switches: baseline.key_switches.checked_sub(saving)?,
        output_marginals: baseline.output_marginals.checked_sub(saving)?,
    })
}

/// Conteggio strutturale A62: A44 con selezione A50 e scan/output A53.
pub fn a62_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let a50 = a50_aligned_operation_counts(gallery_size)?;
    let removed = a38_scan_output_counts(gallery_size);
    let inserted = a53_scan_counts(gallery_size).ok()?.total;
    Some(A62OperationCounts {
        blind_rotations: a50
            .blind_rotations
            .checked_sub(removed.blind_rotations)?
            .checked_add(inserted.blind_rotations)?,
        key_switches: a50
            .key_switches
            .checked_sub(removed.key_switches)?
            .checked_add(inserted.key_switches)?,
        output_marginals: a50
            .output_marginals
            .checked_sub(removed.output_marginals)?
            .checked_add(inserted.output_marginals)?,
    })
}

/// Structural A126 counts: N fewer BR/KS; the same two output marginals replace two PBS.
pub fn a126_aligned_operation_counts(gallery_size: usize) -> Option<A62OperationCounts> {
    let mut counts = a62_aligned_operation_counts(gallery_size)?;
    counts.blind_rotations = counts.blind_rotations.checked_sub(gallery_size as u64)?;
    counts.key_switches = counts.key_switches.checked_sub(gallery_size as u64)?;
    Some(counts)
}

pub fn expected_pbs_count(gallery_size: usize) -> Option<u64> {
    if !(1..=MAX_GALLERY_SIZE).contains(&gallery_size) {
        return None;
    }
    let n = gallery_size as u64;
    Some(
        32 * n
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
/// [`expected_pbs_count`] resta il limite indipendente dai valori. La combinazione uniforme
/// allineata restituisce il conteggio del percorso A38 combinato; ogni altro caso sottrae le
/// tredici riduzioni dense A29 e aggiunge soltanto quelle richieste dai bit realmente non costanti
/// delle soglie.
pub fn expected_pbs_count_for_thresholds(
    gallery_size: usize,
    thresholds: &[i64],
    domain: ScoreDomain,
) -> Option<u64> {
    if thresholds.len() != gallery_size || validate_domain(domain).is_err() {
        return None;
    }
    if aligned_uniform_fast_path_for_thresholds(thresholds, domain) {
        return aligned_a38_pbs_count(gallery_size);
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
    let (key_switching_key, bootstrap_key, _, _) = standard_server_key_parts(server_key)?;
    if !packed_probe.ciphertext_modulus().is_native_modulus()
        || packed_probe.ciphertext_modulus() != server_key.ciphertext_modulus
        || packed_probe.ciphertext_modulus() != key_switching_key.ciphertext_modulus()
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

/// Calcola il fingerprint della definizione testuale congelata del preset A44.
pub fn a44_parameter_fingerprint_sha256() -> String {
    format!("{:x}", Sha256::digest(A44_PARAMETER_CANONICAL.as_bytes()))
}

/// Verifica la parte serializzabile del binding. Il controllo e' intenzionalmente esatto e
/// distingue maiuscole/minuscole: un endpoint non puo' negoziare o degradare silenziosamente a un
/// preset con lo stesso plaintext modulus.
pub fn validate_a44_parameter_binding_text(
    binding: A44ParameterBinding<'_>,
) -> Result<(), PrivateArgminError> {
    if binding.params_id != A44_PARAMS_ID {
        return Err(PrivateArgminError::A44ParameterIdMismatch);
    }
    if binding.fingerprint_sha256 != A44_PARAMETER_FINGERPRINT_SHA256 {
        return Err(PrivateArgminError::A44ParameterFingerprintMismatch);
    }
    if a44_parameter_fingerprint_sha256() != A44_PARAMETER_FINGERPRINT_SHA256 {
        return Err(PrivateArgminError::A44ParameterFingerprintDefinitionMismatch);
    }
    Ok(())
}

fn require_a44_parameter_field(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), PrivateArgminError> {
    if actual != expected {
        return Err(PrivateArgminError::A44ParameterGeometryMismatch {
            field,
            expected: expected as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

/// Verifica i campi del preset che restano osservabili in una [`ServerKey`]. Distribuzioni del
/// rumore e `log2_p_fail` non sono presenti nella chiave generata: sono legati dal fingerprint e,
/// quando esistera' una serializzazione, dovranno essere autenticati dal protocollo esterno.
pub fn validate_a44_parameter_binding(
    binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
) -> Result<(), PrivateArgminError> {
    validate_a44_parameter_binding_text(binding)?;
    require_a44_parameter_field("message_modulus", server_key.message_modulus.0 as usize, 2)?;
    require_a44_parameter_field("carry_modulus", server_key.carry_modulus.0 as usize, 8)?;
    require_a44_parameter_field(
        "max_noise_level",
        server_key.max_noise_level.get() as usize,
        15,
    )?;
    require_a44_parameter_field("max_degree", server_key.max_degree.get() as usize, 15)?;
    require_a44_parameter_field(
        "pbs_order_keyswitch_bootstrap",
        usize::from(standard_server_key_parts(server_key)?.3 == PBSOrder::KeyswitchBootstrap),
        1,
    )?;
    require_a44_parameter_field(
        "ciphertext_modulus_native",
        usize::from(server_key.ciphertext_modulus.is_native_modulus()),
        1,
    )?;

    let (key_switching_key, bootstrap_key, modulus_switch_configuration, _) =
        standard_server_key_parts(server_key)?;
    require_a44_parameter_field(
        "bsk_input_lwe_dimension",
        bootstrap_key.input_lwe_dimension().0,
        859,
    )?;
    require_a44_parameter_field(
        "bsk_output_lwe_dimension",
        bootstrap_key.output_lwe_dimension().0,
        2048,
    )?;
    require_a44_parameter_field("bsk_glwe_size", bootstrap_key.glwe_size().0, 2)?;
    require_a44_parameter_field(
        "bsk_polynomial_size",
        bootstrap_key.polynomial_size().0,
        2048,
    )?;
    require_a44_parameter_field("pbs_base_log", bootstrap_key.decomposition_base_log().0, 23)?;
    require_a44_parameter_field("pbs_level", bootstrap_key.decomposition_level_count().0, 1)?;

    require_a44_parameter_field(
        "ksk_input_lwe_dimension",
        key_switching_key.input_key_lwe_dimension().0,
        2048,
    )?;
    require_a44_parameter_field(
        "ksk_output_lwe_dimension",
        key_switching_key.output_key_lwe_dimension().0,
        859,
    )?;
    require_a44_parameter_field(
        "ks_base_log",
        key_switching_key.decomposition_base_log().0,
        3,
    )?;
    require_a44_parameter_field(
        "ks_level",
        key_switching_key.decomposition_level_count().0,
        5,
    )?;
    require_a44_parameter_field(
        "modulus_switch_standard",
        usize::from(matches!(
            modulus_switch_configuration,
            ModulusSwitchConfiguration::Standard
        )),
        1,
    )?;
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

#[cfg(test)]
fn aligned_output_group_lut(code: u64, bit_offset: u32, group_len: usize) -> u64 {
    assert!((1..=3).contains(&group_len));
    let payload_modulus = 1u64 << group_len;
    if code < payload_modulus {
        code << bit_offset
    } else {
        0
    }
}

#[cfg(test)]
fn aligned_classifier_slot_lut(slot: u64, weight: u64) -> u64 {
    debug_assert!(matches!(weight, 1 | 3));
    match slot {
        // Il grado zero osserva gli slot pari per h'=0..3.
        0 => 2,
        2 => 3,
        4 | 6 => 4,
        // Il grado N/8 osserva gli slot dispari. Sul semigiro alto la negaciclicita'
        // produce automaticamente -weight per h'=4 e zero per h'=5..7.
        1 => weight,
        3 | 5 | 7 => 0,
        _ => unreachable!("la LUT A33 valuta soltanto gli slot 0..7"),
    }
}

#[cfg(test)]
fn aligned_pair_flag_lut(code: u64) -> u64 {
    // Gli input includono l'offset pubblico +4. I codici con almeno un indicatore positivo sono
    // {2,5,6,7,8}; quelli senza positivi sono {0,1,3,4}.
    u64::from(matches!(code, 2 | 5 | 6 | 7 | 8))
}

#[cfg(test)]
fn aligned_candidate_lut(code: u64) -> u64 {
    u64::from(code == 3)
}

fn a34_top_classifier_slot_lut(slot: u64) -> u64 {
    debug_assert!(slot < A34_TOP_CLASSIFIER_MODULUS as u64);
    if slot.is_multiple_of(2) {
        A34_TOP_CLASSIFIER_CODES[(slot / 2) as usize]
    } else {
        0
    }
}

fn a34_canonical_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        0 => 3,
        2 => 1,
        7 => 7,
        _ => 0,
    }
}

fn a34_pair_category_lut(input_phase: u64) -> u64 {
    match input_phase {
        1 | 2 | 4 | 8 => 1,
        3 | 6 | 10 => 3,
        7 | 14 => 7,
        0 => 0,
        _ => 0,
    }
}

fn a34_top_candidate_lut(input_phase: u64) -> u64 {
    u64::from(matches!(input_phase, 3 | 14))
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

fn is_canonical_boolean_bit(bit_index: u32) -> bool {
    (3..=7).contains(&bit_index)
}

fn recodes_bit(bit_index: u32) -> bool {
    // Il bit alto non possiede una correction ciphertext. I bit 3..=6 ricevono invece una uscita
    // Booleana dalla stessa blind rotation della correzione; il bit 7 riusa direttamente la sua
    // correzione, che nasce gia' a Delta_bool.
    bit_index == HIGH_SCORE_BIT
}

fn extracted_bit_weight(bit_index: u32) -> u64 {
    if is_canonical_boolean_bit(bit_index) || recodes_bit(bit_index) {
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
    canonical_bits_lsb_first: Vec<Option<Lwe>>,
}

#[derive(Clone)]
struct WeightedBit {
    ciphertext: Lwe,
}

#[derive(Clone)]
enum CorrectionAccumulator {
    Single(Glwe),
    WithBoolean(Glwe),
}

struct ExtractedCorrection {
    correction: Lwe,
    boolean: Option<Lwe>,
}

fn fused_correction_accumulator_body(
    polynomial_size: PolynomialSize,
    alpha: u64,
    beta: u64,
) -> Vec<u64> {
    assert_eq!(polynomial_size.0 % 4, 0);
    let mut body = vec![alpha.wrapping_neg(); polynomial_size.0];
    body[polynomial_size.0 / 2..].fill(beta.wrapping_neg());
    body
}

fn correction_from_small_bit(
    small_bit: &Lwe,
    accumulator: &CorrectionAccumulator,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    modulus_switch_configuration: &ModulusSwitchConfiguration<u64>,
    output_lwe_size: LweSize,
    alpha: u64,
    pbs_count: &AtomicU64,
) -> ExtractedCorrection {
    let modulus = small_bit.ciphertext_modulus();
    let mut centered = small_bit.clone();
    let (mut correction, boolean) = match accumulator {
        CorrectionAccumulator::Single(accumulator) => {
            lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 62));
            let mut correction = LweCiphertext::new(0u64, output_lwe_size, modulus);
            programmable_bootstrap_lwe_ciphertext(
                &centered,
                &mut correction,
                accumulator,
                fourier_bootstrap_key,
            );
            (correction, None)
        }
        CorrectionAccumulator::WithBoolean(accumulator) => {
            lwe_ciphertext_plaintext_add_assign(&mut centered, Plaintext(1u64 << 61));
            let mut rotated = accumulator.clone();
            blind_rotate_assign_with_modulus_switch(
                &centered,
                &mut rotated,
                fourier_bootstrap_key,
                modulus_switch_configuration,
            );

            let mut correction = LweCiphertext::new(0u64, output_lwe_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut correction, MonomialDegree(0));
            let mut boolean = LweCiphertext::new(0u64, output_lwe_size, modulus);
            extract_lwe_sample_from_glwe_ciphertext(
                &rotated,
                &mut boolean,
                MonomialDegree(rotated.polynomial_size().0 / 2),
            );
            lwe_ciphertext_plaintext_add_assign(
                &mut boolean,
                Plaintext(1u64 << (BOOL_DELTA_LOG - 1)),
            );
            (correction, Some(boolean))
        }
    };
    pbs_count.fetch_add(1, Ordering::Relaxed);
    lwe_ciphertext_plaintext_add_assign(&mut correction, Plaintext(alpha));
    ExtractedCorrection {
        correction,
        boolean,
    }
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
    modulus_switch_configuration: &ModulusSwitchConfiguration<u64>,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    correction_accumulators: &[CorrectionAccumulator],
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
    let mut canonical_bits_lsb_first = vec![None; bit_count as usize];

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
        let extracted = correction_from_small_bit(
            &small,
            &correction_accumulators[bit_index as usize],
            fourier_bootstrap_key,
            modulus_switch_configuration,
            input.lwe_size(),
            alpha,
            pbs_count,
        );
        lwe_ciphertext_sub_assign(&mut residual, &extracted.correction);
        corrections_lsb_first.push(extracted.correction);
        canonical_bits_lsb_first[bit_index as usize] = extracted.boolean;
    }

    CapturedExtractedBits {
        small_lsb_first,
        corrections_lsb_first,
        canonical_bits_lsb_first,
    }
}

/// Variante A34-top che applica anche l'ultima correzione e non esegue il sample terminale.
///
/// Per il ramo alto estrae/corregge esattamente b4..b7. Il residuo successivo e' quindi
/// `h=x>>8` a Delta=2^60; il KS che nel helper generico materializzava b8 non viene eseguito.
fn extract_bits_with_all_corrections(
    input: &Lwe,
    fourier_bootstrap_key: &FourierLweBootstrapKeyOwned,
    modulus_switch_configuration: &ModulusSwitchConfiguration<u64>,
    key_switching_key: &LweKeyswitchKeyOwned<u64>,
    correction_accumulators: &[CorrectionAccumulator],
    delta_log: u32,
    bit_count: u32,
    pbs_count: &AtomicU64,
) -> CapturedExtractedBits {
    assert_eq!(correction_accumulators.len(), bit_count as usize);
    assert!(delta_log + bit_count <= 64);
    let modulus = input.ciphertext_modulus();
    let mut residual = input.clone();
    let mut small_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut corrections_lsb_first = Vec::with_capacity(bit_count as usize);
    let mut canonical_bits_lsb_first = vec![None; bit_count as usize];

    for bit_index in 0..bit_count {
        let shift = 64 - delta_log - bit_index - 1;
        let mut shifted = residual.clone();
        for coefficient in shifted.as_mut() {
            *coefficient <<= shift;
        }
        let mut small = LweCiphertext::new(0u64, key_switching_key.output_lwe_size(), modulus);
        keyswitch_lwe_ciphertext(key_switching_key, &shifted, &mut small);
        small_lsb_first.push(small.clone());

        let alpha = 1u64 << (delta_log + bit_index - 1);
        let extracted = correction_from_small_bit(
            &small,
            &correction_accumulators[bit_index as usize],
            fourier_bootstrap_key,
            modulus_switch_configuration,
            input.lwe_size(),
            alpha,
            pbs_count,
        );
        lwe_ciphertext_sub_assign(&mut residual, &extracted.correction);
        corrections_lsb_first.push(extracted.correction);
        canonical_bits_lsb_first[bit_index as usize] = extracted.boolean;
    }

    CapturedExtractedBits {
        small_lsb_first,
        corrections_lsb_first,
        canonical_bits_lsb_first,
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

fn sum_lwes(values: &[Lwe], zero: &Lwe) -> Lwe {
    let mut sum = zero.clone();
    for value in values {
        lwe_ciphertext_add_assign(&mut sum, value);
    }
    sum
}

fn scale_lwe_signed(input: &Lwe, multiplier: i64) -> Lwe {
    assert_ne!(multiplier, 0);
    let mut output = input.clone();
    let magnitude = multiplier.unsigned_abs();
    if magnitude != 1 {
        lwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(magnitude));
    }
    if multiplier < 0 {
        lwe_ciphertext_opposite_assign(&mut output);
    }
    output
}

fn radix5_exclusive_prefix_or<F>(flags: &[Lwe], zero: &Lwe, or_gate: &F) -> Vec<Lwe>
where
    F: Fn(&[Lwe]) -> Lwe + Sync,
{
    assert!(!flags.is_empty());
    if flags.len() <= A38_REDUCTION_RADIX {
        return (0..flags.len())
            .map(|index| match index {
                0 => zero.clone(),
                1 => flags[0].clone(),
                _ => or_gate(&flags[..index]),
            })
            .collect();
    }
    let block_totals: Vec<Lwe> = flags
        .par_chunks(A38_REDUCTION_RADIX)
        .map(|block| {
            if block.len() == 1 {
                block[0].clone()
            } else {
                or_gate(block)
            }
        })
        .collect();
    let block_prefixes = radix5_exclusive_prefix_or(&block_totals, zero, or_gate);
    (0..flags.len())
        .into_par_iter()
        .map(|index| {
            let block = index / A38_REDUCTION_RADIX;
            let offset = index % A38_REDUCTION_RADIX;
            if offset == 0 {
                return block_prefixes[block].clone();
            }
            let start = block * A38_REDUCTION_RADIX;
            let mut inputs = Vec::with_capacity(offset + usize::from(block > 0));
            if block > 0 {
                inputs.push(block_prefixes[block].clone());
            }
            inputs.extend(flags[start..start + offset].iter().cloned());
            if inputs.len() == 1 {
                inputs.pop().expect("prefisso radix-5 non vuoto")
            } else {
                or_gate(&inputs)
            }
        })
        .collect()
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

/// Calcola l'identificazione privata esatta A41 con due cifre terminali p16 separate.
///
/// Questa API e' intenzionalmente fail-closed: accetta soltanto il percorso uniforme allineato
/// A38. Il client decifra le due cifre e ricostruisce `low_nibble + 16 * high_nibble`, ottenendo
/// `0=rifiuto` oppure `indice+1=match`, con tie risolti sulla prima identita'.
pub fn private_argmin_two_lwe(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    private_argmin_two_lwe_impl(server_key, packed_probe, templates, domain, None)
}

/// Endpoint pubblico A44. Prima di entrare nel grafo A41 verifica sia l'identita' protocollare
/// dichiarata dalla richiesta sia tutta la geometria ricostruibile dalla server key. La risposta
/// ripete il binding canonico, che il client deve verificare prima di decifrare.
pub fn private_argmin_two_lwe_a44(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A44PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_two_lwe_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A44PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
}

/// Endpoint A62 integrato. A44 produce i bit e A34-top; A50 restringe il mask candidato cifrato;
/// A53 restituisce due radici p16 base-15. Il server non le ricompone: soltanto il client calcola
/// `low_digit + 15 * high_digit` dopo la decifratura.
pub fn private_argmin_a62(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A62PrivateArgminOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_a62_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A62PrivateArgminOutput {
        low_digit: output.low_nibble,
        high_digit: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
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

/// Variante diagnostica di [`private_argmin_two_lwe`]. Non decifra alcun checkpoint.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_two_lwe_with_trace(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(PrivateArgminTwoLweOutput, PrivateArgminTrace), PrivateArgminError> {
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_two_lwe_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((output, trace))
}

/// Variante diagnostica dell'endpoint A44. Il trace non modifica ne' aggira i controlli del
/// parameter binding.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_two_lwe_a44_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A44PrivateArgminTwoLweOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let (output, trace) =
        private_argmin_two_lwe_with_trace(server_key, packed_probe, templates, domain)?;
    Ok((
        A44PrivateArgminTwoLweOutput {
            low_nibble: output.low_nibble,
            high_nibble: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

/// Variante diagnostica A62. Il trace contiene solo ciphertext e contatori; non decifra nulla.
#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_a62_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A62PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_a62_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((
        A62PrivateArgminOutput {
            low_digit: output.low_nibble,
            high_digit: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

/// A126: fuse the level3 refresh and level4 zero test; raw noise tails remain open.
pub fn private_argmin_a126(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<A62PrivateArgminOutput, PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let output = private_argmin_a126_impl(server_key, packed_probe, templates, domain, None)?;
    Ok(A62PrivateArgminOutput {
        low_digit: output.low_nibble,
        high_digit: output.high_nibble,
        metrics: output.metrics,
        parameter_binding: A44_PARAMETER_BINDING,
    })
}

#[doc(hidden)]
#[cfg(feature = "diagnostic-trace")]
pub fn private_argmin_a126_with_trace(
    parameter_binding: A44ParameterBinding<'_>,
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
) -> Result<(A62PrivateArgminOutput, PrivateArgminTrace), PrivateArgminError> {
    validate_a44_parameter_binding(parameter_binding, server_key)?;
    let mut trace = PrivateArgminTrace::default();
    let output = private_argmin_a126_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        Some(&mut trace),
    )?;
    Ok((
        A62PrivateArgminOutput {
            low_digit: output.low_nibble,
            high_digit: output.high_nibble,
            metrics: output.metrics,
            parameter_binding: A44_PARAMETER_BINDING,
        },
        trace,
    ))
}

fn private_argmin_a126_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::A53Radix15TwoP16Digits,
        true,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}

fn private_argmin_two_lwe_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::TwoLweRequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::TwoP16Digits,
        false,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}

fn private_argmin_a62_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminTwoLweOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if !aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        return Err(PrivateArgminError::A62RequiresAlignedUniformFastPath);
    }
    let output = private_argmin_aligned_a38_impl(
        server_key,
        packed_probe,
        templates,
        domain,
        AlignedWireFormat::A53Radix15TwoP16Digits,
        false,
        trace,
    )?;
    debug_assert!(output.code.is_none());
    Ok(PrivateArgminTwoLweOutput {
        low_nibble: output.low_nibble,
        high_nibble: output.high_nibble,
        metrics: output.metrics,
    })
}

fn private_argmin_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    mut trace: Option<&mut PrivateArgminTrace>,
) -> Result<PrivateArgminOutput, PrivateArgminError> {
    validate_inputs(server_key, packed_probe, templates, domain)?;
    let thresholds: Vec<i64> = templates.iter().map(|entry| entry.threshold).collect();
    if aligned_uniform_fast_path_for_thresholds(&thresholds, domain) {
        let output = private_argmin_aligned_a38_impl(
            server_key,
            packed_probe,
            templates,
            domain,
            AlignedWireFormat::SingleCode,
            false,
            trace,
        )?;
        return Ok(PrivateArgminOutput {
            code: output.code.expect("uscita single-LWE A38 assente"),
            metrics: output.metrics,
        });
    }
    let total_started = Instant::now();
    let pbs_count = AtomicU64::new(0);
    let n = templates.len();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let (key_switching_key, fourier_bootstrap_key, modulus_switch_configuration, _) =
        standard_server_key_parts(server_key)?;
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    assert_eq!(polynomial_size.0 % 4, 0);
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let bit_positions: Vec<u32> = (0..=HIGH_SCORE_BIT).rev().collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_positions_msb_first = bit_positions.clone();
    }
    let setup_started = Instant::now();
    let setup_pbs = pbs_count.load(Ordering::Relaxed);

    let make_correction_accumulator = |alpha: u64, with_boolean: bool| {
        let plaintexts = if with_boolean {
            fused_correction_accumulator_body(polynomial_size, alpha, bool_delta >> 1)
        } else {
            vec![alpha.wrapping_neg(); polynomial_size.0]
        };
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(plaintexts),
            modulus,
        );
        if with_boolean {
            CorrectionAccumulator::WithBoolean(accumulator)
        } else {
            CorrectionAccumulator::Single(accumulator)
        }
    };
    let make_correction_accumulators =
        |delta_log: u32, correction_count: u32, fused_bits: std::ops::Range<u32>| {
            (0..correction_count)
                .map(|bit_index| {
                    let alpha = 1u64 << (delta_log + bit_index - 1);
                    make_correction_accumulator(alpha, fused_bits.contains(&bit_index))
                })
                .collect::<Vec<_>>()
        };
    let low_correction_accumulators =
        make_correction_accumulators(LOW_MOD16_DELTA_LOG, LOW_EXTRACTED_BITS - 1, 0..0);
    let low_to_full_correction_accumulators =
        make_correction_accumulators(FULL_DELTA_LOG, LOW_EXTRACTED_BITS, 3..4);
    let high_correction_accumulators =
        make_correction_accumulators(HIGH_DELTA_LOG, HIGH_EXTRACTED_BITS - 1, 0..3);
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
        if is_canonical_boolean_bit(bit_index) {
            return WeightedBit {
                ciphertext: full.canonical_bits_lsb_first[bit_index as usize]
                    .as_ref()
                    .expect("i bit 3..=7 sono Booleani canonici")
                    .clone(),
            };
        }
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
                modulus_switch_configuration,
                key_switching_key,
                &low_correction_accumulators,
                LOW_MOD16_DELTA_LOG,
                LOW_EXTRACTED_BITS,
                &pbs_count,
            )
        })
        .collect();
    let low_to_full_bits_flat: Vec<ExtractedCorrection> = (0..n * low_bit_count)
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / low_bit_count;
            let bit_index = flat % low_bit_count;
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index as u32 - 1);
            correction_from_small_bit(
                &low_extracted[gallery_index].small_lsb_first[bit_index],
                &low_to_full_correction_accumulators[bit_index],
                fourier_bootstrap_key,
                modulus_switch_configuration,
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
            for bit in &low_to_full_bits_flat[start..start + low_bit_count] {
                lwe_ciphertext_sub_assign(&mut residual, &bit.correction);
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
            let mut extracted = extract_bits_with_corrections(
                high,
                fourier_bootstrap_key,
                modulus_switch_configuration,
                key_switching_key,
                &high_correction_accumulators,
                HIGH_DELTA_LOG,
                HIGH_EXTRACTED_BITS,
                &pbs_count,
            );
            // La correzione locale 3 e' il bit globale 7 a 2^59: non serve un altro PBS.
            extracted.canonical_bits_lsb_first[3] =
                Some(extracted.corrections_lsb_first[3].clone());
            extracted
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
            let mut corrections_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.correction.clone())
                .collect::<Vec<_>>();
            corrections_lsb_first.extend(high.corrections_lsb_first);
            let mut canonical_bits_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.boolean.clone())
                .collect::<Vec<_>>();
            canonical_bits_lsb_first.extend(high.canonical_bits_lsb_first);
            debug_assert_eq!(small_lsb_first.len(), SCORE_BITS as usize);
            debug_assert_eq!(corrections_lsb_first.len(), SCORE_BITS as usize - 1);
            debug_assert_eq!(canonical_bits_lsb_first.len(), SCORE_BITS as usize);
            CapturedExtractedBits {
                small_lsb_first,
                corrections_lsb_first,
                canonical_bits_lsb_first,
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
        trace.fused_boolean_bits_3_to_6 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[3..=6]
                    .iter()
                    .map(|bit| {
                        bit.as_ref()
                            .expect("i bit 3..=6 provengono da ManyLUT")
                            .clone()
                    })
                    .collect()
            })
            .collect();
        trace.reused_bit7 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[7]
                    .as_ref()
                    .expect("il bit 7 riusa la correzione")
                    .clone()
            })
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

struct A66A53CoreBackend<'a> {
    server_key: &'a ServerKey,
    modulus: CiphertextModulus<u64>,
    big_size: LweSize,
    small_size: LweSize,
    pbs_count: &'a AtomicU64,
    scan_pbs: AtomicU64,
    scan_extra_output_marginals: AtomicU64,
}

impl A66A53CoreBackend<'_> {
    fn validate_body(&self, torus_body: &[u64]) -> Result<(), PrivateArgminError> {
        let expected = standard_server_key_parts(self.server_key)?.1.polynomial_size().0;
        if torus_body.len() != expected {
            return Err(PrivateArgminError::A62A53AccumulatorLengthMismatch {
                actual: torus_body.len(),
                expected,
            });
        }
        Ok(())
    }

    fn record_pbs(&self, output_marginals: u64) {
        self.pbs_count.fetch_add(1, Ordering::Relaxed);
        self.scan_pbs.fetch_add(1, Ordering::Relaxed);
        if output_marginals > 1 {
            self.scan_extra_output_marginals
                .fetch_add(output_marginals - 1, Ordering::Relaxed);
        }
    }
}

impl A53FheBackend for A66A53CoreBackend<'_> {
    type Lwe = Lwe;
    type Accumulator = Glwe;
    type Error = PrivateArgminError;

    fn trivial_zero(&self) -> Self::Lwe {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(
            self.big_size,
            Plaintext(0u64),
            self.modulus,
        )
    }

    fn add_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe) {
        lwe_ciphertext_add_assign(target, source);
    }

    fn sub_assign(&self, target: &mut Self::Lwe, source: &Self::Lwe) {
        lwe_ciphertext_sub_assign(target, source);
    }

    fn add_plaintext_assign(&self, target: &mut Self::Lwe, torus_plaintext: u64) {
        lwe_ciphertext_plaintext_add_assign(target, Plaintext(torus_plaintext));
    }

    fn prepare_raw_accumulator(
        &self,
        torus_body: &[u64],
    ) -> Result<Self::Accumulator, Self::Error> {
        self.validate_body(torus_body)?;
        let (_, bootstrap_key, _, _) = standard_server_key_parts(self.server_key)?;
        Ok(allocate_and_trivially_encrypt_new_glwe_ciphertext(
            bootstrap_key.glwe_size(),
            &PlaintextList::from_container(torus_body.to_vec()),
            self.modulus,
        ))
    }

    fn pbs_prepared(
        &self,
        input: &Self::Lwe,
        accumulator: &Self::Accumulator,
    ) -> Result<Self::Lwe, Self::Error> {
        let (key_switching_key, bootstrap_key, _, _) = standard_server_key_parts(self.server_key)?;
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut output = LweCiphertext::new(0u64, self.big_size, self.modulus);
        programmable_bootstrap_lwe_ciphertext(&switched, &mut output, accumulator, bootstrap_key);
        self.record_pbs(1);
        Ok(output)
    }

    fn pbs_dual_prepared(
        &self,
        input: &Self::Lwe,
        mut accumulator: Self::Accumulator,
        first_degree: usize,
        second_degree: usize,
    ) -> Result<(Self::Lwe, Self::Lwe), Self::Error> {
        let (key_switching_key, bootstrap_key, modulus_switch_configuration, _) =
            standard_server_key_parts(self.server_key)?;
        let polynomial_size = bootstrap_key.polynomial_size().0;
        for degree in [first_degree, second_degree] {
            if degree >= polynomial_size {
                return Err(PrivateArgminError::A62A53SampleDegreeOutOfRange {
                    degree,
                    polynomial_size,
                });
            }
        }
        let mut switched = LweCiphertext::new(0u64, self.small_size, self.modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        blind_rotate_assign_with_modulus_switch(
            &switched, &mut accumulator, bootstrap_key, modulus_switch_configuration,
        );
        let mut first = LweCiphertext::new(0u64, self.big_size, self.modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut first,
            MonomialDegree(first_degree),
        );
        let mut second = LweCiphertext::new(0u64, self.big_size, self.modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator,
            &mut second,
            MonomialDegree(second_degree),
        );
        self.record_pbs(2);
        Ok((first, second))
    }

    fn counters(&self) -> A53PrimitiveCounts {
        let pbs = self.scan_pbs.load(Ordering::Relaxed);
        let extra_marginals = self.scan_extra_output_marginals.load(Ordering::Relaxed);
        A53PrimitiveCounts {
            blind_rotations: pbs,
            key_switches: pbs,
            output_marginals: pbs + extra_marginals,
        }
    }
}

fn a66_a53_gate() -> FutureFheGate<'static> {
    FutureFheGate {
        backend_parameter: BackendParameterContract {
            params_id: A44_PARAMS_ID,
            canonical: A44_PARAMETER_CANONICAL,
            fingerprint_sha256: A44_PARAMETER_FINGERPRINT_SHA256,
            polynomial_size: 2048,
            pbs_message_modulus: PBS_MESSAGE_MODULUS,
            max_noise_level: A53_REQUIRED_MAX_NOISE_LEVEL,
        },
        observed_sources: A66_OBSERVED_SOURCE_GUARDS,
        experiment_ack: A66_EXPERIMENT_ACK,
        pfail_ack: A66_PFAIL_ACK,
    }
}

fn map_a53_error(error: FutureFheError<PrivateArgminError>) -> PrivateArgminError {
    match error {
        FutureFheError::Gate(_) => PrivateArgminError::A62A53GateRejected,
        FutureFheError::Static(_) => PrivateArgminError::A62A53StaticContractRejected,
        FutureFheError::Backend(error) => error,
        FutureFheError::CounterUnderflow => PrivateArgminError::A62A53CounterUnderflow,
        FutureFheError::CounterMismatch { expected, observed } => {
            PrivateArgminError::A62A53CounterMismatch {
                expected_blind_rotations: expected.blind_rotations,
                actual_blind_rotations: observed.blind_rotations,
                expected_key_switches: expected.key_switches,
                actual_key_switches: observed.key_switches,
                expected_output_marginals: expected.output_marginals,
                actual_output_marginals: observed.output_marginals,
            }
        }
    }
}

/// Percorso A38/A62 combinato per una soglia pubblica uniforme normalizzata a `2^10-1`.
///
/// L'ammissibilita' viene incorporata prima dell'argmin, ma il risultato osservabile resta quello
/// del core generale: zero se il minimo globale e' sopra soglia, altrimenti `indice+1` del primo
/// minimo. A34-top conserva i ciphertext separati b7..b0 e classifica `h=x>>8`; A36 risolve i
/// byte bassi in due chunk. A38 usa scan group-3/base-16; A41 ne lascia separate le due radici.
/// A62 sostituisce anche la selezione con A50 canonica radix-15 e la scan con A53 group-4,
/// restituendo due radici p16 base-15 senza somma cifrata. Questa funzione viene chiamata soltanto
/// dopo [`validate_inputs`] e dopo la guardia
/// [`aligned_uniform_fast_path_for_thresholds`].
fn private_argmin_aligned_a38_impl(
    server_key: &ServerKey,
    packed_probe: &Glwe,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    wire_format: AlignedWireFormat,
    fuse_refresh: bool,
    mut trace: Option<&mut PrivateArgminTrace>,
) -> Result<AlignedPrivateArgminOutput, PrivateArgminError> {
    debug_assert!(templates
        .iter()
        .all(|entry| entry.threshold == templates[0].threshold));
    debug_assert_eq!(
        templates[0].threshold.checked_sub(domain.lower),
        Some(ALIGNED_UNIFORM_THRESHOLD)
    );
    let total_started = Instant::now();
    let pbs_count = AtomicU64::new(0);
    let n = templates.len();
    let modulus = packed_probe.ciphertext_modulus();
    let bool_delta = 1u64 << BOOL_DELTA_LOG;
    let code_delta = 1u64 << CODE_DELTA_LOG;
    let full_delta = 1u64 << FULL_DELTA_LOG;
    let low_delta = 1u64 << LOW_MOD16_DELTA_LOG;
    let (key_switching_key, fourier_bootstrap_key, modulus_switch_configuration, _) =
        standard_server_key_parts(server_key)?;
    let polynomial_size = fourier_bootstrap_key.polynomial_size();
    assert_eq!(polynomial_size.0 % PBS_MESSAGE_MODULUS, 0);
    assert_eq!(
        polynomial_size.0, 2048,
        "il layout raw A36 e' auditato per Npoly=2048"
    );
    let glwe_size = fourier_bootstrap_key.glwe_size();
    let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
    let small_size = key_switching_key.output_key_lwe_dimension().to_lwe_size();
    let bit_positions: Vec<u32> = (0..=ALIGNED_SELECTION_HIGH_BIT).rev().collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.aligned_fast_path = true;
        trace.bit_positions_msb_first = bit_positions.clone();
    }

    let setup_started = Instant::now();
    let setup_pbs = pbs_count.load(Ordering::Relaxed);
    let make_correction_accumulator = |alpha: u64, with_boolean: bool| {
        let plaintexts = if with_boolean {
            fused_correction_accumulator_body(polynomial_size, alpha, bool_delta >> 1)
        } else {
            vec![alpha.wrapping_neg(); polynomial_size.0]
        };
        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(plaintexts),
            modulus,
        );
        if with_boolean {
            CorrectionAccumulator::WithBoolean(accumulator)
        } else {
            CorrectionAccumulator::Single(accumulator)
        }
    };
    let make_correction_accumulators =
        |delta_log: u32, correction_count: u32, fused_bits: std::ops::Range<u32>| {
            (0..correction_count)
                .map(|bit_index| {
                    let alpha = 1u64 << (delta_log + bit_index - 1);
                    make_correction_accumulator(alpha, fused_bits.contains(&bit_index))
                })
                .collect::<Vec<_>>()
        };
    let low_correction_accumulators =
        make_correction_accumulators(LOW_MOD16_DELTA_LOG, LOW_EXTRACTED_BITS - 1, 0..0);
    let low_to_full_correction_accumulators =
        make_correction_accumulators(FULL_DELTA_LOG, LOW_EXTRACTED_BITS, 3..4);
    let high_correction_accumulators =
        make_correction_accumulators(HIGH_DELTA_LOG, A34_HIGH_CORRECTION_BITS, 0..3);
    let bit_weights: Vec<u64> = bit_positions
        .iter()
        .map(|bit_index| extracted_bit_weight(*bit_index))
        .collect();
    assert_eq!(
        bit_weights.as_slice(),
        A38_EXPECTED_SOURCE_WEIGHTS.as_slice()
    );
    if let Some(trace) = trace.as_deref_mut() {
        trace.bit_weights_msb_first = bit_weights.clone();
    }
    let a34_top_classifier_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        A34_TOP_CLASSIFIER_MODULUS,
        modulus,
        bool_delta,
        a34_top_classifier_slot_lut,
    );
    let a34_canonical_category_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_canonical_category_lut,
    );
    let a34_pair_category_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_pair_category_lut,
    );
    let a34_top_candidate_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        a34_top_candidate_lut,
    );

    // A36 usa corpi raw p=16: gli stati vivi valgono 2 a Delta_bool. Il plateau OR radix-5
    // copre i soli centri raggiungibili 2,4,6,8,10 e resta a distanza dall'antipodo 18.
    let raw_accumulator = |body: Vec<u64>| {
        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(body),
            modulus,
        )
    };
    let box_size = polynomial_size.0 / PBS_MESSAGE_MODULUS;
    let mut a36_active_step2_body = vec![0u64; polynomial_size.0];
    a36_active_step2_body[box_size..3 * box_size].fill(2 * bool_delta);
    let mut a36_final_boolean_body = vec![0u64; polynomial_size.0];
    a36_final_boolean_body[box_size..3 * box_size].fill(bool_delta);
    let mut a36_radix5_or_body = vec![0u64; polynomial_size.0];
    a36_radix5_or_body[box_size..11 * box_size].fill(2 * bool_delta);
    let a36_active_step2_accumulator = raw_accumulator(a36_active_step2_body);
    let a36_final_boolean_accumulator = raw_accumulator(a36_final_boolean_body);
    let a36_radix5_or_accumulator = raw_accumulator(a36_radix5_or_body);

    // A50, richiesto dagli anchor A53 3390/3009/3930, mantiene invece stati canonici 0/1.
    // Il target-one usa l'intervallo aperto di mezzo slot attorno al centro 1; l'OR copre le
    // somme canoniche 1..=15. Entrambi richiedono il preset A44 max-noise 15.
    assert_eq!(box_size % 2, 0);
    let half_box = box_size / 2;
    let mut a50_target_one_body = vec![0u64; polynomial_size.0];
    a50_target_one_body[half_box..box_size + half_box].fill(bool_delta);
    let mut a50_radix15_or_body = vec![0u64; polynomial_size.0];
    a50_radix15_or_body[half_box..15 * box_size + half_box].fill(bool_delta);
    let a50_target_one_accumulator = raw_accumulator(a50_target_one_body);
    let a50_radix15_or_accumulator = raw_accumulator(a50_radix15_or_body);

    assert!(!fuse_refresh || wire_format == AlignedWireFormat::A53Radix15TwoP16Digits);
    let a126_fusion_accumulator = fuse_refresh.then(|| {
        let bytes = include_bytes!("../artifacts/fused_candidate_zero_body.u64le");
        assert_eq!(bytes.len(), polynomial_size.0 * 8);
        let body = bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        raw_accumulator(body)
    });

    let scan_or_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| u64::from((1..=A38_REDUCTION_RADIX as u64).contains(&slot)),
    );
    let scan_local_first_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| match slot {
            0 => 0,
            1 => 3,
            2 => 2,
            3 | 4 => 1,
            _ => 0,
        },
    );
    let digit_identity_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        bool_delta,
        |slot| slot,
    );
    let root_delta = match wire_format {
        AlignedWireFormat::SingleCode => code_delta,
        AlignedWireFormat::TwoP16Digits | AlignedWireFormat::A53Radix15TwoP16Digits => bool_delta,
    };
    let low_code_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        root_delta,
        |slot| slot,
    );
    let high_code_accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        PBS_MESSAGE_MODULUS,
        modulus,
        root_delta,
        |slot| match wire_format {
            AlignedWireFormat::SingleCode if slot <= 8 => A38_NIBBLE_RADIX * slot,
            AlignedWireFormat::TwoP16Digits | AlignedWireFormat::A53Radix15TwoP16Digits
                if slot <= 8 =>
            {
                slot
            }
            _ => 0,
        },
    );
    let scan_groups = n.div_ceil(A38_SCAN_GROUP_SIZE);
    let scan_selector_accumulators: Vec<Glwe> = (0..scan_groups)
        .map(|group| {
            let group_len = (n - group * A38_SCAN_GROUP_SIZE).min(A38_SCAN_GROUP_SIZE);
            let mut low = [0u64; 8];
            let mut high = [0u64; 8];
            for state in 1..=group_len {
                let identity_code = (A38_SCAN_GROUP_SIZE * group + state) as u64;
                low[state] = identity_code % A38_NIBBLE_RADIX;
                high[state] = identity_code / A38_NIBBLE_RADIX;
            }
            let direct_code_scale =
                scan_groups == 1 && wire_format == AlignedWireFormat::SingleCode;
            let delta = if direct_code_scale {
                code_delta
            } else {
                bool_delta
            };
            let high = if direct_code_scale {
                high.map(|digit| A38_NIBBLE_RADIX * digit)
            } else {
                high
            };
            generate_programmable_bootstrap_glwe_lut(
                polynomial_size,
                glwe_size,
                PBS_MESSAGE_MODULUS,
                modulus,
                delta,
                move |slot| {
                    let slot = slot as usize;
                    if slot < 8 {
                        low[slot]
                    } else {
                        high[slot - 8]
                    }
                },
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

    let apply_a126_fusion = |input: &Lwe| -> (Lwe, Lwe) {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = a126_fusion_accumulator
            .as_ref()
            .expect("A126 accumulator")
            .clone();
        blind_rotate_assign_with_modulus_switch(
            &switched, &mut rotated, fourier_bootstrap_key, modulus_switch_configuration,
        );
        let mut candidate = LweCiphertext::new(0u64, big_size, modulus);
        let mut zero_candidate = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut candidate, MonomialDegree(0));
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut zero_candidate, MonomialDegree(768));
        pbs_count.fetch_add(1, Ordering::Relaxed);
        (candidate, zero_candidate)
    };
    let apply_selector_pbs = |input: &Lwe, accumulator: &Glwe| -> (Lwe, Lwe) {
        let mut switched = LweCiphertext::new(0u64, small_size, modulus);
        keyswitch_lwe_ciphertext(key_switching_key, input, &mut switched);
        let mut rotated = accumulator.clone();
        blind_rotate_assign_with_modulus_switch(
            &switched, &mut rotated, fourier_bootstrap_key, modulus_switch_configuration,
        );
        let mut low = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(&rotated, &mut low, MonomialDegree(0));
        let mut high = LweCiphertext::new(0u64, big_size, modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &rotated,
            &mut high,
            MonomialDegree(polynomial_size.0 / 2),
        );
        pbs_count.fetch_add(1, Ordering::Relaxed);
        (low, high)
    };
    let zero =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(big_size, Plaintext(0u64), modulus);
    let a36_or_gate = |states: &[Lwe]| -> Lwe {
        assert!(!states.is_empty() && states.len() <= A38_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(states, &zero), &a36_radix5_or_accumulator)
    };
    let a50_or_gate = |states: &[Lwe]| -> Lwe {
        assert!(!states.is_empty() && states.len() <= A50_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(states, &zero), &a50_radix15_or_accumulator)
    };
    let scan_or_gate = |bits: &[Lwe]| -> Lwe {
        assert!(!bits.is_empty() && bits.len() <= A38_REDUCTION_RADIX);
        apply_pbs(&sum_lwes(bits, &zero), &scan_or_accumulator)
    };
    let bridge_bit = |full: &CapturedExtractedBits,
                      low: &CapturedExtractedBits,
                      bit_index: u32|
     -> WeightedBit {
        if is_canonical_boolean_bit(bit_index) {
            return WeightedBit {
                ciphertext: full.canonical_bits_lsb_first[bit_index as usize]
                    .as_ref()
                    .expect("i bit 3..=7 sono Booleani canonici")
                    .clone(),
            };
        }
        debug_assert!(bit_index < SPLIT_LOW_BITS);
        let weight = extracted_bit_weight(bit_index);
        let correction_log = bit_source_delta(bit_index) + bit_index;
        let target_log = BOOL_DELTA_LOG + weight.ilog2();
        let mut ciphertext = low.corrections_lsb_first[bit_index as usize].clone();
        lwe_ciphertext_cleartext_mul_assign(
            &mut ciphertext,
            Cleartext(1u64 << (target_log - correction_log)),
        );
        WeightedBit { ciphertext }
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
    let low_extracted: Vec<CapturedExtractedBits> = score_pairs
        .par_iter()
        .map(|(_, low)| {
            extract_bits_with_corrections(
                low,
                fourier_bootstrap_key,
                modulus_switch_configuration,
                key_switching_key,
                &low_correction_accumulators,
                LOW_MOD16_DELTA_LOG,
                LOW_EXTRACTED_BITS,
                &pbs_count,
            )
        })
        .collect();
    let low_to_full_bits_flat: Vec<ExtractedCorrection> = (0..n * low_bit_count)
        .into_par_iter()
        .map(|flat| {
            let gallery_index = flat / low_bit_count;
            let bit_index = flat % low_bit_count;
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index as u32 - 1);
            correction_from_small_bit(
                &low_extracted[gallery_index].small_lsb_first[bit_index],
                &low_to_full_correction_accumulators[bit_index],
                fourier_bootstrap_key,
                modulus_switch_configuration,
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
            for bit in &low_to_full_bits_flat[start..start + low_bit_count] {
                lwe_ciphertext_sub_assign(&mut residual, &bit.correction);
            }
            residual
        })
        .collect();
    let high_extracted: Vec<CapturedExtractedBits> = high_inputs
        .par_iter()
        .map(|high| {
            let mut extracted = extract_bits_with_all_corrections(
                high,
                fourier_bootstrap_key,
                modulus_switch_configuration,
                key_switching_key,
                &high_correction_accumulators,
                HIGH_DELTA_LOG,
                A34_HIGH_CORRECTION_BITS,
                &pbs_count,
            );
            // La correzione locale 3 e' il bit globale 7, gia' a Delta_bool.
            extracted.canonical_bits_lsb_first[3] =
                Some(extracted.corrections_lsb_first[3].clone());
            extracted
        })
        .collect();
    let aligned_residuals: Vec<Lwe> = high_inputs
        .par_iter()
        .zip(&high_extracted)
        .map(|(high_input, high)| {
            let mut residual = high_input.clone();
            for correction in &high.corrections_lsb_first {
                lwe_ciphertext_sub_assign(&mut residual, correction);
            }
            residual
        })
        .collect();
    let full_extracted: Vec<CapturedExtractedBits> = low_extracted
        .iter()
        .zip(&high_extracted)
        .enumerate()
        .map(|(gallery_index, (low, high))| {
            let start = gallery_index * low_bit_count;
            let mut small_lsb_first = low.small_lsb_first.clone();
            small_lsb_first.extend(high.small_lsb_first.clone());
            let mut corrections_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.correction.clone())
                .collect::<Vec<_>>();
            corrections_lsb_first.extend(high.corrections_lsb_first.clone());
            let mut canonical_bits_lsb_first = low_to_full_bits_flat[start..start + low_bit_count]
                .iter()
                .map(|bit| bit.boolean.clone())
                .collect::<Vec<_>>();
            canonical_bits_lsb_first.extend(high.canonical_bits_lsb_first.clone());
            debug_assert_eq!(small_lsb_first.len(), 8);
            debug_assert_eq!(corrections_lsb_first.len(), 8);
            debug_assert_eq!(canonical_bits_lsb_first.len(), 8);
            CapturedExtractedBits {
                small_lsb_first,
                corrections_lsb_first,
                canonical_bits_lsb_first,
            }
        })
        .collect();
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
    let a34_top_codes: Vec<Lwe> = aligned_residuals
        .par_iter()
        .map(|residual| apply_pbs(residual, &a34_top_classifier_accumulator))
        .collect();
    let a34_canonical_categories: Vec<Lwe> = a34_top_codes
        .par_iter()
        .map(|code| {
            let mut input = code.clone();
            lwe_ciphertext_plaintext_add_assign(
                &mut input,
                Plaintext(4u64.wrapping_mul(bool_delta)),
            );
            apply_pbs(&input, &a34_canonical_category_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.high_residuals = high_inputs.clone();
        trace.aligned_residuals = aligned_residuals.clone();
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
        trace.fused_boolean_bits_3_to_6 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[3..=6]
                    .iter()
                    .map(|bit| bit.as_ref().expect("bit A29 assente").clone())
                    .collect()
            })
            .collect();
        trace.reused_bit7 = full_extracted
            .iter()
            .map(|bits| {
                bits.canonical_bits_lsb_first[7]
                    .as_ref()
                    .expect("correzione b7 assente")
                    .clone()
            })
            .collect();
        trace.bridged_bits_by_level = bits_by_level
            .iter()
            .map(|bits| bits.iter().map(|bit| bit.ciphertext.clone()).collect())
            .collect();
        trace.a34_top_codes = a34_top_codes.clone();
        trace.a34_canonical_categories = a34_canonical_categories.clone();
    }
    let extract_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let mut a34_category_reduction_levels = vec![a34_canonical_categories.clone()];
    let mut category_level = a34_canonical_categories;
    while category_level.len() > 1 {
        category_level = category_level
            .par_chunks(2)
            .map(|pair| {
                if pair.len() == 1 {
                    pair[0].clone()
                } else {
                    let mut input = pair[0].clone();
                    lwe_ciphertext_add_assign(&mut input, &pair[1]);
                    apply_pbs(&input, &a34_pair_category_accumulator)
                }
            })
            .collect();
        a34_category_reduction_levels.push(category_level.clone());
    }
    let a34_global_category = category_level
        .pop()
        .expect("riduzione categoria A34-top non vuota");
    let initial_candidates: Vec<Lwe> = a34_top_codes
        .par_iter()
        .map(|code| {
            let mut input = code.clone();
            lwe_ciphertext_add_assign(&mut input, &a34_global_category);
            lwe_ciphertext_plaintext_add_assign(
                &mut input,
                Plaintext(4u64.wrapping_mul(bool_delta)),
            );
            apply_pbs(&input, &a34_top_candidate_accumulator)
        })
        .collect();
    if let Some(trace) = trace.as_deref_mut() {
        trace.a34_category_reduction_levels = a34_category_reduction_levels;
        trace.a34_global_category = Some(a34_global_category);
        trace.aligned_initial_candidates = initial_candidates.clone();
    }

    // A38 usa stati 0/2 e OR radix-5. A62 attiva la macchina canonica A50 0/1 e OR radix-15:
    // questo passaggio e' necessario, oltre alla sola scan A53, per ottenere gli anchor congelati
    // 3390/3009/3930. Entrambi i rami conservano l'argmin esatto e il primo vincitore nei tie.
    let use_a50_selection = wire_format == AlignedWireFormat::A53Radix15TwoP16Digits;
    let source_multipliers = if use_a50_selection {
        A50_SOURCE_MULTIPLIERS
    } else {
        A38_SOURCE_MULTIPLIERS
    };
    let mut candidates: Vec<Lwe> = if use_a50_selection {
        initial_candidates.clone()
    } else {
        initial_candidates
            .par_iter()
            .map(|candidate| scale_lwe_signed(candidate, 2))
            .collect()
    };
    for (level, bits) in bits_by_level.iter().enumerate() {
        let zero_candidates: Vec<Lwe> = if fuse_refresh && level == 4 {
            // bits is the positive canonical b3; weighted_bits would already negate it.
            let inputs: Vec<Lwe> = candidates
                .par_iter()
                .zip(bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    let six_bits = scale_lwe_signed(&bit.ciphertext, 6);
                    lwe_ciphertext_add_assign(&mut encoded, &six_bits);
                    encoded
                })
                .collect();
            let pairs: Vec<(Lwe, Lwe)> = inputs.par_iter().map(apply_a126_fusion).collect();
            if let Some(trace) = trace.as_deref_mut() {
                trace.a126_fusion_inputs = inputs;
                trace.a126_fresh_candidates = pairs
                    .iter()
                    .map(|(candidate, _)| candidate.clone())
                    .collect();
                trace.a126_zero_candidates = pairs.iter().map(|(_, zero)| zero.clone()).collect();
            }
            candidates = pairs
                .iter()
                .map(|(candidate, _)| candidate.clone())
                .collect();
            pairs.into_iter().map(|(_, zero)| zero).collect()
        } else {
            let weighted_bits: Vec<Lwe> = bits
                .par_iter()
                .map(|bit| scale_lwe_signed(&bit.ciphertext, source_multipliers[level]))
                .collect();
            candidates
                .par_iter()
                .zip(&weighted_bits)
                .map(|(candidate, bit)| {
                    let mut encoded = candidate.clone();
                    lwe_ciphertext_add_assign(&mut encoded, bit);
                    if use_a50_selection {
                        apply_pbs(&encoded, &a50_target_one_accumulator)
                    } else {
                        apply_pbs(&encoded, &a36_active_step2_accumulator)
                    }
                })
                .collect()
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.zero_candidates_by_level.push(zero_candidates.clone());
        }
        let mut reduced = zero_candidates.clone();
        while reduced.len() > 1 {
            reduced = if use_a50_selection {
                reduced
                    .par_chunks(A50_REDUCTION_RADIX)
                    .map(|chunk| {
                        if chunk.len() == 1 {
                            chunk[0].clone()
                        } else {
                            a50_or_gate(chunk)
                        }
                    })
                    .collect()
            } else {
                reduced
                    .par_chunks(A38_REDUCTION_RADIX)
                    .map(|chunk| a36_or_gate(chunk))
                    .collect()
            };
        }
        let any_zero = reduced.pop().expect("OR A36 non vuoto");
        let linear_candidates: Vec<Lwe> = candidates
            .par_iter()
            .zip(&zero_candidates)
            .map(|(candidate, zero_candidate)| {
                let mut next = candidate.clone();
                lwe_ciphertext_add_assign(&mut next, zero_candidate);
                lwe_ciphertext_sub_assign(&mut next, &any_zero);
                next
            })
            .collect();
        candidates = if use_a50_selection
            && A38_CHUNK_END_LEVELS.contains(&level)
            && !(fuse_refresh && level == 3)
        {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a50_target_one_accumulator))
                .collect()
        } else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[0] {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a36_active_step2_accumulator))
                .collect()
        } else if !use_a50_selection && level == A38_CHUNK_END_LEVELS[1] {
            linear_candidates
                .par_iter()
                .map(|candidate| apply_pbs(candidate, &a36_final_boolean_accumulator))
                .collect()
        } else {
            linear_candidates
        };
        if let Some(trace) = trace.as_deref_mut() {
            trace.any_zero_by_level.push(any_zero);
            trace.candidates_by_level.push(candidates.clone());
        }
    }
    let select_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let mut a53_roots = None;
    let (low_digits, high_digits) = if wire_format == AlignedWireFormat::A53Radix15TwoP16Digits {
        let backend = A66A53CoreBackend {
            server_key,
            modulus,
            big_size,
            small_size,
            pbs_count: &pbs_count,
            scan_pbs: AtomicU64::new(0),
            scan_extra_output_marginals: AtomicU64::new(0),
        };
        let output =
            materialize_a53_scan(&a66_a53_gate(), &backend, &candidates).map_err(map_a53_error)?;
        if let Some(trace) = trace.as_deref_mut() {
            trace.a53_expected_counts = Some(output.expected_counts);
            trace.a53_observed_counts = Some(output.observed_counts);
            trace.a53_low_digit = Some(output.low_digit.clone());
            trace.a53_high_digit = Some(output.high_digit.clone());
        }
        a53_roots = Some((output.low_digit, output.high_digit));
        (Vec::new(), Vec::new())
    } else {
        let group_flags: Vec<Lwe> = candidates
            .par_chunks(A38_SCAN_GROUP_SIZE)
            .map(|group| {
                if group.len() == 1 {
                    group[0].clone()
                } else {
                    scan_or_gate(group)
                }
            })
            .collect();
        let local_first: Vec<Lwe> = candidates
            .par_chunks(A38_SCAN_GROUP_SIZE)
            .zip(&group_flags)
            .map(|(group, flag)| {
                if group.len() == 1 {
                    return flag.clone();
                }
                let mut encoded = flag.clone();
                lwe_ciphertext_add_assign(&mut encoded, &group[0]);
                lwe_ciphertext_add_assign(&mut encoded, &group[0]);
                lwe_ciphertext_add_assign(&mut encoded, &group[1]);
                apply_pbs(&encoded, &scan_local_first_accumulator)
            })
            .collect();
        let group_prefixes = radix5_exclusive_prefix_or(&group_flags, &zero, &scan_or_gate);
        let selected: Vec<(Lwe, Lwe)> = local_first
            .par_iter()
            .zip(&group_prefixes)
            .zip(&scan_selector_accumulators)
            .map(|((local, prefix), accumulator)| {
                let mut encoded = local.clone();
                for _ in 0..4 {
                    lwe_ciphertext_add_assign(&mut encoded, prefix);
                }
                apply_selector_pbs(&encoded, accumulator)
            })
            .collect();
        let (low_digits, high_digits): (Vec<Lwe>, Vec<Lwe>) = selected.into_iter().unzip();
        if let Some(trace) = trace.as_deref_mut() {
            trace.group_prefixes = group_prefixes.clone();
            trace.a38_scan_group_flags = group_flags;
            trace.a38_scan_local_first = local_first;
            trace.a38_scan_low_digits = low_digits.clone();
            trace.a38_scan_high_digits = high_digits.clone();
        }
        (low_digits, high_digits)
    };
    let scan_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    // L'ammissibilita' e' gia' incorporata nei candidati. Manteniamo lo stadio per compatibilita'
    // delle metriche, ma non esegue PBS e non produce un accept tag separato.
    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let threshold_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);

    let stage_started = Instant::now();
    let stage_pbs = pbs_count.load(Ordering::Relaxed);
    let reduce_digit = |mut digits: Vec<Lwe>, final_accumulator: &Glwe| -> Lwe {
        while digits.len() > 1 {
            let next_len = digits.len().div_ceil(A38_REDUCTION_RADIX);
            let accumulator = if next_len == 1 {
                final_accumulator
            } else {
                &digit_identity_accumulator
            };
            digits = digits
                .par_chunks(A38_REDUCTION_RADIX)
                .map(|chunk| apply_pbs(&sum_lwes(chunk, &zero), accumulator))
                .collect();
        }
        digits.pop().expect("riduzione nibble non vuota")
    };
    let (low_code, high_code, code) = if let Some((low_digit, high_digit)) = a53_roots {
        (low_digit, high_digit, None)
    } else {
        let low_code = reduce_digit(low_digits, &low_code_accumulator);
        let high_code = reduce_digit(high_digits, &high_code_accumulator);
        let code = if wire_format == AlignedWireFormat::SingleCode {
            let mut code = low_code.clone();
            lwe_ciphertext_add_assign(&mut code, &high_code);
            Some(code)
        } else {
            None
        };
        (low_code, high_code, code)
    };
    if let Some(trace) = trace {
        if wire_format == AlignedWireFormat::A53Radix15TwoP16Digits {
            debug_assert!(trace.a38_low_code.is_none());
            debug_assert!(trace.a38_high_code.is_none());
            debug_assert!(trace.final_code.is_none());
        } else {
            trace.a38_low_code = Some(low_code.clone());
            trace.a38_high_code = Some(high_code.clone());
            trace.final_code = code.clone();
        }
    }
    let output_metrics = stage_metrics(stage_started, stage_pbs, &pbs_count);
    let total_pbs_count = pbs_count.load(Ordering::Relaxed);
    let expected_counts = if wire_format == AlignedWireFormat::A53Radix15TwoP16Digits {
        if fuse_refresh {
            a126_aligned_operation_counts(n).unwrap().blind_rotations
        } else {
            a62_aligned_operation_counts(n).unwrap().blind_rotations
        }
    } else {
        aligned_a38_pbs_count(n).unwrap()
    };
    debug_assert_eq!(total_pbs_count, expected_counts);
    Ok(AlignedPrivateArgminOutput {
        low_nibble: low_code,
        high_nibble: high_code,
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
    use tfhe::shortint::client_key::atomic_pattern::AtomicPatternClientKey;

    fn into_standard_client_key_parts(
        client_key: tfhe::shortint::ClientKey,
    ) -> (
        GlweSecretKeyOwned<u64>,
        LweSecretKeyOwned<u64>,
        tfhe::shortint::PBSParameters,
    ) {
        match client_key.atomic_pattern {
            AtomicPatternClientKey::Standard(key) => {
                let (glwe_secret_key, lwe_secret_key, parameters, _) = key.into_raw_parts();
                (glwe_secret_key, lwe_secret_key, parameters)
            }
            _ => panic!("la diagnostica baseline TFHE 1.7 richiede una client key Standard"),
        }
    }

    fn entry<'a>(template: &'a [i64], threshold: i64) -> TemplateView<'a> {
        TemplateView {
            template,
            norm2: template.iter().map(|value| value * value).sum(),
            threshold,
        }
    }

    fn negacyclic_division_sample(body: &[u64], rotation: usize, degree: usize) -> u64 {
        let exponent = degree + rotation;
        let value = body[exponent % body.len()];
        if (exponent / body.len()).is_multiple_of(2) {
            value
        } else {
            value.wrapping_neg()
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
    fn a44_parameter_binding_text_is_exact_and_fail_closed() {
        assert_eq!(
            a44_parameter_fingerprint_sha256(),
            A44_PARAMETER_FINGERPRINT_SHA256
        );
        assert_eq!(
            validate_a44_parameter_binding_text(A44_PARAMETER_BINDING),
            Ok(())
        );
        assert_eq!(
            validate_a44_parameter_binding_text(A44ParameterBinding {
                params_id: "tfhe-rs-0.11.3-wrong",
                fingerprint_sha256: A44_PARAMETER_FINGERPRINT_SHA256,
            }),
            Err(PrivateArgminError::A44ParameterIdMismatch)
        );
        assert_eq!(
            validate_a44_parameter_binding_text(A44ParameterBinding {
                params_id: A44_PARAMS_ID,
                fingerprint_sha256: "00",
            }),
            Err(PrivateArgminError::A44ParameterFingerprintMismatch)
        );
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
    fn execution_planner_aligns_only_when_the_expanded_domain_is_safe() {
        // 74 * 3^2 + 2^2 + 1^2 = 671, che induce esattamente [-987, 2329].
        let mut digiface_shape = [0i64; PROBE_DIM];
        digiface_shape[..74].fill(3);
        digiface_shape[74] = 2;
        digiface_shape[75] = 1;

        let current = [entry(&digiface_shape, 4)];
        let plan = plan_private_argmin_execution(&current).unwrap();
        assert_eq!(
            plan,
            PrivateArgminExecutionPlan {
                cauchy_domain: ScoreDomain {
                    lower: -987,
                    upper: 2329,
                },
                execution_domain: ScoreDomain {
                    lower: -1019,
                    upper: 2329,
                },
                aligned_fast_path: true,
            }
        );
        assert!(aligned_uniform_fast_path_for_thresholds(
            &[4],
            plan.execution_domain
        ));

        let mixed = [entry(&digiface_shape, 4), entry(&digiface_shape, 5)];
        let plan = plan_private_argmin_execution(&mixed).unwrap();
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(!plan.aligned_fast_path);

        // T=37 darebbe lower=-986 e restringerebbe di uno il bound inferiore: fallback.
        let non_covering = [entry(&digiface_shape, 37)];
        let plan = plan_private_argmin_execution(&non_covering).unwrap();
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(!plan.aligned_fast_path);

        // Con upper=2329, T=-743 produce [-1766,2329] (4096 valori); uno in meno eccede.
        let boundary = [entry(&digiface_shape, -743)];
        let plan = plan_private_argmin_execution(&boundary).unwrap();
        assert_eq!(
            plan.execution_domain,
            ScoreDomain {
                lower: -1766,
                upper: 2329,
            }
        );
        assert_eq!(plan.execution_domain.checked_width(), Some(4096));
        assert!(plan.aligned_fast_path);

        let too_wide = [entry(&digiface_shape, -744)];
        let plan = plan_private_argmin_execution(&too_wide).unwrap();
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(!plan.aligned_fast_path);

        let overflowing_threshold = [entry(&digiface_shape, i64::MIN)];
        let plan = plan_private_argmin_execution(&overflowing_threshold).unwrap();
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(!plan.aligned_fast_path);

        // T=36 allinea senza cambiare il dominio stretto.
        let identical = [entry(&digiface_shape, 36)];
        let plan = plan_private_argmin_execution(&identical).unwrap();
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(plan.aligned_fast_path);
    }

    #[test]
    fn execution_planner_preserves_single_score_extremes_and_validation_errors() {
        let zero = [0i64; PROBE_DIM];

        let accept_all = [entry(&zero, 1023)];
        let plan = plan_private_argmin_execution(&accept_all).unwrap();
        assert_eq!(plan.cauchy_domain, ScoreDomain { lower: 0, upper: 0 });
        assert_eq!(plan.execution_domain, plan.cauchy_domain);
        assert!(plan.aligned_fast_path);
        assert_eq!(clear_private_argmin(&[0], &accept_all).unwrap().code, 1);

        let reject_all = [entry(&zero, -1)];
        let plan = plan_private_argmin_execution(&reject_all).unwrap();
        assert_eq!(
            plan.execution_domain,
            ScoreDomain {
                lower: -1024,
                upper: 0,
            }
        );
        assert!(plan.aligned_fast_path);
        assert_eq!(clear_private_argmin(&[0], &reject_all).unwrap().code, 0);

        let wide = [entry(&[3i64; PROBE_DIM], 0)];
        assert!(matches!(
            plan_private_argmin_execution(&wide),
            Err(PrivateArgminError::DomainTooWide {
                width: 8693,
                maximum: MAX_DOMAIN_WIDTH,
            })
        ));
        assert_eq!(
            plan_private_argmin_execution(&[]),
            Err(PrivateArgminError::EmptyGallery)
        );
    }

    #[test]
    fn fused_accumulator_layout_is_exact_through_the_safe_rotation_interval() {
        let polynomial_size = PolynomialSize(2048);
        let beta = 1u64 << (BOOL_DELTA_LOG - 1);
        let quarter = polynomial_size.0 / 4;

        for bit_index in 3..=6 {
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index - 1);
            let body = fused_correction_accumulator_body(polynomial_size, alpha, beta);
            assert!(body[..polynomial_size.0 / 2]
                .iter()
                .all(|&value| value == alpha.wrapping_neg()));
            assert!(body[polynomial_size.0 / 2..]
                .iter()
                .all(|&value| value == beta.wrapping_neg()));

            for bit in [0u64, 1] {
                let base_rotation = quarter + bit as usize * polynomial_size.0;
                for error in -(quarter as isize - 1)..=(quarter as isize - 1) {
                    let rotation = (base_rotation as isize + error)
                        .rem_euclid((2 * polynomial_size.0) as isize)
                        as usize;
                    let correction =
                        negacyclic_division_sample(&body, rotation, 0).wrapping_add(alpha);
                    let boolean =
                        negacyclic_division_sample(&body, rotation, polynomial_size.0 / 2)
                            .wrapping_add(beta);
                    assert_eq!(correction, bit << (FULL_DELTA_LOG + bit_index));
                    assert_eq!(boolean, bit << BOOL_DELTA_LOG);
                }

                // Il lookup usa intervalli semiaperti: il bordo negativo appartiene ancora al
                // plateau corretto, mentre +N/4 e -N/4-1 sono le prime rotazioni non sicure.
                let negative_boundary = (base_rotation as isize - quarter as isize)
                    .rem_euclid((2 * polynomial_size.0) as isize)
                    as usize;
                let negative_outside = (base_rotation as isize - quarter as isize - 1)
                    .rem_euclid((2 * polynomial_size.0) as isize)
                    as usize;
                let positive_boundary = (base_rotation + quarter) % (2 * polynomial_size.0);
                let expected_raw_correction = if bit == 0 {
                    alpha.wrapping_neg()
                } else {
                    alpha
                };
                let expected_raw_boolean = if bit == 0 { beta.wrapping_neg() } else { beta };
                assert_eq!(
                    negacyclic_division_sample(&body, negative_boundary, 0),
                    expected_raw_correction
                );
                assert_eq!(
                    negacyclic_division_sample(&body, negative_boundary, polynomial_size.0 / 2),
                    expected_raw_boolean
                );
                assert_ne!(
                    negacyclic_division_sample(&body, negative_outside, 0),
                    expected_raw_correction
                );
                assert_ne!(
                    negacyclic_division_sample(&body, negative_outside, polynomial_size.0 / 2),
                    expected_raw_boolean
                );
                assert_ne!(
                    negacyclic_division_sample(&body, positive_boundary, 0),
                    expected_raw_correction
                );
                assert_ne!(
                    negacyclic_division_sample(&body, positive_boundary, polynomial_size.0 / 2),
                    expected_raw_boolean
                );
            }
        }

        assert!(std::panic::catch_unwind(|| {
            fused_correction_accumulator_body(PolynomialSize(6), 1, 2)
        })
        .is_err());
    }

    #[test]
    fn fused_and_reused_bits_are_canonical_boolean_inputs() {
        for bit_index in 3..=7 {
            assert!(is_canonical_boolean_bit(bit_index));
            assert_eq!(extracted_bit_weight(bit_index), 1);
        }
        assert!(recodes_bit(HIGH_SCORE_BIT));
        assert_eq!(extracted_bit_weight(HIGH_SCORE_BIT), 1);
        assert!(!(0..=10).any(recodes_bit));
    }

    #[test]
    #[ignore = "micro-diagnostica FHE: genera una chiave fresca e otto blind rotation"]
    fn fused_blind_rotation_emits_both_expected_lwe_messages() {
        use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
        use tfhe::shortint::{ClientKey, ServerKey};

        let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, small_secret_key, parameters) = into_standard_client_key_parts(client_key);
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let (_, fourier_bootstrap_key, modulus_switch_configuration, _) =
            standard_server_key_parts(&server_key).expect("Standard Classic test key");
        let polynomial_size = fourier_bootstrap_key.polynomial_size();
        let glwe_size = fourier_bootstrap_key.glwe_size();
        let big_size = fourier_bootstrap_key.output_lwe_dimension().to_lwe_size();
        let modulus = CiphertextModulus::<u64>::new_native();
        let bool_delta = 1u64 << BOOL_DELTA_LOG;
        let counter = AtomicU64::new(0);
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        for bit_index in 3..=6 {
            let alpha = 1u64 << (FULL_DELTA_LOG + bit_index - 1);
            let accumulator = CorrectionAccumulator::WithBoolean(
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    glwe_size,
                    &PlaintextList::from_container(fused_correction_accumulator_body(
                        polynomial_size,
                        alpha,
                        bool_delta >> 1,
                    )),
                    modulus,
                ),
            );
            for bit in [0u64, 1] {
                let mut encrypted = LweCiphertext::new(
                    0u64,
                    small_secret_key.lwe_dimension().to_lwe_size(),
                    modulus,
                );
                encrypt_lwe_ciphertext(
                    &small_secret_key,
                    &mut encrypted,
                    Plaintext(bit << 63),
                    parameters.lwe_noise_distribution(),
                    &mut generator,
                );
                let output = correction_from_small_bit(
                    &encrypted,
                    &accumulator,
                    fourier_bootstrap_key,
                    modulus_switch_configuration,
                    big_size,
                    alpha,
                    &counter,
                );
                let correction_phase =
                    decrypt_lwe_ciphertext(&big_secret_key, &output.correction).0;
                let boolean_phase = decrypt_lwe_ciphertext(
                    &big_secret_key,
                    output.boolean.as_ref().expect("uscita Booleana assente"),
                )
                .0;
                let correction_log = FULL_DELTA_LOG + bit_index;
                assert_eq!(
                    correction_phase.wrapping_add(1u64 << (correction_log - 1)) >> correction_log,
                    bit
                );
                assert_eq!(
                    boolean_phase.wrapping_add(1u64 << (BOOL_DELTA_LOG - 1)) >> BOOL_DELTA_LOG,
                    bit
                );
            }
        }
        assert_eq!(counter.load(Ordering::Relaxed), 8);
    }

    #[test]
    #[ignore = "micro-diagnostica FHE end-to-end su chiave fresca"]
    fn fused_core_preserves_exact_id_ties_threshold_and_output_contract() {
        use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
        use tfhe::shortint::{ClientKey, ServerKey};

        let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, _, parameters) = into_standard_client_key_parts(client_key);
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let polynomial_size = glwe_secret_key.polynomial_size();
        let modulus = CiphertextModulus::<u64>::new_native();
        let mut packed_probe = GlweCiphertext::new(
            0u64,
            glwe_secret_key.glwe_dimension().to_glwe_size(),
            polynomial_size,
            modulus,
        );
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut packed_probe,
            &PlaintextList::new(0u64, PlaintextCount(polynomial_size.0)),
            parameters.glwe_noise_distribution(),
            &mut generator,
        );
        let zero_template = [0i64; PROBE_DIM];
        let decode_big = |ciphertext: &Lwe, delta_log: u32| {
            decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
                .0
                .wrapping_add(1u64 << (delta_log - 1))
                >> delta_log
        };

        for x in [0u64, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 2048, 4095] {
            let template = TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: 0,
            };
            let domain = ScoreDomain {
                lower: -(x as i64),
                upper: -(x as i64) + MAX_DOMAIN_WIDTH - 1,
            };
            let mut trace = PrivateArgminTrace::default();
            let output = private_argmin_impl(
                &server_key,
                &packed_probe,
                &[template],
                domain,
                Some(&mut trace),
            )
            .unwrap();
            assert_eq!(output.metrics.total_pbs_count, 48);
            assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 1);
            assert_eq!(trace.fused_boolean_bits_3_to_6.len(), 1);
            assert_eq!(trace.fused_boolean_bits_3_to_6[0].len(), 4);
            for (offset, bit) in trace.fused_boolean_bits_3_to_6[0].iter().enumerate() {
                assert_eq!(decode_big(bit, BOOL_DELTA_LOG), (x >> (offset + 3)) & 1);
            }
            assert_eq!(trace.reused_bit7.len(), 1);
            assert_eq!(
                decode_big(&trace.reused_bit7[0], BOOL_DELTA_LOG),
                (x >> 7) & 1
            );
        }

        let tie_domain = ScoreDomain {
            lower: -10,
            upper: MAX_DOMAIN_WIDTH - 11,
        };
        for (thresholds, expected_code) in [([-1, 100], 0), ([0, -1], 1)] {
            let templates = [
                TemplateView {
                    template: &zero_template,
                    norm2: 0,
                    threshold: thresholds[0],
                },
                TemplateView {
                    template: &zero_template,
                    norm2: 0,
                    threshold: thresholds[1],
                },
            ];
            let output =
                private_argmin(&server_key, &packed_probe, &templates, tie_domain).unwrap();
            assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), expected_code);
            assert_eq!(
                output.metrics.total_pbs_count,
                expected_pbs_count_for_thresholds(2, &thresholds, tie_domain).unwrap()
            );
        }
    }

    #[test]
    #[ignore = "micro-diagnostica FHE A34-top: genera una chiave fresca ed esegue il core completo"]
    fn aligned_a34_top_core_preserves_boundaries_reject_ties_and_exact_id() {
        use tfhe::shortint::parameters::v0_11::classic::gaussian::V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64;
        use tfhe::shortint::{ClientKey, ServerKey};

        let client_key = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64);
        let server_key = ServerKey::new(&client_key);
        let (glwe_secret_key, _, parameters) = into_standard_client_key_parts(client_key);
        let big_secret_key = glwe_secret_key.as_lwe_secret_key();
        let polynomial_size = glwe_secret_key.polynomial_size();
        let modulus = CiphertextModulus::<u64>::new_native();
        let mut seeder_box = new_seeder();
        let seeder = seeder_box.as_mut();
        let mut generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut encrypt_zero_probe = || {
            let mut packed_probe = GlweCiphertext::new(
                0u64,
                glwe_secret_key.glwe_dimension().to_glwe_size(),
                polynomial_size,
                modulus,
            );
            encrypt_glwe_ciphertext(
                &glwe_secret_key,
                &mut packed_probe,
                &PlaintextList::new(0u64, PlaintextCount(polynomial_size.0)),
                parameters.glwe_noise_distribution(),
                &mut generator,
            );
            packed_probe
        };
        let decode_big = |ciphertext: &Lwe, delta_log: u32| {
            decrypt_lwe_ciphertext(&big_secret_key, ciphertext)
                .0
                .wrapping_add(1u64 << (delta_log - 1))
                >> delta_log
        };
        let zero_template = [0i64; PROBE_DIM];
        for x in [
            0u64, 256, 512, 768, 1023, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 2816, 3072, 3328,
            3584, 3840, 4095,
        ] {
            let domain = ScoreDomain {
                lower: -(x as i64),
                upper: -(x as i64) + MAX_DOMAIN_WIDTH - 1,
            };
            let threshold = domain.lower + ALIGNED_UNIFORM_THRESHOLD;
            let template = TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold,
            };
            let mut trace = PrivateArgminTrace::default();
            let output = private_argmin_impl(
                &server_key,
                &encrypt_zero_probe(),
                &[template],
                domain,
                Some(&mut trace),
            )
            .unwrap();
            let h = x >> 8;
            let accepted = x <= ALIGNED_UNIFORM_THRESHOLD as u64;
            assert!(trace.aligned_fast_path);
            assert_eq!(output.metrics.total_pbs_count, 29);
            assert_eq!(output.metrics.extract.pbs_count, 13);
            assert_eq!(output.metrics.select.pbs_count, 13);
            assert_eq!(output.metrics.scan.pbs_count, 1);
            assert_eq!(output.metrics.threshold.pbs_count, 0);
            assert_eq!(output.metrics.output.pbs_count, 2);
            assert_eq!(
                decode_big(&output.code, CODE_DELTA_LOG),
                u64::from(accepted)
            );
            assert_eq!(trace.aligned_residuals.len(), 1);
            assert_eq!(
                decode_big(&trace.aligned_residuals[0], FULL_DELTA_LOG + 8) & 15,
                h
            );
            assert_eq!(
                decode_big(&trace.a34_top_codes[0], BOOL_DELTA_LOG) & 31,
                A34_TOP_CLASSIFIER_CODES[h as usize]
            );
            let expected_category = match h {
                0 => 1,
                1 => 3,
                2 => 7,
                _ => 0,
            };
            assert_eq!(
                decode_big(&trace.a34_canonical_categories[0], BOOL_DELTA_LOG) & 31,
                expected_category
            );
            assert_eq!(
                decode_big(trace.a34_global_category.as_ref().unwrap(), BOOL_DELTA_LOG) & 31,
                expected_category
            );
            assert_eq!(
                decode_big(&trace.aligned_initial_candidates[0], BOOL_DELTA_LOG),
                u64::from(accepted)
            );
            assert!(trace.accept_tag.is_none());
            assert!(trace.selected_threshold_bits_msb_first.is_empty());
            assert!(trace.selected_below.is_none());
        }

        let mut unit_template = [0i64; PROBE_DIM];
        unit_template[0] = 1;
        let run_pair = |first: TemplateView<'_>,
                        second: TemplateView<'_>,
                        domain: ScoreDomain,
                        expected_code: u64,
                        expected_winners: [u64; 2],
                        packed_probe: Glwe| {
            let mut trace = PrivateArgminTrace::default();
            let output = private_argmin_impl(
                &server_key,
                &packed_probe,
                &[first, second],
                domain,
                Some(&mut trace),
            )
            .unwrap();
            assert!(trace.aligned_fast_path);
            assert_eq!(output.metrics.total_pbs_count, 67);
            assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), expected_code);
            assert_eq!(trace.winners.len(), 2);
            assert_eq!(
                trace
                    .winners
                    .iter()
                    .map(|winner| decode_big(winner, BOOL_DELTA_LOG))
                    .collect::<Vec<_>>(),
                expected_winners
            );
        };

        // Il primo score e' 1 (x'=1024, rifiutato), il secondo 0 (x'=1023, accettato).
        // I bit bassi del primo sono tutti zero: il test impedisce che la scorciatoia del primo
        // livello lo faccia risorgere dopo il pre-filtro.
        run_pair(
            TemplateView {
                template: &unit_template,
                norm2: 1,
                threshold: 0,
            },
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: 0,
            },
            ScoreDomain {
                lower: -1023,
                upper: 65,
            },
            2,
            [0, 1],
            encrypt_zero_probe(),
        );
        run_pair(
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: 0,
            },
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: 0,
            },
            ScoreDomain {
                lower: -1023,
                upper: 0,
            },
            1,
            [1, 0],
            encrypt_zero_probe(),
        );
        run_pair(
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: -1,
            },
            TemplateView {
                template: &zero_template,
                norm2: 0,
                threshold: -1,
            },
            ScoreDomain {
                lower: -1024,
                upper: 0,
            },
            0,
            [0, 0],
            encrypt_zero_probe(),
        );

        // La galleria primaria esercita il tail dispari della riduzione binaria e rende osservabili
        // i conteggi progettuali completi. I template non nulli propagano il rumore del probe nel
        // prodotto; tutti i punteggi sono pari a uno e ammessi, quindi il primo tie resta ID 1.
        let large_gallery = vec![
            TemplateView {
                template: &unit_template,
                norm2: 1,
                threshold: 1,
            };
            127
        ];
        let output = private_argmin(
            &server_key,
            &encrypt_zero_probe(),
            &large_gallery,
            ScoreDomain {
                lower: -1022,
                upper: 65,
            },
        )
        .unwrap();
        assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 1);
        assert_eq!(output.metrics.extract.pbs_count, 1651);
        assert_eq!(output.metrics.select.pbs_count, 2121);
        assert_eq!(output.metrics.scan.pbs_count, 222);
        assert_eq!(output.metrics.threshold.pbs_count, 0);
        assert_eq!(output.metrics.output.pbs_count, 150);
        assert_eq!(output.metrics.total_pbs_count, 4144);

        let mut max_id_gallery = vec![
            TemplateView {
                template: &unit_template,
                norm2: 1,
                threshold: 4,
            };
            127
        ];
        max_id_gallery.push(TemplateView {
            template: &zero_template,
            norm2: 0,
            threshold: 4,
        });
        let output = private_argmin(
            &server_key,
            &encrypt_zero_probe(),
            &max_id_gallery,
            ScoreDomain {
                lower: -1019,
                upper: 65,
            },
        )
        .unwrap();
        assert_eq!(decode_big(&output.code, CODE_DELTA_LOG), 128);
        assert_eq!(output.metrics.total_pbs_count, 4174);
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
                    assert!(aligned_output_group_lut(code, bit_offset, positions.len())
                        .checked_mul(code_delta)
                        .is_some());
                    let payload_modulus = 1u64 << positions.len();
                    assert_eq!(
                        aligned_output_group_lut(code, bit_offset, positions.len()),
                        if code < payload_modulus {
                            code << bit_offset
                        } else {
                            0
                        }
                    );
                }
            }
        }
    }

    fn clear_a34_top_code(h: u64) -> u64 {
        assert!(h < 16);
        let base = a34_top_classifier_slot_lut(2 * (h % 8));
        if h < 8 {
            base & 31
        } else {
            base.wrapping_neg() & 31
        }
    }

    #[test]
    fn a34_top_classifier_and_reducers_are_exhaustive_on_reachable_states() {
        for slot in (1..A34_TOP_CLASSIFIER_MODULUS as u64).step_by(2) {
            assert_eq!(a34_top_classifier_slot_lut(slot), 0);
        }
        for h in 0..16u64 {
            let code = clear_a34_top_code(h);
            assert_eq!(code, A34_TOP_CLASSIFIER_CODES[h as usize]);
            assert_eq!(
                code,
                if h < 8 {
                    A34_TOP_CLASSIFIER_CODES[h as usize]
                } else {
                    A34_TOP_CLASSIFIER_CODES[(h - 8) as usize].wrapping_neg() & 31
                }
            );
            let canonical_input = code.wrapping_add(4) & 31;
            assert!(canonical_input < A34_TOP_CLASSIFIER_MODULUS as u64);
            assert_eq!(
                a34_canonical_category_lut(canonical_input),
                match h {
                    0 => 1,
                    1 => 3,
                    2 => 7,
                    _ => 0,
                }
            );
        }

        let categories = [1u64, 3, 7, 0];
        for (left_rank, &left) in categories.iter().enumerate() {
            for (right_rank, &right) in categories.iter().enumerate() {
                let phase = left + right;
                assert!(phase < A34_TOP_CLASSIFIER_MODULUS as u64);
                assert_eq!(
                    a34_pair_category_lut(phase),
                    categories[left_rank.min(right_rank)]
                );
            }
        }

        for (minimum_h, &global_category) in categories.iter().enumerate() {
            for h in 0..16u64 {
                let phase = clear_a34_top_code(h)
                    .wrapping_add(global_category)
                    .wrapping_add(4)
                    & 31;
                assert!(phase < A34_TOP_CLASSIFIER_MODULUS as u64);
                assert_eq!(
                    a34_top_candidate_lut(phase),
                    u64::from(h == minimum_h as u64)
                );
            }
        }
    }

    fn clear_sparse_classifier(h: u64, weight: u64) -> (u64, u64) {
        assert!(h < 8);
        let base = h % 4;
        let mut code = aligned_classifier_slot_lut(2 * base, weight);
        let mut flag = aligned_classifier_slot_lut(2 * base + 1, weight);
        if h >= 4 {
            code = code.wrapping_neg() & 31;
            flag = flag.wrapping_neg() & 31;
        }
        (code, flag)
    }

    fn clear_aligned_sparse_code(values: &[u64]) -> u64 {
        assert!(!values.is_empty() && values.len() <= MAX_GALLERY_SIZE);
        assert!(values.iter().all(|&value| value < MAX_DOMAIN_WIDTH as u64));
        let classified: Vec<(u64, u64)> = values
            .iter()
            .enumerate()
            .map(|(index, &value)| clear_sparse_classifier(value >> 9, [1, 3][index % 2]))
            .collect();
        let pair_flags: Vec<u64> = classified
            .chunks(2)
            .map(|pair| {
                let code = (4 + pair.iter().map(|(_, flag)| *flag).sum::<u64>()) & 31;
                aligned_pair_flag_lut(code)
            })
            .collect();
        let any_b9_zero = u64::from(pair_flags.contains(&1));
        let codes: Vec<u64> = classified
            .iter()
            .map(|(code, _)| (code + any_b9_zero) & 31)
            .collect();
        let b8_zero: Vec<u64> = codes
            .iter()
            .zip(values)
            .map(|(&code, &value)| aligned_candidate_lut((code + 2 * ((value >> 8) & 1)) & 31))
            .collect();
        let any_b8_zero = u64::from(b8_zero.contains(&1));
        let mut candidates: Vec<bool> = codes
            .iter()
            .zip(&b8_zero)
            .map(|(&code, &zero)| {
                aligned_candidate_lut(code.wrapping_sub(zero).wrapping_add(any_b8_zero) & 31) == 1
            })
            .collect();
        for bit in (0..=ALIGNED_SELECTION_HIGH_BIT).rev() {
            let any_zero = values
                .iter()
                .zip(&candidates)
                .any(|(&value, &candidate)| candidate && ((value >> bit) & 1) == 0);
            for (&value, candidate) in values.iter().zip(&mut candidates) {
                if *candidate {
                    *candidate = ((value >> bit) & 1) == u64::from(!any_zero);
                }
            }
        }
        candidates
            .iter()
            .position(|candidate| *candidate)
            .map_or(0, |index| index as u64 + 1)
    }

    #[test]
    fn aligned_sparse_classifier_and_pair_lut_are_exhaustive() {
        let expected_codes = [2, 3, 4, 4, 30, 29, 28, 28];
        for weight in [1u64, 3] {
            for h in 0..8u64 {
                let (code, flag) = clear_sparse_classifier(h, weight);
                assert_eq!(code, expected_codes[h as usize]);
                assert_eq!(
                    flag,
                    match h {
                        0 => weight,
                        4 => 32 - weight,
                        _ => 0,
                    }
                );
            }
        }
        for left_h in 0..8u64 {
            for right_h in 0..8u64 {
                let (_, left) = clear_sparse_classifier(left_h, 1);
                let (_, right) = clear_sparse_classifier(right_h, 3);
                let packed = (left + right + 4) & 31;
                assert!(packed <= 8);
                assert_eq!(
                    aligned_pair_flag_lut(packed),
                    u64::from(left_h == 0 || right_h == 0)
                );
            }
            let (_, singleton) = clear_sparse_classifier(left_h, 1);
            let packed = (singleton + 4) & 31;
            assert_eq!(aligned_pair_flag_lut(packed), u64::from(left_h == 0));
        }
    }

    #[test]
    fn aligned_sparse_clear_model_preserves_exact_id_and_first_tie() {
        for value in 0..MAX_DOMAIN_WIDTH as u64 {
            assert_eq!(
                clear_aligned_sparse_code(&[value]),
                u64::from(value <= ALIGNED_UNIFORM_THRESHOLD as u64),
                "single value={value}"
            );
        }
        let cases = [
            (vec![0], 1),
            (vec![1023], 1),
            (vec![1024], 0),
            (vec![4095], 0),
            (vec![1024, 1023], 2),
            (vec![512, 0, 768], 2),
            (vec![77, 77, 78], 1),
            (vec![1024, 1536, 4095], 0),
        ];
        for (values, expected) in cases {
            assert_eq!(clear_aligned_sparse_code(&values), expected, "{values:?}");
        }
        let mut last_wins = vec![1000u64; MAX_GALLERY_SIZE];
        last_wins[MAX_GALLERY_SIZE - 1] = 0;
        assert_eq!(clear_aligned_sparse_code(&last_wins), 128);

        let mut state = 0xA33A_11C3_D5E7_F901u64;
        for case_index in 0..10_000usize {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = 1 + case_index % MAX_GALLERY_SIZE;
            let mut values = Vec::with_capacity(n);
            for _ in 0..n {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                values.push((state >> 32) & 4095);
            }
            if case_index % 17 == 0 && n > 1 {
                values[1] = values[0];
            }
            let winner = values
                .iter()
                .enumerate()
                .min_by_key(|(index, value)| (**value, *index))
                .unwrap();
            let expected = if *winner.1 <= ALIGNED_UNIFORM_THRESHOLD as u64 {
                winner.0 as u64 + 1
            } else {
                0
            };
            assert_eq!(
                clear_aligned_sparse_code(&values),
                expected,
                "case={case_index}, values={values:?}"
            );
        }
    }

    #[test]
    fn aligned_fast_path_guard_is_exact_and_fail_closed() {
        let aligned = ScoreDomain {
            lower: -1019,
            upper: 2329,
        };
        assert!(aligned_uniform_fast_path_for_thresholds(
            &[4, 4, 4],
            aligned
        ));
        assert!(!aligned_uniform_fast_path_for_thresholds(&[], aligned));
        assert!(!aligned_uniform_fast_path_for_thresholds(
            &[4, 5, 4],
            aligned
        ));
        assert!(!aligned_uniform_fast_path_for_thresholds(
            &[4, 4],
            ScoreDomain {
                lower: -987,
                upper: 2329,
            }
        ));
        assert!(!aligned_uniform_fast_path_for_thresholds(
            &[i64::MAX],
            ScoreDomain {
                lower: i64::MIN,
                upper: i64::MIN + 4095,
            }
        ));
    }

    #[test]
    fn deterministic_pbs_counts_include_odd_tail_and_n_one() {
        assert_eq!(expected_pbs_count(0), None);
        assert_eq!(expected_pbs_count(1), Some(48));
        assert_eq!(expected_pbs_count(3), Some(141));
        assert_eq!(expected_pbs_count(64), Some(2767));
        assert_eq!(expected_pbs_count(127), Some(5524));
        assert_eq!(expected_pbs_count(128), Some(5559));
        assert_eq!(expected_pbs_count(129), None);

        let aligned = ScoreDomain {
            lower: -1019,
            upper: 2329,
        };
        for (n, pbs, ks, marginals) in [
            (1, 29, 26, 33),
            (2, 67, 61, 75),
            (3, 95, 86, 107),
            (64, 2076, 1884, 2332),
            (127, 4144, 3763, 4652),
            (128, 4174, 3790, 4686),
        ] {
            assert_eq!(aligned_a34_top_pbs_count(n), Some(pbs));
            assert_eq!(
                a34_aligned_operation_counts(n),
                Some(A34OperationCounts {
                    blind_rotations: pbs,
                    key_switches: ks,
                    output_marginals: marginals,
                })
            );
        }
        let a44_n127 = a44_aligned_operation_counts(127).unwrap();
        let a50_n127 = a50_aligned_operation_counts(127).unwrap();
        let removed_scan_n127 = a38_scan_output_counts(127);
        let inserted_scan_n127 = a53_scan_counts(127).unwrap().total;
        assert_eq!(a44_n127.blind_rotations, 3655);
        assert_eq!(a50_n127.blind_rotations, 3455);
        assert_eq!(removed_scan_n127.blind_rotations, 201);
        assert_eq!(inserted_scan_n127.blind_rotations, 136);
        assert_eq!(3455 - 201 + 136, 3390);
        for (n, pbs, ks, marginals) in [
            (1, 25, 22, 30),
            (2, 60, 54, 69),
            (3, 85, 76, 98),
            (4, 110, 98, 127),
            (64, 1713, 1521, 1985),
            (127, 3390, 3009, 3930),
            (128, 3415, 3031, 3959),
        ] {
            assert_eq!(
                a62_aligned_operation_counts(n),
                Some(A62OperationCounts {
                    blind_rotations: pbs,
                    key_switches: ks,
                    output_marginals: marginals,
                })
            );
        }
        for (n, pbs, ks, marginals) in [
            (1, 25, 22, 30),
            (2, 60, 54, 69),
            (3, 85, 76, 98),
            (64, 1835, 1643, 2113),
            (127, 3655, 3274, 4206),
            (128, 3682, 3298, 4237),
        ] {
            assert_eq!(aligned_a38_pbs_count(n), Some(pbs));
            assert_eq!(
                a38_aligned_operation_counts(n),
                Some(A38OperationCounts {
                    blind_rotations: pbs,
                    key_switches: ks,
                    output_marginals: marginals,
                })
            );
            assert_eq!(
                expected_pbs_count_for_thresholds(n, &vec![4; n], aligned),
                Some(pbs)
            );
        }
        assert_eq!(aligned_a34_top_pbs_count(0), None);
        assert_eq!(aligned_a34_top_pbs_count(129), None);
        assert_eq!(a34_aligned_operation_counts(0), None);
        assert_eq!(a34_aligned_operation_counts(129), None);
        assert_eq!(aligned_a38_pbs_count(0), None);
        assert_eq!(aligned_a38_pbs_count(129), None);
        assert_eq!(a38_aligned_operation_counts(0), None);
        assert_eq!(a38_aligned_operation_counts(129), None);
        assert_eq!(a62_aligned_operation_counts(0), None);
        assert_eq!(a62_aligned_operation_counts(129), None);
        assert_eq!(
            expected_pbs_count_for_thresholds(
                127,
                &[4; 127],
                ScoreDomain {
                    lower: -987,
                    upper: 2329,
                },
            ),
            Some(4965)
        );

        let domain = ScoreDomain {
            lower: -10,
            upper: 10,
        };
        assert_eq!(
            expected_pbs_count_for_thresholds(3, &[0, 0, 0], domain),
            Some(128)
        );
        assert_eq!(
            expected_pbs_count_for_thresholds(64, &[0; 64], domain),
            Some(2494)
        );
        assert_eq!(
            expected_pbs_count_for_thresholds(127, &[0; 127], domain),
            Some(4965)
        );
        assert_eq!(
            expected_pbs_count_for_thresholds(128, &[0; 128], domain),
            Some(5000)
        );
        assert_eq!(4965 - 3 * 127, 4584);
        assert_eq!(expected_pbs_count_for_thresholds(3, &[0, 1], domain), None);
    }
}

// Explicitly adapted three-ID-digit control; all preceding parent functions are retained.
pub mod wide_control;
