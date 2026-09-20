//! Score, template, parameter and output contracts shared by current and historical paths.
use crate::a53_scan::PrimitiveCounts as A53PrimitiveCounts;
use std::fmt::{Display, Formatter};
use tfhe::core_crypto::prelude::{GlweCiphertextOwned, LweCiphertextOwned};

pub(super) type Lwe = LweCiphertextOwned<u64>;
pub(super) type Glwe = GlweCiphertextOwned<u64>;

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
/// [`crate::compat::ServerKey`] gia' generato. In un protocollo serializzato questa stringa deve quindi stare in
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
