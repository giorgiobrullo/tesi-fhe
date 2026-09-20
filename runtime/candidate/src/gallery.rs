//! Gallery admission, score domains and revision-preserving updates.
use crate::protocol::*;
use pfks_core::service::{self, EvaluationKeys, ExecutionPlan, ScoreDomain, TemplateView};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) template: Vec<i64>,
    pub(crate) norm2: i64,
    pub(crate) l1: i64,
    pub(crate) threshold: i64,
}

pub(crate) struct Galleria {
    pub(crate) dim: usize,
    pub(crate) t_default: i64,
    pub(crate) iscritti: Vec<Entry>,
    pub(crate) chiave: Option<EvaluationKeys>,
    pub(crate) chiave_sha256: Option<String>,
    pub(crate) g4_sha256: Option<String>,
    pub(crate) epoch: u64,
    pub(crate) revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GalleryExecutionMetadata {
    pub(crate) plan: ExecutionPlan,
    pub(crate) counts: service::Counts,
}

impl Entry {
    pub(crate) fn new(name: String, template: Vec<i64>, threshold: i64) -> Result<Self, String> {
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

    pub(crate) fn score_domain(&self) -> Result<ScoreDomain, String> {
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

pub(crate) fn ceil_sqrt_nonnegative(value: i64) -> Result<i64, String> {
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

pub(crate) fn gallery_domain(entries: &[Entry]) -> Result<Option<ScoreDomain>, String> {
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

pub(crate) fn template_views(entries: &[Entry]) -> Vec<TemplateView<'_>> {
    entries
        .iter()
        .map(|entry| TemplateView {
            template: &entry.template,
            norm2: entry.norm2,
            threshold: entry.threshold,
        })
        .collect()
}

pub(crate) fn gallery_execution_metadata(
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

pub(crate) fn domain_width(domain: ScoreDomain) -> Result<i64, String> {
    domain
        .upper
        .checked_sub(domain.lower)
        .and_then(|x| x.checked_add(1))
        .ok_or_else(|| "larghezza del dominio non rappresentabile".to_string())
}

pub(crate) fn process_epoch() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ u64::from(std::process::id()).rotate_left(32)
}

pub(crate) fn next_revision(revision: u64) -> Result<u64, String> {
    revision
        .checked_add(1)
        .ok_or_else(|| "contatore di revisione esaurito".to_string())
}

pub(crate) fn upsert_entry(
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

pub(crate) fn reset_gallery(gallery: &mut Galleria) -> Result<(), String> {
    let revision = next_revision(gallery.revision)?;
    gallery.iscritti.clear();
    gallery.revision = revision;
    Ok(())
}
