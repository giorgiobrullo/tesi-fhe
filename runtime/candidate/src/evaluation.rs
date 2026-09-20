//! One admitted native query, evaluated against a fixed gallery snapshot.
use crate::dispatch;
use crate::gallery::{template_views, Galleria};
use crate::protocol::LOW_MOD16_OFFSET;
use crate::wire::{bytes_to_u64, decode_probe_header, serialize_exact_output};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::atomic_pattern::AtomicPatternServerKey;
use tfhe::shortint::server_key::ShortintBootstrappingKey;

pub(crate) fn varco(
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
