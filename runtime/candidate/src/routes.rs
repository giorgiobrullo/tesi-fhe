//! Application routes. Evaluation remains synchronous under the gallery lock.
use crate::evaluation::varco;
use crate::gallery::{reset_gallery, upsert_entry, Galleria};
use crate::keys::deserialize_bound_server_key;
use crate::profile::QueryProfile;
use crate::protocol::*;
use crate::wire::{json_quote, sha256_hex};
use crate::{metadata, runtime, supplement};
use std::sync::Mutex;
use std::time::Instant;
use tfhe::core_crypto::prelude::CiphertextModulus;

pub(crate) type Response = (u16, &'static str, String, Vec<u8>);

pub(crate) fn handle(
    metodo: &str,
    path: &str,
    corpo: &[u8],
    stato: &Mutex<Galleria>,
    modulus: CiphertextModulus<u64>,
) -> Response {
    match (metodo, path) {
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
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                supplement::upload(&mut g, &corpo)
            }))
            .unwrap_or_else(|_| Err("invalid G4 key geometry or installation state".into()));
            match result {
                Ok(value) => (
                    200,
                    "application/json",
                    String::new(),
                    value.to_string().into_bytes(),
                ),
                Err(error) => (
                    400,
                    "application/json",
                    String::new(),
                    serde_json::json!({"errore":error}).to_string().into_bytes(),
                ),
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
                    return (
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
                        return (
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
                (
                    400,
                    "application/json",
                    String::new(),
                    b"{\"errore\":\"chiave G4 mancante\"}".to_vec(),
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
    }
}
