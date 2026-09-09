//! One public plan schema shared by status, enrollment and structural count receipts.
use serde_json::{json, Value};

use super::*;

pub(super) fn counts_json(counts: service::Counts) -> Value {
    json!({
        "br": counts.br,
        "ks": counts.ks,
        "marginals": counts.marginals,
        "pfks": counts.pfks,
        "initial_samples": counts.initial_samples,
    })
}

fn domain_json(domain: ScoreDomain) -> Value {
    json!({
        "l": domain.lower,
        "u": domain.upper,
        "larghezza": domain_width(domain).expect("validated domain width"),
    })
}

fn execution_json(metadata: Option<GalleryExecutionMetadata>) -> Value {
    let Some(metadata) = metadata else {
        return json!({
            "dominio": null,
            "dominio_esecuzione": null,
            "percorso_argmin": null,
            "endpoint_fhe": null,
            "endpoint_domain_supported": false,
            "execution_mode": null,
            "soglia_uniforme": null,
            "sentinel_score": null,
            "aligned_fast_path": false,
            "conteggi": null,
        });
    };
    let plan = metadata.plan;
    json!({
        "dominio": domain_json(plan.cauchy_domain),
        "dominio_esecuzione": domain_json(plan.execution_domain),
        "percorso_argmin": dispatch::path_name(plan.mode),
        "endpoint_fhe": dispatch::endpoint_name(plan.mode),
        "endpoint_domain_supported": true,
        "execution_mode": dispatch::mode_name(plan.mode),
        "soglia_uniforme": plan.threshold,
        "sentinel_score": dispatch::sentinel_score(plan.mode),
        "aligned_fast_path": plan.aligned_fast_path,
        "conteggi": counts_json(metadata.counts),
    })
}

fn contract_json(profile: Option<QueryProfile>) -> Value {
    json!({
        "http_contract": HTTP_CONTRACT,
        "wire_version": WIRE_VERSION,
        "probe_magic": PROBE_MAGIC,
        "probe_layout": PROBE_LAYOUT_DUAL_SAME_GLWE,
        "query_profile": profile.map(QueryProfile::name),
        "query_profile_id": profile.map(QueryProfile::wire).unwrap_or(0),
        "score_delta_log": profile.map(QueryProfile::score_delta_log).unwrap_or(0),
        "low_mod16_offset": LOW_MOD16_OFFSET,
        "low_mod16_delta_log": LOG_LOW_MOD16_DELTA,
        "output_magic": OUTPUT_MAGIC,
        "output_mode": OUTPUT_MODE_EXACT_ID_THREE_LWE,
        "digit_delta_log": LOG_DIGIT_DELTA,
        "output_lwes": OUTPUT_LWES,
        "digit_base": OUTPUT_DIGIT_BASE,
        "params_id": A44_PARAMS_ID,
        "params_fingerprint_sha256": A44_PARAMETER_FINGERPRINT_SHA256,
        "variant_id": VARIANT_ID,
        "circuit_sha256": CIRCUIT_SHA256,
        "core_id_contract": service::ID_CONTRACT,
        "threshold_policy": "winner_own_inclusive",
        "score_domain_max_width": SCORE_DOMAIN_MAX_WIDTH,
        "cauchy_coverage_required": true,
        "max_gallery_size": MAX_GALLERY,
        "pfks_window_payload_bytes": service::WINDOW_PAYLOAD_BYTES,
        "head_fourier_payload_bytes": service::head_key::HEAD_FOURIER_PAYLOAD_BYTES,
        "server_key_body_limit_bytes": MAX_SERVER_KEY_BODY_BYTES,
        "g4_key_body_limit_bytes": MAX_G4_KEY_BODY_BYTES,
        "runtime_mode": runtime::MODE_NAME,
        "g4_required": runtime::mode().uses_g4(),
        "service_source_sha256": runtime::SOURCE_SHA256,
        "core_source_sha256": runtime::CORE_SOURCE_SHA256,
        "max_noise_level": 15,
        "small_lwe_dimension": 859,
        "client_key_magic": CLIENT_KEY_MAGIC,
        "server_key_magic": SERVER_KEY_MAGIC,
        "codice": "0=rifiuto; i+1=identita_accettata",
        "ricostruzione_client": "low+15*middle+225*high",
        "un_solo_lwe": false,
    })
}

pub(super) fn status_json(gallery: &Galleria) -> Result<Value, String> {
    let metadata = gallery_execution_metadata(&gallery.iscritti)?;
    let profile = if metadata.is_some() {
        Some(QueryProfile::for_gallery(gallery.iscritti.len())?)
    } else {
        None
    };
    let names: Vec<&str> = gallery
        .iscritti
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    let thresholds: Vec<i64> = gallery
        .iscritti
        .iter()
        .map(|entry| entry.threshold)
        .collect();
    let mut status = execution_json(metadata);
    let fields = status.as_object_mut().expect("execution metadata object");
    fields.extend(
        json!({
            "iscritti": gallery.iscritti.len(),
            "nomi": names,
            "soglie": thresholds,
            "chiave": gallery.chiave.is_some(),
            "chiave_sha256": gallery.chiave_sha256,
            "g4_sha256": gallery.g4_sha256,
            "g4_ready": !runtime::mode().uses_g4() || gallery.g4_sha256.is_some(),
            "dim": gallery.dim,
            "soglia_default": gallery.t_default,
            "epoch": gallery.epoch,
            "revision": gallery.revision,
            "contratto_esatto": contract_json(profile),
            "runtime_optimization": runtime::metadata(),
        })
        .as_object()
        .expect("status object")
        .clone(),
    );
    Ok(status)
}

pub(super) fn enrollment_json(
    gallery: &Galleria,
    index: usize,
    threshold: i64,
    metadata: GalleryExecutionMetadata,
) -> Value {
    let mut response = execution_json(Some(metadata));
    response
        .as_object_mut()
        .expect("execution metadata object")
        .extend(
            json!({
                "ok": true,
                "indice": index,
                "iscritti": gallery.iscritti.len(),
                "soglia": threshold,
                "galleria_epoch": gallery.epoch,
                "galleria_revision": gallery.revision,
            })
            .as_object()
            .expect("enrollment object")
            .clone(),
        );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gallery() -> Galleria {
        crate::tests::initialize_runtime();
        Galleria {
            dim: PROBE_DIM,
            t_default: 4,
            iscritti: Vec::new(),
            chiave: None,
            chiave_sha256: None,
            g4_sha256: None,
            epoch: 123,
            revision: 0,
        }
    }

    fn template() -> Vec<i64> {
        let mut template = vec![0; PROBE_DIM];
        template[..74].fill(3);
        template[74] = 2;
        template[75] = 1;
        template
    }

    #[test]
    fn empty_status_has_no_implied_execution_plan() {
        let status = status_json(&gallery()).unwrap();
        for key in [
            "dominio",
            "dominio_esecuzione",
            "percorso_argmin",
            "endpoint_fhe",
            "execution_mode",
            "soglia_uniforme",
            "sentinel_score",
            "conteggi",
        ] {
            assert!(status[key].is_null(), "{key}");
        }
        assert_eq!(status["endpoint_domain_supported"], false);
        assert_eq!(status["aligned_fast_path"], false);
        assert_eq!(status["nomi"], json!([]));
        assert_eq!(status["soglie"], json!([]));
        assert!(status["contratto_esatto"]["query_profile"].is_null());
        assert_eq!(status["contratto_esatto"]["query_profile_id"], 0);
        assert_eq!(status["contratto_esatto"]["score_delta_log"], 0);
        assert_eq!(status["contratto_esatto"]["wire_version"], 9);
        assert_eq!(status["contratto_esatto"]["output_lwes"], 3);
    }

    #[test]
    fn actual_uniform_and_mixed_admission_share_one_json_schema() {
        // Independent numeric anchors for this norm-671 public fixture.
        // Tuple order: BR, KS, marginals, PFKS, initial samples.
        // The mixed pair omits the shared zero ID-middle payload after repacking.
        for (thresholds, expected_mode, expected_sentinel, aligned, expected_counts) in [
            (vec![4], "uniform_sentinel", Some(1024), true, [8, 8, 11, 2, 1]),
            (vec![273], "uniform_sentinel", Some(1261), false, [8, 8, 11, 2, 1]),
            (vec![i64::MIN], "uniform_all_reject", None, false, [0, 0, 0, 0, 0]),
            (vec![i64::MAX], "uniform_all_accept", None, false, [4, 4, 6, 0, 1]),
            (vec![4, 273], "mixed_winner_threshold", None, false, [18, 16, 27, 9, 2]),
        ] {
            let mut gallery = gallery();
            let mut last = None;
            for (index, threshold) in thresholds.iter().copied().enumerate() {
                last = Some(
                    upsert_entry(
                        &mut gallery,
                        format!("public_{index}"),
                        template(),
                        threshold,
                    )
                    .unwrap(),
                );
            }
            let (index, metadata) = last.unwrap();
            let status = status_json(&gallery).unwrap();
            let enrollment = enrollment_json(&gallery, index, thresholds[index], metadata);
            for key in execution_json(Some(metadata)).as_object().unwrap().keys() {
                assert_eq!(status[key], enrollment[key], "{key}");
            }
            assert_eq!(status["execution_mode"], expected_mode);
            assert_eq!(status["sentinel_score"], json!(expected_sentinel));
            assert_eq!(status["aligned_fast_path"], aligned);
            assert_eq!(status["endpoint_domain_supported"], true);
            assert_eq!(
                status["dominio"],
                json!({"l": -987, "u": 2329, "larghezza": 3317})
            );
            assert_eq!(status["soglie"], json!(thresholds));
            assert_eq!(status["contratto_esatto"]["query_profile"], "head51");
            assert_eq!(status["contratto_esatto"]["query_profile_id"], 2);
            assert_eq!(status["contratto_esatto"]["score_delta_log"], 51);
            assert_eq!(
                status["conteggi"],
                json!({
                    "br": expected_counts[0], "ks": expected_counts[1],
                    "marginals": expected_counts[2], "pfks": expected_counts[3],
                    "initial_samples": expected_counts[4],
                })
            );
            if expected_mode == "mixed_winner_threshold" {
                assert!(status["soglia_uniforme"].is_null());
                assert_eq!(status["percorso_argmin"], "fast_mixed_winner_threshold");
                assert_eq!(status["endpoint_fhe"], "head_mean_mixed_parallel");
            } else {
                assert_eq!(status["soglia_uniforme"], thresholds[0]);
                assert_eq!(status["percorso_argmin"], "fast_uniform");
                assert_eq!(status["endpoint_fhe"], "head_mean_uniform_parallel");
            }
        }
    }

    #[test]
    fn quoted_names_and_signed_extremes_roundtrip_as_json() {
        let mut gallery = gallery();
        let name = "a\"b\\c\n";
        upsert_entry(&mut gallery, name.into(), template(), i64::MIN).unwrap();
        let status = status_json(&gallery).unwrap();
        let decoded: Value = serde_json::from_str(&status.to_string()).unwrap();
        assert_eq!(decoded["nomi"][0], name);
        assert_eq!(decoded["soglie"][0], i64::MIN);
        assert_eq!(decoded["soglia_uniforme"], i64::MIN);
        assert_eq!(
            decoded["conteggi"],
            json!({"br": 0, "ks": 0, "marginals": 0, "pfks": 0, "initial_samples": 0})
        );
    }
}
