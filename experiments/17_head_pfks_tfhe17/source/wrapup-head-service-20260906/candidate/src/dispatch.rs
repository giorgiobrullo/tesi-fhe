//! Fixed public size dispatch, with an explicit domain restriction before FHE.
pub use pfks_core::service::Counts;
use pfks_core::service::EvaluationKeys;
use crate::profile::QueryProfile;
use pipeline_tfhe_rs::{
    a126_aligned_operation_counts, private_argmin_a126, ScoreDomain, TemplateView,
    A44_PARAMETER_BINDING,
};
use tfhe::core_crypto::prelude::{GlweCiphertextOwned, LweCiphertextOwned};

pub fn endpoint_name(n: usize) -> &'static str {
    if n == 127 {
        "head_mean_parallel"
    } else {
        "a126"
    }
}

pub fn counts(n: usize) -> Option<Counts> {
    let baseline = a126_aligned_operation_counts(n)?;
    Some(if n == 127 {
        pfks_core::service::N127_COUNTS
    } else {
        Counts {
            br: baseline.blind_rotations,
            ks: baseline.key_switches,
            marginals: baseline.output_marginals,
            pfks: 0,
            initial_samples: 2 * n as u64,
        }
    })
}

pub fn evaluate(
    server: &EvaluationKeys,
    packed: &GlweCiphertextOwned<u64>,
    templates: &[TemplateView<'_>],
    domain: ScoreDomain,
    profile: QueryProfile,
) -> Result<(LweCiphertextOwned<u64>, LweCiphertextOwned<u64>, Counts), String> {
    profile.validate_gallery(templates.len())?;
    let expected = counts(templates.len()).ok_or("gallery range must be 1..128")?;
    if templates.len() == 127 {
        let views: Vec<_> = templates
            .iter()
            .map(|entry| pfks_core::service::TemplateView {
                template: entry.template,
                norm2: entry.norm2,
                threshold: entry.threshold,
            })
            .collect();
        let domain = pfks_core::service::ScoreDomain {
            lower: domain.lower,
            upper: domain.upper,
        };
        server.evaluate(packed, &views, domain)
    } else {
        let output = private_argmin_a126(
            A44_PARAMETER_BINDING,
            server.ordinary(),
            packed,
            templates,
            domain,
        )
        .map_err(|error| format!("A126 evaluation: {error:?}"))?;
        if output.parameter_binding != A44_PARAMETER_BINDING
            || output.metrics.total_pbs_count != expected.br
        {
            return Err("A126 output binding or operation ledger differs".into());
        }
        Ok((output.low_digit, output.high_digit, expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_size_dispatch_and_complete_ledgers() {
        for n in 1..=128 {
            assert_eq!(endpoint_name(n) == "head_mean_parallel", n == 127);
            if n == 127 {
                assert_eq!(
                    counts(n),
                    Some(pfks_core::service::N127_COUNTS)
                );
            } else {
                let ordinary = a126_aligned_operation_counts(n).unwrap();
                assert_eq!(
                    counts(n),
                    Some(Counts {
                        br: ordinary.blind_rotations,
                        ks: ordinary.key_switches,
                        marginals: ordinary.output_marginals,
                        pfks: 0,
                        initial_samples: 2 * n as u64
                    })
                );
            }
        }
        assert_eq!(counts(0), None);
        assert_eq!(counts(129), None);
    }
}
