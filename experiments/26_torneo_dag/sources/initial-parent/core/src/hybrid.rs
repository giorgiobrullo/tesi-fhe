//! Complete public-template score producer and actual Head Delta59 inputs to the PFKS tree.
use super::*;
use crate::private_argmin::{ScoreDomain, TemplateView};

pub(super) struct Bridge {
    pub tuples: Vec<[Lwe; OUTPUTS]>,
    pub full_scores: Vec<Lwe>,
    pub heads: Vec<wide::Result>,
    pub blind_rotations: u64,
    pub key_switches_structural: u64,
    pub output_marginals_structural: u64,
    pub gadget_levels: u64,
}

pub(super) fn bridge(
    server: &ServerKey, packed: &Glwe, templates: &[TemplateView<'_>], domain: ScoreDomain,
    head_keys: &wide::Keys<'_>, normalizer_keys: &wide::Keys<'_>,
) -> Result<Bridge, private_argmin::PrivateArgminError> {
    let full_scores = private_argmin::head_pfks_score_prefix(server, packed, templates, domain)?;
    let heads: Vec<_> = full_scores.iter()
        .map(|score| wide::ingress(score, head_keys, normalizer_keys)).collect();
    let tuples = heads.iter().enumerate().map(|(index, head)| {
        let identity = (index + 1) as u64;
        std::array::from_fn(|lane| {
            if lane < 3 {
                head.outputs[2 - lane].clone()
            } else {
                let digit = if lane == 3 { identity % 15 } else { identity / 15 };
                allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    LweSize(2049), Plaintext(digit * SCORE_DELTA), packed.ciphertext_modulus())
            }
        })
    }).collect();
    let blind_rotations = heads.iter().map(|result| result.counts.br as u64).sum();
    let key_switches_structural = heads.iter().map(|result| result.counts.ks as u64).sum();
    let output_marginals_structural = heads.iter().map(|result| result.counts.samples as u64).sum();
    let gadget_levels = heads.iter().map(|result| result.counts.gadget_levels as u64).sum();
    Ok(Bridge { tuples, full_scores, heads, blind_rotations, key_switches_structural,
        output_marginals_structural, gadget_levels })
}
