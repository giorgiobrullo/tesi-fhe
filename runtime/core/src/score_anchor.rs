//! Reuse a raw score product for at most sixteen public coordinate differences.
//! Helpers preserve the full LWE extracted at coefficient 511, not unused GLWE body words.
use crate::private_argmin::{TemplateView, PROBE_DIM};
use crate::Glwe;

pub(crate) fn differences(
    anchor: &TemplateView<'_>,
    entry: &TemplateView<'_>,
) -> Option<Vec<(usize, u64)>> {
    let mut terms = Vec::new();
    for (i, (&a, &b)) in anchor.template.iter().zip(entry.template).enumerate() {
        if a != b {
            terms.push((PROBE_DIM - 1 - i, (-2 * (b - a)) as u64));
            if terms.len() > 16 {
                return None;
            }
        }
    }
    Some(terms)
}

/// Update every mask coefficient and body511, the sole body coefficient extracted.
pub(crate) fn from_anchor(probe: &Glwe, anchor: &Glwe, terms: &[(usize, u64)]) -> Glwe {
    let n = probe.polynomial_size().0;
    let mut product = anchor.clone();
    let mask_len = (probe.glwe_size().0 - 1) * n;
    for (source, target) in probe.as_ref()[..mask_len]
        .chunks(n)
        .zip(product.as_mut()[..mask_len].chunks_mut(n))
    {
        for &(degree, scalar) in terms {
            for (i, &word) in source.iter().enumerate() {
                let exponent = i + degree;
                let value = word.wrapping_mul(scalar);
                let slot = &mut target[exponent % n];
                *slot = if exponent < n {
                    slot.wrapping_add(value)
                } else {
                    slot.wrapping_sub(value)
                };
            }
        }
    }
    let source_body = probe.get_body();
    let mut body = product.get_mut_body();
    for &(degree, scalar) in terms {
        let word = source_body.as_ref()[PROBE_DIM - 1 - degree];
        body.as_mut()[PROBE_DIM - 1] =
            body.as_ref()[PROBE_DIM - 1].wrapping_add(word.wrapping_mul(scalar));
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_add_mul_assign;
    use tfhe::core_crypto::prelude::*;

    fn stock(probe: &Glwe, template: &[i64]) -> Glwe {
        let n = probe.polynomial_size();
        let mut p = Polynomial::new(0u64, n);
        for (i, &g) in template.iter().enumerate() {
            p.as_mut()[PROBE_DIM - 1 - i] = (-2 * g) as u64;
        }
        let mut output = Glwe::new(0, probe.glwe_size(), n, probe.ciphertext_modulus());
        for (mut out, input) in output
            .as_mut_polynomial_list()
            .iter_mut()
            .zip(probe.as_polynomial_list().iter())
        {
            polynomial_wrapping_add_mul_assign(&mut out, &input, &p);
        }
        output
    }

    #[test]
    fn sparse_anchor_preserves_every_extracted_word_and_the_sixteen_term_cutoff() {
        for seed in 0..8usize {
            let mut probe = Glwe::new(
                0,
                GlweSize(2),
                PolynomialSize(2048),
                CiphertextModulus::new_native(),
            );
            let mut state = seed as u64 + 1;
            for word in probe.as_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *word = state;
            }
            let anchor: Vec<i64> = (0..512).map(|i| ((i * 17 + seed) % 7) as i64 - 3).collect();
            let a = TemplateView {
                template: &anchor,
                norm2: 0,
                threshold: 0,
            };
            let original = stock(&probe, &anchor);
            for changes in [0, 1, 8, 16, 17] {
                let mut template = anchor.clone();
                for i in 0..changes {
                    let at = (i * 31 + seed) % 512;
                    template[at] = if template[at] == 3 { -3 } else { 3 };
                }
                let entry = TemplateView {
                    template: &template,
                    norm2: 0,
                    threshold: 0,
                };
                let full = stock(&probe, &template);
                let terms = differences(&a, &entry);
                assert_eq!(terms.is_some(), changes <= 16);
                if let Some(terms) = terms {
                    let candidate = from_anchor(&probe, &original, &terms);
                    let mut expected =
                        LweCiphertext::new(0u64, LweSize(2049), CiphertextModulus::new_native());
                    let mut actual = expected.clone();
                    extract_lwe_sample_from_glwe_ciphertext(
                        &full,
                        &mut expected,
                        MonomialDegree(PROBE_DIM - 1),
                    );
                    extract_lwe_sample_from_glwe_ciphertext(
                        &candidate,
                        &mut actual,
                        MonomialDegree(PROBE_DIM - 1),
                    );
                    assert_eq!(actual, expected);
                }
            }
        }
    }
}
