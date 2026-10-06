//! Client-only PFKS key-row measurement. No key generation, PFKS, KS, PBS or filesystem calls.
//! Measure rows without any payload/output, then predict from public payload digits.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tfhe::core_crypto::prelude::*;

#[derive(Clone, Copy)]
pub enum KeyFunction {
    /// A137: f(1)=-1, polynomial=-1, effective F=1.
    ConstantNegativeIdentity,
    /// A137: f(1)=1, signed W0 with radius63 at N2048.
    Window { radius: usize },
}

#[derive(Clone, Copy)]
pub enum Projection {
    Coefficient,
    /// Measures (eta*W0)[target], not each primitive eta coefficient separately.
    WindowSum {
        radius: usize,
    },
}

fn at(poly: &[u64], degree: isize) -> u64 {
    let n = poly.len() as isize;
    let value = poly[degree.rem_euclid(n) as usize];
    if degree.div_euclid(n).rem_euclid(2) == 0 {
        value
    } else {
        value.wrapping_neg()
    }
}

fn window(n: usize, radius: usize) -> Vec<u64> {
    assert!(2 * radius + 1 <= n && radius <= 63);
    let mut polynomial = vec![0u64; n];
    for degree in -(radius as isize)..=radius as isize {
        let coefficient = degree.rem_euclid(n as isize) as usize;
        polynomial[coefficient] = if degree < 0 { u64::MAX } else { 1 };
    }
    polynomial
}

fn unit(n: usize) -> Vec<u64> {
    let mut polynomial = vec![0; n];
    polynomial[0] = 1;
    polynomial
}

/// Exact sparse right-polynomial product; kernel is identity or signed width<=127 window.
fn multiply_kernel(left: &[u64], kernel: &[u64]) -> Vec<u64> {
    let n = left.len();
    assert_eq!(kernel.len(), n);
    let mut out = vec![0u64; n];
    for (j, &k) in kernel.iter().enumerate().filter(|(_, k)| **k != 0) {
        assert!(k == 1 || k == u64::MAX);
        for (i, &value) in left.iter().enumerate() {
            let mut product = value.wrapping_mul(k);
            if i + j >= n {
                product = product.wrapping_neg();
            }
            out[(i + j) % n] = out[(i + j) % n].wrapping_add(product);
        }
    }
    out
}

fn hash_words(words: &[u64]) -> String {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}

// Intentionally no Debug/Serialize: it contains output-secret linear transforms.
struct ClientFunctional {
    kernel: Vec<u64>,
    secret_times_kernel: Vec<Vec<u64>>,
}
impl ClientFunctional {
    fn phase(&self, ciphertext: &[u64], target: isize) -> u64 {
        let n = self.kernel.len();
        assert_eq!(ciphertext.len(), (self.secret_times_kernel.len() + 1) * n);
        let mut phase = 0u64;
        for (j, &body) in ciphertext[ciphertext.len() - n..].iter().enumerate() {
            phase = phase.wrapping_add(body.wrapping_mul(at(&self.kernel, target - j as isize)));
        }
        for (mask, secret) in ciphertext[..ciphertext.len() - n]
            .chunks_exact(n)
            .zip(&self.secret_times_kernel)
        {
            for (j, &word) in mask.iter().enumerate() {
                phase = phase.wrapping_sub(word.wrapping_mul(at(secret, target - j as isize)));
            }
        }
        phase
    }
}

/// Contains actual secret bits and measured row phases. Keep in client memory only.
/// No serializers or row-data accessor are supplied. Public hashes do not prove execution.
pub struct ClientRowSamples {
    key_hash: String,
    kernel_hash: String,
    input_secret: Vec<u64>,
    functional: ClientFunctional,
    function_times_kernel: Vec<u64>,
    base: usize,
    levels: usize,
    targets: Vec<usize>,
    // Actual key order: all mask rows then body; within each, levels descending.
    errors: Vec<Vec<u64>>,
}

impl ClientRowSamples {
    pub fn key_hash(&self) -> &str {
        &self.key_hash
    }
    pub fn kernel_hash(&self) -> &str {
        &self.kernel_hash
    }
    pub fn measured_row_levels(&self) -> usize {
        self.errors.len()
    }
    pub fn measured_target_count(&self) -> usize {
        self.targets.len()
    }
}

/// A data-independent measurement stage: no payload or PFKS-output arguments exist.
/// Default first gate: Coefficient, one target, one family, actual A137 24x1.
pub fn measure_key_rows(
    key: &LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>,
    input_secret: &LweSecretKeyView<'_, u64>,
    output_secret: &GlweSecretKeyOwned<u64>,
    function: KeyFunction,
    projection: Projection,
    targets: &[usize],
) -> ClientRowSamples {
    let n = key.output_polynomial_size().0;
    let base = key.decomposition_base_log().0;
    let levels = key.decomposition_level_count().0;
    let rows = key.input_key_lwe_dimension().0 + 1;
    assert!(n.is_power_of_two() && n <= 2048 && rows <= 2049);
    assert!(base > 0 && base <= 24 && levels > 0 && levels <= 4 && base * levels < 64);
    assert!(key.ciphertext_modulus().is_native_modulus());
    assert_eq!(key.input_key_lwe_dimension(), input_secret.lwe_dimension());
    assert_eq!(
        key.output_polynomial_size(),
        output_secret.polynomial_size()
    );
    assert_eq!(
        key.output_key_glwe_dimension(),
        output_secret.glwe_dimension()
    );
    assert!(input_secret
        .as_ref()
        .iter()
        .chain(output_secret.as_ref())
        .all(|&s| s <= 1));
    assert!(!targets.is_empty() && targets.len() <= 32);
    let mut unique = targets.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), targets.len());
    assert!(targets.iter().all(|&t| t < n));
    let effective_function = match function {
        KeyFunction::ConstantNegativeIdentity => unit(n),
        KeyFunction::Window { radius } => window(n, radius),
    };
    let kernel = match projection {
        Projection::Coefficient => unit(n),
        Projection::WindowSum { radius } => window(n, radius),
    };
    let function_times_kernel = multiply_kernel(&effective_function, &kernel);
    let functional = ClientFunctional {
        secret_times_kernel: output_secret
            .as_ref()
            .chunks_exact(n)
            .map(|secret| multiply_kernel(secret, &kernel))
            .collect(),
        kernel,
    };
    let mut errors = Vec::with_capacity(rows * levels);
    for (row_index, block) in key.iter().enumerate() {
        let u = if row_index + 1 == rows {
            u64::MAX
        } else {
            input_secret.as_ref()[row_index]
        };
        for (level_index, row_ciphertext) in block.iter().enumerate() {
            let level = levels - level_index;
            let gadget = 1u64 << (64 - base * level);
            let samples = targets
                .iter()
                .map(|&target| {
                    let expected = u
                        .wrapping_mul(gadget)
                        .wrapping_mul(function_times_kernel[target]);
                    functional
                        .phase(row_ciphertext.as_ref(), target as isize)
                        .wrapping_sub(expected)
                })
                .collect();
            errors.push(samples);
        }
    }
    assert_eq!(errors.len(), rows * levels);
    ClientRowSamples {
        key_hash: hash_words(key.as_ref()),
        kernel_hash: hash_words(&functional.kernel),
        input_secret: input_secret.as_ref().to_vec(),
        functional,
        function_times_kernel,
        base,
        levels,
        targets: targets.to_vec(),
        errors,
    }
}

/// Scalar summaries are still client-local observations, not service outputs or tail bounds.
pub struct Prediction {
    pub modular: u64,
    pub centered: i64,
    /// Lift of centered measured row-functional values, not necessarily primitive-coefficient lift.
    pub lifted: i128,
    pub wrap_quotient: i128,
    pub distinct_nonzero_row_functionals: usize,
}

pub fn predict(
    samples: &ClientRowSamples,
    payloads: &[&LweCiphertextOwned<u64>],
    target_degrees: &[isize],
    weights: &[i64],
) -> Prediction {
    assert!(!payloads.is_empty() && payloads.len() <= 8);
    assert_eq!(payloads.len(), target_degrees.len());
    assert_eq!(payloads.len(), weights.len());
    assert!(weights.iter().all(|&weight| (-128..=128).contains(&weight)));
    let n = samples.functional.kernel.len() as isize;
    let decomposer = SignedDecomposer::<u64>::new(
        DecompositionBaseLog(samples.base),
        DecompositionLevelCount(samples.levels),
    );
    let mut coefficients: BTreeMap<(usize, usize), i128> = BTreeMap::new();
    for ((payload, &degree), &weight) in payloads.iter().zip(target_degrees).zip(weights) {
        assert_eq!(payload.as_ref().len(), samples.input_secret.len() + 1);
        assert!(payload.ciphertext_modulus().is_native_modulus());
        let target_index = samples
            .targets
            .iter()
            .position(|&t| t == degree.rem_euclid(n) as usize)
            .expect("row functional was not independently measured");
        let sign = if degree.div_euclid(n).rem_euclid(2) == 0 {
            1i128
        } else {
            -1i128
        };
        for (row, &word) in payload.as_ref().iter().enumerate() {
            let rounded = decomposer.closest_representable(word);
            for (index, term) in decomposer.decompose(rounded).enumerate() {
                assert_eq!(term.level().0, samples.levels - index);
                *coefficients
                    .entry((row * samples.levels + index, target_index))
                    .or_default() -= sign * i128::from(weight) * i128::from(term.value() as i64);
            }
        }
    }
    coefficients.retain(|_, value| *value != 0);
    let lifted =
        coefficients
            .iter()
            .fold(0i128, |sum, (&(row_level, target_index), &coefficient)| {
                sum.checked_add(
                    coefficient
                        .checked_mul(i128::from(samples.errors[row_level][target_index] as i64))
                        .expect("bounded coefficient product"),
                )
                .expect("bounded lifted sum")
            });
    let modular = lifted as u64;
    let centered = modular as i64;
    Prediction {
        modular,
        centered,
        lifted,
        wrap_quotient: (lifted - i128::from(centered)) / (1i128 << 64),
        distinct_nonzero_row_functionals: coefficients.len(),
    }
}

pub struct Comparison {
    pub predicted: Prediction,
    pub observed_aggregate: u64,
    pub modular_equal: bool,
}

/// The PFKS output first enters HERE, after independent measurement and prediction.
/// Comparing closure does not authenticate the function label or establish a row-error tail.
pub fn compare_payload(
    samples: &ClientRowSamples,
    payload: &LweCiphertextOwned<u64>,
    actual_pfks_output: &GlweCiphertextOwned<u64>,
    target_degree: isize,
) -> Comparison {
    let predicted = predict(samples, &[payload], &[target_degree], &[1]);
    let n = samples.functional.kernel.len();
    assert_eq!(actual_pfks_output.polynomial_size().0, n);
    assert!(actual_pfks_output.ciphertext_modulus().is_native_modulus());
    let decomposer = SignedDecomposer::<u64>::new(
        DecompositionBaseLog(samples.base),
        DecompositionLevelCount(samples.levels),
    );
    let words = payload.as_ref();
    let rounded_phase = words[..words.len() - 1]
        .iter()
        .zip(&samples.input_secret)
        .fold(
            decomposer.closest_representable(words[words.len() - 1]),
            |phase, (&a, &s)| {
                phase.wrapping_sub(s.wrapping_mul(decomposer.closest_representable(a)))
            },
        );
    let observed_aggregate = samples
        .functional
        .phase(actual_pfks_output.as_ref(), target_degree)
        .wrapping_sub(
            rounded_phase.wrapping_mul(at(&samples.function_times_kernel, target_degree)),
        );
    Comparison {
        modular_equal: predicted.modular == observed_aggregate,
        predicted,
        observed_aggregate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent full product for explicit nontrivial-mask fixture construction.
    fn full_product(a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = a.len();
        let mut out = vec![0u64; n];
        for (i, &a) in a.iter().enumerate() {
            for (j, &b) in b.iter().enumerate() {
                let product = a.wrapping_mul(b);
                if i + j < n {
                    out[i + j] = out[i + j].wrapping_add(product);
                } else {
                    out[i + j - n] = out[i + j - n].wrapping_sub(product);
                }
            }
        }
        out
    }

    #[test]
    fn actual_library_pfks_matches_independently_measured_rows() {
        let input_secret = LweSecretKey::from_container(vec![1u64, 0]);
        let output_secret =
            GlweSecretKey::from_container(vec![1u64, 0, 1, 1, 0, 0, 1, 0], PolynomialSize(8));
        for function in [
            KeyFunction::ConstantNegativeIdentity,
            KeyFunction::Window { radius: 1 },
        ] {
            let f = match function {
                KeyFunction::ConstantNegativeIdentity => unit(8),
                _ => window(8, 1),
            };
            let mut words = Vec::new();
            let mut known_errors = Vec::new();
            for (row, &u) in [1u64, 0, u64::MAX].iter().enumerate() {
                for level in (1..=2).rev() {
                    let mask: Vec<u64> = (0..8)
                        .map(|j| (19 * row + 7 * level + j + 1) as u64)
                        .collect();
                    let product = full_product(&mask, output_secret.as_ref());
                    let eta: Vec<u64> = (0..8)
                        .map(|j| ((3 * row + 5 * level + 7 * j) as i64 % 13 - 6) as u64)
                        .collect();
                    let body: Vec<u64> = (0..8)
                        .map(|j| {
                            product[j]
                                .wrapping_add(
                                    u.wrapping_mul(1u64 << (64 - 8 * level)).wrapping_mul(f[j]),
                                )
                                .wrapping_add(eta[j])
                        })
                        .collect();
                    words.extend(mask);
                    words.extend(body);
                    known_errors.push(eta);
                }
            }
            let key = LwePrivateFunctionalPackingKeyswitchKey::from_container(
                words,
                DecompositionBaseLog(8),
                DecompositionLevelCount(2),
                GlweSize(2),
                PolynomialSize(8),
                CiphertextModulus::new_native(),
            );
            let payload = LweCiphertext::from_container(
                vec![
                    (3u64 << 56) + (5 << 48),
                    (11u64 << 56) + (13 << 48),
                    (7u64 << 56) + (17 << 48),
                ],
                CiphertextModulus::new_native(),
            );
            for projection in [Projection::Coefficient, Projection::WindowSum { radius: 1 }] {
                let samples = measure_key_rows(
                    &key,
                    &input_secret.as_view(),
                    &output_secret,
                    function,
                    projection,
                    &[0, 3],
                );
                let kernel = match projection {
                    Projection::Coefficient => unit(8),
                    _ => window(8, 1),
                };
                for (row_level, eta) in known_errors.iter().enumerate() {
                    let expected = full_product(eta, &kernel);
                    assert_eq!(samples.errors[row_level], vec![expected[0], expected[3]]);
                }
                let mut output = GlweCiphertext::new(
                    0u64,
                    GlweSize(2),
                    PolynomialSize(8),
                    CiphertextModulus::new_native(),
                );
                private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &key,
                    &mut output,
                    &payload,
                );
                for target in [-8isize, 0, 3, 8, 11] {
                    assert!(compare_payload(&samples, &payload, &output, target).modular_equal);
                }
                let predicted_before = predict(&samples, &[&payload], &[0], &[1]).modular;
                output.get_mut_body().as_mut()[0] ^= 1;
                assert!(!compare_payload(&samples, &payload, &output, 0).modular_equal);
                assert_eq!(
                    predicted_before,
                    predict(&samples, &[&payload], &[0], &[1]).modular
                );
                let cancel = predict(&samples, &[&payload, &payload], &[0, 0], &[1, -1]);
                assert_eq!(cancel.lifted, 0);
                assert_eq!(cancel.distinct_nonzero_row_functionals, 0);
            }
        }
    }
}
