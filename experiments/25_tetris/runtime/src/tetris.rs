//! Tetris Algorithms2/3/4: SetI tau4, rank2 -> prefix-rank1, native u64.
//! Exact GLWE KS diagnoses algebra/noise; it is not the paper's splitFFT timing.
use crate::splitfft::SplitFourierKs;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::core_crypto::prelude::*;

pub const N: usize = 1024;
pub const D: u64 = 1 << 59;
pub type Lwe = LweCiphertextOwned<u64>;
pub type Glwe = GlweCiphertextOwned<u64>;
pub type Generator = EncryptionRandomGenerator<DefaultRandomGenerator>;
const G: [&[(usize, i64)]; 4] = [
    &[(0, 1)],
    &[(N / 2, -1)],
    &[(0, 1), (N / 4, -1), (3 * N / 4, 1)],
    &[
        (N / 2, -1),
        (N / 8, -1),
        (3 * N / 8, 1),
        (5 * N / 8, 1),
        (7 * N / 8, -1),
    ],
];

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub input_adapter: LweKeyswitchKeyOwned<u64>,
    pub output_adapter: LweKeyswitchKeyOwned<u64>,
    pub bsk: FourierLweBootstrapKeyOwned,
    pub autos: Vec<(usize, GlweKeyswitchKeyOwned<u64>)>,
    pub ss_body: GlweKeyswitchKeyOwned<u64>,
    pub ss_mask_negative_products: GlweKeyswitchKeyOwned<u64>,
}
#[derive(Serialize, Deserialize)]
pub struct Secrets {
    pub small: LweSecretKeyOwned<u64>,
    pub refresh: GlweSecretKeyOwned<u64>,
    pub evaluation: GlweSecretKeyOwned<u64>,
}
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Times {
    pub input_adapter_s: f64,
    pub refresh_s: f64,
    pub trace_s: f64,
    pub dec_ss_s: f64,
    pub cmux_s: f64,
    pub output_adapter_s: f64,
}
impl Times {
    pub fn add(&mut self, other: &Self) {
        self.input_adapter_s += other.input_adapter_s;
        self.refresh_s += other.refresh_s;
        self.trace_s += other.trace_s;
        self.dec_ss_s += other.dec_ss_s;
        self.cmux_s += other.cmux_s;
        self.output_adapter_s += other.output_adapter_s;
    }
}
#[derive(Serialize, Deserialize)]
pub struct NibbleEvidence {
    pub input: Lwe,
    pub small: Lwe,
    pub mean_correction: u64,
    pub switched_degrees: Vec<usize>,
    // Indexed [MSB-first prefix bit][gadget level-1].
    pub refreshed: Vec<Vec<Glwe>>,
    pub traced: Vec<Vec<Glwe>>,
    pub ggsws: Vec<GgswCiphertextOwned<u64>>,
    pub times: Times,
}
pub struct Bits {
    pub fourier:
        Vec<FourierGgswCiphertext<aligned_vec::ABox<[tfhe::core_crypto::fft_impl::fft64::c64]>>>,
}

pub fn gaussian_glwe() -> DynamicDistribution<u64> {
    DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.0f64.powi(-51)))
}
fn gaussian_small() -> DynamicDistribution<u64> {
    // Table2: absolute 2.8147e14; retain printed decimal, not a hidden retune.
    DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2.8147e14 / 2.0f64.powi(64)))
}
pub fn auto_poly(input: &[u64], degree: usize) -> Vec<u64> {
    assert_eq!(input.len(), N);
    assert_eq!(degree % 2, 1);
    let mut out = vec![0; N];
    for (i, &word) in input.iter().enumerate() {
        let e = i * degree;
        out[e % N] = if (e / N) % 2 == 0 {
            word
        } else {
            word.wrapping_neg()
        };
    }
    out
}
fn auto_glwe(input: &Glwe, degree: usize) -> Glwe {
    let mut output = input.clone();
    for (src, dst) in input
        .as_ref()
        .chunks_exact(N)
        .zip(output.as_mut().chunks_exact_mut(N))
    {
        dst.copy_from_slice(&auto_poly(src, degree));
    }
    output
}
fn new_glwe(rank: usize) -> Glwe {
    Glwe::new(
        0,
        GlweSize(rank + 1),
        PolynomialSize(N),
        CiphertextModulus::new_native(),
    )
}
fn glwe_ks(
    input: &GlweSecretKeyOwned<u64>,
    output: &GlweSecretKeyOwned<u64>,
    base: usize,
    levels: usize,
    generator: &mut Generator,
) -> GlweKeyswitchKeyOwned<u64> {
    allocate_and_generate_new_glwe_keyswitch_key(
        input,
        output,
        DecompositionBaseLog(base),
        DecompositionLevelCount(levels),
        gaussian_glwe(),
        CiphertextModulus::new_native(),
        generator,
    )
}
pub struct Acceleration {
    autos: Vec<SplitFourierKs>,
    ss_body: SplitFourierKs,
    ss_mask_negative_products: SplitFourierKs,
}
impl Acceleration {
    pub fn payload_bytes(&self) -> usize {
        self.autos
            .iter()
            .map(SplitFourierKs::fourier_payload_bytes)
            .sum::<usize>()
            + self.ss_body.fourier_payload_bytes()
            + self.ss_mask_negative_products.fourier_payload_bytes()
    }
}
impl Keys {
    pub fn accelerate(&self) -> Acceleration {
        Acceleration {
            autos: self
                .autos
                .iter()
                .map(|(_, key)| SplitFourierKs::from_standard(key, 38))
                .collect(),
            ss_body: SplitFourierKs::from_standard(&self.ss_body, 38),
            ss_mask_negative_products: SplitFourierKs::from_standard(
                &self.ss_mask_negative_products,
                38,
            ),
        }
    }
    pub fn generate(
        big: &GlweSecretKeyOwned<u64>,
        big_noise: DynamicDistribution<u64>,
        generator: &mut Generator,
        secret_generator: &mut SecretRandomGenerator<DefaultRandomGenerator>,
    ) -> (Self, Secrets) {
        assert_eq!((big.glwe_dimension().0, big.polynomial_size().0), (1, 2048));
        let small =
            allocate_and_generate_new_binary_lwe_secret_key(LweDimension(710), secret_generator);
        let refresh = allocate_and_generate_new_binary_glwe_secret_key(
            GlweDimension(2),
            PolynomialSize(N),
            secret_generator,
        );
        let evaluation =
            GlweSecretKey::from_container(refresh.as_ref()[..N].to_vec(), PolynomialSize(N));
        let input_adapter = allocate_and_generate_new_lwe_keyswitch_key(
            &big.as_lwe_secret_key(),
            &small,
            DecompositionBaseLog(4),
            DecompositionLevelCount(4),
            gaussian_small(),
            CiphertextModulus::new_native(),
            generator,
        );
        let output_adapter = allocate_and_generate_new_lwe_keyswitch_key(
            &evaluation.as_lwe_secret_key(),
            &big.as_lwe_secret_key(),
            DecompositionBaseLog(4),
            DecompositionLevelCount(4),
            big_noise,
            CiphertextModulus::new_native(),
            generator,
        );
        let std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small,
            &refresh,
            DecompositionBaseLog(12),
            DecompositionLevelCount(3),
            gaussian_glwe(),
            CiphertextModulus::new_native(),
            generator,
        );
        let mut bsk = FourierLweBootstrapKey::new(
            LweDimension(710),
            GlweSize(3),
            PolynomialSize(N),
            DecompositionBaseLog(12),
            DecompositionLevelCount(3),
        );
        convert_standard_lwe_bootstrap_key_to_fourier(&std_bsk, &mut bsk);
        let autos = (1..=10)
            .map(|d| {
                let degree = (1 << d) + 1;
                let words: Vec<_> = refresh
                    .as_ref()
                    .chunks_exact(N)
                    .flat_map(|p| auto_poly(p, degree))
                    .collect();
                let switched_secret = GlweSecretKey::from_container(words, PolynomialSize(N));
                (
                    degree,
                    glwe_ks(&switched_secret, &refresh, 10, 4, generator),
                )
            })
            .collect();
        let ss_body = glwe_ks(&refresh, &evaluation, 13, 3, generator);
        let mut products = Vec::new();
        for secret_poly in refresh.as_ref().chunks_exact(N) {
            let mut product = Polynomial::new(0u64, PolynomialSize(N));
            polynomial_wrapping_mul(
                &mut product,
                &Polynomial::from_container(secret_poly),
                &Polynomial::from_container(evaluation.as_ref()),
            );
            products.extend(product.as_ref().iter().map(|x| x.wrapping_neg()));
        }
        let negative_products = GlweSecretKey::from_container(products, PolynomialSize(N));
        let ss_mask_negative_products = glwe_ks(&negative_products, &evaluation, 13, 3, generator);
        (
            Self {
                input_adapter,
                output_adapter,
                bsk,
                autos,
                ss_body,
                ss_mask_negative_products,
            },
            Secrets {
                small,
                refresh,
                evaluation,
            },
        )
    }
    pub fn nibble(&self, input: &Lwe) -> (Bits, NibbleEvidence) {
        self.nibble_with_backend(input, None)
    }
    pub fn nibble_with_backend(
        &self,
        input: &Lwe,
        acceleration: Option<&Acceleration>,
    ) -> (Bits, NibbleEvidence) {
        let (bits, evidence, _) = self.nibble_internal(input, acceleration, true);
        (bits, evidence.unwrap())
    }
    pub fn nibble_without_evidence(
        &self,
        input: &Lwe,
        acceleration: &Acceleration,
    ) -> (Bits, Times) {
        let (bits, evidence, times) = self.nibble_internal(input, Some(acceleration), false);
        assert!(evidence.is_none());
        (bits, times)
    }
    fn nibble_internal(
        &self,
        input: &Lwe,
        acceleration: Option<&Acceleration>,
        retain: bool,
    ) -> (Bits, Option<NibbleEvidence>, Times) {
        assert_eq!(input.lwe_size().0, 2049);
        let mut times = Times::default();
        let clock = Instant::now();
        // Existing normalized nibble is m*2^59. Scale the entire ciphertext,
        // then center each full-torus bin at (m+1/2)*2^60 before input KS.
        let mut full = input.clone();
        for word in full.as_mut() {
            *word = word.wrapping_mul(2);
        }
        *full.get_mut_body().data = full.get_body().data.wrapping_add(D);
        let mut small = Lwe::new(0, LweSize(711), CiphertextModulus::new_native());
        keyswitch_lwe_ciphertext(&self.input_adapter, &full, &mut small);
        times.input_adapter_s = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        // theta=1: the two gadget scales share one BR, with even rotation degrees.
        let mut acc = new_glwe(2);
        for (i, word) in acc.get_mut_body().as_mut().iter_mut().enumerate() {
            *word = (1u64 << (64 - 8 * (i % 2 + 1) - 1)).wrapping_neg();
        }
        let mut switched_degrees: Vec<usize> = small
            .as_ref()
            .iter()
            .map(|&x| {
                (tfhe::core_crypto::fft_impl::common::modulus_switch(x, CiphertextModulusLog(10))
                    << 1) as usize
            })
            .collect();
        // Algorithm6 mean compensation for the theta1 coarse modulus. Mean(s)=1/2.
        // error_i is (rounded mask_i - mask_i) in original torus units.
        let error_sum: i128 = small
            .get_mask()
            .as_ref()
            .iter()
            .zip(&switched_degrees)
            .map(|(&word, &degree)| {
                ((degree as u64).wrapping_mul(1u64 << 53).wrapping_sub(word) as i64) as i128
            })
            .sum();
        let mean_correction = (error_sum / 2) as u64;
        let corrected_body = small.get_body().data.wrapping_add(mean_correction);
        *switched_degrees.last_mut().unwrap() = (tfhe::core_crypto::fft_impl::common::modulus_switch(
            corrected_body,
            CiphertextModulusLog(10),
        ) << 1) as usize;
        let ms = ManySwitched(switched_degrees.clone());
        blind_rotate_assign(&ms, &mut acc, &self.bsk);
        let mut refreshed = Vec::new();
        for polynomial in G {
            let mut levels = Vec::new();
            for level in 1..=2 {
                let shifted = monomial(&acc, 2 * N - (level - 1));
                let mut output = new_glwe(2);
                for &(degree, sign) in polynomial {
                    let term = monomial(&shifted, degree);
                    for (dst, &src) in output.as_mut().iter_mut().zip(term.as_ref()) {
                        *dst = if sign == 1 {
                            dst.wrapping_add(src)
                        } else {
                            dst.wrapping_sub(src)
                        };
                    }
                }
                *output.get_mut_body().as_mut().first_mut().unwrap() =
                    output.get_body().as_ref()[0].wrapping_add(1u64 << (64 - 8 * level - 1));
                levels.push(output);
            }
            refreshed.push(levels);
        }
        times.refresh_s = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        let retained_refresh = retain.then(|| refreshed.clone());
        let mut traced = refreshed;
        for levels in &mut traced {
            for ct in levels {
                // Primary RevHomTrace source floors unsigned division by two.
                // This differs from the paper's nearest symbol by <=1/2 coefficient.
                for (auto_index, (degree, key)) in self.autos.iter().enumerate() {
                    for word in ct.as_mut() {
                        *word >>= 1;
                    }
                    let transformed = auto_glwe(ct, *degree);
                    let mut switched = new_glwe(2);
                    if let Some(cache) = acceleration {
                        cache.autos[auto_index].apply(&transformed, &mut switched);
                    } else {
                        keyswitch_glwe_ciphertext(key, &transformed, &mut switched);
                    }
                    glwe_ciphertext_add_assign(ct, &switched);
                }
            }
        }
        times.trace_s = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        let mut ggsws = Vec::new();
        let mut fourier = Vec::new();
        for levels in &traced {
            let mut ggsw = GgswCiphertext::new(
                0,
                GlweSize(2),
                PolynomialSize(N),
                DecompositionBaseLog(8),
                DecompositionLevelCount(2),
                CiphertextModulus::new_native(),
            );
            // TFHE1.7 physically stores gadget levels in descending order.
            for (idx, mut matrix) in ggsw.iter_mut().enumerate() {
                let src = &levels[1 - idx];
                let mut body = new_glwe(1);
                if let Some(cache) = acceleration {
                    cache.ss_body.apply(src, &mut body);
                } else {
                    keyswitch_glwe_ciphertext(&self.ss_body, src, &mut body);
                }
                let mut masks_only = src.clone();
                masks_only.get_mut_body().as_mut().fill(0);
                let mut mask = new_glwe(1);
                if let Some(cache) = acceleration {
                    cache
                        .ss_mask_negative_products
                        .apply(&masks_only, &mut mask);
                } else {
                    keyswitch_glwe_ciphertext(
                        &self.ss_mask_negative_products,
                        &masks_only,
                        &mut mask,
                    );
                }
                // phase(b,0) = -b*S'; negative-product KS adds sum(a_i*S_i*S').
                for (dst, &b) in mask
                    .get_mut_mask()
                    .as_mut()
                    .iter_mut()
                    .zip(src.get_body().as_ref())
                {
                    *dst = dst.wrapping_add(b);
                }
                let mut rows = matrix.as_mut_glwe_list();
                rows.get_mut(0).as_mut().copy_from_slice(mask.as_ref());
                rows.get_mut(1).as_mut().copy_from_slice(body.as_ref());
            }
            let mut transformed = FourierGgswCiphertext::new(
                GlweSize(2),
                PolynomialSize(N),
                DecompositionBaseLog(8),
                DecompositionLevelCount(2),
            );
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut transformed);
            if retain {
                ggsws.push(ggsw);
            }
            fourier.push(transformed);
        }
        times.dec_ss_s = clock.elapsed().as_secs_f64();
        let evidence = if retain {
            Some(NibbleEvidence {
                input: input.clone(),
                small,
                mean_correction,
                switched_degrees,
                refreshed: retained_refresh.unwrap(),
                traced,
                ggsws,
                times: times.clone(),
            })
        } else {
            None
        };
        (Bits { fourier }, evidence, times)
    }

    pub fn digit_sign(&self, left: &Bits, right: &Bits) -> (Lwe, Glwe, Times) {
        let mut times = Times::default();
        let clock = Instant::now();
        let mut table = new_glwe(1);
        for (coefficient, dst) in table.get_mut_body().as_mut().iter_mut().enumerate() {
            let index = coefficient / 4;
            let a = prefix_decode(index / 16);
            let b = prefix_decode(index % 16);
            *dst = ((a as i64 - b as i64).signum() as u64).wrapping_mul(D);
        }
        for (idx, bit) in left.fourier.iter().chain(&right.fourier).enumerate() {
            let degree = 4 * (1 << (7 - idx));
            let mut rotated = monomial(&table, 2 * N - degree);
            glwe_ciphertext_sub_assign(&mut rotated, &table);
            add_external_product_assign(&mut table, bit, &rotated);
        }
        let mut sample = Lwe::new(0, LweSize(N + 1), CiphertextModulus::new_native());
        extract_lwe_sample_from_glwe_ciphertext(&table, &mut sample, MonomialDegree(0));
        times.cmux_s = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        let mut output = Lwe::new(0, LweSize(2049), CiphertextModulus::new_native());
        keyswitch_lwe_ciphertext(&self.output_adapter, &sample, &mut output);
        times.output_adapter_s = clock.elapsed().as_secs_f64();
        (output, table, times)
    }
}
struct ManySwitched(Vec<usize>);
impl ModulusSwitchedLweCiphertext<usize> for ManySwitched {
    fn log_modulus(&self) -> CiphertextModulusLog {
        CiphertextModulusLog(11)
    }
    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.0.len() - 1)
    }
    fn body(&self) -> usize {
        *self.0.last().unwrap()
    }
    fn mask(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.0[..self.0.len() - 1].iter().copied()
    }
}
pub fn monomial(input: &Glwe, degree: usize) -> Glwe {
    let mut out = input.clone();
    for mut poly in out.as_mut_polynomial_list().iter_mut() {
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(degree));
    }
    out
}
pub fn prefix_encode(value: usize) -> usize {
    let mut prefix = 0;
    let mut out = 0;
    for bit in (0..4).rev() {
        prefix ^= (value >> bit) & 1;
        out = (out << 1) | prefix;
    }
    out
}
pub fn prefix_decode(value: usize) -> usize {
    value ^ (value >> 1)
}
pub fn phase(ct: &Glwe, secret: &GlweSecretKeyOwned<u64>) -> Vec<u64> {
    let mut words = PlaintextList::new(0, PlaintextCount(N));
    decrypt_glwe_ciphertext(secret, ct, &mut words);
    words.into_container()
}
pub fn distance(a: u64, b: u64) -> u64 {
    (a.wrapping_sub(b) as i64).unsigned_abs()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_prefix_family_all_bins() {
        for m in 0..16 {
            assert_eq!(prefix_decode(prefix_encode(m)), m);
            for (j, polynomial) in G.iter().enumerate() {
                let mut f = new_glwe(2);
                f.get_mut_body().as_mut().fill((-1i64) as u64);
                f = monomial(&f, 2 * N - (m * 128 + 64));
                let observed = polynomial.iter().fold(0u64, |a, &(d, s)| {
                    a.wrapping_add(monomial(&f, d).get_body().as_ref()[0].wrapping_mul(s as u64))
                });
                let expected = 2 * ((prefix_encode(m) >> (3 - j)) & 1) as i64 - 1;
                assert_eq!(observed as i64, expected, "m={m} prefix={j}");
            }
        }
    }
}
