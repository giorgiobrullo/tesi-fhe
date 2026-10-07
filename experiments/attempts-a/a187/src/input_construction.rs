// A149 packed input construction block, byte-preserving apart from indentation.
{
// One real, nontrivial encrypted packed probe shared by all four public products.
// Public offsets target diagnostic score centers; this is not an enrollment scene.
let probe: Vec<i64> = (0..512).map(|i| if i % 2 == 0 { 1 } else { -1 }).collect();
let mut plaintext = vec![0u64; 2048];
for i in 0..512 {
    plaintext[i] = (probe[i] as u64).wrapping_shl(52);
    plaintext[1024 + i] = (probe[i] as u64).wrapping_shl(60);
}
let mut packed = GlweCiphertext::new(
    0,
    glwe_secret.glwe_dimension().to_glwe_size(),
    glwe_secret.polynomial_size(),
    modulus,
);
encrypt_glwe_ciphertext(
    &glwe_secret,
    &mut packed,
    &PlaintextList::from_container(plaintext),
    parameters.glwe_noise_distribution(),
    &mut generator,
);
let mut full = Vec::new();
let mut low = Vec::new();
for (i, x) in scores.iter().enumerate() {
    let mut template = vec![0i64; 512];
    template[..113 + i].fill(if i % 2 == 0 { 3 } else { -3 });
    let dot: i64 = probe.iter().zip(&template).map(|(a, b)| a * b).sum();
    let mut poly = vec![0u64; 2048];
    for j in 0..512 {
        poly[511 - j] = (-2 * template[j]) as u64;
    }
    let poly = Polynomial::from_container(poly);
    let mut product =
        GlweCiphertext::new(0, packed.glwe_size(), packed.polynomial_size(), modulus);
    for (mut out, input) in product
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(packed.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_mul_assign(&mut out, &input, &poly);
    }
    for (degree, log, outputs) in [(511, 52, &mut full), (1535, 60, &mut low)] {
        let mut ct =
            LweCiphertext::new(0, big_secret.lwe_dimension().to_lwe_size(), modulus);
        extract_lwe_sample_from_glwe_ciphertext(
            &product,
            &mut ct,
            MonomialDegree(degree),
        );
        lwe_ciphertext_plaintext_add_assign(
            &mut ct,
            Plaintext(((*x as i64 + 2 * dot) as u64).wrapping_shl(log)),
        );
        assert!(ct.get_mask().as_ref().iter().any(|v| *v != 0));
        outputs.push(ct);
    }
}
(full, low)
}
