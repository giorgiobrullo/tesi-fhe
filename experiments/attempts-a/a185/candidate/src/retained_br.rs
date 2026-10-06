// Native-u64 specialization of TFHE0.11.3 fft64/crypto/bootstrap.rs:286ff.
// Original BSD-3-Clause-Clear license is preserved in candidate/.
// The same body division, raw-mask zero branch, mask order, monomial difference,
// and Fourier external-product calls are retained. Owned scratch GLWEs replace
// temporary stack views. The returned receipt contains the degrees actually used.
// An unchanged stock BR on the same input/LUT/key is a mandatory byte control.
use tfhe::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_div;
include!("private_polynomial_helper.rs");
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign, add_external_product_assign_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::Fft;

struct A175Receipt {
    body: usize,
    masks: Vec<usize>,
    raw_mask_nonzero: Vec<bool>,
}

fn a175_retained_blind_rotate(
    input: &Lwe,
    lut: &mut Glwe,
    bsk: &FourierLweBootstrapKeyOwned,
) -> A175Receipt {
    assert!(input.ciphertext_modulus().is_native_modulus());
    assert!(lut.ciphertext_modulus().is_native_modulus());
    assert_eq!(input.lwe_size(), bsk.input_lwe_dimension().to_lwe_size());
    assert_eq!(lut.glwe_size(), bsk.glwe_size());
    assert_eq!(lut.polynomial_size(), bsk.polynomial_size());
    let polynomial_size = lut.polynomial_size();
    let body = pbs_modulus_switch(*input.get_body().data, polynomial_size);
    for mut poly in lut.as_mut_polynomial_list().iter_mut() {
        let temporary = Polynomial::from_container(poly.as_ref().to_vec());
        polynomial_wrapping_monic_monomial_div(&mut poly, &temporary, MonomialDegree(body));
    }
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        add_external_product_assign_scratch::<u64>(lut.glwe_size(), polynomial_size, fft)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let mut difference = GlweCiphertext::new(
        0u64,
        lut.glwe_size(),
        polynomial_size,
        lut.ciphertext_modulus(),
    );
    let mut receipt = A175Receipt {
        body,
        masks: Vec::with_capacity(input.lwe_size().0 - 1),
        raw_mask_nonzero: Vec::with_capacity(input.lwe_size().0 - 1),
    };
    for (word, ggsw) in input
        .get_mask()
        .as_ref()
        .iter()
        .zip(bsk.as_view().into_ggsw_iter())
    {
        let nonzero = *word != 0;
        receipt.raw_mask_nonzero.push(nonzero);
        if nonzero {
            let degree = pbs_modulus_switch(*word, polynomial_size);
            receipt.masks.push(degree);
            for (mut out, before) in difference
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(lut.as_polynomial_list().iter())
            {
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut out,
                    &before,
                    MonomialDegree(degree),
                );
            }
            add_external_product_assign(
                lut.as_mut_view(),
                ggsw,
                difference.as_view(),
                fft,
                buffers.stack(),
            );
        } else {
            // Stock skips the external product on raw zero, not on rounded zero.
            receipt.masks.push(0);
        }
    }
    receipt
}
