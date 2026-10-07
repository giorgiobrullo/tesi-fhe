pub(crate) fn polynomial_wrapping_monic_monomial_mul_and_subtract<Scalar, OutputCont, InputCont>(
    output: &mut Polynomial<OutputCont>,
    input: &Polynomial<InputCont>,
    monomial_degree: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    /// performs the operation: dst = -src - src_orig, with wrapping arithmetic
    fn copy_with_neg_and_subtract<Scalar: UnsignedInteger>(
        dst: &mut [Scalar],
        src: &[Scalar],
        src_orig: &[Scalar],
    ) {
        for ((dst, src), src_orig) in dst.iter_mut().zip(src).zip(src_orig) {
            *dst = src.wrapping_neg().wrapping_sub(*src_orig);
        }
    }

    /// performs the operation: dst = src - src_orig, with wrapping arithmetic
    fn copy_without_neg_and_subtract<Scalar: UnsignedInteger>(
        dst: &mut [Scalar],
        src: &[Scalar],
        src_orig: &[Scalar],
    ) {
        for ((dst, src), src_orig) in dst.iter_mut().zip(src).zip(src_orig) {
            *dst = src.wrapping_sub(*src_orig);
        }
    }

    assert!(
        output.polynomial_size() == input.polynomial_size(),
        "Output polynomial size {:?} is not the same as input polynomial size {:?}.",
        output.polynomial_size(),
        input.polynomial_size(),
    );

    let polynomial_size = output.polynomial_size().0;
    let remaining_degree = monomial_degree.0 % polynomial_size;

    let full_cycles_count = monomial_degree.0 / polynomial_size;
    if full_cycles_count % 2 == 0 {
        copy_with_neg_and_subtract(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
        copy_without_neg_and_subtract(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
    } else {
        copy_without_neg_and_subtract(
            &mut output[..remaining_degree],
            &input[polynomial_size - remaining_degree..],
            &input[..remaining_degree],
        );
        copy_with_neg_and_subtract(
            &mut output[remaining_degree..],
            &input[..polynomial_size - remaining_degree],
            &input[remaining_degree..],
        );
    }
}
