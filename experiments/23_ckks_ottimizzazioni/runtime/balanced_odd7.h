#pragma once

#include "openfhe.h"
#include <array>

namespace ckks_polynomial_micro {

// Evaluates constant + c0*x + c1*x^3 + c2*x^5 + c3*x^7.
// FLEXIBLEAUTO defers rescaling to the ordinary EvalMult/EvalSquare interfaces.
// Compare GetLevel()+GetNoiseScaleDeg()-1, not GetLevel() alone.
// No input ciphertext is mutated by these interfaces.
// The expected effective-depth increment of three is a gate to verify.
inline lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvaluateOdd7Balanced(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& input,
    const std::array<double, 4>& coefficients,
    double constant = 0.0) {
    auto x2 = context->EvalSquare(input);
    auto x4 = context->EvalSquare(x2);
    auto c0x = context->EvalMult(input, coefficients[0]);
    auto c1x = context->EvalMult(input, coefficients[1]);
    auto c2x = context->EvalMult(input, coefficients[2]);
    auto c3x = context->EvalMult(input, coefficients[3]);
    auto lowCubic = context->EvalAdd(c0x, context->EvalMult(c1x, x2));
    auto highCubic = context->EvalAdd(c2x, context->EvalMult(c3x, x2));
    auto result = context->EvalAdd(lowCubic, context->EvalMult(highCubic, x4));
    if (constant != 0.0) result = context->EvalAdd(result, constant);
    return result;
}

}  // namespace ckks_polynomial_micro
