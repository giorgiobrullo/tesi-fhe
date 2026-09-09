#pragma once

#include "balanced_odd7.h"
#include <stdexcept>

namespace ckks_polynomial_micro {

inline lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ReduceBalancedOperandOnce(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& input) {
    const auto parameters = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(
        input->GetCryptoParameters());
    if (!parameters || parameters->GetScalingTechnique() != lbcrypto::FLEXIBLEAUTO ||
        parameters->GetCompositeDegree() != 1 ||
        (input->GetNoiseScaleDeg() != 1 && input->GetNoiseScaleDeg() != 2))
        throw std::runtime_error("Shared powers require ordinary degree-one/two FLEXIBLEAUTO CKKS");
    if (input->GetNoiseScaleDeg() == 1) return input;
    const auto towers = input->GetElements().at(0).GetNumOfElements();
    auto reduced = context->Compress(input, static_cast<uint32_t>(towers), 1);
    if (reduced->GetLevel() != input->GetLevel() + 1 || reduced->GetNoiseScaleDeg() != 1 ||
        reduced->GetElements().at(0).GetNumOfElements() + 1 != towers)
        throw std::runtime_error("Shared powers changed the expected rescale schedule");
    return reduced;
}

// Same balanced graph as v1. Its x2 operand used to be independently reduced
// for x4 and both cubic products. With FLEXIBLEAUTO, aligning c1x/c3x at L,
// degree2 against reduced x2 at L+1, degree1 performs exactly their old single
// reduction. The multiplication core then receives byte-identical operands.
inline lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvaluateOdd7SharedPowers(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& input,
    const std::array<double, 4>& coefficients,
    double constant = 0.0) {
    auto x = ReduceBalancedOperandOnce(context, input);
    auto x2 = context->EvalSquare(x);
    auto reducedX2 = ReduceBalancedOperandOnce(context, x2);
    auto x4 = context->EvalSquare(reducedX2);
    auto c0x = context->EvalMult(x, coefficients[0]);
    auto c1x = context->EvalMult(x, coefficients[1]);
    auto c2x = context->EvalMult(x, coefficients[2]);
    auto c3x = context->EvalMult(x, coefficients[3]);
    auto lowCubic = context->EvalAdd(c0x, context->EvalMult(c1x, reducedX2));
    auto highCubic = context->EvalAdd(c2x, context->EvalMult(c3x, reducedX2));
    auto result = context->EvalAdd(lowCubic, context->EvalMult(highCubic, x4));
    if (constant != 0.0) result = context->EvalAdd(result, constant);
    return result;
}

}  // namespace ckks_polynomial_micro
