#pragma once

#include "balanced_odd7.h"
#include <stdexcept>

namespace ckks_polynomial_micro {

// OpenFHE 1.5.1 FLEXIBLEAUTO repeats this same reduction for EvalSquare
// and each of the four scalar EvalMult calls. Compress clones the input;
// current tower count prevents additional modulus truncation. The original
// balanced evaluator then receives exactly the degree-one input each branch
// would otherwise create independently.
inline lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvaluateOdd7SharedRescale(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& input,
    const std::array<double, 4>& coefficients,
    double constant = 0.0) {
    const auto parameters = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(
        input->GetCryptoParameters());
    if (!parameters || parameters->GetScalingTechnique() != lbcrypto::FLEXIBLEAUTO ||
        parameters->GetCompositeDegree() != 1)
        throw std::runtime_error("Shared rescale requires ordinary FLEXIBLEAUTO CKKS");
    if (input->GetNoiseScaleDeg() != 1 && input->GetNoiseScaleDeg() != 2)
        throw std::runtime_error("Unexpected balanced input noise-scale degree");

    auto reduced = input;
    if (input->GetNoiseScaleDeg() == 2) {
        const auto towers = input->GetElements().at(0).GetNumOfElements();
        reduced = context->Compress(input, static_cast<uint32_t>(towers), 1);
        if (reduced->GetLevel() != input->GetLevel() + 1 ||
            reduced->GetNoiseScaleDeg() != 1 ||
            reduced->GetElements().at(0).GetNumOfElements() + 1 != towers)
            throw std::runtime_error("Shared rescale changed the expected level schedule");
    }
    return EvaluateOdd7Balanced(context, reduced, coefficients, constant);
}

}  // namespace ckks_polynomial_micro
