// Public exact setup and record binding. This helper has no ciphertext or key.
#include "direct_coefficients.hpp"
struct DirectPolynomial {
  NTL::ZZX polynomial;
  std::vector<long> coefficients;
  std::string digest;
};

DirectPolynomial direct_polynomial() {
  const auto odd=a117::univariate_less_coefficients(kP);
  need(odd.size()==4095,"direct comparison odd coefficient count");
  NTL::ZZX polynomial;
  for(long j=0;j<4095;++j)NTL::SetCoeff(polynomial,2*j+1,odd[j]);
  NTL::SetCoeff(polynomial,8190,4096);
  need(NTL::deg(polynomial)==8190&&NTL::coeff(polynomial,0)==0,"direct comparison degree/zero");
  std::vector<long> coefficients;coefficients.reserve(8191);
  std::string bytes;bytes.reserve(2*8191);
  for(long i=0;i<8191;++i) {
    const long value=NTL::conv<long>(NTL::coeff(polynomial,i));
    need(value>=0&&value<kP&&value==kDirectCoefficients[i],"actual direct comparison coefficient");
    coefficients.push_back(value);
    bytes.push_back(static_cast<char>((value>>8)&255));bytes.push_back(static_cast<char>(value&255));
  }
  const auto digest=sha256(bytes);need(digest==kDirectCoefficientSha,"actual direct comparison digest");
  return {polynomial,coefficients,digest};
}

void direct_fields(Json& row,const DirectPolynomial& direct) {
  row.add("comparison_evaluator","helib::polyEval(Ctxt&,NTL::ZZX,const Ctxt&,long)")
      .add("comparison_baby_step_k",kDirectBabyStep).add("comparison_polynomial_degree",8190)
      .add("comparison_coefficient_count",static_cast<long>(direct.coefficients.size()))
      .add("comparison_coefficients",direct.coefficients)
      .add("comparison_coefficient_sha256_u16be",direct.digest)
      .add("comparison_source_structural_depth",13).add("comparison_expected_multiplyBy_calls",139);
  field(row,"comparison_capacity_prediction",nullptr);
}
